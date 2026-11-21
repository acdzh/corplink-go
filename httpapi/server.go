// Package httpapi 把 corplink.Client 暴露成 HTTP JSON 契约。
//
// 库本身不含任何监听与序列化：这一层只做编码与静态资源，
// 监听到哪里由端侧决定（CLI 监听本机端口，Android 可以完全不启用）。
package httpapi

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"time"

	"github.com/acdzh/corplink-go/corplink"
)

// shutdownTimeout 是关闭 HTTP 服务的等待上限。
const shutdownTimeout = 5 * time.Second

//go:embed static/*
var assets embed.FS

// Server 是控制面板的 HTTP 层，不做任何鉴权。
type Server struct {
	// PanelAddr 是面板对外的监听地址，用于拼订阅链接。
	PanelAddr string
	// Static 覆盖内置静态资源；为空时用包内嵌的控制面板页面。
	Static fs.FS
}

// Handler 返回面板的 HTTP 处理器。
func (s *Server) Handler(c *corplink.Client) http.Handler {
	mux := http.NewServeMux()
	registerAPI(mux, s, c)

	static := s.Static
	if static == nil {
		if sub, err := fs.Sub(assets, "static"); err == nil {
			static = sub
		}
	}
	if static != nil {
		mux.Handle("/", http.FileServer(http.FS(static)))
	}
	return mux
}

// Serve 在 addr 上提供面板服务，ctx 结束后优雅关闭。
func (s *Server) Serve(ctx context.Context, addr string, c *corplink.Client) error {
	if addr != "" {
		s.PanelAddr = addr
	}
	srv := &http.Server{Addr: addr, Handler: s.Handler(c)}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
