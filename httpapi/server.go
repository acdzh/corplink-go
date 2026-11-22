// Package httpapi 把 corplink.Client 暴露成 HTTP JSON 契约。
//
// 库本身不含任何监听与序列化：这一层只做编码与静态资源，
// 监听到哪里由端侧决定（CLI 监听本机端口，Android 可以完全不启用）。
package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
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

// Server 是控制面板的 HTTP 层。
//
// 默认不鉴权（只监听本机时够用）；一旦通过 -panel-auth 配了用户名密码，
// 所有请求都要先过 HTTP Basic Auth —— 面板能改配置、能断连接，
// 监听 0.0.0.0 又没鉴权等于把隧道控制权交给整个局域网。
type Server struct {
	// PanelAddr 是面板对外的监听地址，用于拼订阅链接。
	PanelAddr string
	// Static 覆盖内置静态资源；为空时用包内嵌的控制面板页面。
	Static fs.FS
	// User 与 Pass 非空时启用 Basic Auth。
	User string
	Pass string
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
	if s.User != "" || s.Pass != "" {
		return basicAuth(mux, s.User, s.Pass)
	}
	return mux
}

// basicAuth 给处理器加一层 HTTP Basic Auth。
//
// 用 subtle.ConstantTimeCompare 比较摘要，避免按响应时间逐字符猜密码。
func basicAuth(next http.Handler, user, pass string) http.Handler {
	want := sha256.Sum256([]byte(user + ":" + pass))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, pwd, ok := r.BasicAuth()
		if ok {
			got := sha256.Sum256([]byte(name + ":" + pwd))
			if subtle.ConstantTimeCompare(got[:], want[:]) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="corplink"`)
		http.Error(w, "需要认证", http.StatusUnauthorized)
	})
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
