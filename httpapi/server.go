// Package httpapi 把 corplink.Client 暴露成 HTTP JSON 契约。
//
// 库本身不含任何监听与序列化：这一层只做编码、可选的令牌校验与静态资源，
// 监听到哪里由端侧决定（CLI 监听本机端口，Android 可以完全不启用）。
package httpapi

import (
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"time"

	"github.com/acdzh/corplink-go/corplink"
)

// 鉴权参数。令牌为空时整个面板不校验，直接用浏览器打开即可。
const (
	// tokenHeader 是携带令牌的请求头，供命令行与脚本使用。
	tokenHeader = "X-Corplink-Token"
	// tokenQuery 是首次打开页面时携带令牌的查询参数。
	tokenQuery = "token"
	// tokenCookie 是校验通过后写入的会话 Cookie，页面内的 fetch 依赖它。
	tokenCookie = "corplink_token"
	// shutdownTimeout 是关闭 HTTP 服务的等待上限。
	shutdownTimeout = 5 * time.Second
)

//go:embed static/*
var assets embed.FS

// Server 是控制面板的 HTTP 层。
type Server struct {
	// Token 是访问令牌；为空表示不校验，任何请求直接放行。
	Token string
	// PanelAddr 是面板对外的监听地址，用于拼订阅链接。
	PanelAddr string
	// Static 覆盖内置静态资源；为空时用包内嵌的控制面板页面。
	Static fs.FS
}

// AccessToken 返回当前生效的令牌，为空表示面板不校验。
func (s *Server) AccessToken() string { return s.Token }

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
	return s.guard(mux)
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

// guard 在配置了令牌时校验请求：请求头、查询参数与 Cookie 任一命中即可。
// 带查询参数的一次性访问会换成 Cookie，页面里的 fetch 就不用再拼 token。
func (s *Server) guard(next http.Handler) http.Handler {
	if s.Token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented := s.presentedToken(r)
		if subtle.ConstantTimeCompare([]byte(presented), []byte(s.Token)) != 1 {
			http.Error(w, "无效的面板令牌：请用带 token 参数的地址打开面板", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get(tokenQuery) != "" {
			http.SetCookie(w, &http.Cookie{
				Name:     tokenCookie,
				Value:    s.Token,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
		}
		next.ServeHTTP(w, r)
	})
}

// presentedToken 提取请求携带的令牌。
func (s *Server) presentedToken(r *http.Request) string {
	if v := r.Header.Get(tokenHeader); v != "" {
		return v
	}
	if v := r.URL.Query().Get(tokenQuery); v != "" {
		return v
	}
	if ck, err := r.Cookie(tokenCookie); err == nil {
		return ck.Value
	}
	return ""
}
