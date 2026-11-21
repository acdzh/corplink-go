// Package httpapi 把 corplink.Client 暴露成 HTTP JSON 契约。
//
// 库本身不含任何监听与序列化：这一层只做令牌鉴权、编码与静态资源，
// 监听到哪里由端侧决定（CLI 监听本机端口，Android 可以完全不启用）。
package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/http"
	"sync"
	"time"

	"github.com/acdzh/corplink-go/corplink"
)

// 鉴权参数。
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
	// Token 是访问令牌；为空时 Handler 生成随机令牌，只用一次进程生命周期。
	Token string
	// PanelAddr 是面板对外的监听地址，用于拼订阅链接。
	PanelAddr string
	// Static 覆盖内置静态资源；为空时用包内嵌的控制面板页面。
	Static fs.FS

	// tokenOnce 保证随机令牌只生成一次，避免并发请求拿到不同的值。
	tokenOnce sync.Once
	// token 是实际生效的令牌。
	token string
}

// AccessToken 返回实际生效的令牌，端侧据此打印带令牌的地址。
func (s *Server) AccessToken() string { return s.ensureToken() }

// ensureToken 解析配置的令牌，为空时生成一次性随机令牌。
func (s *Server) ensureToken() string {
	s.tokenOnce.Do(func() {
		s.token = s.Token
		if s.token == "" {
			s.token = randomToken()
		}
	})
	return s.token
}

// Handler 返回面板的 HTTP 处理器；所有路径都要求令牌。
func (s *Server) Handler(c *corplink.Client) http.Handler {
	s.ensureToken()
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

// guard 校验令牌：请求头、查询参数与 Cookie 任一命中即可，
// 带查询参数的一次性访问会换成 Cookie，页面里的 fetch 就不用再拼 token。
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented := s.presentedToken(r)
		if subtle.ConstantTimeCompare([]byte(presented), []byte(s.ensureToken())) != 1 {
			http.Error(w, "无效的面板令牌：请用带 token 参数的地址打开面板", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get(tokenQuery) != "" {
			http.SetCookie(w, &http.Cookie{
				Name:     tokenCookie,
				Value:    s.ensureToken(),
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

// randomToken 生成 32 位十六进制令牌。
func randomToken() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// 随机源不可用时退回时间戳，仍比无鉴权好。
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(buf[:])
}
