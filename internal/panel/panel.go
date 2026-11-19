// Package panel 提供控制面板：JSON API 与手写 HTML 页面。
//
// 面板只依赖 HTTP 契约，浏览器、桌面壳（MyGo 原生窗口）都调同一组 /api/*，
// 这样 UI 形态可以随便换，核心逻辑不动。
package panel

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/acdzh/corplink-go/internal/agent"
	"github.com/acdzh/corplink-go/internal/config"
	"github.com/acdzh/corplink-go/internal/sub"
	"github.com/acdzh/corplink-go/internal/totp"
)

//go:embed static/*
var assets embed.FS

// Options 是构造面板所需的参数。
type Options struct {
	// Agent 是隧道管理器。
	Agent *agent.Agent
	// Config 是运行配置。
	Config *config.Config
	// Token 是订阅路径里的随机标识。
	Token string
	// ProxyHost 与 ProxyPort 是订阅里写的代理地址。
	ProxyHost string
	ProxyPort int
	// PanelHost 是面板自身地址，用于展示订阅链接。
	PanelHost string
}

// Handler 返回面板的 HTTP 处理器。
func Handler(opts Options) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"state":     opts.Agent.State(),
			"logged_in": opts.Agent.LoggedIn(),
			"error":     opts.Agent.LastError(),
		})
	})
	mux.HandleFunc("/api/nodes", func(w http.ResponseWriter, _ *http.Request) {
		type item struct {
			Name     string `json:"name"`
			IP       string `json:"ip"`
			Protocol int    `json:"protocol_mode"`
		}
		nodes := opts.Agent.Nodes()
		out := make([]item, 0, len(nodes))
		for _, n := range nodes {
			name := n.EnName
			if name == "" {
				name = n.Name
			}
			if name == "" {
				name = n.IP
			}
			out = append(out, item{Name: name, IP: n.IP, Protocol: n.ProtocolMode})
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("/api/connect", func(w http.ResponseWriter, r *http.Request) {
		if err := opts.Agent.Connect(r.Context(), r.URL.Query().Get("node")); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, opts.Agent.State())
	})
	mux.HandleFunc("/api/disconnect", func(w http.ResponseWriter, _ *http.Request) {
		opts.Agent.Disconnect()
		writeJSON(w, opts.Agent.State())
	})
	mux.HandleFunc("/api/latency", func(w http.ResponseWriter, r *http.Request) {
		ms, err := opts.Agent.Latency(r.Context(), r.URL.Query().Get("node"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]int64{"ms": ms})
	})
	mux.HandleFunc("/api/refresh", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		if err := opts.Agent.RefreshNodes(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]int{"nodes": len(opts.Agent.Nodes())})
	})
	mux.HandleFunc("/sub/"+opts.Token, func(w http.ResponseWriter, _ *http.Request) {
		body := sub.Single(sub.SingleOptions{
			Name:     "CORPLINK",
			Host:     opts.ProxyHost,
			Port:     opts.ProxyPort,
			Username: opts.Config.SocksUser,
			Password: opts.Config.SocksPass,
			Routes:   opts.Agent.Routes(),
			Domains:  opts.Agent.Domains(),
		})
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("/api/totp", func(w http.ResponseWriter, _ *http.Request) {
		if opts.Config.Code == "" {
			writeJSON(w, map[string]any{"has_secret": false})
			return
		}
		code, remaining, err := totp.Code(opts.Config.Code, time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"has_secret": true, "code": code, "remaining": remaining})
	})
	mux.HandleFunc("/api/sub", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{
			"url": fmt.Sprintf("http://%s/sub/%s", opts.PanelHost, opts.Token),
		})
	})

	if static, err := fs.Sub(assets, "static"); err == nil {
		mux.Handle("/", http.FileServer(http.FS(static)))
	}
	return mux
}

// writeJSON 输出 JSON 响应。
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
