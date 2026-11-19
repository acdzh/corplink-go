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
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/acdzh/corplink-go/internal/agent"
	"github.com/acdzh/corplink-go/internal/config"
	"github.com/acdzh/corplink-go/internal/login"
	"github.com/acdzh/corplink-go/internal/sub"
	"github.com/acdzh/corplink-go/internal/totp"
)

//go:embed static/*
var assets embed.FS

// Options 是构造面板所需的参数。
type Options struct {
	// Agent 是隧道管理器。
	Agent *agent.Agent
	// Login 是登录流程服务。
	Login *login.Service
	// Config 是运行配置。
	Config *config.Config
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
			"state":       opts.Agent.State(),
			"logged_in":   opts.Agent.LoggedIn(),
			"error":       opts.Agent.LastError(),
			"mfa_pending": opts.Login.Pending(),
		})
	})
	mux.HandleFunc("/api/nodes", func(w http.ResponseWriter, _ *http.Request) {
		nodes := opts.Agent.Nodes()
		out := make([]map[string]any, 0, len(nodes))
		for _, n := range nodes {
			name := n.EnName
			if name == "" {
				name = n.Name
			}
			if name == "" {
				name = n.IP
			}
			out = append(out, map[string]any{
				"name":          name,
				"raw_name":      n.Name,
				"ip":            n.IP,
				"internal_ip":   n.InternalIP,
				"domain_name":   n.DomainName,
				"tag":           n.TagName,
				"type":          n.Type,
				"icon":          n.Icon,
				"protocol_mode": n.ProtocolMode,
				"api_port":      n.APIPort,
				"vpn_port":      n.VPNPort,
			})
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, opts.Agent.Stats())
	})
	mux.HandleFunc("/api/latency/all", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		writeJSON(w, opts.Agent.LatencyAll(ctx))
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
	mux.HandleFunc("/sub", func(w http.ResponseWriter, _ *http.Request) {
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
	mux.HandleFunc("/api/login/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "只支持 POST", http.StatusMethodNotAllowed)
			return
		}
		url, err := opts.Login.Start(r.Context(), r.URL.Query().Get("alias"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"url": url})
	})
	mux.HandleFunc("/api/login/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "只支持 POST", http.StatusMethodNotAllowed)
			return
		}
		var in struct {
			Callback string `json:"callback"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "解析请求体: "+err.Error(), http.StatusBadRequest)
			return
		}
		result, err := opts.Login.Callback(r.Context(), in.Callback)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, result)
	})
	mux.HandleFunc("/api/login/mfa", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "只支持 POST", http.StatusMethodNotAllowed)
			return
		}
		var in struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "解析请求体: "+err.Error(), http.StatusBadRequest)
			return
		}
		code := strings.TrimSpace(in.Code)
		if code == "" && opts.Config.Code != "" {
			// 未填写时用已保存的 TOTP secret 自动生成。
			generated, _, err := totp.Code(opts.Config.Code, time.Now())
			if err != nil {
				http.Error(w, "生成 TOTP: "+err.Error(), http.StatusInternalServerError)
				return
			}
			code = generated
		}
		result, err := opts.Login.MFA(r.Context(), code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, result)
	})
	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "只支持 POST", http.StatusMethodNotAllowed)
			return
		}
		if err := opts.Login.Logout(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]bool{"logged_in": false})
	})
	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, currentSettings(opts.Config))
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "只支持 GET/POST", http.StatusMethodNotAllowed)
			return
		}
		var in settingsPayload
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "解析请求体: "+err.Error(), http.StatusBadRequest)
			return
		}
		restart, err := applySettings(opts.Config, in)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := opts.Config.Save(); err != nil {
			http.Error(w, "保存配置: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"saved":            true,
			"restart_required": restart,
		})
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
			"url": fmt.Sprintf("http://%s/sub", opts.PanelHost),
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

// settingsPayload 是面板提交的配置字段。
// settingsPayload 是面板提交的配置字段。
//
// 字段用指针：区分"没提交"和"提交了空值"，避免部分更新把其他项清空。
type settingsPayload struct {
	// ProxyListen 是混合代理监听地址。
	ProxyListen *string `json:"proxy_listen"`
	// PanelListen 是控制面板监听地址。
	PanelListen *string `json:"panel_listen"`
	// AutoNode 是启动时自动连接的节点。
	AutoNode *string `json:"auto_node"`
	// KeepaliveSeconds 是会话保活间隔（秒）。
	KeepaliveSeconds *int `json:"keepalive_seconds"`
	// SocksUser 与 SocksPass 是代理认证。
	SocksUser *string `json:"socks5_username"`
	SocksPass *string `json:"socks5_password"`
	// LogLevel 是日志级别。
	LogLevel *string `json:"log_level"`
}

// currentSettings 返回可编辑的配置快照。
func currentSettings(cfg *config.Config) settingsPayload {
	proxyListen := cfg.SocksListen
	panelListen := cfg.PanelListen
	if proxyListen == "" {
		proxyListen = "127.0.0.1:3710"
	}
	if panelListen == "" {
		panelListen = "127.0.0.1:13140"
	}
	return settingsPayload{
		ProxyListen:      &proxyListen,
		PanelListen:      &panelListen,
		AutoNode:         &cfg.AutoNode,
		KeepaliveSeconds: &cfg.KeepaliveSeconds,
		SocksUser:        &cfg.SocksUser,
		SocksPass:        &cfg.SocksPass,
		LogLevel:         &cfg.LogLevel,
	}
}

// ptr 返回字符串指针，便于构造部分更新字段。
func ptr(v string) *string { return &v }

// applySettings 校验并写入配置，返回需要重启才生效的字段名。
func applySettings(cfg *config.Config, in settingsPayload) ([]string, error) {
	restart := make([]string, 0, 4)
	if in.ProxyListen != nil {
		v := strings.TrimSpace(*in.ProxyListen)
		if v != "" && v != cfg.SocksListen {
			if _, _, err := net.SplitHostPort(v); err != nil {
				return nil, fmt.Errorf("代理监听地址非法: %w", err)
			}
			cfg.SocksListen = v
			restart = append(restart, "proxy_listen")
		}
	}
	if in.PanelListen != nil {
		v := strings.TrimSpace(*in.PanelListen)
		if v != "" && v != cfg.PanelListen {
			if _, _, err := net.SplitHostPort(v); err != nil {
				return nil, fmt.Errorf("面板监听地址非法: %w", err)
			}
			cfg.PanelListen = v
			restart = append(restart, "panel_listen")
		}
	}
	if in.AutoNode != nil {
		v := strings.TrimSpace(*in.AutoNode)
		if v != cfg.AutoNode {
			cfg.AutoNode = v
			restart = append(restart, "auto_node")
		}
	}
	if in.KeepaliveSeconds != nil && *in.KeepaliveSeconds != cfg.KeepaliveSeconds {
		if *in.KeepaliveSeconds < 0 {
			return nil, fmt.Errorf("保活间隔不能为负")
		}
		cfg.KeepaliveSeconds = *in.KeepaliveSeconds
		restart = append(restart, "keepalive_seconds")
	}
	if in.SocksUser != nil && in.SocksPass != nil && (*in.SocksUser != cfg.SocksUser || *in.SocksPass != cfg.SocksPass) {
		cfg.SocksUser = *in.SocksUser
		cfg.SocksPass = *in.SocksPass
		restart = append(restart, "socks5_auth")
	}
	if in.LogLevel != nil {
		v := strings.TrimSpace(*in.LogLevel)
		if v != "" && v != cfg.LogLevel {
			cfg.LogLevel = v
			restart = append(restart, "log_level")
		}
	}
	return restart, nil
}
