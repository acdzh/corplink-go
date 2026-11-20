// Package panel 提供控制面板：JSON API 与手写 HTML 页面。
//
// 面板只依赖 HTTP 契约，浏览器、桌面壳（MyGo 原生窗口）都调同一组 /api/*，
// 这样 UI 形态可以随便换，核心逻辑不动。
package panel

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/acdzh/corplink-go/internal/agent"
	"github.com/acdzh/corplink-go/internal/api"
	"github.com/acdzh/corplink-go/internal/config"
	"github.com/acdzh/corplink-go/internal/login"
	"github.com/acdzh/corplink-go/internal/sign"
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
	// Client 是已登录的 API 客户端，用于代理节点图标等资源。
	Client *api.Client
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
			"state":        opts.Agent.State(),
			"logged_in":    opts.Agent.LoggedIn(),
			"error":        opts.Agent.LastError(),
			"mfa_pending":  opts.Login.Pending(),
			"mode":         opts.Agent.Mode(),
			"auto":         opts.Agent.Auto(),
			"company_name": opts.Config.CompanyName,
			"server":       opts.Config.Server,
			"proxy_addr":   fmt.Sprintf("%s:%d", opts.ProxyHost, opts.ProxyPort),
			"panel_addr":   opts.PanelHost,
			"has_totp":     opts.Config.Code != "",
		})
	})
	mux.HandleFunc("/api/routes", func(w http.ResponseWriter, _ *http.Request) {
		routes := opts.Agent.Routes()
		if routes == nil {
			routes = []string{}
		}
		domains := opts.Agent.Domains()
		if domains == nil {
			domains = []string{}
		}
		writeJSON(w, map[string]any{
			"routes":  routes,
			"domains": domains,
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
	mux.HandleFunc("/api/icon", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("u")
		if target == "" {
			http.NotFound(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		data, contentType, err := opts.Client.GetRaw(ctx, target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if contentType == "" {
			contentType = "image/png"
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete || (r.Method == http.MethodPost && r.URL.Query().Get("action") == "clear") {
			opts.Agent.ClearEvents()
			writeJSON(w, map[string]bool{"cleared": true})
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "只支持 GET/DELETE/POST", http.StatusMethodNotAllowed)
			return
		}
		events := opts.Agent.Events()
		if events == nil {
			events = []agent.Event{}
		}
		writeJSON(w, events)
	})
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, opts.Agent.Stats())
	})

	mux.HandleFunc("/api/latencies", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, opts.Agent.Latencies())
	})
	mux.HandleFunc("/api/latency/all", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		writeJSON(w, opts.Agent.PingAll(ctx))
	})
	mux.HandleFunc("/api/connect", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("node")
		if err := opts.Agent.Connect(r.Context(), name); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// 记住用户选择，重启后沿用。
		opts.Config.Mode = name
		if err := opts.Config.Save(); err != nil {
			fmt.Printf("保存连接模式失败: %v\n", err)
		}
		writeJSON(w, opts.Agent.State())
	})
	mux.HandleFunc("/api/disconnect", func(w http.ResponseWriter, _ *http.Request) {
		opts.Agent.Disconnect()
		writeJSON(w, opts.Agent.State())
	})
	mux.HandleFunc("/api/latency", func(w http.ResponseWriter, r *http.Request) {
		ms, err := opts.Agent.Ping(r.Context(), r.URL.Query().Get("node"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
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
	mux.HandleFunc("/clash.yml", func(w http.ResponseWriter, _ *http.Request) {
		// 防回环：把控制面域名与全部节点 IP 置顶为直连。
		var directDomains []string
		if u, err := neturl.Parse(opts.Config.Server); err == nil && u.Hostname() != "" {
			directDomains = append(directDomains, u.Hostname())
		}
		var nodeIPs []string
		for _, n := range opts.Agent.Nodes() {
			nodeIPs = append(nodeIPs, n.IP)
			nodeIPs = append(nodeIPs, n.BackupIPs...)
		}

		body := sub.Clash(sub.Options{
			DirectDomains: directDomains,
			NodeIPs:       nodeIPs,
			Host:          opts.ProxyHost,
			Port:          opts.ProxyPort,
			Username:      opts.Config.SocksUser,
			Password:      opts.Config.SocksPass,
			Routes:        opts.Agent.Routes(),
			Domains:       opts.Agent.Domains(),
		})
		writeSubscription(w, body)
	})

	mux.HandleFunc("/api/login/methods", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "只支持 GET", http.StatusMethodNotAllowed)
			return
		}
		methods, err := opts.Login.Methods(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]any{"methods": methods})
	})
	mux.HandleFunc("/api/login/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "只支持 POST", http.StatusMethodNotAllowed)
			return
		}
		info, err := opts.Login.StartWithInfo(r.Context(), r.URL.Query().Get("alias"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, info)
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
	mux.HandleFunc("/api/login/mfa/send", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "只支持 POST", http.StatusMethodNotAllowed)
			return
		}
		var in struct {
			Type string `json:"type"`
		}
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&in)
		}
		if err := opts.Login.SendMFA(r.Context(), strings.TrimSpace(in.Type)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]bool{"sent": true})
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
		restart, err := applySettings(r.Context(), opts.Client, opts.Config, in)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := opts.Config.Save(); err != nil {
			http.Error(w, "保存配置: "+err.Error(), http.StatusInternalServerError)
			return
		}
		opts.Agent.LogEvent("info", "已保存系统配置")
		writeJSON(w, map[string]any{
			"saved":            true,
			"restart_required": restart,
			"company_name":     opts.Config.CompanyName,
			"server":           opts.Config.Server,
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
			"url": fmt.Sprintf("http://%s/clash.yml", opts.PanelHost),
		})
	})

	if static, err := fs.Sub(assets, "static"); err == nil {
		mux.Handle("/", http.FileServer(http.FS(static)))
	}
	return mux
}

// writeSubscription 按常见订阅惯例回写标题等响应头，
// 这样 Clash Verge 等客户端导入时会自动用上配置名，而不是拿 URL 当名字。
func writeSubscription(w http.ResponseWriter, body string) {
	name := sub.Title
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte(name)))
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+neturl.PathEscape(name))
	w.Header().Set("Profile-Update-Interval", "24")
	w.Header().Set("Cache-Control", "private, no-cache, no-transform")
	_, _ = w.Write([]byte(body))
}

// writeJSON 输出 JSON 响应。
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// settingsPayload 是面板提交的配置字段。
//
// 字段用指针：区分"没提交"和"提交了空值"，避免部分更新把其他项清空。
type settingsPayload struct {
	// CompanyName 是企业标识，用于解析服务端地址。
	CompanyName *string `json:"company_name"`
	// Server 是企业服务端地址，留空可由企业代码自动解析。
	Server *string `json:"server"`
	// ActivateCode 是设备激活标识。
	ActivateCode *string `json:"activate_code"`
	// ProxyListen 是混合代理监听地址。
	ProxyListen *string `json:"proxy_listen"`
	// PanelListen 是控制面板监听地址。
	PanelListen *string `json:"panel_listen"`
	// AutoModeIntervalSeconds 是测速间隔（秒）。
	AutoModeIntervalSeconds *int `json:"auto_mode_interval_seconds"`
	// KeepaliveSeconds 是会话保活间隔（秒）。
	KeepaliveSeconds *int `json:"keepalive_seconds"`
	// SocksUser 与 SocksPass 是代理认证。
	SocksUser *string `json:"socks5_username"`
	SocksPass *string `json:"socks5_password"`
	// LogLevel 是日志级别。
	LogLevel *string `json:"log_level"`
	// DeviceModel 与 DeviceBrand 影响 UA 与 query 上报。
	DeviceModel *string `json:"device_model"`
	DeviceBrand *string `json:"device_brand"`
	// OSVersion 与 OSPatch 是系统 API level 与补丁日期。
	OSVersion *string `json:"os_version"`
	OSPatch   *string `json:"os_version_patch"`
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
		CompanyName:             &cfg.CompanyName,
		Server:                  &cfg.Server,
		ActivateCode:            &cfg.ActivateCode,
		ProxyListen:             &proxyListen,
		PanelListen:             &panelListen,
		AutoModeIntervalSeconds: &cfg.AutoModeIntervalSeconds,
		KeepaliveSeconds:        &cfg.KeepaliveSeconds,
		SocksUser:               &cfg.SocksUser,
		SocksPass:               &cfg.SocksPass,
		LogLevel:                &cfg.LogLevel,
		DeviceModel:             &cfg.DeviceModel,
		DeviceBrand:             &cfg.DeviceBrand,
		OSVersion:               &cfg.OSVersion,
		OSPatch:                 &cfg.OSPatch,
	}
}

// ptr 返回字符串指针，便于构造部分更新字段。
func ptr(v string) *string {
	return &v
}

// applySettings 校验并写入配置，返回需要重启才生效的字段名。
func applySettings(ctx context.Context, client *api.Client, cfg *config.Config, in settingsPayload) ([]string, error) {
	restart := make([]string, 0, 4)
	oldCompany := cfg.CompanyName
	oldServer := cfg.Server
	oldActivate := cfg.ActivateCode

	if in.CompanyName != nil {
		cfg.CompanyName = strings.TrimSpace(*in.CompanyName)
	}
	if in.Server != nil {
		cfg.Server = strings.TrimSpace(*in.Server)
	}
	if in.ActivateCode != nil {
		cfg.ActivateCode = strings.TrimSpace(*in.ActivateCode)
	}
	companyChanged := cfg.CompanyName != oldCompany
	serverNotManuallyChanged := in.Server == nil || strings.TrimSpace(*in.Server) == oldServer
	if cfg.CompanyName != "" && (cfg.Server == "" || (companyChanged && serverNotManuallyChanged)) {
		info, err := api.MatchCompany(ctx, cfg.CompanyName)
		if err != nil {
			return nil, fmt.Errorf("解析企业代码 %q 失败: %w", cfg.CompanyName, err)
		}
		cfg.Server = info.Domain
	}
	if cfg.Server != oldServer && client != nil {
		if err := client.SetServer(cfg.Server); err != nil {
			return nil, err
		}
	}
	if (cfg.ActivateCode != oldActivate || cfg.CompanyName != oldCompany) && client != nil {
		activate := cfg.ActivateCode
		if activate == "" {
			activate = cfg.CompanyName
		}
		client.SetSigner(sign.NewSigner(activate, cfg.DeviceID))
	}

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
	if in.AutoModeIntervalSeconds != nil && *in.AutoModeIntervalSeconds != cfg.AutoModeIntervalSeconds {
		if *in.AutoModeIntervalSeconds < 0 {
			return nil, fmt.Errorf("自动选路间隔不能为负")
		}
		cfg.AutoModeIntervalSeconds = *in.AutoModeIntervalSeconds
		restart = append(restart, "auto_mode_interval_seconds")
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
	if in.DeviceModel != nil {
		v := strings.TrimSpace(*in.DeviceModel)
		if v != "" && v != cfg.DeviceModel {
			cfg.DeviceModel = v
			restart = append(restart, "device_model")
		}
	}
	if in.DeviceBrand != nil {
		v := strings.TrimSpace(*in.DeviceBrand)
		if v != "" && v != cfg.DeviceBrand {
			cfg.DeviceBrand = v
			restart = append(restart, "device_brand")
		}
	}
	if in.OSVersion != nil {
		v := strings.TrimSpace(*in.OSVersion)
		if v != "" && v != cfg.OSVersion {
			cfg.OSVersion = v
			restart = append(restart, "os_version")
		}
	}
	if in.OSPatch != nil {
		v := strings.TrimSpace(*in.OSPatch)
		if v != "" && v != cfg.OSPatch {
			cfg.OSPatch = v
			restart = append(restart, "os_version_patch")
		}
	}
	return restart, nil
}
