package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"time"

	"github.com/acdzh/corplink-go/corplink"
	"github.com/acdzh/corplink-go/corplink/sub"
)

// 请求超时。
const (
	// pingAllTimeout 是全量测速的请求上限。
	pingAllTimeout = 20 * time.Second
	// refreshTimeout 是刷新节点列表的请求上限。
	refreshTimeout = 20 * time.Second
	// iconTimeout 是代取节点图标的请求上限。
	iconTimeout = 10 * time.Second
)

// registerAPI 注册全部 JSON 路由。
func registerAPI(mux *http.ServeMux, s *Server, c *corplink.Client) {
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, _ *http.Request) {
		st := c.Status()
		writeJSON(w, map[string]any{
			"state":        st.State,
			"logged_in":    st.LoggedIn,
			"error":        st.Error,
			"mfa_pending":  st.MFAPending,
			"mode":         st.Mode,
			"auto":         st.Auto,
			"company_name": st.CompanyName,
			"server":       st.Server,
			"proxy_addr":   st.ProxyAddr,
			"panel_addr":   s.PanelAddr,
			"has_totp":     st.HasTOTP,
		})
	})
	mux.HandleFunc("/api/routes", func(w http.ResponseWriter, _ *http.Request) {
		routes := c.Routes()
		if routes == nil {
			routes = []string{}
		}
		domains := c.Domains()
		if domains == nil {
			domains = []string{}
		}
		writeJSON(w, map[string]any{
			"routes":  routes,
			"domains": domains,
		})
	})
	mux.HandleFunc("/api/nodes", func(w http.ResponseWriter, _ *http.Request) {
		nodes := c.Nodes()
		if nodes == nil {
			nodes = []corplink.Node{}
		}
		writeJSON(w, nodes)
	})
	mux.HandleFunc("/api/icon", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("u")
		if target == "" {
			http.NotFound(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), iconTimeout)
		defer cancel()
		data, contentType, err := c.FetchIcon(ctx, target)
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
			c.ClearEvents()
			writeJSON(w, map[string]bool{"cleared": true})
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "只支持 GET/DELETE/POST", http.StatusMethodNotAllowed)
			return
		}
		events := c.Events()
		if events == nil {
			events = []corplink.Event{}
		}
		writeJSON(w, events)
	})
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, c.Stats())
	})
	mux.HandleFunc("/api/latencies", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, c.Latencies())
	})
	mux.HandleFunc("/api/latency/all", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), pingAllTimeout)
		defer cancel()
		writeJSON(w, c.PingAll(ctx))
	})
	mux.HandleFunc("/api/connect", func(w http.ResponseWriter, r *http.Request) {
		if err := c.Connect(r.Context(), r.URL.Query().Get("node")); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, c.State())
	})
	mux.HandleFunc("/api/disconnect", func(w http.ResponseWriter, _ *http.Request) {
		c.Disconnect()
		writeJSON(w, c.State())
	})
	mux.HandleFunc("/api/latency", func(w http.ResponseWriter, r *http.Request) {
		ms, err := c.Ping(r.Context(), r.URL.Query().Get("node"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]int64{"ms": ms})
	})
	mux.HandleFunc("/api/refresh", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), refreshTimeout)
		defer cancel()
		if err := c.RefreshNodes(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]int{"nodes": len(c.Nodes())})
	})
	mux.HandleFunc("/clash.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeSubscription(w, c.ClashProfile())
	})

	mux.HandleFunc("/api/login/methods", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "只支持 GET", http.StatusMethodNotAllowed)
			return
		}
		methods, err := c.LoginMethods(r.Context())
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
		info, err := c.LoginStart(r.Context(), r.URL.Query().Get("alias"))
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
		result, err := c.LoginCallback(r.Context(), in.Callback)
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
		if err := c.LoginSendMFA(r.Context(), in.Type); err != nil {
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
		result, err := c.LoginMFA(r.Context(), in.Code)
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
		if err := c.LoginLogout(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]bool{"logged_in": false})
	})
	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, c.Settings())
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "只支持 GET/POST", http.StatusMethodNotAllowed)
			return
		}
		var in corplink.Settings
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "解析请求体: "+err.Error(), http.StatusBadRequest)
			return
		}
		restart, err := c.UpdateSettings(r.Context(), in)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		st := c.Status()
		writeJSON(w, map[string]any{
			"saved":            true,
			"restart_required": restart,
			"company_name":     st.CompanyName,
			"server":           st.Server,
		})
	})
	mux.HandleFunc("/api/totp", func(w http.ResponseWriter, _ *http.Request) {
		code, err := c.TOTP()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !code.Bound {
			writeJSON(w, map[string]any{"has_secret": false})
			return
		}
		writeJSON(w, map[string]any{"has_secret": true, "code": code.Code, "remaining": code.Remaining})
	})
	mux.HandleFunc("/api/sub", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{
			"url": fmt.Sprintf("http://%s/clash.yml", s.PanelAddr),
		})
	})
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
