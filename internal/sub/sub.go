// Package sub 生成 Clash 订阅。
//
// 设计：只暴露一个本地端口、只下发一份配置，分流交给 Clash。
// 若配置了 ExtraSubscription（例如自己的机场），会把它里面的日本节点
// 并入配置，并单独成一个「日本出口」组，供 Antigravity 等流量使用。
package sub

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// 名称常量，保证面板与订阅里的一致。
const (
	// Title 是配置标题。
	Title = "Corplink Go"
	// ProxyName 是公司隧道代理名。
	ProxyName = "CorpLink"
	// JapanGroup 是日本出口选择组。
	JapanGroup = "日本出口"
)

// AntigravityDomains 是需要走日本出口的域名后缀。
// 放在公司分流规则之前，命中优先。
var AntigravityDomains = []string{
	"antigravity.google",
	"cloudcode-pa.googleapis.com",
	"generativelanguage.googleapis.com",
	"gemini.google.com",
	"accounts.google.com",
	"googleapis.com",
	"gstatic.com",
	"googleusercontent.com",
}

// Options 是生成订阅所需的输入。
type Options struct {
	// Host 是 SOCKS5 服务地址。
	Host string
	// Port 是 SOCKS5 端口。
	Port int
	// Username 与 Password 非空时写入认证。
	Username string
	Password string
	// Routes 是服务端下发的分流网段。
	Routes []string
	// Domains 是服务端下发的分流域名后缀。
	Domains []string
	// ExtraProxies 是并入配置的额外代理（例如机场的日本节点）。
	ExtraProxies []map[string]any
}

// Clash 生成 Clash 配置。
func Clash(opts Options) string {
	host := opts.Host
	if host == "" {
		host = "127.0.0.1"
	}

	corp := map[string]any{
		"name":   ProxyName,
		"type":   "socks5",
		"server": host,
		"port":   opts.Port,
		"udp":    true,
	}
	if opts.Username != "" {
		corp["username"] = opts.Username
		corp["password"] = opts.Password
	}

	proxies := []any{corp}
	japanNames := make([]string, 0, len(opts.ExtraProxies))
	for _, extra := range opts.ExtraProxies {
		name, _ := extra["name"].(string)
		if name == "" {
			continue
		}
		japanNames = append(japanNames, name)
		proxies = append(proxies, extra)
	}

	var groups []any
	if len(japanNames) > 0 {
		jpProxies := append(append([]string{}, japanNames...), ProxyName, "DIRECT")
		groups = append(groups, map[string]any{
			"name":    JapanGroup,
			"type":    "select",
			"proxies": jpProxies,
		})
	}

	// DNS：fake-ip 让域名规则直接命中，内网域名交给隧道内解析。
	dns := map[string]any{
		"enable":        true,
		"enhanced-mode": "fake-ip",
		"fake-ip-range": "198.18.0.1/16",
		"nameserver":    []string{"223.5.5.5", "119.29.29.29"},
		"fallback":      []string{"1.1.1.1", "8.8.8.8"},
	}

	rules := make([]string, 0, len(opts.Routes)+len(opts.Domains)+len(AntigravityDomains)+2)
	if len(japanNames) > 0 {
		for _, domain := range AntigravityDomains {
			rules = append(rules, fmt.Sprintf("DOMAIN-SUFFIX,%s,%s", domain, JapanGroup))
		}
	}
	seen := make(map[string]bool, len(opts.Routes)+len(opts.Domains))
	for _, route := range opts.Routes {
		route = normalizeCIDR(route)
		if route == "" || seen["cidr:"+route] {
			continue
		}
		seen["cidr:"+route] = true
		kind := "IP-CIDR"
		if strings.Contains(route, ":") {
			kind = "IP-CIDR6"
		}
		rules = append(rules, fmt.Sprintf("%s,%s,%s,no-resolve", kind, route, ProxyName))
	}
	for _, domain := range opts.Domains {
		domain = strings.TrimSpace(strings.TrimPrefix(domain, "*."))
		if domain == "" || seen["domain:"+domain] {
			continue
		}
		seen["domain:"+domain] = true
		rules = append(rules, fmt.Sprintf("DOMAIN-SUFFIX,%s,%s", domain, ProxyName))
	}
	rules = append(rules, "MATCH,DIRECT")

	doc := map[string]any{
		"proxies": proxies,
		"dns":     dns,
		"rules":   rules,
	}
	if len(groups) > 0 {
		doc["proxy-groups"] = groups
	}

	var b strings.Builder
	b.WriteString("# " + Title + "\n")
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	_ = enc.Encode(doc)
	_ = enc.Close()
	return b.String()
}

// FetchExtra 拉取额外订阅并取出其中的 proxies。
//
// 兼容两种常见格式：YAML（Clash 订阅）与 Base64 包裹的 YAML（机场常见）。
// 只挑带 JP/日本 关键字的节点；一个都没有时返回全部节点。
func FetchExtra(rawURL string) ([]map[string]any, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, nil
	}

	// 机场面板按查询参数或 UA 决定返回格式，显式要 Clash 格式最稳妥；
	// UA 只作为兜底（有些面板只认 UA）。
	reqURL := rawURL
	if !strings.Contains(reqURL, "flag=") {
		if strings.Contains(reqURL, "?") {
			reqURL += "&flag=clash"
		} else {
			reqURL += "?flag=clash"
		}
	}

	// 缓存 5 分钟：Clash 拉订阅可能很频繁，不必每次都打机场。
	extraMu.Lock()
	if cached, ok := extraCache[rawURL]; ok && time.Since(cached.at) < 5*time.Minute {
		proxies := cached.proxies
		extraMu.Unlock()
		return proxies, nil
	}
	extraMu.Unlock()

	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("构造额外订阅请求: %w", err)
	}
	// 机场通常按 UA 决定返回格式：Clash 客户端拿到 YAML，其他客户端拿到
	// base64 的节点 URI 列表。这里伪装成 Clash，直接要 YAML。
	req.Header.Set("User-Agent", "clash-verge/v1.7.7")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("拉取额外订阅: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("拉取额外订阅返回 %d", resp.StatusCode)
	}
	body := make([]byte, 0, 64<<10)
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
		if len(body) > 4<<20 {
			break
		}
	}
	text := string(body)
	if !strings.Contains(text, "proxies:") {
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text)); err == nil {
			text = string(decoded)
		}
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, fmt.Errorf("解析额外订阅: %w", err)
	}
	var japan []map[string]any
	for _, proxy := range doc.Proxies {
		name, _ := proxy["name"].(string)
		upper := strings.ToUpper(name)
		if strings.Contains(upper, "JP") || strings.Contains(name, "日本") ||
			strings.Contains(upper, "JAPAN") || strings.Contains(upper, "TOKYO") ||
			strings.Contains(upper, "OSAKA") {
			japan = append(japan, proxy)
		}
	}
	result := japan
	if len(result) == 0 {
		result = doc.Proxies
	}
	extraMu.Lock()
	extraCache[rawURL] = extraEntry{at: time.Now(), proxies: result}
	extraMu.Unlock()
	return result, nil
}

var (
	extraMu    sync.Mutex
	extraCache = map[string]extraEntry{}
)

// extraEntry 是机场订阅的缓存条目。
type extraEntry struct {
	at      time.Time
	proxies []map[string]any
}

// normalizeCIDR 把裸 IP 补成 CIDR，非法的返回空串。
func normalizeCIDR(route string) string {
	route = strings.TrimSpace(route)
	if route == "" {
		return ""
	}
	if strings.Contains(route, "/") {
		if _, _, err := net.ParseCIDR(route); err != nil {
			return ""
		}
		return route
	}
	ip := net.ParseIP(route)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return route + "/32"
	}
	return route + "/128"
}
