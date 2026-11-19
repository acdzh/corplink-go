// Package sub 生成 Clash 订阅。
//
// 设计：一个本地端口跑公司隧道，分流规则交给 Clash；
// 如果配置了额外出口（config.Exits），每个出口也生成一个本地 socks 代理，
// 并合成「日本出口」选择组，供 Antigravity 这类需要特定地区出口的流量使用。
package sub

import (
	"fmt"
	"net"
	"strings"

	"gopkg.in/yaml.v3"
)

// 名称常量，保证面板与订阅里的一致。
const (
	// Title 是配置标题。
	Title = "Corplink Go"
	// ProxyName 是主（公司）隧道代理名。
	ProxyName = "CorpLink"
	// ExitGroup 是额外出口的选择组名。
	ExitGroup = "日本出口"
)

// AntigravityDomains 是需要走额外出口的域名后缀。
// 排在公司分流规则之前，命中优先。
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

// ExitProxy 描述一个额外出口生成的代理。
type ExitProxy struct {
	// Name 是代理名（出口名）。
	Name string
	// Port 是本地端口。
	Port int
}

// Options 是生成订阅所需的输入。
type Options struct {
	// Host 是本地监听地址。
	Host string
	// Port 是主隧道端口。
	Port int
	// Username 与 Password 非空时写入认证。
	Username string
	Password string
	// Routes 是服务端下发的分流网段。
	Routes []string
	// Domains 是服务端下发的分流域名后缀。
	Domains []string
	// Exits 是额外出口。
	Exits []ExitProxy
	// NodeIPs 是节点公网 IP（含备用），必须直连：
	// 否则 Clash 开 TUN/全局模式时会把这些流量再送回本代理，形成回环。
	NodeIPs []string
}

// Clash 生成 Clash 配置。
func Clash(opts Options) string {
	host := opts.Host
	if host == "" {
		host = "127.0.0.1"
	}

	socks := func(name string, port int) map[string]any {
		proxy := map[string]any{
			"name":   name,
			"type":   "socks5",
			"server": host,
			"port":   port,
			"udp":    true,
		}
		if opts.Username != "" {
			proxy["username"] = opts.Username
			proxy["password"] = opts.Password
		}
		return proxy
	}

	proxies := []any{socks(ProxyName, opts.Port)}
	exitNames := make([]string, 0, len(opts.Exits))
	for _, exit := range opts.Exits {
		if exit.Name == "" || exit.Port == 0 {
			continue
		}
		exitNames = append(exitNames, exit.Name)
		proxies = append(proxies, socks(exit.Name, exit.Port))
	}

	var groups []any
	if len(exitNames) > 0 {
		group := map[string]any{
			"name":    ExitGroup,
			"type":    "select",
			"proxies": append(append([]string{}, exitNames...), ProxyName, "DIRECT"),
		}
		groups = append(groups, group)
	}

	dns := map[string]any{
		"enable":        true,
		"enhanced-mode": "fake-ip",
		"fake-ip-range": "198.18.0.1/16",
		"nameserver":    []string{"223.5.5.5", "119.29.29.29"},
		"fallback":      []string{"1.1.1.1", "8.8.8.8"},
	}

	rules := make([]string, 0, len(opts.Routes)+len(opts.Domains)+len(AntigravityDomains)+len(opts.NodeIPs)+2)
	// 0a. 本程序自身的出站流量必须直连（进程级兜底，mihomo 在 macOS/Windows 支持）。
	rules = append(rules, "PROCESS-NAME,CorplinkGo,DIRECT")
	// 0b. 节点自身的公网 IP 也必须直连，否则 TUN/全局模式下会自己连自己。
	nodeSeen := make(map[string]bool, len(opts.NodeIPs))
	for _, ip := range opts.NodeIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" || nodeSeen[ip] {
			continue
		}
		nodeSeen[ip] = true
		kind := "IP-CIDR"
		if strings.Contains(ip, ":") {
			kind = "IP-CIDR6"
		}
		suffix := "/32"
		if kind == "IP-CIDR6" {
			suffix = "/128"
		}
		if strings.Contains(ip, "/") {
			suffix = ""
		}
		rules = append(rules, fmt.Sprintf("%s,%s%s,DIRECT,no-resolve", kind, ip, suffix))
	}
	if len(exitNames) > 0 {
		for _, domain := range AntigravityDomains {
			rules = append(rules, fmt.Sprintf("DOMAIN-SUFFIX,%s,%s", domain, ExitGroup))
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
