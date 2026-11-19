// Package sub 生成 Clash 订阅。
//
// 设计：只暴露一个本地端口、只下发一份配置，分流完全交给 Clash。
// 服务端下发的分流网段与域名翻译成规则，命中走「节点选择」，其余直连。
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
	// ProxyName 是代理名。
	ProxyName = "CorpLink"
	// GroupName 是选择组名。
	GroupName = "节点选择"
)

// Options 是生成订阅所需的输入。
type Options struct {
	// Host 是本地监听地址。
	Host string
	// Port 是本地代理端口。
	Port int
	// Username 与 Password 非空时写入认证。
	Username string
	Password string
	// Routes 是服务端下发的分流网段。
	Routes []string
	// Domains 是服务端下发的分流域名后缀。
	Domains []string
	// DirectDomains 是必须直连的域名（本程序的控制面域名），
	// 否则 fake-ip + 域名规则会把我们自己的请求送回代理。
	DirectDomains []string
	// NodeIPs 是节点公网 IP（含备用），必须直连：
	// 否则 Clash 在 TUN 模式下会把本程序的出站流量再送回代理，形成回环。
	NodeIPs []string
}

// Clash 生成 Clash 配置。
func Clash(opts Options) string {
	host := opts.Host
	if host == "" {
		host = "127.0.0.1"
	}

	proxy := map[string]any{
		"name":   ProxyName,
		"type":   "socks5",
		"server": host,
		"port":   opts.Port,
		"udp":    true,
	}
	if opts.Username != "" {
		proxy["username"] = opts.Username
		proxy["password"] = opts.Password
	}

	dns := map[string]any{
		"enable":        true,
		"enhanced-mode": "fake-ip",
		"fake-ip-range": "198.18.0.1/16",
		"nameserver":    []string{"223.5.5.5", "119.29.29.29"},
		"fallback":      []string{"1.1.1.1", "8.8.8.8"},
	}

	rules := make([]string, 0, len(opts.Routes)+len(opts.Domains)+len(opts.NodeIPs)+len(opts.DirectDomains)+2)

	// 0. 防回环：控制面域名与节点 IP 直连。
	for _, domain := range opts.DirectDomains {
		domain = strings.TrimSpace(strings.TrimPrefix(domain, "*."))
		if domain == "" {
			continue
		}
		rules = append(rules, fmt.Sprintf("DOMAIN-SUFFIX,%s,DIRECT", domain))
	}
	nodeSeen := make(map[string]bool, len(opts.NodeIPs))
	for _, ip := range opts.NodeIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" || nodeSeen[ip] {
			continue
		}
		nodeSeen[ip] = true
		kind, suffix := "IP-CIDR", "/32"
		if strings.Contains(ip, ":") {
			kind, suffix = "IP-CIDR6", "/128"
		}
		if strings.Contains(ip, "/") {
			suffix = ""
		}
		rules = append(rules, fmt.Sprintf("%s,%s%s,DIRECT,no-resolve", kind, ip, suffix))
	}

	// 1. 公司分流：服务端下发的网段与域名。
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
		rules = append(rules, fmt.Sprintf("%s,%s,%s,no-resolve", kind, route, GroupName))
	}
	for _, domain := range opts.Domains {
		domain = strings.TrimSpace(strings.TrimPrefix(domain, "*."))
		if domain == "" || seen["domain:"+domain] {
			continue
		}
		seen["domain:"+domain] = true
		rules = append(rules, fmt.Sprintf("DOMAIN-SUFFIX,%s,%s", domain, GroupName))
	}
	rules = append(rules, "MATCH,DIRECT")

	doc := map[string]any{
		"proxies": []any{proxy},
		// 客户端（Clash Verge 等）只渲染 proxy-groups，必须保留一个。
		"proxy-groups": []any{map[string]any{
			"name":    GroupName,
			"type":    "select",
			"proxies": []string{ProxyName, "DIRECT"},
		}},
		"dns":   dns,
		"rules": rules,
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
