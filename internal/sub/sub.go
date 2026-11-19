// Package sub 生成 Clash 订阅。
//
// 设计要点：只暴露一个本地端口、只下发一份配置；分流完全交给 Clash ——
// 把服务端 /vpn/conn 返回的分流网段与域名后缀翻译成规则，命中走代理，其余直连。
package sub

import (
	"fmt"
	"net"
	"strings"
)

// 名称常量，保证面板与订阅里的一致。
const (
	// Title 是配置标题。
	Title = "Corplink Go"
	// ProxyName 是唯一代理名。
	ProxyName = "CorpLink"
	// Target 是规则指向的目标：直接指向唯一代理，不额外建组。
	Target = ProxyName
)

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
}

// Clash 生成 Clash 配置。
func Clash(opts Options) string {
	host := opts.Host
	if host == "" {
		host = "127.0.0.1"
	}
	var b strings.Builder
	b.WriteString("# " + Title + "\n")
	b.WriteString("proxies:\n")
	fmt.Fprintf(&b, "  - name: %q\n", ProxyName)
	b.WriteString("    type: socks5\n")
	fmt.Fprintf(&b, "    server: %s\n", host)
	fmt.Fprintf(&b, "    port: %d\n", opts.Port)
	b.WriteString("    udp: true\n")
	if opts.Username != "" {
		fmt.Fprintf(&b, "    username: %q\n", opts.Username)
		fmt.Fprintf(&b, "    password: %q\n", opts.Password)
	}

	// DNS：fake-ip 让域名规则直接命中，不必依赖本机能否解析内网域名；
	// 内网域名的真正解析发生在隧道内（由代理侧完成）。
	b.WriteString("dns:\n")
	b.WriteString("  enable: true\n")
	b.WriteString("  enhanced-mode: fake-ip\n")
	b.WriteString("  fake-ip-range: 198.18.0.1/16\n")
	b.WriteString("  nameserver:\n")
	b.WriteString("    - 223.5.5.5\n")
	b.WriteString("    - 119.29.29.29\n")
	b.WriteString("  fallback:\n")
	b.WriteString("    - 1.1.1.1\n")
	b.WriteString("    - 8.8.8.8\n")

	b.WriteString("rules:\n")
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
		fmt.Fprintf(&b, "  - %s,%s,%s,no-resolve\n", kind, route, Target)
	}
	for _, domain := range opts.Domains {
		domain = strings.TrimSpace(strings.TrimPrefix(domain, "*."))
		if domain == "" || seen["domain:"+domain] {
			continue
		}
		seen["domain:"+domain] = true
		fmt.Fprintf(&b, "  - DOMAIN-SUFFIX,%s,%s\n", domain, Target)
	}
	b.WriteString("  - MATCH,DIRECT\n")
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
