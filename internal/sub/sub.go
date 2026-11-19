// Package sub 生成 Clash 订阅。
//
// 订阅按"单端口单节点、懒建立"的方式组织：每个节点一个本地 SOCKS5 端口，
// 但只有被选中的节点才会真正建隧道，其余端口仅监听不占连接。
package sub

import (
	"fmt"
	"net"
	"strings"
)

// SingleOptions 是单节点订阅的输入。
type SingleOptions struct {
	// Name 是代理名。
	Name string
	// Host 是 SOCKS5 服务地址。
	Host string
	// Port 是 SOCKS5 端口。
	Port int
	// Username 与 Password 非空时写入认证。
	Username string
	Password string
	// Routes 与 Domains 是分流规则来源。
	Routes  []string
	Domains []string
	// Full 表示全量模式：未命中规则的流量也走代理。
	Full bool
}

// Single 生成"只有一个代理"的订阅：切换节点由控制面板完成，Clash 侧保持稳定。
func Single(opts SingleOptions) string {
	name := opts.Name
	if name == "" {
		name = "CORPLINK"
	}
	host := opts.Host
	if host == "" {
		host = "127.0.0.1"
	}
	group := "CORP"

	var b strings.Builder
	b.WriteString("mode: rule\n")
	b.WriteString("proxies:\n")
	fmt.Fprintf(&b, "  - name: %q\n", name)
	b.WriteString("    type: socks5\n")
	fmt.Fprintf(&b, "    server: %s\n", host)
	fmt.Fprintf(&b, "    port: %d\n", opts.Port)
	b.WriteString("    udp: true\n")
	if opts.Username != "" {
		fmt.Fprintf(&b, "    username: %q\n", opts.Username)
		fmt.Fprintf(&b, "    password: %q\n", opts.Password)
	}
	b.WriteString("proxy-groups:\n")
	fmt.Fprintf(&b, "  - name: %q\n", group)
	b.WriteString("    type: select\n")
	b.WriteString("    proxies:\n")
	fmt.Fprintf(&b, "      - %q\n", name)
	b.WriteString("      - DIRECT\n")
	b.WriteString("rules:\n")
	seen := map[string]bool{}
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
		fmt.Fprintf(&b, "  - %s,%s,%s,no-resolve\n", kind, route, group)
	}
	for _, domain := range opts.Domains {
		domain = strings.TrimSpace(strings.TrimPrefix(domain, "*."))
		if domain == "" || seen["domain:"+domain] {
			continue
		}
		seen["domain:"+domain] = true
		fmt.Fprintf(&b, "  - DOMAIN-SUFFIX,%s,%s\n", domain, group)
	}
	if opts.Full {
		fmt.Fprintf(&b, "  - MATCH,%s\n", group)
	} else {
		b.WriteString("  - MATCH,DIRECT\n")
	}
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
