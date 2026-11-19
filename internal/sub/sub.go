// Package sub 生成 Clash 订阅配置。
//
// 提供两份配置，对应官方客户端的两种模式：
//
//	极速（split）  —— 使用服务端下发的分流路由与域名规则，其余直连
//	全局（global） —— 所有流量都走代理
//
// 选哪个节点由我们自己的面板决定，Clash 侧只负责按规则转发。
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
	ProxyName = "极速"
	// GroupName 是唯一选择组名。
	GroupName = "Global"
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
	// Split 为真时按服务端下发的分流规则生成，否则全量走代理。
	Split bool
	// Routes 是分流网段。
	Routes []string
	// Domains 是分流域名后缀。
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
	b.WriteString("proxy-groups:\n")
	fmt.Fprintf(&b, "  - name: %q\n", GroupName)
	b.WriteString("    type: select\n")
	b.WriteString("    proxies:\n")
	fmt.Fprintf(&b, "      - %q\n", ProxyName)
	b.WriteString("      - DIRECT\n")
	b.WriteString("      - REJECT\n")

	// DNS：内网域名由代理侧远端解析，本地只需要解析直连流量；
	// fake-ip 能让域名规则直接命中，不依赖本地能否解析内网域名。
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
	if opts.Split {
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
			fmt.Fprintf(&b, "  - %s,%s,%s,no-resolve\n", kind, route, GroupName)
		}
		for _, domain := range opts.Domains {
			domain = strings.TrimSpace(strings.TrimPrefix(domain, "*."))
			if domain == "" || seen["domain:"+domain] {
				continue
			}
			seen["domain:"+domain] = true
			fmt.Fprintf(&b, "  - DOMAIN-SUFFIX,%s,%s\n", domain, GroupName)
		}
		b.WriteString("  - MATCH,DIRECT\n")
	} else {
		b.WriteString("  - MATCH," + GroupName + "\n")
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
