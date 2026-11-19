// Package sub 生成 Clash 订阅。
//
// 订阅按"单端口单节点、懒建立"的方式组织：每个节点一个本地 SOCKS5 端口，
// 但只有被选中的节点才会真正建隧道，其余端口仅监听不占连接。
package sub

import (
	"fmt"
	"strings"

	"github.com/acdzh/corplink-go/internal/api"
	"github.com/acdzh/corplink-go/internal/vpn"
)

// Options 是生成订阅所需的输入。
type Options struct {
	// Entries 是节点与本地端口的映射。
	Entries []vpn.Entry
	// SocksHost 是订阅里写的服务端地址。
	SocksHost string
	// GroupName 是代理组名。
	GroupName string
	// Routes 是需要走代理的网段。
	Routes []string
	// Domains 是需要走代理的域名后缀。
	Domains []string
	// Username 与 Password 非空时写入 SOCKS5 认证。
	Username string
	Password string
}

// YAML 生成 Clash 订阅内容。
func YAML(opts Options) string {
	group := opts.GroupName
	if group == "" {
		group = "CORP"
	}
	host := opts.SocksHost
	if host == "" {
		host = "127.0.0.1"
	}

	var b strings.Builder
	b.WriteString("proxies:\n")
	names := make([]string, 0, len(opts.Entries))
	for _, e := range opts.Entries {
		name := nodeName(e.Node)
		names = append(names, name)
		fmt.Fprintf(&b, "  - name: %q\n", name)
		b.WriteString("    type: socks5\n")
		fmt.Fprintf(&b, "    server: %s\n", host)
		fmt.Fprintf(&b, "    port: %d\n", e.Port)
		b.WriteString("    udp: true\n")
		if opts.Username != "" {
			fmt.Fprintf(&b, "    username: %q\n", opts.Username)
			fmt.Fprintf(&b, "    password: %q\n", opts.Password)
		}
	}

	b.WriteString("proxy-groups:\n")
	fmt.Fprintf(&b, "  - name: %q\n", group)
	b.WriteString("    type: select\n")
	b.WriteString("    proxies:\n")
	for _, name := range names {
		fmt.Fprintf(&b, "      - %q\n", name)
	}
	b.WriteString("      - DIRECT\n")

	b.WriteString("rules:\n")
	seen := map[string]bool{}
	for _, route := range opts.Routes {
		route = strings.TrimSpace(route)
		if route == "" || seen["cidr:"+route] {
			continue
		}
		seen["cidr:"+route] = true
		fmt.Fprintf(&b, "  - IP-CIDR,%s,%s,no-resolve\n", route, group)
	}
	for _, domain := range opts.Domains {
		domain = strings.TrimSpace(domain)
		domain = strings.TrimPrefix(domain, "*.")
		if domain == "" || seen["domain:"+domain] {
			continue
		}
		seen["domain:"+domain] = true
		fmt.Fprintf(&b, "  - DOMAIN-SUFFIX,%s,%s\n", domain, group)
	}
	b.WriteString("  - MATCH,DIRECT\n")
	return b.String()
}

// nodeName 生成订阅里显示的节点名。
func nodeName(node api.VpnInfo) string {
	if node.EnName != "" {
		return node.EnName
	}
	if node.Name != "" {
		return node.Name
	}
	return fmt.Sprintf("%s:%d", node.IP, node.VPNPort)
}
