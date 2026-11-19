// Package sub 生成 Clash 订阅配置。
//
// 配置刻意保持最小：只有一个节点（本机混合代理）和一个选择组，
// 选节点、分流模式都在我们自己的面板里做，Clash 侧只当哑管道用。
package sub

import (
	"fmt"
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
	b.WriteString("rules:\n")
	b.WriteString("  - MATCH," + GroupName + "\n")
	return b.String()
}
