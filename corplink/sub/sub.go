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
	// DynamicDomains 是需要走隧道/内网解析的动态域名（vpn_dynamic_domain_route_split 展开）。
	DynamicDomains []string
	// VPNDNS 是内网 DNS，用于给内网域名单独指定解析服务器。
	VPNDNS []string
	// DNSTarget 是客户端应当使用的内网 DNS 地址（形如 10.0.0.141:10053）。
	//
	// 优先于 VPNDNS：10.8.8.18 这类隧道内 DNS 只在隧道里可达，客户端机器
	// 直接用会超时，表现为"内网域名找不到 DNS"。本程序自己起的本地 DNS
	// 才是在隧道外可达的入口，订阅里必须指向它。
	DNSTarget string
}

// normalizeDomain 把服务端下发的域名写法归一成 Clash 能用的裸后缀。
//
// 实测租户会同时下发 "byted.org"、"*.bytedance.net"、"*tiktokv.com"（星号后
// 没有点）以及带前导空格的条目；不归一的话会生成 "+.*tiktokv.com"、
// "DOMAIN-SUFFIX,*.google.com" 这种 Clash 不认的规则，那条域名等于没配。
func normalizeDomain(raw string) string {
	domain := strings.ToLower(strings.TrimSpace(raw))
	for {
		trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(domain, "*"), "."))
		if trimmed == domain {
			break
		}
		domain = trimmed
	}
	if domain == "" || strings.ContainsAny(domain, "* /:") {
		return ""
	}
	return domain
}

// Clash 生成 Clash 配置。
func Clash(opts Options) string {
	host := opts.Host
	if host == "" {
		host = "127.0.0.1"
	}

	proxy := map[string]any{
		"name":   &yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: ProxyName},
		"type":   "socks5",
		"server": host,
		"port":   opts.Port,
		"udp":    true,
	}

	dns := map[string]any{
		"enable":        true,
		"enhanced-mode": "fake-ip",
		"fake-ip-range": "198.18.0.1/16",
		"nameserver":    []string{"223.5.5.5", "119.29.29.29"},
		"fallback":      []string{"1.1.1.1", "8.8.8.8"},
	}
	// 内网域名必须由能走隧道的 DNS 解析：否则公司域名在公网 DNS 上直接 NXDOMAIN，
	// 表现为"连上了但公司站点打不开"。DNSTarget（本程序的本地 DNS）优先，
	// 因为 vpn_dns 只在隧道内可达，客户端直接指向它会全部超时。
	dnsServers := opts.VPNDNS
	if opts.DNSTarget != "" {
		dnsServers = []string{opts.DNSTarget}
	}
	if len(dnsServers) > 0 && (len(opts.Domains) > 0 || len(opts.DynamicDomains) > 0) {
		policy := map[string]any{}
		for _, dnsIP := range dnsServers {
			for _, domain := range append(append([]string{}, opts.Domains...), opts.DynamicDomains...) {
				// 服务端同时下发 "x.com"、"*.x.com" 甚至 "*x.com"（星号后没点），
				// 统一成裸域名再写 policy；通配写法也不能丢，否则该租户的内网域名
				// 会退回公网 DNS，表现就是"内网站点找不到 DNS"。
				domain = normalizeDomain(domain)
				if domain == "" {
					continue
				}
				policy["+."+domain] = []string{dnsIP}
			}
		}
		if len(policy) > 0 {
			dns["nameserver-policy"] = policy
		}
	}

	rules := make([]string, 0, len(opts.Routes)+len(opts.Domains)+len(opts.NodeIPs)+len(opts.DirectDomains)+2)

	// 0. 防回环：控制面域名与节点 IP 直连。
	for _, domain := range opts.DirectDomains {
		domain = normalizeDomain(domain)
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
	for _, domain := range append(append([]string{}, opts.Domains...), opts.DynamicDomains...) {
		domain = normalizeDomain(domain)
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
