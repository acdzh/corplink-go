package sub

import (
	"strings"
	"testing"
)

// TestClashContainsEssentialParts 校验生成配置包含代理、规则与 DNS。
func TestClashContainsEssentialParts(t *testing.T) {
	out := Clash(Options{
		Host:    "127.0.0.1",
		Port:    3710,
		Routes:  []string{"10.0.0.0/8", "10.1.2.3"},
		Domains: []string{"*.example.com"},
	})
	for _, want := range []string{
		"# " + Title,
		"proxies:",
		`name: "` + ProxyName + `"`,
		"port: 3710",
		"proxy-groups:",
		"dns:",
		"enhanced-mode: fake-ip",
		"IP-CIDR,10.0.0.0/8,节点选择,no-resolve",
		"IP-CIDR,10.1.2.3/32,节点选择,no-resolve",
		"DOMAIN-SUFFIX,example.com,节点选择",
		"MATCH,DIRECT",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("配置缺少 %q\n%s", want, out)
		}
	}
}

// TestClashSkipsInvalidRoutes 校验非法路由被丢弃。
func TestClashSkipsInvalidRoutes(t *testing.T) {
	out := Clash(Options{Routes: []string{"not-an-ip", ""}})
	if strings.Contains(out, "not-an-ip") {
		t.Fatalf("非法路由不应出现在配置里:\n%s", out)
	}
}
