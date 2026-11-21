package sub

import (
	"strings"
	"testing"
)

// TestDNSTargetOverridesVPNDNS 校验订阅里的内网解析指向客户端可达的本地 DNS。
//
// 回归点：nameserver-policy 过去直接写 vpn_dns（10.8.8.18），它只在隧道里可达，
// 客户端在隧道外查这些域名会全部超时，现象就是"内网站点找不到 DNS"。
func TestDNSTargetOverridesVPNDNS(t *testing.T) {
	out := Clash(Options{
		Domains:   []string{"byted.org", "*.byted.org"},
		VPNDNS:    []string{"10.8.8.18"},
		DNSTarget: "10.0.0.141:10053",
	})
	if !strings.Contains(out, "+.byted.org:") || !strings.Contains(out, "10.0.0.141:10053") {
		t.Fatalf("nameserver-policy 应指向本地 DNS，实际配置：%v", out)
	}
	if strings.Contains(out, "10.8.8.18") {
		t.Fatalf("不应再写隧道内 DNS（客户端不可达），实际配置：%v", out)
	}
}

// TestDNSTargetWildcardOnly 校验只下发通配域名时也能生成 policy。
func TestDNSTargetWildcardOnly(t *testing.T) {
	out := Clash(Options{Domains: []string{"*.corp.example"}, DNSTarget: "10.0.0.141:10053"})
	if !strings.Contains(out, "+.corp.example:") {
		t.Fatalf("通配域名应归一化成裸域名，实际配置：%v", out)
	}
}

// TestDNSTargetEmptyFallsBack 校验没有本地 DNS 时回退到 vpn_dns。
func TestDNSTargetEmptyFallsBack(t *testing.T) {
	out := Clash(Options{Domains: []string{"example.com"}, VPNDNS: []string{"10.8.8.18"}})
	if !strings.Contains(out, "10.8.8.18") {
		t.Fatalf("无本地 DNS 时应回退 vpn_dns，实际配置：%v", out)
	}
}
