package sub

import (
	"strings"
	"testing"
)

// TestNormalizeDomainForms 覆盖服务端实际下发的四种域名写法。
func TestNormalizeDomainForms(t *testing.T) {
	cases := map[string]string{
		"byted.org":        "byted.org",
		"*.bytedance.net":  "bytedance.net",
		"*tiktokv.com":     "tiktokv.com",
		"  *.google.com  ": "google.com",
		"*.*.corp.example": "corp.example",
		"":                 "",
		"*":                "",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Fatalf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRulesHaveNoWildcards 校验生成的规则与 DNS policy 里没有 Clash 不认的星号。
func TestRulesHaveNoWildcards(t *testing.T) {
	out := Clash(Options{
		Domains:   []string{"*.bytedance.net", "*tiktokv.com", "byted.org"},
		DNSTarget: "10.0.0.141:10053",
	})
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "*") {
			t.Fatalf("规则里残留星号：%q", line)
		}
	}
	for _, want := range []string{"+.tiktokv.com:", "+.bytedance.net:", "+.byted.org:"} {
		if !strings.Contains(out, want) {
			t.Fatalf("缺少 %s，实际配置：%v", want, out)
		}
	}
}
