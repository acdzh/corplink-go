package login

import (
	"reflect"
	"testing"
)

// TestPickMfaTypePrefersEmail 校验默认方式按"能否确定送达"排序。
//
// 回归点：本租户 /api/mfa/type 给的是 type=mobile、types=[mobile,email]，
// 之前直接取列表第一项 → 选到短信。账号没绑手机号时验证码永远到不了，
// 表现就是"登录一直不成功"。
func TestPickMfaTypePrefersEmail(t *testing.T) {
	cases := []struct {
		name      string
		available []string
		fallback  string
		want      string
	}{
		{"本租户列表", []string{"mobile", "email"}, "mobile", "email"},
		{"只有短信", []string{"mobile"}, "mobile", "mobile"},
		{"含 otp 时优先邮箱", []string{"mobile", "otp", "email"}, "", "email"},
		{"只有 otp", []string{"otp"}, "", "otp"},
		{"空列表用回退", nil, "mobile", "mobile"},
		{"全空退回邮箱", nil, "", "email"},
		{"未知方式保留服务端顺序", []string{"sms2", "email"}, "", "email"},
	}
	for _, tc := range cases {
		if got := pickMfaType(tc.available, tc.fallback); got != tc.want {
			t.Fatalf("%s: pickMfaType(%v, %q) = %q, want %q", tc.name, tc.available, tc.fallback, got, tc.want)
		}
	}
}

// TestSupportedAuthTypes 校验按官方白名单过滤并去重，且保持服务端顺序。
func TestSupportedAuthTypes(t *testing.T) {
	got := supportedAuthTypes([]string{"mobile", "sms", "", "email", "mobile", "password"})
	want := []string{"mobile", "email", "password"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("supportedAuthTypes = %v, want %v", got, want)
	}
}

// TestMfaTypeAllowed 校验空列表不拦、非空列表只放行已声明的方式。
func TestMfaTypeAllowed(t *testing.T) {
	if !mfaTypeAllowed("mobile", nil) {
		t.Fatal("列表为空时不应拦截")
	}
	if !mfaTypeAllowed("email", []string{"mobile", "email"}) {
		t.Fatal("email 在列表里应放行")
	}
	if mfaTypeAllowed("email", []string{"mobile"}) {
		t.Fatal("email 不在列表里应拦截")
	}
}

// TestParseNext 校验 LoginV2Result 的解析（含移动端回显）。
func TestParseNext(t *testing.T) {
	raw := []byte(`{"result":"success","next":{"action":"2FA","auth_list":["mobile","email"],"email":"zhu***@example.com","mobile":"138****8888"}}`)
	next := parseNext(raw)
	if next.Action != "2FA" {
		t.Fatalf("action = %q", next.Action)
	}
	if !reflect.DeepEqual(next.AuthList, []string{"mobile", "email"}) {
		t.Fatalf("auth_list = %v", next.AuthList)
	}
	if next.Email != "zhu***@example.com" || next.Mobile != "138****8888" {
		t.Fatalf("回显账号解析错误: %+v", next)
	}
	if got := parseNext([]byte("not json")); got.Action != "" {
		t.Fatalf("非法 JSON 应返回空结构，得到 %+v", got)
	}
}
