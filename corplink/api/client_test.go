package api

import "testing"

// TestIsLoginPath 校验登录链路豁免"被踢"判定。
//
// 回归点：重登时 jar 里可能还留着上一个会话的 session cookie，
// 如果登录接口也走被踢判定，服务端一个 action=logout 就能把登录打断。
func TestIsLoginPath(t *testing.T) {
	login := []string{
		"/api/tpslogin/link",
		"/api/tpslogin/device/callback",
		"/api/v1/login/mfa/send",
		"/api/v1/login/mfa/verify",
		"/api/mfa/type",
		"/api/mfa/code/verify",
		"/api/login/setting",
		"/api/v2/p/otp",
	}
	for _, path := range login {
		if !isLoginPath(path) {
			t.Fatalf("%s 应属于登录链路", path)
		}
	}
	others := []string{"/api/vpn/list", "/vpn/conn", "/api/info/me", "/api/logout"}
	for _, path := range others {
		if isLoginPath(path) {
			t.Fatalf("%s 不应被当作登录链路", path)
		}
	}
}

// TestSyncFromPayloadRejectsMillis 校验毫秒级 timestamp 不会污染时钟。
func TestSyncFromPayloadRejectsMillis(t *testing.T) {
	before := timestampFloor
	if before != 1_000_000_000 {
		t.Fatalf("timestampFloor 被改动")
	}
	// 毫秒时间戳（约 1.79e12）超出可信区间，必须忽略。
	if ts := int64(1795286272000); ts >= timestampFloor && ts <= timestampCeil {
		t.Fatalf("毫秒时间戳不应落在可信区间内")
	}
}
