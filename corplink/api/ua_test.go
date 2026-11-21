package api

import "testing"

// TestUserAgentUsesAndroidRelease 校验 UA 里是 Android 版本号而不是 SDK level。
//
// 官方客户端拼的是 Build.VERSION.RELEASE（"13"），query 里的 os_version 才是
// SDK level（"33"）。写成 "Android 33" 是最明显的"非官方客户端"特征。
func TestUserAgentUsesAndroidRelease(t *testing.T) {
	meta := Meta{AppVersion: "3.3.24", Brand: "google", Model: "Pixel 7", OSVersion: "33", Language: "zh"}
	want := "CorpLink/3.3.24 (googlePixel 7; Android 13; zh)"
	if got := UserAgent(meta); got != want {
		t.Fatalf("UserAgent = %q, want %q", got, want)
	}
	if got := AndroidRelease("34"); got != "14" {
		t.Fatalf("AndroidRelease(34) = %q", got)
	}
	if got := AndroidRelease("99"); got != "99" {
		t.Fatalf("未知 SDK 应原样返回，得到 %q", got)
	}
	// 不依赖配置的裸请求（/api/match）也必须拼出完整的官方 UA。
	if got := DefaultUserAgent(); got != want {
		t.Fatalf("DefaultUserAgent = %q, want %q", got, want)
	}
}

// TestMetaQueryKeepsSDKLevel 校验 query 里仍然是 SDK level（33），不受 UA 改动影响。
func TestMetaQueryKeepsSDKLevel(t *testing.T) {
	q := Meta{OS: "Android", OSVersion: "33", AppVersion: "3.3.24", BuildNumber: "2485", Language: "zh", ClientSource: "FeiLian"}.Query()
	if q.Get("os_version") != "33" {
		t.Fatalf("os_version = %q，应为 SDK level 33", q.Get("os_version"))
	}
}
