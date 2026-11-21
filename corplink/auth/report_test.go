package auth

import (
	"strings"
	"testing"

	"github.com/acdzh/corplink-go/corplink/api"
)

// TestReportDeviceNameNeverLeaksTool 校验上报的设备名不会带出本项目痕迹。
//
// 设备名会显示在租户控制台的"登录设备"里，是最直接的暴露面。
func TestReportDeviceNameNeverLeaksTool(t *testing.T) {
	cases := []struct {
		name  string
		model string
		want  string
	}{
		{"corplink-go", "Pixel 7", "Pixel 7"},
		{"CorpLink-Go", "Pixel 7", "Pixel 7"},
		{"", "Pixel 7", "Pixel 7"},
		{"我的笔记本", "Pixel 7", "我的笔记本"},
		{"corplink-go", "", "Android Device"},
	}
	for _, tc := range cases {
		got := reportDeviceName(tc.name, tc.model)
		if got != tc.want {
			t.Fatalf("reportDeviceName(%q, %q) = %q, want %q", tc.name, tc.model, got, tc.want)
		}
	}
}

// TestDeviceReportItemsSafe 校验完整载荷里不含本项目名字。
func TestDeviceReportItemsSafe(t *testing.T) {
	items := deviceReportItems(api.Meta{Model: "Pixel 7", Brand: "google", OSVersion: "33"}, "corplink-go", "", "")
	for _, item := range items {
		text, _ := item["value"].(string)
		if strings.Contains(strings.ToLower(text), "corplink") {
			t.Fatalf("上报载荷泄露项目名: %v", item)
		}
	}
	keys := map[string]bool{}
	for _, item := range items {
		keys[item["key"].(string)] = true
	}
	for _, want := range []string{"device_name", "model", "brand", "nic_detail_list"} {
		if !keys[want] {
			t.Fatalf("载荷缺少 %s", want)
		}
	}
}
