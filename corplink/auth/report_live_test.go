//go:build live

package auth

import (
	"context"
	"testing"
	"time"

	"github.com/acdzh/corplink-go/corplink/api"
	"github.com/acdzh/corplink-go/corplink/config"
)

// TestLiveReportDevice 用真实会话验证上报载荷被服务端接受（含 device_name 等自定义项）。
func TestLiveReportDevice(t *testing.T) {
	cfg, err := config.Load("/tmp/cplogin-e2e/config.json")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	client, err := api.New(api.Options{Server: cfg.Server, DeviceID: cfg.DeviceID, Language: cfg.Language, Meta: config.Meta(cfg), Verbose: true})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := client.LoadCookies(cfg.SessionPath()); err != nil {
		t.Fatalf("load cookies: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := NewService(client).ReportDevice(ctx, false, config.Meta(cfg), cfg.DeviceName, cfg.DeviceModel, cfg.DeviceBrand); err != nil {
		t.Fatalf("report: %v", err)
	}
	t.Log("设备上报被接受")
}
