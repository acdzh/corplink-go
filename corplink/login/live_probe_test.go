//go:build live

package login

import (
	"context"
	"testing"
	"time"

	"github.com/acdzh/corplink-go/corplink/api"
	"github.com/acdzh/corplink-go/corplink/auth"
	"github.com/acdzh/corplink-go/corplink/config"
	"github.com/acdzh/corplink-go/corplink/sign"
)

// TestLivePickLoginMfaType 用真实租户数据确认默认二次验证方式。
//
// 需要本地已有可用会话（~/.corplink-go）；不联网时不要带上 -tags live。
func TestLivePickLoginMfaType(t *testing.T) {
	path, err := config.DefaultPath()
	if err != nil {
		t.Fatalf("default path: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	client, err := api.New(api.Options{Server: cfg.Server, DeviceID: cfg.DeviceID, Language: cfg.Language, Meta: config.Meta(cfg)})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := client.LoadCookies(cfg.SessionPath()); err != nil {
		t.Fatalf("load cookies: %v", err)
	}
	client.SetSigner(sign.NewSigner(cfg.CompanyName, cfg.DeviceID))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	typ, err := auth.NewService(client).MfaType(ctx, mfaScene)
	if err != nil {
		t.Fatalf("mfa/type: %v", err)
	}
	t.Logf("服务端: type=%s types=%v email=%s", typ.Type, typ.Types, typ.Email)
	if got := pickMfaType(supportedAuthTypes(typ.Types), typ.Type); got != "email" {
		t.Fatalf("默认方式 = %q，应为 email（本租户账号未绑手机号，选 mobile 会卡死登录）", got)
	}
}
