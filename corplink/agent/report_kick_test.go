package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/acdzh/corplink-go/corplink/api"
	"github.com/acdzh/corplink-go/corplink/config"
)

// TestReport1000KeepsSession 校验连接被服务端终止时不清理登录态。
//
// 回归点：report 回 code=1000 只表示这条隧道连接被终止，过去会走 handleKicked
// （清 cookie + 删 session.json），把连接抖动升级成必须重新登录。
func TestReport1000KeepsSession(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":1000,"action":"alert","message":"kicked"}`))
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())

	cfg := config.Default()
	cfg.DeviceID = "device-test"
	main, err := api.New(api.Options{Server: "https://example.com", DeviceID: cfg.DeviceID, Meta: config.Meta(cfg)})
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse("https://example.com")
	main.SetCookies([]*http.Cookie{{Name: "session", Value: "keep-me", Path: "/"}})
	_ = base

	a := New(context.Background(), cfg, main, Options{})
	a.reportNode = api.VpnInfo{IP: "127.0.0.1", APIPort: port}
	a.reportIP = "10.0.0.2"
	a.reportPubKey = "pub"
	a.reportMode = "Full"

	a.sendReport(reportConnect)

	if got := main.Cookie("session"); got != "keep-me" {
		t.Fatalf("登录 cookie 被清掉了：session=%q", got)
	}
	found := false
	for _, e := range a.Events() {
		if strings.Contains(e.Message, "保留登录态") {
			found = true
		}
	}
	if !found {
		t.Fatalf("应记录保留登录态的事件，实际事件：%v", a.Events())
	}
	_ = fmt.Sprint()
}
