package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/acdzh/corplink-go/corplink/api"
	"github.com/acdzh/corplink-go/corplink/config"
	"github.com/acdzh/corplink-go/corplink/dpop"
)

// TestRecoveryFor 覆盖官方客户端的错误码映射。
func TestRecoveryFor(t *testing.T) {
	cases := map[int]RecoveryMode{
		3015:     RecoveryRefresh,
		10220018: RecoveryRefresh,
		10420003: RecoveryRefresh,
		10420004: RecoveryRefresh,
		10420005: RecoveryRefresh,
		10420006: RecoveryRefresh,
		10220021: RecoveryReconcile,
		0:        RecoveryNone,
		11020003: RecoveryNone,
	}
	for code, want := range cases {
		if got := RecoveryFor(code); got != want {
			t.Fatalf("RecoveryFor(%d) = %q，应为 %q", code, got, want)
		}
	}
}

// TestTokenExpiry 覆盖 vpn-token 的 exp 解析（不验签，只读 payload）。
func TestTokenExpiry(t *testing.T) {
	token := "eyJhbGciOiJQUzI1NiJ9.eyJleHAiOjE3OTY0OTU4NzZ9.c2ln"
	exp, ok := dpop.TokenExpiry(token)
	if !ok {
		t.Fatal("应解析出 exp")
	}
	if exp.Unix() != 1796495876 {
		t.Fatalf("exp = %d", exp.Unix())
	}
	if _, ok := dpop.TokenExpiry("not-a-jwt"); ok {
		t.Fatal("非 JWT 应返回 false")
	}
	if _, ok := dpop.TokenExpiry("a.b.c"); ok {
		t.Fatal("payload 非 JSON 应返回 false")
	}
}

// TestRecoverConnRetries 覆盖 /vpn/conn 返回票据类错误后的自愈重试。
func TestRecoverConnRetries(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			_, _ = w.Write([]byte("{\"code\":3015,\"action\":\"alert\",\"message\":\"Session 无效\"}"))
			return
		}
		_, _ = w.Write([]byte("{\"code\":0,\"data\":{\"ip\":\"10.0.0.2\"}}"))
	}))
	defer srv.Close()

	cfg := config.Default()
	cfg.Server = srv.URL
	cfg.DeviceID = "device-x"
	main, err := api.New(api.Options{Server: srv.URL, DeviceID: cfg.DeviceID, Meta: config.Meta(cfg)})
	if err != nil {
		t.Fatalf("构造客户端: %v", err)
	}
	var gotMode RecoveryMode
	var gotCode int
	a := New(context.Background(), cfg, main, Options{
		Recover: func(_ context.Context, code int, mode RecoveryMode) error {
			gotCode, gotMode = code, mode
			return nil
		},
	})
	node, err := api.New(api.Options{Server: srv.URL, DeviceID: cfg.DeviceID, InsecureSkipVerify: true, Meta: config.Meta(cfg)})
	if err != nil {
		t.Fatalf("构造节点客户端: %v", err)
	}
	node.SetSigner(func(api.Endpoint, string, *url.URL, []byte, string, string, string) (string, error) { return "", nil })
	body := map[string]any{"public_key": "x"}
	first, err := node.Do(context.Background(), api.EndpointVPNConn, nil, body)
	if err != nil {
		t.Fatalf("首次连接: %v", err)
	}
	if first.Code != 3015 {
		t.Fatalf("首次应返回 3015，实际 %d", first.Code)
	}
	retried, ok := a.recoverConn(context.Background(), node, first, body)
	if !ok {
		t.Fatal("3015 应触发自愈重试")
	}
	if gotMode != RecoveryRefresh || gotCode != 3015 {
		t.Fatalf("恢复参数不对: mode=%q code=%d", gotMode, gotCode)
	}
	if !retried.OK() {
		t.Fatalf("重试应成功，实际 %d", retried.Code)
	}
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("应请求两次，实际 %d", calls)
	}
}

// TestRecoverConnSkipsNonRecoverable 覆盖不认识的错误码不重试。
func TestRecoverConnSkipsNonRecoverable(t *testing.T) {
	cfg := config.Default()
	cfg.Server = "http://127.0.0.1:1"
	cfg.DeviceID = "device-x"
	main, err := api.New(api.Options{Server: cfg.Server, DeviceID: cfg.DeviceID, Meta: config.Meta(cfg)})
	if err != nil {
		t.Fatalf("构造客户端: %v", err)
	}
	called := false
	a := New(context.Background(), cfg, main, Options{
		Recover: func(context.Context, int, RecoveryMode) error { called = true; return nil },
	})
	if _, ok := a.recoverConn(context.Background(), main, &api.Envelope{Code: 11020003}, nil); ok {
		t.Fatal("非恢复错误码不应重试")
	}
	if called {
		t.Fatal("非恢复错误码不应调用恢复回调")
	}
}

// TestExcludeHost 覆盖"把控制面 API 地址从分流网段里减出去"。
func TestExcludeHost(t *testing.T) {
	out := excludeHost([]string{"10.0.0.0/8", "192.168.0.0/16"}, "10.1.2.3")
	for _, route := range out {
		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			t.Fatalf("产出非法路由 %q: %v", route, err)
		}
		if prefix.Contains(netip.MustParseAddr("10.1.2.3")) {
			t.Fatalf("路由 %q 仍包含 API 地址", route)
		}
	}
	// 另一个网段应原样保留
	found := false
	for _, route := range out {
		if route == "192.168.0.0/16" {
			found = true
		}
	}
	if !found {
		t.Fatal("未命中的网段应原样保留")
	}
	// 覆盖面积必须等价于原网段减去这一个地址
	if !prefixCovers(out, "10.2.3.4") {
		t.Fatal("减除后应仍覆盖同一网段内的其他地址")
	}
}

// prefixCovers 判断路由集合是否覆盖给定地址。
func prefixCovers(routes []string, addr string) bool {
	target := netip.MustParseAddr(addr)
	for _, route := range routes {
		if prefix, err := netip.ParsePrefix(route); err == nil && prefix.Contains(target) {
			return true
		}
	}
	return false
}

// TestEffectiveMTU 覆盖 MTU 收敛到物理网卡上限。
func TestEffectiveMTU(t *testing.T) {
	if got := effectiveMTU(0); got <= 0 {
		t.Fatalf("MTU 兜底失败: %d", got)
	}
	if got := effectiveMTU(1280); got != 1280 {
		t.Fatalf("小于链路上限时不应改写: %d", got)
	}
}

// TestRetryableConnectErr 覆盖重试判定（官方只对 1010 重试）。
func TestRetryableConnectErr(t *testing.T) {
	if !retryableConnectErr(&api.BusinessError{Code: codeConnRetry}) {
		t.Fatal("1010 应重试")
	}
	if retryableConnectErr(&api.BusinessError{Code: 3015}) {
		t.Fatal("3015 不应重试")
	}
	if !retryableConnectErr(errors.New("dial timeout")) {
		t.Fatal("网络错误应重试")
	}
}

// TestConnMode 覆盖 mode 字段映射。
func TestConnMode(t *testing.T) {
	if RouteFull.connMode() != "Full" || RouteSplit.connMode() != "Split" {
		t.Fatalf("mode 映射错误: %q %q", RouteFull.connMode(), RouteSplit.connMode())
	}
}
