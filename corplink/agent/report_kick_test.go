package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/acdzh/corplink-go/corplink/api"
	"github.com/acdzh/corplink-go/corplink/config"
	"github.com/acdzh/corplink-go/corplink/tunnel"
	"github.com/acdzh/corplink-go/corplink/wgkey"
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

// failingTUN 模拟"端侧建网卡失败"：让续连停在 /vpn/conn 之后，不起真实隧道。
type failingTUN struct{}

// TUN 始终返回错误。
func (failingTUN) TUN(tunnel.Config) (tun.Device, error) {
	return nil, fmt.Errorf("测试网卡不可用")
}

// newKickAgent 构造一个只面对假节点的 Agent，节点名固定为 node-a。
//
// 上报与连接共用同一个 httptest 服务：按路径区分 /vpn/report 与 /vpn/conn。
func newKickAgent(t *testing.T, srv *httptest.Server, opts Options) (*Agent, api.VpnInfo) {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("解析测试服务地址: %v", err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("解析测试服务端口: %v", err)
	}
	cfg := config.Default()
	cfg.DeviceID = "device-test"
	cfg.ActivateCode = "activate-test"
	main, err := api.New(api.Options{Server: "https://example.com", DeviceID: cfg.DeviceID, Meta: config.Meta(cfg)})
	if err != nil {
		t.Fatalf("构造客户端: %v", err)
	}
	node := api.VpnInfo{Name: "node-a", IP: "127.0.0.1", APIPort: port, VPNPort: 51820}
	a := New(context.Background(), cfg, main, opts)
	// 假节点不会有真实 WireGuard 握手，这里跳过握手校验，只验证上层状态机。
	a.handshakeProbe = func(*tunnel.Tunnel, time.Time, time.Duration) error { return nil }
	a.mu.Lock()
	a.nodes = []api.VpnInfo{node}
	a.reportNode = node
	a.reportIP = "10.0.0.2"
	a.reportPubKey = "pub"
	a.reportMode = "Full"
	a.mu.Unlock()
	return a, node
}

// assertEvent 断言事件日志里出现过指定文本。
func assertEvent(t *testing.T, a *Agent, want string) {
	t.Helper()
	for _, e := range a.Events() {
		if strings.Contains(e.Message, want) {
			return
		}
	}
	t.Fatalf("事件里应包含 %q，实际：%v", want, a.Events())
}

// TestReport1000ResumesWithCredentials 校验被终止后用既有凭据续连。
//
// 续连必须复用同一个节点的 sign_token/identities（prepareNode 的 reconnect=true），
// 否则服务端会把续连当成新会话，隧道地址也随之变化；续连失败后那次新建连接
// 反过来不能带这两个字段（首次连接带上会被判 10220005）。
func TestReport1000ResumesWithCredentials(t *testing.T) {
	connBodies := make(chan map[string]any, 4)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == api.EndpointVPNReport.Path {
			_, _ = w.Write([]byte(`{"code":1000,"action":"alert","message":"kicked"}`))
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		connBodies <- body
		_, _ = w.Write([]byte(`{"code":0,"data":{"ip":"10.0.0.2","public_key":"peer-key","setting":{"vpn_mtu":1420,"vpn_dns":"10.0.0.53"}}}`))
	}))
	defer srv.Close()

	a, node := newKickAgent(t, srv, Options{TUN: failingTUN{}})
	a.setConnCredentials(nodeName(node), "sign-resume", "identities-resume")

	// 上报拿到 1000：断开 -> 续连 -> 兜底新建，两步在 sendReport 里同步走完。
	a.sendReport(reportConnect)

	first := <-connBodies
	if got := first["sign_token"]; got != "sign-resume" {
		t.Fatalf("续连请求应带 sign_token，实际 %v", got)
	}
	if got := first["identities"]; got != "identities-resume" {
		t.Fatalf("续连请求应带 identities，实际 %v", got)
	}
	second := <-connBodies
	if got, ok := second["sign_token"]; ok {
		t.Fatalf("新建连接不应带 sign_token，实际 %v", got)
	}
	if got, ok := second["identities"]; ok {
		t.Fatalf("新建连接不应带 identities，实际 %v", got)
	}
	assertEvent(t, a, "续连失败（")
	assertEvent(t, a, "改为新建连接")
	assertEvent(t, a, "保持断开")
	if a.State().Connected {
		t.Fatal("两次尝试都失败时应保持断开")
	}
}

// TestReport1000ResumeSuccessRestartsReport 校验续连成功后隧道与上报循环都恢复。
func TestReport1000ResumeSuccessRestartsReport(t *testing.T) {
	peer, err := wgkey.Generate()
	if err != nil {
		t.Fatalf("生成对端密钥: %v", err)
	}
	payload := fmt.Sprintf(`{"code":0,"data":{"ip":"10.0.0.2","public_key":%q,"setting":{"vpn_mtu":1420,"vpn_dns":"10.0.0.53","vpn_route_full":["10.0.0.0/8"]}}}`, peer.PublicKey)
	connBodies := make(chan map[string]any, 4)
	var reports int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == api.EndpointVPNReport.Path {
			if atomic.AddInt32(&reports, 1) == 1 {
				_, _ = w.Write([]byte(`{"code":1000,"action":"alert","message":"kicked"}`))
				return
			}
			_, _ = w.Write([]byte(`{"code":0}`))
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		connBodies <- body
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	a, node := newKickAgent(t, srv, Options{})
	a.setConnCredentials(nodeName(node), "sign-resume", "identities-resume")
	defer a.Disconnect()

	a.sendReport(reportConnect)

	if !a.State().Connected {
		t.Fatalf("续连成功后应处于已连接状态，事件：%v", a.Events())
	}
	if got := a.State().Node; got != nodeName(node) {
		t.Fatalf("续连应沿用同一个节点，实际 %s", got)
	}
	first := <-connBodies
	if got := first["sign_token"]; got != "sign-resume" {
		t.Fatalf("续连请求应带 sign_token，实际 %v", got)
	}
	select {
	case extra := <-connBodies:
		t.Fatalf("续连成功后不应再新建连接，却收到请求体 %v", extra)
	default:
	}
	a.mu.RLock()
	reporting := a.reportStop != nil
	resumes := a.kickResumes
	a.mu.RUnlock()
	if !reporting {
		t.Fatal("续连成功后应继续正常上报循环")
	}
	if resumes != 0 {
		t.Fatalf("链路恢复后连续续连计数应清零，实际 %d", resumes)
	}
	assertEvent(t, a, "续连成功")
}

// TestReport1000ResumeSkipsUnknownNode 校验节点不在列表时放弃续连。
func TestReport1000ResumeSkipsUnknownNode(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == api.EndpointVPNReport.Path {
			_, _ = w.Write([]byte(`{"code":1000,"action":"alert","message":"kicked"}`))
			return
		}
		t.Errorf("续连目标节点不在列表时不应发起连接请求: %s", r.URL.Path)
	}))
	defer srv.Close()

	a, _ := newKickAgent(t, srv, Options{TUN: failingTUN{}})
	a.setConnCredentials("node-a", "sign-resume", "identities-resume")
	// 节点列表换成了别的节点：上次连接的 node-a 已经不在了。
	a.mu.Lock()
	a.nodes = []api.VpnInfo{{Name: "node-b", IP: "127.0.0.1", APIPort: 1}}
	a.mu.Unlock()

	a.sendReport(reportConnect)

	assertEvent(t, a, "放弃续连")
	assertEvent(t, a, "不在节点列表中")
	if a.State().Connected {
		t.Fatal("放弃续连后应保持断开")
	}
}

// TestReport1000ResumeStopsAtLimit 校验连续被终止时续连次数有上限。
func TestReport1000ResumeStopsAtLimit(t *testing.T) {
	var conns int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == api.EndpointVPNReport.Path {
			_, _ = w.Write([]byte(`{"code":1000,"action":"alert","message":"kicked"}`))
			return
		}
		atomic.AddInt32(&conns, 1)
		_, _ = w.Write([]byte(`{"code":0,"data":{"ip":"10.0.0.2","public_key":"peer-key"}}`))
	}))
	defer srv.Close()

	a, node := newKickAgent(t, srv, Options{TUN: failingTUN{}})
	a.setConnCredentials(nodeName(node), "sign-resume", "identities-resume")
	a.mu.Lock()
	a.kickResumes = kickResumeLimit
	a.mu.Unlock()

	a.sendReport(reportConnect)

	if got := atomic.LoadInt32(&conns); got != 0 {
		t.Fatalf("超过续连上限后不应再发起连接，实际 %d 次", got)
	}
	assertEvent(t, a, "停止自动续连")

	// 链路恢复（一次上报成功）后计数清零，下一次被终止仍会自动续连。
	a.markReportHealthy()
	a.mu.RLock()
	got := a.kickResumes
	a.mu.RUnlock()
	if got != 0 {
		t.Fatalf("上报成功后连续续连计数应清零，实际 %d", got)
	}
}
