// Package agent 维护"当前这条隧道"。
//
// 与之前每节点一个端口不同，这里全局只有一条活动隧道：切换节点是先把新隧道建好，
// 再原子替换，最后关闭旧隧道（make-before-break），对外始终是同一个本地端口。
package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"log/slog"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/acdzh/corplink-go/corplink/api"
	"github.com/acdzh/corplink-go/corplink/clock"
	"github.com/acdzh/corplink-go/corplink/config"
	"github.com/acdzh/corplink-go/corplink/dpop"
	"github.com/acdzh/corplink-go/corplink/sign"
	"github.com/acdzh/corplink-go/corplink/totp"
	"github.com/acdzh/corplink-go/corplink/tunnel"
	"github.com/acdzh/corplink-go/corplink/wgkey"
)

// 建连与切换参数。
const (
	// connectTimeout 是向节点申请配置并建隧道的超时。
	connectTimeout = 30 * time.Second
	// latencyTimeout 是测节点延迟的超时。
	latencyTimeout = 6 * time.Second
	// pingTimeout 是请求节点 /vpn/ping 的超时。
	pingTimeout = 1500 * time.Millisecond
)

// RecoveryMode 是 DPoP 相关失败后的恢复动作。
//
// 取值对应官方客户端的 DpopRecoveryMode：REFRESH 重新签发 vpn-token，
// RECONCILE_KEY 重新登记设备密钥（服务端认为本地公钥不是它记的那把）。
type RecoveryMode string

const (
	// RecoveryNone 表示该错误码不需要 DPoP 恢复。
	RecoveryNone RecoveryMode = ""
	// RecoveryRefresh 表示重新请求节点列表以换一张 vpn-token。
	RecoveryRefresh RecoveryMode = "refresh"
	// RecoveryReconcile 表示重新登记设备密钥。
	RecoveryReconcile RecoveryMode = "reconcile"
)

// vpnTokenRenewMargin 是 vpn-token 的续签余量：剩余不足这个时间就提前换一张。
const vpnTokenRenewMargin = 48 * time.Hour

// defaultCentralDNSVip 是官方对内网 DNS dnat 网段的缺省值（ServerOperator.java:23）。
const defaultCentralDNSVip = "30.100.0.0/14"

// 连接重试与协议回退参数，对齐官方 ServerOperator 的 3 dot × 3 次。
const (
	// connCandidates 是自动模式下最多尝试的候选节点数。
	connCandidates = 3
	// connAttempts 是单个候选节点的最大尝试次数。
	connAttempts = 3
	// codeConnRetry 是官方唯一会重试的业务码（节点侧瞬时失败）。
	codeConnRetry = 1010
	// codeConnMFA 表示连接需要二次认证（VpnConfigModel 里由 3002 映射而来）。
	codeConnMFA = 20210002
	// handshakeFailLimit 是连续握手超时多少次后切换传输协议。
	handshakeFailLimit = 2
)

// RecoveryFor 把服务端错误码映射成恢复动作。
//
// 错误码取自官方客户端 DpopVpnRecovery.Companion.modeFor：
// 10220018 与 10420003~10420006 表示设备证明/票据失效，需要换票；
// 10220021 表示服务端记的公钥与本机不一致，需要重新登记。
// 3015 是飞连通用的"Session 无效"，在 DPoP 场景下等价于会话还没有 vpn-token。
func RecoveryFor(code int) RecoveryMode {
	switch code {
	case 3015, 10220018, 10420003, 10420004, 10420005, 10420006:
		return RecoveryRefresh
	case 10220021:
		return RecoveryReconcile
	}
	return RecoveryNone
}

// Stats 是隧道流量与握手状态。
type Stats struct {
	// Connected 表示隧道是否已建立。
	Connected bool `json:"connected"`
	// Node 是当前节点名。
	Node string `json:"node"`
	// Address 是隧道内地址。
	Address string `json:"address"`
	// TxBytes 是发出的字节数。
	TxBytes int64 `json:"tx_bytes"`
	// RxBytes 是收到的字节数。
	RxBytes int64 `json:"rx_bytes"`
	// LastHandshake 是最近一次握手时间戳。
	LastHandshake int64 `json:"last_handshake"`
	// UptimeSeconds 是连接持续秒数。
	UptimeSeconds int64 `json:"uptime_seconds"`
}

// State 是当前活动连接的状态快照。
type State struct {
	// Connected 表示隧道是否已建立。
	Connected bool `json:"connected"`
	// Node 是当前节点名。
	Node string `json:"node"`
	// Address 是隧道内地址。
	Address string `json:"address"`
	// Since 是连接建立时间。
	Since string `json:"since"`
	// Routes 是当前分流网段数量。
	Routes int `json:"routes"`
	// DNS 是隧道内 DNS。
	DNS []string `json:"dns"`
	// Protocol 是隧道传输协议（UDP 或 TCP）。
	Protocol string `json:"protocol"`
	// Endpoint 是节点 WireGuard 对端地址。
	Endpoint string `json:"endpoint"`
	// MTU 是隧道最大传输单元。
	MTU int `json:"mtu"`
	// Domains 是服务端下发的分流域名数量。
	Domains int `json:"domains"`
	// Tag 是当前节点标签。
	Tag string `json:"tag"`
}

// RouteMode 是隧道分流模式。
type RouteMode string

const (
	// RouteFull 把服务端下发的全量路由送进隧道（全局）。
	RouteFull RouteMode = "full"
	// RouteSplit 只把内网网段送进隧道（分流）。
	RouteSplit RouteMode = "split"
)

// TUNProvider 提供隧道使用的网卡；为空时使用内置 netstack 网卡。
type TUNProvider interface {
	// TUN 按隧道参数返回网卡，返回的网卡交给 wireguard-go 托管。
	TUN(cfg tunnel.Config) (tun.Device, error)
}

// Options 是构造 Agent 的可选依赖。
type Options struct {
	// TUN 覆盖网卡实现（Android 传 VpnService 的 fd）。
	TUN TUNProvider
	// Logger 接收运行日志；为空时丢弃。
	Logger *slog.Logger
	// DeviceLogger 接收 WireGuard 内部日志；为空时静默。
	DeviceLogger *device.Logger
	// DPoP 提供设备密钥；节点连接接口要带设备证明，为空时退回无证明形态。
	DPoP *dpop.Store
	// Recover 在连接返回 DPoP 相关错误码时执行恢复动作；为空则不重试。
	Recover func(ctx context.Context, code int, mode RecoveryMode) error
	// SolveVPNMFA 在连接返回 20210002（连接期二次认证）时求一个验证码并完成校验。
	SolveVPNMFA func(ctx context.Context) error
	// OnKicked 在会话被服务端终止（101 / logout_reason / report 1000）时回调。
	OnKicked func(reason string)
	// Verbose 打开节点侧请求日志（/vpn/conn、/vpn/report）。
	Verbose bool
}

// Agent 管理唯一活动隧道。
type Agent struct {
	cfg          *config.Config
	client       *api.Client
	meta         api.Meta
	provider     TUNProvider
	log          *slog.Logger
	deviceLogger *device.Logger
	dpop         *dpop.Store
	recover      func(ctx context.Context, code int, mode RecoveryMode) error
	solveVPNMFA  func(ctx context.Context) error
	onKickedFn   func(reason string)
	verbose      bool

	mu sync.RWMutex
	// onKicked 在会话被服务端终止时回调（清会话、停重连）。
	onKicked func(reason string)
	// reportStop 是连接上报循环的停止信号（关闭即停止）。
	reportStop chan struct{}
	// reportNode / reportIP / reportPubKey / reportMode 是上报所需的连接信息。
	reportNode   api.VpnInfo
	reportIP     string
	reportPubKey string
	reportMode   string
	// credNode / signToken / identities 是最近一次连接的下发凭据（与节点绑定）。
	credNode   string
	signToken  string
	identities string
	// auto 为真时后台循环会自动选最优节点。
	auto bool
	// protoOverride 记录每个节点被迫切换到的传输协议（握手连续失败后设置）。
	protoOverride map[string]int
	// handshakeFails 记录每个节点连续握手超时次数。
	handshakeFails map[string]int
	// latencies 是最近一次测速结果，节点名 -> 毫秒（-1 表示失败）。
	latencies map[string]int64
	events    []Event
	nodes     []api.VpnInfo
	current   *active
	lastErr   error
}

// active 是一条活动隧道及其元信息。
type active struct {
	node    api.VpnInfo
	tun     *tunnel.Tunnel
	addr    string
	dns     []string
	domains []string
	// dynamicDomains 是当前隧道的动态域名清单。
	dynamicDomains []string
	mtu            int
	protocol       string
	since          time.Time
}

// New 构造 Agent；不发请求、不建隧道，节点列表由调用方在启动阶段拉取。
func New(_ context.Context, cfg *config.Config, client *api.Client, opts Options) *Agent {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	a := &Agent{
		cfg:            cfg,
		client:         client,
		meta:           config.Meta(cfg),
		provider:       opts.TUN,
		log:            logger,
		deviceLogger:   opts.DeviceLogger,
		dpop:           opts.DPoP,
		recover:        opts.Recover,
		solveVPNMFA:    opts.SolveVPNMFA,
		onKickedFn:     opts.OnKicked,
		verbose:        opts.Verbose,
		latencies:      map[string]int64{},
		protoOverride:  map[string]int{},
		handshakeFails: map[string]int{},
	}
	return a
}

// SetRecover 注册 DPoP 恢复回调（连接失败时按错误码自愈）。
func (a *Agent) SetRecover(fn func(ctx context.Context, code int, mode RecoveryMode) error) {
	a.recover = fn
}

// RefreshNodes 重新拉取节点列表。
func (a *Agent) RefreshNodes(ctx context.Context) error {
	recordErr := func(err error) error {
		a.mu.Lock()
		a.lastErr = err
		a.mu.Unlock()
		a.addEvent("warn", "拉取节点列表失败: %v", err)
		return err
	}
	env, err := a.client.Do(ctx, api.EndpointVPNList, nil, nil)
	if err != nil {
		var kicked *api.KickedError
		if errors.As(err, &kicked) {
			a.handleKicked(err)
			return recordErr(err)
		}
		// 网络抖动（RST/超时）在移动网络与出口 NAT 上很常见，退避一次再试。
		select {
		case <-ctx.Done():
			return recordErr(err)
		case <-time.After(800 * time.Millisecond):
		}
		env, err = a.client.Do(ctx, api.EndpointVPNList, nil, nil)
		if err != nil {
			return recordErr(err)
		}
	}
	if !env.OK() {
		return recordErr(env.Error())
	}
	var nodes []api.VpnInfo
	if err := json.Unmarshal(env.Data, &nodes); err != nil {
		return recordErr(err)
	}
	// 专属节点排在最后：官方客户端把 dedicated 节点单独拎到列表末尾，
	// 这里在入库时定序，CLI / 面板 / 桌面端拿到的顺序保持一致。
	sort.SliceStable(nodes, func(i, j int) bool {
		return !nodes[i].Dedicated && nodes[j].Dedicated
	})
	a.mu.Lock()
	a.nodes = nodes
	a.lastErr = nil
	a.mu.Unlock()
	a.addEvent("info", "已刷新节点列表，共 %d 个节点", len(nodes))
	return nil
}

// Nodes 返回节点列表副本。
func (a *Agent) Nodes() []api.VpnInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]api.VpnInfo, len(a.nodes))
	copy(out, a.nodes)
	return out
}

// LoggedIn 判断当前是否持有登录会话。
func (a *Agent) LoggedIn() bool {
	return a.client.HasSession()
}

// LastError 返回最近一次节点拉取错误。
func (a *Agent) LastError() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.lastErr == nil {
		return ""
	}
	return a.lastErr.Error()
}

// Mode 返回当前连接模式：auto 或固定节点名。
func (a *Agent) Mode() string {
	if a.Auto() {
		return "auto"
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.current == nil {
		return ""
	}
	return nodeName(a.current.node)
}

// State 返回当前状态。
func (a *Agent) State() State {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.current == nil {
		return State{}
	}
	return State{
		Connected: true,
		Node:      nodeName(a.current.node),
		Address:   a.current.addr,
		Since:     a.current.since.Format(time.RFC3339),
		Routes:    len(a.current.tun.Routes()),
		DNS:       a.current.dns,
		Protocol:  a.current.protocol,
		Endpoint:  fmt.Sprintf("%s:%d", a.current.node.IP, a.current.node.VPNPort),
		MTU:       a.current.mtu,
		Domains:   len(a.current.domains),
		Tag:       a.current.node.TagName,
	}
}

// Tun 返回当前隧道，未连接时为 nil。
func (a *Agent) Tun() *tunnel.Tunnel {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.current == nil {
		return nil
	}
	return a.current.tun
}

// Routes 返回当前分流网段。
func (a *Agent) Routes() []string {
	tun := a.Tun()
	if tun == nil {
		return nil
	}
	return tun.Routes()
}

// Domains 返回当前域名分流后缀。
func (a *Agent) Domains() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.current == nil {
		return nil
	}
	return a.current.domains
}

// DialContext 通过当前隧道拨号；没有隧道时退回系统栈。
//
// 本地 DNS 服务用它把内网查询送进隧道，公网查询走系统。
func (a *Agent) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	a.mu.RLock()
	cur := a.current
	a.mu.RUnlock()
	if cur != nil && cur.tun != nil {
		if conn, err := cur.tun.DialContext(ctx, network, addr); err == nil {
			return conn, nil
		}
	}
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// DynamicDomains 返回当前隧道的动态域名清单（服务端 dynamic_domain）。
func (a *Agent) DynamicDomains() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.current == nil {
		return nil
	}
	return a.current.dynamicDomains
}

// VPNDNS 返回当前隧道使用的内网 DNS 地址。
func (a *Agent) VPNDNS() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.current == nil {
		return nil
	}
	return a.current.dns
}

// Allowed 判断地址是否在分流网段内。
func (a *Agent) Allowed(addr netip.Addr) bool {
	tun := a.Tun()
	if tun == nil {
		return false
	}
	return tun.Allowed(addr)
}

// Connect 连接指定节点；name 为 auto 时先测速再选最快的节点。
func (a *Agent) Connect(ctx context.Context, name string) error {
	if name == "auto" {
		a.addEvent("info", "正在测速并自动选择最快节点...")
		best, ok := a.fastest(ctx)
		if !ok {
			err := fmt.Errorf("没有可用节点")
			a.mu.Lock()
			a.lastErr = err
			a.mu.Unlock()
			a.addEvent("error", "自动选路连接失败: %v", err)
			return err
		}
		a.SetAuto(true)
		return a.connectNode(ctx, best)
	}
	a.SetAuto(false)
	return a.connectNode(ctx, name)
}

// connectNode 连接指定节点，不改变自动模式开关。
//
// 重试策略对齐官方 ServerOperator：自动模式准备 3 个候选节点，手动模式只有 1 个；
// 每个候选最多试 3 次，只对"节点侧瞬时错误"重试（官方仅对 1010 重试）。
func (a *Agent) connectNode(ctx context.Context, name string) error {
	// 启动阶段列表可能因网络抖动没拉到，连接前补一次，避免直接报"节点列表为空"。
	if len(a.Nodes()) == 0 {
		_ = a.RefreshNodes(ctx)
	}
	candidates, err := a.candidates(ctx, name)
	if err != nil {
		return err
	}
	var lastErr error
	for _, node := range candidates {
		for attempt := 1; attempt <= connAttempts; attempt++ {
			err := a.connectOnce(ctx, node)
			if err == nil {
				return nil
			}
			lastErr = err
			if !retryableConnectErr(err) {
				break
			}
			a.addEvent("warn", "连接 %s 第 %d 次失败（%v），重试", nodeName(node), attempt, err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			}
		}
	}
	if lastErr != nil {
		a.mu.Lock()
		a.lastErr = lastErr
		a.mu.Unlock()
		a.addEvent("error", "连接失败: %v", lastErr)
	}
	return lastErr
}

// candidates 按官方策略给出候选节点：自动模式取最快的若干个，手动模式只有一个。
func (a *Agent) candidates(ctx context.Context, name string) ([]api.VpnInfo, error) {
	if name != "auto" {
		node, err := a.pick(name)
		if err != nil {
			return nil, err
		}
		return []api.VpnInfo{node}, nil
	}
	a.addEvent("info", "正在测速并自动选择最快节点...")
	lat := a.PingAll(ctx)
	nodes := a.Nodes()
	sort.SliceStable(nodes, func(i, j int) bool {
		return compareLatency(lat, nodes[i], nodes[j])
	})
	out := make([]api.VpnInfo, 0, connCandidates)
	for _, n := range nodes {
		if n.Dedicated {
			continue
		}
		if v, ok := lat[nodeName(n)]; ok && v < 0 {
			continue
		}
		out = append(out, n)
		if len(out) >= connCandidates {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("没有可用节点")
	}
	return out, nil
}

// compareLatency 按延迟升序比较两个节点。
func compareLatency(lat map[string]int64, a, b api.VpnInfo) bool {
	la, oka := lat[nodeName(a)]
	lb, okb := lat[nodeName(b)]
	switch {
	case oka && okb:
		return la < lb
	case oka:
		return true
	case okb:
		return false
	}
	return false
}

// connectOnce 是一个候选节点的一次完整尝试。
func (a *Agent) connectOnce(ctx context.Context, node api.VpnInfo) error {
	target := nodeName(node)
	a.addEvent("info", "正在连接节点 %s...", target)
	connCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	plan, err := a.prepareNode(connCtx, node, RouteFull, false)
	if err != nil {
		return err
	}
	var dev tun.Device
	if a.provider != nil {
		dev, err = a.provider.TUN(plan.cfg)
		if err != nil {
			return fmt.Errorf("创建 %s 的网卡失败: %w", target, err)
		}
	}
	if err := a.establish(connCtx, plan, dev); err != nil {
		return err
	}
	a.noteProtocol(nodeName(node), plan.cfg.Protocol)
	return nil
}

// retryableConnectErr 判断错误是否值得重试（官方只对 1010 与网络抖动重试）。
//
// 协议解析错误不重试：重试只会把同一个坏响应再拉一遍。
func retryableConnectErr(err error) bool {
	var biz *api.BusinessError
	if errors.As(err, &biz) {
		return biz.Code == codeConnRetry
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return false
	}
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return false
	}
	return true
}

// Disconnect 关闭当前隧道。
func (a *Agent) Disconnect() {
	a.mu.Lock()
	old := a.current
	a.current = nil
	a.mu.Unlock()
	a.stopReport(true)
	if old != nil {
		old.tun.Close()
		a.addEvent("info", "已断开节点 %s", nodeName(old.node))
	}
}

// Keepalive 定期调用一个轻量接口，维持服务端会话并检测是否被踢。
//
// 服务端不下发会话过期时间（Set-Cookie 里没有 Max-Age，/api/info/me 也没有 TTL 字段），
// 因此采用"低频探活 + 立即识别 101"的策略，而不是高频轮询。
func (a *Agent) Keepalive(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 20 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			env, err := a.client.Do(probeCtx, api.EndpointInfoMe, nil, nil)
			cancel()
			var probeErr error
			a.mu.Lock()
			switch {
			case err != nil:
				a.lastErr = err
				probeErr = err
			case !env.OK():
				a.lastErr = env.Error()
				probeErr = a.lastErr
			default:
				a.lastErr = nil
			}
			a.mu.Unlock()
			if probeErr != nil {
				var kicked *api.KickedError
				if errors.As(probeErr, &kicked) {
					a.addEvent("warn", "会话已被服务端终止: %s", kicked.Error())
					a.handleKicked(probeErr)
					continue
				}
				a.addEvent("warn", "会话保活探测异常: %v", probeErr)
			} else {
				// 服务端若刷新了 Cookie，落盘保存，避免重启后失效。
				_ = a.client.SaveCookies(a.cfg.SessionPath())
			}
			// vpn-token 只有 14 天，且只在请求节点列表时才会续签：
			// 保活时顺手看一眼余量，不够就换一张，避免用到过期才发现。
			if a.shouldRenewVPNToken() {
				renewCtx, renewCancel := context.WithTimeout(ctx, 20*time.Second)
				if err := a.RenewVPNToken(renewCtx); err != nil {
					a.addEvent("warn", "续签 vpn-token 失败: %v", err)
				} else {
					a.addEvent("info", "vpn-token 已续签")
				}
				renewCancel()
			}
		}
	}
}

// Stats 返回当前隧道的流量与握手状态。
func (a *Agent) Stats() Stats {
	a.mu.RLock()
	cur := a.current
	a.mu.RUnlock()
	if cur == nil {
		return Stats{}
	}
	out := Stats{
		Connected:     true,
		Node:          nodeName(cur.node),
		Address:       cur.addr,
		UptimeSeconds: int64(time.Since(cur.since).Seconds()),
	}
	raw, err := cur.tun.Stats()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "tx_bytes":
			out.TxBytes, _ = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			out.RxBytes, _ = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_sec":
			out.LastHandshake, _ = strconv.ParseInt(value, 10, 64)
		}
	}
	return out
}

// LatencyAll 并发测所有节点的 /vpn/ping 耗时（毫秒），失败为 -1。
func (a *Agent) LatencyAll(ctx context.Context) map[string]int64 {
	return a.PingAll(ctx)
}

// Ping 对单个节点执行 /vpn/ping 测速并更新缓存。
func (a *Agent) Ping(ctx context.Context, name string) (int64, error) {
	node, err := a.pick(name)
	if err != nil {
		return -1, err
	}
	ms := pingNode(ctx, node)
	key := nodeName(node)
	a.mu.Lock()
	if a.latencies == nil {
		a.latencies = map[string]int64{}
	}
	a.latencies[key] = ms
	a.mu.Unlock()
	return ms, nil
}

// Warmup 在登录成功后按官方客户端的顺序拉一批基础配置，
// 既补齐本地能力，也让请求序列更接近真实客户端。
func (a *Agent) Warmup(ctx context.Context) {
	for _, ep := range []api.Endpoint{
		api.EndpointInfoMe,
		api.EndpointTenantConfig,
		api.EndpointSecurityCfg,
		api.EndpointApplication,
	} {
		probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		_, _ = a.client.Do(probeCtx, ep, nil, nil)
		cancel()
	}
}

// Latencies 返回最近一次测速结果（节点名 -> 毫秒，-1 表示失败）。
func (a *Agent) Latencies() map[string]int64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make(map[string]int64, len(a.latencies))
	for k, v := range a.latencies {
		out[k] = v
	}
	return out
}

// PollLatency 后台定期测速并缓存结果，供界面直接展示延迟。
// 只测速，不触发任何连接。
func (a *Agent) PollLatency(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	refresh := func() { a.PingAll(ctx) }
	go func() {
		refresh()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()
}

// PingAll 用官方客户端的测速接口（GET https://{ip}:{api_port}/vpn/ping）
// 并发测所有普通节点，返回节点名到往返耗时的映射，失败为 -1。
// 专属节点不参与批量测速：官方客户端同样跳过 dedicated 节点，
// 只在用户手动点测速时单独请求。
func (a *Agent) PingAll(ctx context.Context) map[string]int64 {
	nodes := a.Nodes()
	out := make(map[string]int64, len(nodes))
	type result struct {
		name string
		ms   int64
	}
	results := make(chan result, len(nodes))
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for _, node := range nodes {
		node := node
		if node.Dedicated {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			name := nodeName(node)
			ms := pingNode(ctx, node)
			// 边测边写：界面能逐条看到延迟，而不是等全部测完。
			a.mu.Lock()
			if a.latencies == nil {
				a.latencies = map[string]int64{}
			}
			a.latencies[name] = ms
			a.mu.Unlock()
			results <- result{name: name, ms: ms}
		}()
	}
	wg.Wait()
	close(results)
	for r := range results {
		out[r.name] = r.ms
	}
	return out
}

// pingNode 请求节点的 /vpn/ping 并返回毫秒耗时，失败返回 -1。
func pingNode(ctx context.Context, node api.VpnInfo) int64 {
	transport := &http.Transport{
		// 节点使用自签证书，且这里只测连通性，不做身份校验。
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   pingTimeout,
		Transport: transport,
	}
	url := fmt.Sprintf("https://%s:%d/vpn/ping", pingTarget(node), node.APIPort)
	reqCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return -1
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return -1
	}
	return time.Since(start).Milliseconds()
}

// Event 是一条运行事件，用于面板展示。
type Event struct {
	// Time 是事件时间。
	Time string `json:"time"`
	// Level 是 info/warn/error。
	Level string `json:"level"`
	// Message 是事件内容。
	Message string `json:"message"`
}

// LogEvent 对外提供事件记录入口，供登录与配置等模块写入运行日志。
func (a *Agent) LogEvent(level, format string, args ...any) {
	a.addEvent(level, format, args...)
}

// ClearEvents 清空当前内存中的运行事件日志。
func (a *Agent) ClearEvents() {
	a.mu.Lock()
	a.events = nil
	a.mu.Unlock()
}

// addEvent 记录一条事件，仅保留最近 100 条。
func (a *Agent) addEvent(level, format string, args ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, Event{
		Time:    time.Now().Format("15:04:05"),
		Level:   level,
		Message: fmt.Sprintf(format, args...),
	})
	if len(a.events) > 100 {
		a.events = a.events[len(a.events)-100:]
	}
}

// Events 返回最近事件副本。
func (a *Agent) Events() []Event {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]Event, len(a.events))
	copy(out, a.events)
	return out
}

// SetAuto 设置是否处于自动选路模式。
func (a *Agent) SetAuto(v bool) {
	a.mu.Lock()
	a.auto = v
	a.mu.Unlock()
}

// Auto 返回是否处于自动选路模式。
func (a *Agent) Auto() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.auto
}

// fastest 返回测速最快、且允许自动选路的节点名。
func (a *Agent) fastest(ctx context.Context) (string, bool) {
	best, _ := bestNode(a.Nodes(), a.PingAll(ctx))
	return best, best != ""
}

// bestNode 在允许自动选路的节点里挑延迟最低的一个，返回节点名与延迟。
//
// 专属节点（dedicated）由服务端保留给特定账号，官方客户端的自动选路组
// 不含这些节点，这里同样跳过；全部节点都是专属节点时宁可返回空。
func bestNode(nodes []api.VpnInfo, latencies map[string]int64) (string, int64) {
	best := ""
	var bestMs int64 = -1
	for _, node := range nodes {
		if node.Dedicated {
			continue
		}
		ms, ok := latencies[nodeName(node)]
		if !ok || ms < 0 {
			continue
		}
		if bestMs < 0 || ms < bestMs {
			best, bestMs = nodeName(node), ms
		}
	}
	return best, bestMs
}

// pingTarget 返回用于测速的地址：主 IP 不通时依次尝试 backup_ips。
func pingTarget(node api.VpnInfo) string {
	for _, ip := range append([]string{node.IP}, node.BackupIPs...) {
		if ip == "" {
			continue
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(node.APIPort)), 800*time.Millisecond)
		if err != nil {
			continue
		}
		_ = conn.Close()
		return ip
	}
	return node.IP
}

// AutoSelect 启动自动选路：定时测速，连上最快节点；当前节点明显变慢时切换。
func (a *Agent) AutoSelect(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	// 启动时先跑一轮，避免等一个周期才连上。
	a.autoRound(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.autoRound(ctx)
		}
	}
}

// autoRound 执行一轮"测速 + 择优 + 必要时切换"。
func (a *Agent) autoRound(ctx context.Context) {
	if !a.Auto() {
		return
	}
	state := a.State()
	// 未连接时不做任何事：启动不自动连，等用户主动点。
	if !state.Connected {
		return
	}
	latencies := a.PingAll(ctx)
	best, bestMs := bestNode(a.Nodes(), latencies)
	if best == "" {
		return
	}
	currentMs := latencies[state.Node]
	// 当前节点不可达，或比最优慢 40% 以上且差距超过 30ms 时切换。
	shouldSwitch := currentMs < 0 || (bestMs >= 0 && currentMs > bestMs+30 && int64(float64(bestMs)*1.4) < currentMs)
	if shouldSwitch && best != state.Node {
		if err := a.connectNode(ctx, best); err == nil {
			a.addEvent("info", "自动选路切换: %s (%d ms) -> %s (%d ms)", state.Node, currentMs, best, bestMs)
			a.log.Info("自动选路切换", "from", state.Node, "from_ms", currentMs, "to", best, "to_ms", bestMs)
		}
	}
}

// Latency 测节点 API 端口的 TLS 建连耗时，用毫秒表示。
func (a *Agent) Latency(ctx context.Context, name string) (int64, error) {
	node, err := a.pick(name)
	if err != nil {
		return 0, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, latencyTimeout)
	defer cancel()
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", node.IP, node.APIPort))
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start).Milliseconds(), nil
}

// pick 按名称或 IP 选择节点，空名则取第一个。
func (a *Agent) pick(name string) (api.VpnInfo, error) {
	nodes := a.Nodes()
	if len(nodes) == 0 {
		return api.VpnInfo{}, fmt.Errorf("节点列表为空")
	}
	if name == "" {
		return nodes[0], nil
	}
	for _, n := range nodes {
		if nodeName(n) == name || n.IP == name {
			return n, nil
		}
	}
	return api.VpnInfo{}, fmt.Errorf("找不到节点 %q", name)
}

// Plan 是一次待建立的隧道参数：端侧可以按它先创建网卡，再把网卡交回 Establish。
type Plan struct {
	// node 是节点信息。
	node api.VpnInfo
	// cfg 是 WireGuard 隧道参数。
	cfg tunnel.Config
	// dns 是隧道内 DNS。
	dns []string
	// domains 是服务端下发的分流域名（内网 DNS 后缀）。
	domains []string
	// dynamicDomains 是服务端下发的动态域名（需要走隧道/内网解析）。
	dynamicDomains []string
	// mtu 是隧道 MTU。
	mtu int
	// protocol 是传输协议展示名。
	protocol string
	// target 是节点展示名。
	target string
	// publicKey 是本端 WireGuard 公钥，连接上报要用。
	publicKey string
	// routesFull 是服务端下发的全量路由。
	routesFull []string
	// routesSplit 是服务端下发的分流路由。
	routesSplit []string
	// mode 是本次建隧道使用的分流模式。
	mode RouteMode
}

// Addresses 返回本端隧道地址（不带掩码）。
func (p *Plan) Addresses() []string { return p.cfg.Addresses }

// Routes 返回按当前模式选中的网段。
func (p *Plan) Routes() []string { return p.cfg.AllowedIPs }

// RoutesFull 返回全量路由（全局模式用）。
func (p *Plan) RoutesFull() []string { return p.routesFull }

// RoutesSplit 返回分流路由（分流模式用）。
func (p *Plan) RoutesSplit() []string { return p.routesSplit }

// Mode 返回本次建隧道使用的分流模式。
func (p *Plan) Mode() RouteMode { return p.mode }

// DNS 返回隧道内 DNS。
func (p *Plan) DNS() []string { return p.cfg.DNS }

// MTU 返回隧道 MTU。
func (p *Plan) MTU() int { return p.mtu }

// Node 返回节点展示名。
func (p *Plan) Node() string { return p.target }

// Prepare 向节点申请隧道配置并生成参数，但不建立隧道。
//
// Android 等需要先创建系统网卡的端侧走这条路径：拿 Plan 建好网卡后交回 Establish。
func (a *Agent) Prepare(ctx context.Context, name string, mode RouteMode) (*Plan, error) {
	node, err := a.pick(name)
	if err != nil {
		return nil, err
	}
	return a.prepareNode(ctx, node, mode, false)
}

// connMode 把本地分流模式映射成服务端的 mode 取值（Full / Split）。
func (m RouteMode) connMode() string {
	if m == RouteSplit {
		return "Split"
	}
	return "Full"
}

// connCredentials 返回指定节点上次连接拿到的重连凭据。
//
// 凭据与节点绑定：换节点时旧凭据无效，必须丢弃。
func (a *Agent) connCredentials(node string) (signToken, identities string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.credNode != node {
		return "", ""
	}
	return a.signToken, a.identities
}

// setConnCredentials 记录最近一次连接签发的重连凭据。
func (a *Agent) setConnCredentials(node, signToken, identities string) {
	a.mu.Lock()
	a.credNode, a.signToken, a.identities = node, signToken, identities
	a.mu.Unlock()
}

// clearConnCredentials 丢弃重连凭据（会话终止或换节点时调用）。
func (a *Agent) clearConnCredentials() {
	a.mu.Lock()
	a.credNode, a.signToken, a.identities = "", "", ""
	a.mu.Unlock()
}

// mergeRoutes 合并两组路由并去重。
func mergeRoutes(base, extra []string) []string {
	if len(extra) == 0 {
		return base
	}
	seen := make(map[string]struct{}, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, list := range [][]string{base, extra} {
		for _, route := range list {
			route = strings.TrimSpace(route)
			if route == "" {
				continue
			}
			if _, ok := seen[route]; ok {
				continue
			}
			seen[route] = struct{}{}
			out = append(out, route)
		}
	}
	return out
}

// natRoutes 把 NAT 地址段与内网 DNS 的 dnat vip 补成路由。
//
// 官方把 central_dns.vip 缺省成 30.100.0.0/14（ServerOperator.java:23），
// 少了这段时内网域名解析会 timeout：DNS 包根本没进隧道。
func natRoutes(s api.WgSetting) []string {
	var out []string
	vip := strings.TrimSpace(s.CentralDNS.Vip)
	if vip == "" {
		vip = defaultCentralDNSVip
	}
	if vip != "" {
		out = append(out, vip)
	}
	for _, nat := range s.IPNats {
		out = append(out, nat.IPs...)
	}
	return out
}

// excludeHost 把某个 host 从路由集合里减掉。
//
// 单个地址从网段里摘出来可以用前缀二分实现：逐层判断 host 落在哪一半，
// 把另一半保留下来，最终最多产生 (32-len) 个前缀。
func excludeHost(routes []string, host string) []string {
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return routes
	}
	out := make([]string, 0, len(routes)+4)
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil || !prefix.Contains(addr) {
			out = append(out, route)
			continue
		}
		if prefix.Bits() == prefix.Addr().BitLen() {
			// 单地址且正好是这个 host：整条丢掉。
			continue
		}
		out = append(out, subtractHost(prefix, addr)...)
	}
	return out
}

// subtractHost 返回 prefix 去掉 host 之后剩余的前缀集合。
func subtractHost(prefix netip.Prefix, host netip.Addr) []string {
	bits := prefix.Bits()
	maxBits := prefix.Addr().BitLen()
	out := make([]string, 0, maxBits-bits)
	current := prefix
	for current.Bits() < maxBits {
		left, right := splitPrefix(current)
		switch {
		case left.Contains(host):
			out = append(out, right.String())
			current = left
		default:
			out = append(out, left.String())
			current = right
		}
	}
	return out
}

// splitPrefix 把一个前缀对半切开。
func splitPrefix(prefix netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := prefix.Bits() + 1
	left := netip.PrefixFrom(prefix.Addr(), bits).Masked()
	// 右半边的网络地址 = 左半边网络地址 + 该位上的 1
	bytes := left.Addr().AsSlice()
	byteIdx := (bits - 1) / 8
	bitIdx := 7 - (bits-1)%8
	bytes[byteIdx] |= 1 << uint(bitIdx)
	rightAddr, _ := netip.AddrFromSlice(bytes)
	right := netip.PrefixFrom(rightAddr, bits).Masked()
	return left, right
}

// SetSolveVPNMFA 注册连接期二次认证的求解函数。
func (a *Agent) SetSolveVPNMFA(fn func(ctx context.Context) error) {
	a.solveVPNMFA = fn
}

// SetOnKicked 注册"会话被终止"的回调。
func (a *Agent) SetOnKicked(fn func(reason string)) {
	a.onKickedFn = fn
}

// handleKicked 统一处理"会话被服务端终止"：断隧道、停上报、回调上层清会话。
//
// 之前这种行为只被记进 lastErr，界面会一直显示"已连接"但所有请求都失败。
func (a *Agent) handleKicked(err error) {
	reason := ""
	var kicked *api.KickedError
	if errors.As(err, &kicked) {
		reason = kicked.Reason
		if reason == "" {
			reason = kicked.Scene
		}
	}
	if reason == "" && err != nil {
		reason = err.Error()
	}
	a.Disconnect()
	a.clearConnCredentials()
	if a.onKickedFn != nil {
		a.onKickedFn(reason)
	}
}

// noteProtocol 记录某个节点当前实际使用的传输协议。
func (a *Agent) noteProtocol(name string, protocol int) {
	a.mu.Lock()
	a.handshakeFails[name] = 0
	a.mu.Unlock()
}

// protocolFor 返回该节点本次应使用的传输协议。
//
// 优先用握手失败后被动切换到的协议，其次用服务端声明的 protocol_mode。
func (a *Agent) protocolFor(node api.VpnInfo) int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if forced, ok := a.protoOverride[nodeName(node)]; ok {
		return forced
	}
	if node.ProtocolMode == 1 {
		return tunnel.ProtocolTCP
	}
	return tunnel.ProtocolUDP
}

// flipProtocol 在连续握手超时后把节点切到另一种传输协议。
//
// 官方 tryProtocolDetect（VpnManagerImpl.java:1527）做的就是这件事：
// UDP 被运营商封时切 TCP，反之亦然。
func (a *Agent) flipProtocol(name string) (int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.handshakeFails[name]++
	if a.handshakeFails[name] < handshakeFailLimit {
		return 0, false
	}
	current := a.protoOverride[name]
	if current == tunnel.ProtocolTCP {
		a.protoOverride[name] = tunnel.ProtocolUDP
	} else {
		a.protoOverride[name] = tunnel.ProtocolTCP
	}
	a.handshakeFails[name] = 0
	return a.protoOverride[name], true
}

// effectiveMTU 把服务端 MTU 收敛到本机出网网卡能承载的大小。
//
// 服务端常下发 1500，但 PPPoE/部分 4G 链路上限只有 1492/1400：
// 直接照抄会大包黑洞（小包通、TLS 卡死）。官方用主动探测，这里退一步用
// 物理网卡 MTU 减封装开销做上限，零额外流量。
func effectiveMTU(serverMTU int) int {
	if serverMTU <= 0 {
		serverMTU = 1280
	}
	ifaceMTU := physicalMTU()
	if ifaceMTU <= 0 {
		return serverMTU
	}
	// 预留 WireGuard + UDP/IP 封装开销。
	if limit := ifaceMTU - 80; limit > 0 && limit < serverMTU {
		return limit
	}
	return serverMTU
}

// physicalMTU 返回最大的非回环、已启用网卡 MTU。
func physicalMTU() int {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	best := 0
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.MTU > best {
			best = iface.MTU
		}
	}
	return best
}

// otpCode 返回本次连接要带的 TOTP 动态码。
//
// 官方客户端的 /vpn/conn 请求体带 otp 字段：租户开启"连接二次认证"时
// 服务端会用它校验，未开启时忽略。没有 secret 就留空，由服务端决定是否放行。
func (a *Agent) otpCode() string {
	if a.cfg == nil || a.cfg.Code == "" {
		return ""
	}
	code, _, err := totp.Code(a.cfg.Code, clock.Now())
	if err != nil {
		a.addEvent("warn", "生成连接用 TOTP 失败: %v", err)
		return ""
	}
	return code
}

// recoverConn 按错误码执行一次恢复，然后重试 /vpn/conn。
//
// 恢复动作可能换掉会话里的 vpn-token，所以重试前要把主客户端的 Cookie
// 重新灌进节点客户端，否则证明里的 ath 还是旧票。
func (a *Agent) recoverConn(ctx context.Context, nodeClient *api.Client, env *api.Envelope, body map[string]any) (*api.Envelope, bool) {
	mode := RecoveryFor(env.Code)
	if mode == RecoveryNone || a.recover == nil {
		return nil, false
	}
	a.addEvent("warn", "连接返回 %d，触发 DPoP 恢复（%s）", env.Code, mode)
	if err := a.recover(ctx, env.Code, mode); err != nil {
		a.addEvent("warn", "DPoP 恢复失败: %v", err)
		return nil, false
	}
	nodeClient.SetCookies(a.client.Cookies())
	retried, err := nodeClient.Do(ctx, api.EndpointVPNConn, nil, body)
	if err != nil {
		a.addEvent("warn", "恢复后重试连接失败: %v", err)
		return nil, false
	}
	if retried.OK() {
		a.addEvent("info", "DPoP 恢复后连接成功")
	}
	return retried, true
}

// RenewVPNToken 请求一次节点列表，让服务端按当前设备密钥重新签发 vpn-token。
func (a *Agent) RenewVPNToken(ctx context.Context) error {
	env, err := a.client.Do(ctx, api.EndpointVPNList, nil, nil)
	if err != nil {
		return err
	}
	if !env.OK() {
		return env.Error()
	}
	if path := a.cfg.SessionPath(); path != "" {
		if err := a.client.SaveCookies(path); err != nil {
			return err
		}
	}
	return nil
}

// vpnToken 返回当前会话里的 vpn-token 原文。
func (a *Agent) vpnToken() string { return a.client.Cookie("vpn-token") }

// shouldRenewVPNToken 判断是否需要提前续签 vpn-token。
//
// 没有 session 说明还没登录，续签必然失败，直接跳过避免刷日志。
func (a *Agent) shouldRenewVPNToken() bool {
	if a.client.Cookie("session") == "" {
		return false
	}
	token := a.vpnToken()
	if token == "" {
		return true
	}
	exp, ok := dpop.TokenExpiry(token)
	if !ok {
		return true
	}
	return time.Until(exp) < vpnTokenRenewMargin
}

// prepareNode 用已选定的节点申请隧道参数。
func (a *Agent) prepareNode(ctx context.Context, node api.VpnInfo, mode RouteMode, reconnect bool) (*Plan, error) {
	nodeClient, err := api.New(api.Options{
		Server:             fmt.Sprintf("https://%s:%d", node.IP, node.APIPort),
		DeviceID:           a.cfg.DeviceID,
		Language:           a.cfg.Language,
		InsecureSkipVerify: true,
		Meta:               a.meta,
		Verbose:            a.verbose,
	})
	if err != nil {
		return nil, err
	}
	nodeClient.SetCookies(a.client.Cookies())
	// 节点接口同时要 v1 签名与 DPoP 设备证明；后者在密钥未登记时自动跳过。
	if a.dpop != nil {
		a.dpop.Attach(nodeClient, sign.NewSigner(a.activate(), a.cfg.DeviceID))
	} else {
		nodeClient.SetSigner(sign.NewSigner(a.activate(), a.cfg.DeviceID))
	}

	pair, err := wgkey.Generate()
	if err != nil {
		return nil, err
	}
	// 请求体字段对齐官方 VpnConfigModel.java:73-80：
	// mode 表达 Full/Split，export_id 选出口，sign_token/identities 是重连凭据，
	// not_auto 让服务端区分自动/手动连接（配额与统计都按它记账）。
	// 字段类型必须与服务端 JSON 绑定一致：not_auto 是布尔、export_id 是整数，
	// 传成字符串会直接回 10200001「Json绑定异常」。
	connBody := map[string]any{
		"public_key": pair.PublicKey,
		"otp":        a.otpCode(),
		"mode":       mode.connMode(),
		"not_auto":   !a.Auto(),
	}
	if node.ExportID > 0 {
		connBody["export_id"] = node.ExportID
	}
	// sign_token / identities 只在"重连既有连接"时才带：首次连接带上它，
	// 服务端会把它当成一个真实凭据去校验，直接回 10220005「没有 VPN 使用权限」。
	if reconnect {
		if signToken, identities := a.connCredentials(nodeName(node)); signToken != "" || identities != "" {
			connBody["sign_token"] = signToken
			connBody["identities"] = identities
		}
	}
	env, err := nodeClient.Do(ctx, api.EndpointVPNConn, nil, connBody)
	if err != nil {
		return nil, err
	}
	if !env.OK() && env.Code == codeConnMFA {
		// 连接期二次认证：官方把请求挂起，等 MFA 完成后用同一个 body 续跑。
		a.addEvent("info", "节点要求连接期二次认证，正在验证...")
		if a.solveVPNMFA != nil {
			if err := a.solveVPNMFA(ctx); err != nil {
				a.addEvent("warn", "连接期二次认证失败: %v", err)
			} else if retried, err := nodeClient.Do(ctx, api.EndpointVPNConn, nil, connBody); err == nil {
				env = retried
			}
		}
	}
	if !env.OK() {
		// 票据/设备证明类错误先自愈再重试一次，避免每次都要求人工介入。
		if retried, ok := a.recoverConn(ctx, nodeClient, env, connBody); ok {
			env = retried
		}
	}
	if !env.OK() {
		return nil, env.Error()
	}
	info, err := api.ParseWgInfo(env.Data)
	if err != nil {
		return nil, err
	}
	// 记下重连凭据：下次（含 DPoP 自愈重试）要把它们带回去，
	// 否则服务端会把重连当作新会话，分配地址也随之变化。
	a.setConnCredentials(nodeName(node), info.SignToken, info.Identities)
	dns := make([]string, 0, 2)
	for _, d := range []string{info.Setting.VpnDNS, info.Setting.VpnDNSBackup} {
		if d != "" {
			dns = append(dns, d)
		}
	}
	addresses := []string{info.IP}
	if info.IPv6 != "" {
		addresses = append(addresses, info.IPv6)
	}
	protocol := a.protocolFor(node)
	protocolName := "UDP"
	if protocol == tunnel.ProtocolTCP {
		protocolName = "TCP"
	}
	mtu := effectiveMTU(int(info.Setting.VpnMTU))
	// 两套路由都由服务端下发：全局用全量，分流只走内网网段。
	// 任一为空时回落到另一套，避免服务端只下发一份时隧道没有路由。
	// 路由来自四张表：v4/v6 × 全量/分流，外加 NAT 与内网 DNS 的 dnat 网段。
	routesFull := mergeRoutes(info.Setting.VpnRouteFull, info.Setting.V6RouteFull)
	routesSplit := mergeRoutes(info.Setting.VpnRouteSplit, info.Setting.V6RouteSplit)
	routesFull = mergeRoutes(routesFull, natRoutes(info.Setting))
	routesSplit = mergeRoutes(routesSplit, natRoutes(info.Setting))
	if len(routesFull) == 0 {
		routesFull = routesSplit
	}
	if len(routesSplit) == 0 {
		routesSplit = routesFull
	}
	// 分流表若覆盖了节点 API 地址，请求会被塞进隧道导致握手超时甚至掉线，
	// 这里按官方做法把 API 地址从网段里减出去。
	routesSplit = excludeHost(routesSplit, node.IP)
	if mode != RouteSplit {
		mode = RouteFull
	}
	allowed := routesFull
	if mode == RouteSplit {
		allowed = routesSplit
	}
	tunnelCfg := tunnel.Config{
		PrivateKey:   pair.PrivateKey,
		PeerKey:      info.PublicKey,
		PresharedKey: info.PresharedKey,
		Endpoint:     fmt.Sprintf("%s:%d", node.IP, node.VPNPort),
		Addresses:    addresses,
		DNS:          dns,
		AllowedIPs:   allowed,
		MTU:          mtu,
		Protocol:     protocol,
		Logger:       a.deviceLogger,
	}
	if mtu <= 0 {
		mtu = 1420
	}
	return &Plan{
		node:           node,
		publicKey:      pair.PublicKey,
		cfg:            tunnelCfg,
		dns:            dns,
		domains:        info.Setting.VpnDNSDomain,
		dynamicDomains: info.Setting.DynamicDomain,
		mtu:            mtu,
		protocol:       protocolName,
		target:         nodeName(node),
		routesFull:     routesFull,
		routesSplit:    routesSplit,
		mode:           mode,
	}, nil
}

// Establish 用外部网卡建立 plan 描述的隧道；网卡所有权转移给本方法，失败时会被关闭。
func (a *Agent) Establish(ctx context.Context, plan *Plan, dev tun.Device) error {
	if plan == nil {
		return fmt.Errorf("缺少隧道参数")
	}
	return a.establish(ctx, plan, dev)
}

// establish 用网卡建立隧道，并按 make-before-break 替换当前活动隧道。
func (a *Agent) establish(_ context.Context, plan *Plan, dev tun.Device) error {
	tun, err := startTunnel(plan.cfg, dev)
	if err != nil {
		if dev != nil {
			_ = dev.Close()
		}
		return err
	}
	next := &active{
		node:           plan.node,
		tun:            tun,
		addr:           plan.cfg.Addresses[0],
		dns:            plan.dns,
		domains:        plan.domains,
		dynamicDomains: plan.dynamicDomains,
		mtu:            plan.mtu,
		protocol:       plan.protocol,
		since:          time.Now(),
	}
	a.mu.Lock()
	old := a.current
	a.current = next
	a.lastErr = nil
	a.mu.Unlock()
	if old != nil {
		// make-before-break：新隧道就绪后再释放旧隧道。
		time.AfterFunc(5*time.Second, old.tun.Close)
	}
	a.addEvent("info", "已连接 %s（隧道 %s，%s，路由 %d 条）", plan.target, next.addr, next.protocol, len(next.tun.Routes()))
	// 连上后开始周期上报：服务端靠它记录在线状态，也用 code=1000 通知被踢。
	a.startReport(plan)
	return nil
}

// activate 返回签名用的租户标识。
func (a *Agent) activate() string {
	if a.cfg.ActivateCode != "" {
		return a.cfg.ActivateCode
	}
	return a.cfg.CompanyName
}

// nodeName 生成节点显示名。
func nodeName(node api.VpnInfo) string {
	if node.EnName != "" {
		return node.EnName
	}
	if node.Name != "" {
		return node.Name
	}
	return fmt.Sprintf("%s:%d", node.IP, node.VPNPort)
}

// Watchdog 周期性检查隧道健康：握手长时间没有更新就重连。
//
// 用于两种模式：自动模式下交给 AutoSelect 换节点，这里负责"同节点重建"，
// 解决网关空闲切断后需要手动点连接的问题。
func (a *Agent) Watchdog(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			st := a.Stats()
			if !st.Connected {
				continue
			}
			// 握手超过 90 秒没更新视为链路失效（keepalive 是 10 秒）。
			if st.LastHandshake > 0 && time.Now().Unix()-st.LastHandshake > 90 {
				name := st.Node
				// 连续握手超时先怀疑传输协议被墙：切一次协议再重连，
				// 避免官方 tryProtocolDetect 负责的那类"UDP 封了永远连不上"。
				if flipped, ok := a.flipProtocol(name); ok {
					a.addEvent("warn", "链路 %s 连续握手超时，切换传输协议后重连（protocol=%d）", name, flipped)
				} else {
					a.addEvent("warn", "链路 %s 握手超时，准备重连", name)
				}
				if a.Auto() {
					// 自动模式下重新选一次最快节点。
					if best, ok := a.fastest(ctx); ok {
						name = best
					}
				}
				if err := a.connectNode(ctx, name); err != nil {
					a.addEvent("error", "重连 %s 失败: %v", name, err)
				}
			}
		}
	}
}
