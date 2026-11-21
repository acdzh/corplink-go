// Package agent 维护"当前这条隧道"。
//
// 与之前每节点一个端口不同，这里全局只有一条活动隧道：切换节点是先把新隧道建好，
// 再原子替换，最后关闭旧隧道（make-before-break），对外始终是同一个本地端口。
package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"log/slog"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/acdzh/corplink-go/corplink/api"
	"github.com/acdzh/corplink-go/corplink/config"
	"github.com/acdzh/corplink-go/corplink/sign"
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
}

// Agent 管理唯一活动隧道。
type Agent struct {
	cfg          *config.Config
	client       *api.Client
	meta         api.Meta
	provider     TUNProvider
	log          *slog.Logger
	deviceLogger *device.Logger

	mu sync.RWMutex
	// auto 为真时后台循环会自动选最优节点。
	auto bool
	// latencies 是最近一次测速结果，节点名 -> 毫秒（-1 表示失败）。
	latencies map[string]int64
	events    []Event
	nodes     []api.VpnInfo
	current   *active
	lastErr   error
}

// active 是一条活动隧道及其元信息。
type active struct {
	node     api.VpnInfo
	tun      *tunnel.Tunnel
	addr     string
	dns      []string
	domains  []string
	mtu      int
	protocol string
	since    time.Time
}

// New 构造 Agent；不发请求、不建隧道，节点列表由调用方在启动阶段拉取。
func New(_ context.Context, cfg *config.Config, client *api.Client, opts Options) *Agent {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	a := &Agent{
		cfg:          cfg,
		client:       client,
		meta:         config.Meta(cfg),
		provider:     opts.TUN,
		log:          logger,
		deviceLogger: opts.DeviceLogger,
		latencies:    map[string]int64{},
	}
	return a
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
		return recordErr(err)
	}
	if !env.OK() {
		return recordErr(env.Error())
	}
	var nodes []api.VpnInfo
	if err := json.Unmarshal(env.Data, &nodes); err != nil {
		return recordErr(err)
	}
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
func (a *Agent) connectNode(ctx context.Context, name string) error {
	node, err := a.pick(name)
	if err != nil {
		a.mu.Lock()
		a.lastErr = err
		a.mu.Unlock()
		a.addEvent("error", "选择节点失败: %v", err)
		return err
	}
	target := nodeName(node)
	a.addEvent("info", "正在连接节点 %s...", target)
	connCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	plan, err := a.prepareNode(connCtx, node)
	if err != nil {
		a.mu.Lock()
		a.lastErr = err
		a.mu.Unlock()
		a.addEvent("error", "连接 %s 失败: %v", target, err)
		return err
	}
	var dev tun.Device
	if a.provider != nil {
		dev, err = a.provider.TUN(plan.cfg)
		if err != nil {
			a.mu.Lock()
			a.lastErr = err
			a.mu.Unlock()
			a.addEvent("error", "创建 %s 的网卡失败: %v", target, err)
			return err
		}
	}
	if err := a.establish(connCtx, plan, dev); err != nil {
		a.mu.Lock()
		a.lastErr = err
		a.mu.Unlock()
		a.addEvent("error", "连接 %s 失败: %v", target, err)
		return err
	}
	return nil
}

// Disconnect 关闭当前隧道。
func (a *Agent) Disconnect() {
	a.mu.Lock()
	old := a.current
	a.current = nil
	a.mu.Unlock()
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
				a.addEvent("warn", "会话保活探测异常: %v", probeErr)
			} else {
				// 服务端若刷新了 Cookie，落盘保存，避免重启后失效。
				_ = a.client.SaveCookies(a.cfg.SessionPath())
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
// 并发测所有节点，返回节点名到往返耗时的映射，失败为 -1。
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

// fastest 返回测速最快的节点名。
func (a *Agent) fastest(ctx context.Context) (string, bool) {
	latencies := a.PingAll(ctx)
	best := ""
	var bestMs int64 = -1
	for name, ms := range latencies {
		if ms < 0 {
			continue
		}
		if bestMs < 0 || ms < bestMs {
			best, bestMs = name, ms
		}
	}
	return best, best != ""
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
	best := ""
	var bestMs int64 = -1
	for name, ms := range latencies {
		if ms < 0 {
			continue
		}
		if bestMs < 0 || ms < bestMs {
			best, bestMs = name, ms
		}
	}
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
	// domains 是服务端下发的分流域名。
	domains []string
	// mtu 是隧道 MTU。
	mtu int
	// protocol 是传输协议展示名。
	protocol string
	// target 是节点展示名。
	target string
}

// Addresses 返回本端隧道地址（不带掩码）。
func (p *Plan) Addresses() []string { return p.cfg.Addresses }

// Routes 返回需要走隧道的网段。
func (p *Plan) Routes() []string { return p.cfg.AllowedIPs }

// DNS 返回隧道内 DNS。
func (p *Plan) DNS() []string { return p.cfg.DNS }

// MTU 返回隧道 MTU。
func (p *Plan) MTU() int { return p.mtu }

// Node 返回节点展示名。
func (p *Plan) Node() string { return p.target }

// Prepare 向节点申请隧道配置并生成参数，但不建立隧道。
//
// Android 等需要先创建系统网卡的端侧走这条路径：拿 Plan 建好网卡后交回 Establish。
func (a *Agent) Prepare(ctx context.Context, name string) (*Plan, error) {
	node, err := a.pick(name)
	if err != nil {
		return nil, err
	}
	return a.prepareNode(ctx, node)
}

// prepareNode 用已选定的节点申请隧道参数。
func (a *Agent) prepareNode(ctx context.Context, node api.VpnInfo) (*Plan, error) {
	nodeClient, err := api.New(api.Options{
		Server:             fmt.Sprintf("https://%s:%d", node.IP, node.APIPort),
		DeviceID:           a.cfg.DeviceID,
		Language:           a.cfg.Language,
		InsecureSkipVerify: true,
		Meta:               a.meta,
	})
	if err != nil {
		return nil, err
	}
	nodeClient.SetCookies(a.client.Cookies())
	nodeClient.SetSigner(sign.NewSigner(a.activate(), a.cfg.DeviceID))

	pair, err := wgkey.Generate()
	if err != nil {
		return nil, err
	}
	env, err := nodeClient.Do(ctx, api.EndpointVPNConn, nil, map[string]string{
		"public_key": pair.PublicKey,
		"otp":        "",
	})
	if err != nil {
		return nil, err
	}
	if !env.OK() {
		return nil, env.Error()
	}
	info, err := api.ParseWgInfo(env.Data)
	if err != nil {
		return nil, err
	}
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
	protocol := tunnel.ProtocolUDP
	protocolName := "UDP"
	if node.ProtocolMode == 1 {
		protocol = tunnel.ProtocolTCP
		protocolName = "TCP"
	}
	mtu := int(info.Setting.VpnMTU)
	// 数据面固定用服务端下发的全量路由：我们只负责提供代理，
	// 哪些流量进代理由 Clash 等使用方通过规则决定。
	allowed := info.Setting.VpnRouteFull
	if len(allowed) == 0 {
		allowed = info.Setting.VpnRouteSplit
	}
	tunnelCfg := tunnel.Config{
		PrivateKey: pair.PrivateKey,
		PeerKey:    info.PublicKey,
		Endpoint:   fmt.Sprintf("%s:%d", node.IP, node.VPNPort),
		Addresses:  addresses,
		DNS:        dns,
		AllowedIPs: allowed,
		MTU:        mtu,
		Protocol:   protocol,
		Logger:     a.deviceLogger,
	}
	if mtu <= 0 {
		mtu = 1420
	}
	return &Plan{
		node:     node,
		cfg:      tunnelCfg,
		dns:      dns,
		domains:  info.Setting.VpnDNSDomain,
		mtu:      mtu,
		protocol: protocolName,
		target:   nodeName(node),
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
		node:     plan.node,
		tun:      tun,
		addr:     plan.cfg.Addresses[0],
		dns:      plan.dns,
		domains:  plan.domains,
		mtu:      plan.mtu,
		protocol: plan.protocol,
		since:    time.Now(),
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
				a.addEvent("warn", "链路 %s 握手超时，准备重连", st.Node)
				name := st.Node
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
