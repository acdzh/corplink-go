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

	"github.com/acdzh/corplink-go/internal/api"
	"github.com/acdzh/corplink-go/internal/config"
	"github.com/acdzh/corplink-go/internal/sign"
	"github.com/acdzh/corplink-go/internal/tunnel"
	"github.com/acdzh/corplink-go/internal/wgkey"
)

// 建连与切换参数。
const (
	// connectTimeout 是向节点申请配置并建隧道的超时。
	connectTimeout = 30 * time.Second
	// latencyTimeout 是测节点延迟的超时。
	latencyTimeout = 6 * time.Second
	// pingTimeout 是请求节点 /vpn/ping 的超时。
	pingTimeout = 5 * time.Second
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
}

// Agent 管理唯一活动隧道。
type Agent struct {
	cfg    *config.Config
	client *api.Client
	meta   api.Meta

	mu      sync.RWMutex
	nodes   []api.VpnInfo
	current *active
	lastErr error
}

// active 是一条活动隧道及其元信息。
type active struct {
	node    api.VpnInfo
	tun     *tunnel.Tunnel
	addr    string
	dns     []string
	domains []string
	since   time.Time
}

// New 构造 Agent 并尝试拉取节点列表。
//
// 拉取失败（例如会话过期）不阻塞启动：面板仍可打开，便于在界面里重新登录。
func New(ctx context.Context, cfg *config.Config, client *api.Client) *Agent {
	a := &Agent{cfg: cfg, client: client, meta: config.Meta(cfg)}
	if err := a.RefreshNodes(ctx); err != nil {
		a.lastErr = err
	}
	return a
}

// RefreshNodes 重新拉取节点列表。
func (a *Agent) RefreshNodes(ctx context.Context) error {
	env, err := a.client.Do(ctx, api.EndpointVPNList, nil, nil)
	if err != nil {
		return err
	}
	if !env.OK() {
		return env.Error()
	}
	var nodes []api.VpnInfo
	if err := json.Unmarshal(env.Data, &nodes); err != nil {
		return err
	}
	a.mu.Lock()
	a.nodes = nodes
	a.lastErr = nil
	a.mu.Unlock()
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

// Connect 连接指定节点；已连接时先建新隧道再切换。
func (a *Agent) Connect(ctx context.Context, name string) error {
	node, err := a.pick(name)
	if err != nil {
		return err
	}
	connCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	next, err := a.build(connCtx, node)
	if err != nil {
		return err
	}
	a.mu.Lock()
	old := a.current
	a.current = next
	a.mu.Unlock()
	if old != nil {
		// make-before-break：新隧道就绪后再释放旧隧道。
		time.AfterFunc(5*time.Second, old.tun.Close)
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
			a.mu.Lock()
			switch {
			case err != nil:
				a.lastErr = err
			case !env.OK():
				a.lastErr = env.Error()
			default:
				a.lastErr = nil
			}
			a.mu.Unlock()
			if err == nil && env.OK() {
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

// LatencyAll 并发测所有节点的 API 端口建连耗时（毫秒），失败为 -1。
func (a *Agent) LatencyAll(ctx context.Context) map[string]int64 {
	nodes := a.Nodes()
	out := make(map[string]int64, len(nodes))
	type result struct {
		name string
		ms   int64
	}
	results := make(chan result, len(nodes))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, node := range nodes {
		node := node
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ms, err := a.Latency(ctx, nodeName(node))
			if err != nil {
				ms = -1
			}
			results <- result{name: nodeName(node), ms: ms}
		}()
	}
	wg.Wait()
	close(results)
	for r := range results {
		out[r.name] = r.ms
	}
	return out
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
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, node := range nodes {
		node := node
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results <- result{name: nodeName(node), ms: pingNode(ctx, node)}
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
	client := &http.Client{
		Timeout: pingTimeout,
		Transport: &http.Transport{
			// 节点使用自签证书，且这里只测连通性，不做身份校验。
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	url := fmt.Sprintf("https://%s:%d/vpn/ping", node.IP, node.APIPort)
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
	state := a.State()
	if !state.Connected {
		if err := a.Connect(ctx, best); err == nil {
			fmt.Printf("自动选路: 连接 %s（%dms）\n", best, bestMs)
		}
		return
	}
	currentMs := latencies[state.Node]
	// 当前节点不可达，或比最优慢 40% 以上且差距超过 30ms 时切换。
	shouldSwitch := currentMs < 0 || (bestMs >= 0 && currentMs > bestMs+30 && int64(float64(bestMs)*1.4) < currentMs)
	if shouldSwitch && best != state.Node {
		if err := a.Connect(ctx, best); err == nil {
			fmt.Printf("自动选路: %s(%dms) -> %s(%dms)\n", state.Node, currentMs, best, bestMs)
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

// build 向节点申请配置并启动隧道。
func (a *Agent) build(ctx context.Context, node api.VpnInfo) (*active, error) {
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
	if node.ProtocolMode == 1 {
		protocol = tunnel.ProtocolTCP
	}
	// 数据面固定用服务端下发的全量路由：我们只负责提供代理，
	// 哪些流量进代理由 Clash 等使用方通过规则决定。
	allowed := info.Setting.VpnRouteFull
	if len(allowed) == 0 {
		allowed = info.Setting.VpnRouteSplit
	}
	tun, err := tunnel.Start(tunnel.Config{
		PrivateKey: pair.PrivateKey,
		PeerKey:    info.PublicKey,
		Endpoint:   fmt.Sprintf("%s:%d", node.IP, node.VPNPort),
		Addresses:  addresses,
		DNS:        dns,
		AllowedIPs: allowed,
		MTU:        int(info.Setting.VpnMTU),
		Protocol:   protocol,
	})
	if err != nil {
		return nil, err
	}
	return &active{
		node:    node,
		tun:     tun,
		addr:    info.IP,
		dns:     dns,
		domains: info.Setting.VpnDNSDomain,
		since:   time.Now(),
	}, nil
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
