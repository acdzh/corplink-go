// Package agent 维护"当前这条隧道"。
//
// 与之前每节点一个端口不同，这里全局只有一条活动隧道：切换节点是先把新隧道建好，
// 再原子替换，最后关闭旧隧道（make-before-break），对外始终是同一个本地端口。
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
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
)

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
	tun, err := tunnel.Start(tunnel.Config{
		PrivateKey:  pair.PrivateKey,
		PeerKey:     info.PublicKey,
		Endpoint:    fmt.Sprintf("%s:%d", node.IP, node.VPNPort),
		Addresses:   addresses,
		DNS:         dns,
		AllowedIPs:  info.Setting.VpnRouteSplit,
		MTU:         int(info.Setting.VpnMTU),
		Protocol:    protocol,
		SocksListen: "127.0.0.1:0",
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
