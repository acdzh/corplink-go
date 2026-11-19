// Package vpn 管理按需建立的多节点隧道。
//
// 订阅里每个节点对应一个本地端口，但隧道是"懒建立"的：只有当该端口真的收到连接
// （也就是用户/Clash 选中了这个节点）才会向该节点申请配置并起隧道，空闲超时后回收。
// 因此订阅里列出全部节点也不会同时占用多条服务端会话。
package vpn

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acdzh/corplink-go/internal/api"
	"github.com/acdzh/corplink-go/internal/sign"
	"github.com/acdzh/corplink-go/internal/tunnel"
	"github.com/acdzh/corplink-go/internal/wgkey"
)

// 生命周期参数。
const (
	// idleTimeout 是隧道空闲多久后回收。
	idleTimeout = 90 * time.Second
	// minTunnels 是至少保留的隧道数。
	minTunnels = 1
	// dialTimeout 是本地端口转发到隧道 SOCKS 的超时。
	dialTimeout = 10 * time.Second
)

// Session 是一个节点上的一条隧道。
type Session struct {
	// Node 是节点信息。
	Node api.VpnInfo
	// Tunnel 是已建立的隧道。
	Tunnel *tunnel.Tunnel
	// conns 是当前活跃连接数。
	conns atomic.Int32
	// lastUsed 是最后活跃时间（unix 秒）。
	lastUsed atomic.Int64
}

// Manager 负责按需创建、复用与回收隧道。
type Manager struct {
	client   *api.Client
	meta     api.Meta
	activate string
	deviceID string
	max      int

	mu       sync.Mutex
	sessions map[string]*Session
}

// NewManager 构造隧道管理器，maxTunnels 控制同时存在的隧道上限。
func NewManager(client *api.Client, meta api.Meta, activate, deviceID string, maxTunnels int) *Manager {
	if maxTunnels <= 0 {
		maxTunnels = 2
	}
	return &Manager{
		client:   client,
		meta:     meta,
		activate: activate,
		deviceID: deviceID,
		max:      maxTunnels,
		sessions: map[string]*Session{},
	}
}

// Entry 是订阅里一个节点与它对应本地端口的组合。
type Entry struct {
	// Node 是节点信息。
	Node api.VpnInfo
	// Port 是本机映射端口。
	Port int
}

// Assign 为节点分配本地端口，按节点名排序保证订阅稳定。
func Assign(nodes []api.VpnInfo, base int) []Entry {
	sorted := make([]api.VpnInfo, len(nodes))
	copy(sorted, nodes)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].EnName == sorted[j].EnName {
			return sorted[i].IP < sorted[j].IP
		}
		return sorted[i].EnName < sorted[j].EnName
	})
	out := make([]Entry, 0, len(sorted))
	for i, node := range sorted {
		out = append(out, Entry{Node: node, Port: base + i})
	}
	return out
}

// ServePort 在本地端口上接受连接，按需为对应节点建隧道并转发。
func (m *Manager) ServePort(ctx context.Context, entry Entry) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", entry.Port))
	if err != nil {
		return fmt.Errorf("监听 %d: %w", entry.Port, err)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil
		}
		go m.handle(ctx, conn, entry.Node)
	}
}

// handle 处理单条连接：确保隧道存在，再转发到隧道自己的 SOCKS 端口。
func (m *Manager) handle(ctx context.Context, client net.Conn, node api.VpnInfo) {
	defer client.Close()
	sess, err := m.ensure(ctx, node)
	if err != nil {
		return
	}
	sess.conns.Add(1)
	defer sess.conns.Add(-1)
	sess.lastUsed.Store(time.Now().Unix())

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	upstream, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", sess.Tunnel.SocksAddr())
	if err != nil {
		return
	}
	defer upstream.Close()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, client)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
}

// ensure 取出或创建隧道。
func (m *Manager) ensure(ctx context.Context, node api.VpnInfo) (*Session, error) {
	key := nodeKey(node)
	m.mu.Lock()
	if sess, ok := m.sessions[key]; ok {
		m.mu.Unlock()
		return sess, nil
	}
	m.mu.Unlock()

	sess, err := m.build(ctx, node)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	if existing, ok := m.sessions[key]; ok {
		m.mu.Unlock()
		sess.Tunnel.Close()
		return existing, nil
	}
	m.sessions[key] = sess
	m.evictLocked()
	m.mu.Unlock()
	return sess, nil
}

// build 向节点申请配置并启动隧道。
func (m *Manager) build(ctx context.Context, node api.VpnInfo) (*Session, error) {
	nodeClient, err := api.New(api.Options{
		Server:             fmt.Sprintf("https://%s:%d", node.IP, node.APIPort),
		DeviceID:           m.deviceID,
		Language:           m.meta.Language,
		InsecureSkipVerify: true,
		Meta:               m.meta,
	})
	if err != nil {
		return nil, err
	}
	nodeClient.SetCookies(m.client.Cookies())
	nodeClient.SetSigner(sign.NewSigner(m.activate, m.deviceID))

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
	protocol := tunnel.ProtocolUDP
	if node.ProtocolMode == 1 {
		protocol = tunnel.ProtocolTCP
	}
	dns := []string{}
	for _, d := range []string{info.Setting.VpnDNS, info.Setting.VpnDNSBackup} {
		if d != "" {
			dns = append(dns, d)
		}
	}
	addresses := []string{info.IP}
	if info.IPv6 != "" {
		addresses = append(addresses, info.IPv6)
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
	sess := &Session{Node: node, Tunnel: tun}
	sess.lastUsed.Store(time.Now().Unix())
	return sess, nil
}

// evictLocked 在超限时关闭最久未使用的空闲隧道。
func (m *Manager) evictLocked() {
	for len(m.sessions) > m.max {
		var victim *Session
		var victimKey string
		for key, sess := range m.sessions {
			if sess.conns.Load() > 0 {
				continue
			}
			if victim == nil || sess.lastUsed.Load() < victim.lastUsed.Load() {
				victim = sess
				victimKey = key
			}
		}
		if victim == nil {
			return
		}
		victim.Tunnel.Close()
		delete(m.sessions, victimKey)
	}
}

// Reap 周期性回收空闲隧道。
func (m *Manager) Reap(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().Unix()
			m.mu.Lock()
			for key, sess := range m.sessions {
				if sess.conns.Load() > 0 {
					continue
				}
				if now-sess.lastUsed.Load() > int64(idleTimeout.Seconds()) && len(m.sessions) > minTunnels {
					sess.Tunnel.Close()
					delete(m.sessions, key)
				}
			}
			m.mu.Unlock()
		}
	}
}

// Close 关闭所有隧道。
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, sess := range m.sessions {
		sess.Tunnel.Close()
		delete(m.sessions, key)
	}
}

// nodeKey 用节点 IP 与 WireGuard 端口作为唯一标识。
func nodeKey(node api.VpnInfo) string {
	return fmt.Sprintf("%s:%d", node.IP, node.VPNPort)
}
