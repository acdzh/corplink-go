// Package vpn 管理按需建立的多节点隧道。
//
// 订阅里每个节点对应一个本地端口，但隧道是"懒建立"的：只有当该端口真的收到连接
// （也就是用户/Clash 选中了这个节点）才会向该节点申请配置并起隧道，空闲超时后回收。
// 因此订阅里列出全部节点也不会同时占用多条服务端会话。
package vpn

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
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

	allowed []netip.Prefix

	mu       sync.Mutex
	sessions map[string]*Session
}

// NewManager 构造隧道管理器，maxTunnels 控制同时存在的隧道上限。
func NewManager(client *api.Client, meta api.Meta, activate, deviceID string, maxTunnels int, routes []string) *Manager {
	if maxTunnels <= 0 {
		maxTunnels = 2
	}
	return &Manager{
		client:   client,
		meta:     meta,
		activate: activate,
		deviceID: deviceID,
		max:      maxTunnels,
		allowed:  parsePrefixes(routes),
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

// handle 处理单条连接。
//
// SOCKS5 要求服务端先回复问候再收请求，因此这里自己完成问候，再窥探目标地址：
// 落在隧道分流网段之外的连接（例如 Clash 对公网地址做延迟测试）直接拒绝，
// 不触发建隧道；只有真正访问内网的连接才会让对应节点按需建连。
func (m *Manager) handle(ctx context.Context, client net.Conn, node api.VpnInfo) {
	defer client.Close()
	br := bufio.NewReader(client)

	target, request, err := readSocks5Request(client, br)
	if err != nil {
		return
	}
	if target.IsValid() && len(m.allowed) > 0 && !containsAddr(m.allowed, target) {
		// 目标不在分流网段内，隧道里本来也到不了，直接回 SOCKS5 拒绝。
		_, _ = client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

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

	// 与隧道内 SOCKS5 服务重新完成一次问候（客户端那次已由我们自己回复）。
	if _, err := upstream.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return
	}
	var method [2]byte
	if _, err := io.ReadFull(upstream, method[:]); err != nil {
		return
	}
	if _, err := upstream.Write(request); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, br)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
}

// readSocks5Request 完成客户端问候并读出 CONNECT 请求，返回目标地址与请求原文。
//
// 域名目标无法在此判定，返回零值地址，交由隧道内解析。
func readSocks5Request(conn net.Conn, r *bufio.Reader) (netip.Addr, []byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return netip.Addr{}, nil, err
	}
	if head[0] != 0x05 {
		return netip.Addr{}, nil, fmt.Errorf("非法 SOCKS 版本 %d", head[0])
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(r, methods); err != nil {
		return netip.Addr{}, nil, err
	}
	// 只支持无认证方式（0x00）。
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return netip.Addr{}, nil, err
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(r, req); err != nil {
		return netip.Addr{}, nil, err
	}
	switch req[3] {
	case 0x01:
		body := make([]byte, 6)
		if _, err := io.ReadFull(r, body); err != nil {
			return netip.Addr{}, nil, err
		}
		req = append(req, body...)
		var a [4]byte
		copy(a[:], body[:4])
		return netip.AddrFrom4(a), req, nil
	case 0x04:
		body := make([]byte, 18)
		if _, err := io.ReadFull(r, body); err != nil {
			return netip.Addr{}, nil, err
		}
		req = append(req, body...)
		var a [16]byte
		copy(a[:], body[:16])
		return netip.AddrFrom16(a), req, nil
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return netip.Addr{}, nil, err
		}
		body := make([]byte, int(lenBuf[0])+2)
		if _, err := io.ReadFull(r, body); err != nil {
			return netip.Addr{}, nil, err
		}
		req = append(append(req, lenBuf...), body...)
		return netip.Addr{}, req, nil
	default:
		return netip.Addr{}, nil, fmt.Errorf("未知 ATYP %d", req[3])
	}
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

// peekSocks5 读取 SOCKS5 问候与请求，返回目标地址与已消费的原始字节。
//
// 域名目标无法在此判定，返回零值地址，由隧道内解析。
func peekSocks5(r *bufio.Reader) (netip.Addr, []byte, error) {
	var raw []byte
	read := func(n int) ([]byte, error) {
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		raw = append(raw, buf...)
		return buf, nil
	}
	if _, err := read(2); err != nil { // VER, NMETHODS
		return netip.Addr{}, nil, err
	}
	nmethods := int(raw[1])
	if _, err := read(nmethods); err != nil {
		return netip.Addr{}, nil, err
	}
	head, err := read(4) // VER, CMD, RSV, ATYP
	if err != nil {
		return netip.Addr{}, nil, err
	}
	switch head[3] {
	case 0x01:
		body, err := read(6)
		if err != nil {
			return netip.Addr{}, nil, err
		}
		var a [4]byte
		copy(a[:], body[:4])
		return netip.AddrFrom4(a), raw, nil
	case 0x04:
		body, err := read(18)
		if err != nil {
			return netip.Addr{}, nil, err
		}
		var a [16]byte
		copy(a[:], body[:16])
		return netip.AddrFrom16(a), raw, nil
	case 0x03:
		lenBuf, err := read(1)
		if err != nil {
			return netip.Addr{}, nil, err
		}
		if _, err := read(int(lenBuf[0]) + 2); err != nil {
			return netip.Addr{}, nil, err
		}
		return netip.Addr{}, raw, nil
	default:
		return netip.Addr{}, nil, fmt.Errorf("未知 ATYP %d", head[3])
	}
}

// parsePrefixes 把路由字符串解析成前缀列表，非法项忽略。
func parsePrefixes(routes []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(routes))
	for _, route := range routes {
		route = strings.TrimSpace(route)
		if route == "" {
			continue
		}
		if !strings.Contains(route, "/") {
			if strings.Contains(route, ":") {
				route += "/128"
			} else {
				route += "/32"
			}
		}
		if prefix, err := netip.ParsePrefix(route); err == nil {
			out = append(out, prefix)
		}
	}
	return out
}

// containsAddr 判断地址是否落在任一分流网段内。
func containsAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
