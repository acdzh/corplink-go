// Package proxy 在同一个端口上同时提供 SOCKS5 与 HTTP 代理。
//
// 与 Clash 的 mixed-port 类似：读到首字节 0x05 按 SOCKS5 处理，否则按 HTTP 代理处理。
// 所有连接都经当前活动隧道（用户态 WireGuard + netstack）拨出，域名在隧道内解析。
package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/acdzh/corplink-go/corplink/agent"
)

// 连接与握手参数。
const (
	// dialTimeout 是隧道内拨号超时。
	dialTimeout = 15 * time.Second
	// handshakeTimeout 是读取代理请求头的超时。
	handshakeTimeout = 20 * time.Second
	// resolveTimeout 是隧道内域名解析的上限。解析不走 ctx 时一旦上游 DNS 抖动，
	// 整个 SOCKS 握手会卡到客户端（Clash/mihomo 默认 5s）先超时。
	// 隧道内解析偶尔要 3~6 秒（一次页面要解析十几个主机），3 秒会把正常解析判死，
	// 表现为"页面开了但资源全挂"。放到 8 秒，同时靠单飞去重压住并发解析。
	resolveTimeout = 4 * time.Second
	// resolveCacheTTL 是域名解析结果的缓存时间：连接级缓存能挡掉绝大部分重复解析。
	resolveCacheTTL = 5 * time.Minute
	// maxResolveCache 是缓存条目上限。
	maxResolveCache = 1024
)

// Server 是混合代理服务。
type Server struct {
	agent *agent.Agent

	mu       sync.Mutex
	cache    map[string]resolveEntry
	inflight map[string]*lookupCall
	// dnsAddr 是本地 DNS 服务地址，空则退回隧道内解析。
	dnsAddr string
	// refreshing 记录正在后台刷新的域名，避免同一个域名并发刷新。
	refreshing map[string]bool
}

// lookupCall 是一次正在进行的解析，多个连接共享同一份结果（单飞）。
type lookupCall struct {
	done  chan struct{}
	addrs []string
	err   error
}

// resolveEntry 是一条解析缓存。
type resolveEntry struct {
	addr    netip.Addr
	expires time.Time
}

// New 构造混合代理。
// New 构造混合代理。解析优先走本地 DNS 服务（默认 127.0.0.1:10053，
// corplink 自己的 DNS 有缓存），比每次重新穿透隧道解析快一个数量级。
func New(a *agent.Agent) *Server {
	return &Server{agent: a, cache: make(map[string]resolveEntry)}
}

// ResetCache 清空解析缓存（隧道重连后地址可能变化）。
func (s *Server) ResetCache() {
	s.mu.Lock()
	s.cache = make(map[string]resolveEntry)
	s.mu.Unlock()
}

// Serve 在监听器上接受连接，按协议分发。
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

// handle 嗅探首字节决定走 SOCKS5 还是 HTTP。
func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReader(conn)
	head, err := br.Peek(1)
	if err != nil {
		return
	}
	if head[0] == 0x05 {
		s.handleSocks5(conn, br)
		return
	}
	s.handleHTTP(conn, br)
}

// handleSocks5 处理 SOCKS5 CONNECT。
func (s *Server) handleSocks5(conn net.Conn, br *bufio.Reader) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	if head[0] != 0x05 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	// 不做认证：直接在问候阶段选「无认证」。
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	cmd := req[1]
	var host string
	var port int
	switch req[3] {
	case 0x01:
		buf := make([]byte, 6)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
		port = int(binary.BigEndian.Uint16(buf[4:]))
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(br, lenBuf); err != nil {
			return
		}
		buf := make([]byte, int(lenBuf[0])+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		host = string(buf[:len(buf)-2])
		port = int(binary.BigEndian.Uint16(buf[len(buf)-2:]))
	case 0x04:
		buf := make([]byte, 18)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
		port = int(binary.BigEndian.Uint16(buf[16:]))
	default:
		socksReply(conn, 0x08)
		return
	}
	if cmd != 0x01 {
		// 只支持 CONNECT，UDP ASSOCIATE 暂不实现。
		socksReply(conn, 0x07)
		return
	}

	upstream, err := s.dial(context.Background(), host, port)
	if err != nil {
		socksReply(conn, 0x05)
		return
	}
	defer upstream.Close()
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	bridge(conn, br, upstream)
}

// handleHTTP 处理 HTTP 代理（CONNECT 与绝对 URI 两种）。
func (s *Server) handleHTTP(conn net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	host, port := targetOf(req)
	if host == "" {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	upstream, err := s.dial(context.Background(), host, port)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer upstream.Close()

	if req.Method == http.MethodConnect {
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		_ = conn.SetDeadline(time.Time{})
		bridge(conn, br, upstream)
		return
	}

	// 普通 HTTP 代理请求：改写请求行为 origin-form 后原样转发。
	req.RequestURI = ""
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.Header.Del("Proxy-Connection")
	if err := req.Write(upstream); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	// 必须回写完整响应（状态行 + 头 + 正文），只拷贝 body 会让客户端解析失败。
	if err := resp.Write(conn); err != nil {
		return
	}
}

// dial 在隧道内拨号；域名先在隧道内解析，目标不在分流网段内则直接拒绝。
func (s *Server) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	tun := s.agent.Tun()
	if tun == nil {
		return nil, fmt.Errorf("未连接")
	}
	addr, err := s.resolve(tun, host)
	if err != nil {
		return nil, err
	}
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	return tun.DialContext(dialCtx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(port)))
}

// resolve 解析目标地址，域名走隧道内 DNS 并优先 IPv4。
//
// 带缓存 + 超时：隧道内 DNS 偶发抖动时，不能让每个新连接都重新卡 3 秒以上；
// 解析失败要快速失败（客户端能立刻重试），而不是把连接挂死。
func (s *Server) resolve(tun tunLike, host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr, nil
	}
	if addr, ok := s.loadCached(host); ok {
		return addr, nil
	}
	addrs, err := s.resolveShared(tun, host)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("解析 %s 失败", host)
	}
	var fallback netip.Addr
	for _, raw := range addrs {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		if addr.Is4() {
			return addr, nil
		}
		if !fallback.IsValid() {
			fallback = addr
		}
	}
	if fallback.IsValid() {
		return fallback, nil
	}
	return netip.Addr{}, fmt.Errorf("解析 %s 失败", host)
}

// SetDNSAddr 指定本地 DNS 服务地址（如 127.0.0.1:10053）。
func (s *Server) SetDNSAddr(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dnsAddr = addr
}

// lookupHost 解析域名：优先问本地 DNS（有缓存），失败再退回隧道内解析。
func (s *Server) lookupHost(tun tunLike, host string) ([]string, error) {
	if s.dnsAddr != "" {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(ctx, "udp", s.dnsAddr)
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
		defer cancel()
		if addrs, err := resolver.LookupHost(ctx, host); err == nil && len(addrs) > 0 {
			return addrs, nil
		}
	}
	return s.lookupWithTimeout(tun, host)
}

// resolveShared 让同一个域名的并发解析只打一次隧道 DNS。
//
// 浏览器打开一个页面会同时要十几个主机，逐个去隧道里解析既慢又容易把
// netstack 的 DNS 打满，表现出来就是大量资源超时。
func (s *Server) resolveShared(tun tunLike, host string) ([]string, error) {
	s.mu.Lock()
	if call, ok := s.inflight[host]; ok {
		s.mu.Unlock()
		select {
		case <-call.done:
			return call.addrs, call.err
		case <-time.After(resolveTimeout):
			return nil, fmt.Errorf("解析 %s 超时（等待同一域名的并发解析）", host)
		}
	}
	if s.inflight == nil {
		s.inflight = map[string]*lookupCall{}
	}
	call := &lookupCall{done: make(chan struct{})}
	s.inflight[host] = call
	s.mu.Unlock()

	addrs, err := s.lookupHost(tun, host)

	s.mu.Lock()
	call.addrs, call.err = addrs, err
	delete(s.inflight, host)
	s.mu.Unlock()
	close(call.done)
	if err == nil {
		s.storeCached(host, addrs)
	}
	return addrs, err
}

// loadCached 读解析缓存。
//
// 过期条目不再直接删掉，而是先返回旧地址、后台异步刷新（stale-while-revalidate）：
// 隧道内解析冷启动要 1~5 秒，直接删会让用户正好撞上这个冷启动。
func (s *Server) loadCached(host string) (netip.Addr, bool) {
	s.mu.Lock()
	entry, ok := s.cache[host]
	if !ok {
		s.mu.Unlock()
		return netip.Addr{}, false
	}
	expired := time.Now().After(entry.expires)
	if expired && !s.refreshing[host] {
		if s.refreshing == nil {
			s.refreshing = map[string]bool{}
		}
		s.refreshing[host] = true
		go s.refresh(host)
	}
	s.mu.Unlock()
	// 过期也先用旧值：地址变了顶多连一次旧 IP，比让用户等解析快得多。
	return entry.addr, true
}

// refresh 在后台刷新一条过期缓存。
func (s *Server) refresh(host string) {
	defer func() {
		s.mu.Lock()
		delete(s.refreshing, host)
		s.mu.Unlock()
	}()
	if s.agent == nil {
		return
	}
	tun, err := s.agent.Tunnel()
	if err != nil {
		return
	}
	if addrs, err := s.lookupHost(tun, host); err == nil {
		s.storeCached(host, addrs)
	}
}

// storeCached 写解析缓存。
func (s *Server) storeCached(host string, addrs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cache) >= maxResolveCache {
		for k := range s.cache {
			delete(s.cache, k)
			break
		}
	}
	for _, raw := range addrs {
		addr, err := netip.ParseAddr(raw)
		if err == nil && addr.Is4() {
			s.cache[host] = resolveEntry{addr: addr, expires: time.Now().Add(resolveCacheTTL)}
			return
		}
	}
}

// lookupWithTimeout 给隧道内的 DNS 解析加超时，避免握手被上游抖动拖死。
func (s *Server) lookupWithTimeout(tun tunLike, host string) ([]string, error) {
	type result struct {
		addrs []string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		addrs, err := tun.LookupHost(host)
		done <- result{addrs: addrs, err: err}
	}()
	select {
	case r := <-done:
		return r.addrs, r.err
	case <-time.After(resolveTimeout):
		return nil, fmt.Errorf("解析 %s 超时（%s）", host, resolveTimeout)
	}
}

// tunLike 抽象出代理需要的隧道能力，便于测试。
type tunLike interface {
	LookupHost(host string) ([]string, error)
}

// targetOf 从请求里取出目标主机与端口。
func targetOf(req *http.Request) (string, int) {
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	if host == "" {
		return "", 0
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		port, _ := strconv.Atoi(p)
		return h, port
	}
	port := 80
	if req.URL != nil && req.URL.Scheme == "https" {
		port = 443
	}
	return host, port
}

// socksReply 回复一条 SOCKS5 失败响应。
func socksReply(conn net.Conn, code byte) {
	_, _ = conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

// bridge 双向转发。
func bridge(client net.Conn, clientReader io.Reader, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, clientReader)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
}
