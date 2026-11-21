// Package dnsserver 在本地提供一个 DNS 服务，解析走隧道。
//
// 官方客户端启动后会在 127.0.0.1:53 起一个解析服务：内网域名用隧道内 DNS，
// 其余走系统 DNS。没有它的时候，用户在 Clash/直连场景下要么解析不到公司域名，
// 要么把内网查询泄漏给运营商 DNS。
//
// 本包只做必要的事：
//   - UDP + TCP 双栈监听（TCP 用于大响应与 truncation 回退）
//   - 按域后缀分流：命中内网列表走隧道内 DNS，其余走系统 DNS
//   - 上游失败自动切换备用 DNS
//   - 轻量缓存（按 qname+qtype，TTL 取响应里的最小值）
package dnsserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// 解析参数。
const (
	// queryTimeout 是单次上游查询超时。
	queryTimeout = 4 * time.Second
	// maxUDPSize 是 UDP 响应的最大字节数，超过则回退 TCP。
	maxUDPSize = 1400
	// minCacheTTL / maxCacheTTL 限定缓存时间，避免被异常 TTL 拖住。
	minCacheTTL = 5 * time.Second
	maxCacheTTL = 10 * time.Minute
	// maxCacheEntries 是缓存条目上限。
	maxCacheEntries = 1024
)

// Dialer 通过隧道拨号；为 nil 时走系统栈。
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Options 是启动参数。
type Options struct {
	// Listen 是监听地址，形如 127.0.0.1:10053。
	Listen string
	// Upstream 是隧道内 DNS 地址（通常是服务端下发的 vpn_dns 与 vpn_dns_backup）。
	Upstream []string
	// UpstreamFunc 动态返回隧道内 DNS；隧道重连后地址可能变化，优先用它。
	UpstreamFunc func() []string
	// SplitFunc 动态返回内网域名后缀；为空时用 SplitDomains。
	SplitFunc func() []string
	// PhysicalFunc 动态返回当前物理网络的 DNS；为空时自动发现并缓存。
	PhysicalFunc func() []string
	// ExcludeFunc 动态返回"强制走物理网络 DNS"的域名（服务端排除表）。
	ExcludeFunc func() []string
	// SplitMode 为真时才按域名分流；默认 false —— 连上隧道后所有查询都发给
	// 公司 DNS（与官方一致：VpnService.addDnsServer 只下发 vpn_dns/vpn_dns_backup）。
	SplitMode bool
	// SystemUpstream 是非内网域名的上游，为空时读 /etc/resolv.conf。
	SystemUpstream []string
	// SplitDomains 是走内网 DNS 的域名后缀（含通配写法）。
	SplitDomains []string
	// Dial 提供隧道拨号；为 nil 时用系统栈。
	Dial Dialer
}

// Server 是一个本地 DNS 服务。
type Server struct {
	opts   Options
	udp    *net.UDPConn
	tcp    *net.TCPListener
	cancel context.CancelFunc

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// cacheEntry 是一条缓存。
type cacheEntry struct {
	msg     []byte
	expires time.Time
}

// New 构造服务（不监听）。
func New(opts Options) *Server {
	if len(opts.SystemUpstream) == 0 {
		opts.SystemUpstream = systemNameservers()
	}
	return &Server{opts: opts, cache: make(map[string]cacheEntry)}
}

// Addr 返回实际监听地址。
func (s *Server) Addr() string {
	if s.udp != nil {
		return s.udp.LocalAddr().String()
	}
	return s.opts.Listen
}

// Start 开始监听并处理请求。
func (s *Server) Start() error {
	addr, err := net.ResolveUDPAddr("udp", s.opts.Listen)
	if err != nil {
		return fmt.Errorf("解析 DNS 监听地址: %w", err)
	}
	udp, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("监听 DNS UDP: %w", err)
	}
	tcpAddr, err := net.ResolveTCPAddr("tcp", s.opts.Listen)
	if err != nil {
		_ = udp.Close()
		return fmt.Errorf("解析 DNS TCP 地址: %w", err)
	}
	tcp, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		_ = udp.Close()
		return fmt.Errorf("监听 DNS TCP: %w", err)
	}
	s.udp, s.tcp = udp, tcp
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go s.serveUDP(ctx)
	go s.serveTCP(ctx)
	return nil
}

// Close 停止服务。
func (s *Server) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.udp != nil {
		_ = s.udp.Close()
	}
	if s.tcp != nil {
		_ = s.tcp.Close()
	}
	return nil
}

// serveUDP 处理 UDP 查询。
func (s *Server) serveUDP(ctx context.Context) {
	buf := make([]byte, 4096)
	for {
		n, remote, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go func() {
			resp, err := s.resolve(ctx, query, false)
			if err != nil || len(resp) == 0 {
				return
			}
			if len(resp) > maxUDPSize {
				// 超长响应让客户端改用 TCP（TC 位置 1）。
				resp = truncatedResponse(query)
			}
			_, _ = s.udp.WriteToUDP(resp, remote)
		}()
	}
}

// serveTCP 处理 TCP 查询。
func (s *Server) serveTCP(ctx context.Context) {
	for {
		conn, err := s.tcp.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go func(c net.Conn) {
			defer c.Close()
			for {
				_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
				var lenBuf [2]byte
				if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
					return
				}
				size := int(binary.BigEndian.Uint16(lenBuf[:]))
				if size <= 0 || size > 8192 {
					return
				}
				query := make([]byte, size)
				if _, err := io.ReadFull(c, query); err != nil {
					return
				}
				resp, err := s.resolve(ctx, query, true)
				if err != nil || len(resp) == 0 {
					return
				}
				out := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
				copy(out[2:], resp)
				_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := c.Write(out); err != nil {
					return
				}
			}
		}(conn)
	}
}

// resolve 解析一次查询：查缓存 → 选上游 → 转发。
func (s *Server) resolve(ctx context.Context, query []byte, tcp bool) ([]byte, error) {
	question, err := parseQuestion(query)
	if err != nil {
		return nil, err
	}
	key := cacheKey(question)
	if !tcp {
		if cached := s.loadCache(key); cached != nil {
			return withID(cached, query), nil
		}
	}
	upstreams := s.upstreamsFor(question.Name.String())
	var lastErr error
	for _, upstream := range upstreams {
		if s.sameAsListen(upstream) {
			continue
		}
		resp, err := s.forward(ctx, upstream, query, tcp)
		if err != nil {
			lastErr = err
			continue
		}
		s.saveCache(key, resp)
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的上游 DNS")
	}
	return nil, lastErr
}

// upstreamsFor 按域名选择上游：命中内网后缀走隧道 DNS，其余走系统 DNS。
// sameAsListen 判断上游是否就是我们自己，避免把查询打回自身形成环。
func (s *Server) sameAsListen(upstream string) bool {
	addr := withDefaultPort(upstream)
	if s.udp == nil {
		return false
	}
	return addr == s.udp.LocalAddr().String() || addr == s.opts.Listen
}

func (s *Server) upstreamsFor(name string) []string {
	lower := strings.ToLower(strings.TrimSuffix(name, "."))
	// 排除表优先：官方把 vpn_global_exclude / exclude_dynamic_domain /
	// exclude_static_domain 里的域名交给物理网络 DNS 解析，避免内网 DNS 回错误答案。
	if s.matchAny(lower, s.excludeDomains()) {
		return s.physicalUpstreams()
	}
	tunnel := s.tunnelUpstreams()
	if !s.opts.SplitMode {
		// 官方默认形态：连上隧道后所有查询都走 vpn_dns（主备），
		// 断开时自然回落物理网络 DNS。
		if len(tunnel) > 0 {
			return tunnel
		}
		return s.physicalUpstreams()
	}
	if s.matchAny(lower, s.splitDomains()) && len(tunnel) > 0 {
		return tunnel
	}
	return s.physicalUpstreams()
}

// matchAny 判断域名是否命中后缀表（支持 *.x 写法）。
func (s *Server) matchAny(name string, suffixes []string) bool {
	for _, suffix := range suffixes {
		suffix = strings.ToLower(strings.TrimSpace(suffix))
		suffix = strings.TrimPrefix(suffix, "*.")
		if suffix == "" {
			continue
		}
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}

// excludeDomains 返回需要走物理网络 DNS 的域名。
func (s *Server) excludeDomains() []string {
	if s.opts.ExcludeFunc != nil {
		return s.opts.ExcludeFunc()
	}
	return nil
}

// physicalUpstreams 返回物理网络 DNS；优先动态发现，其次静态配置。
func (s *Server) physicalUpstreams() []string {
	if s.opts.PhysicalFunc != nil {
		if ups := s.opts.PhysicalFunc(); len(ups) > 0 {
			return ups
		}
	}
	return s.opts.SystemUpstream
}

// Reset 清空缓存；连接状态或网络变化后调用。
func (s *Server) Reset() {
	s.mu.Lock()
	s.cache = make(map[string]cacheEntry)
	s.mu.Unlock()
}

// forward 把原始查询转发给上游，返回原始响应。
func (s *Server) forward(parent context.Context, upstream string, query []byte, tcp bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, queryTimeout)
	defer cancel()
	network := "udp"
	if tcp {
		network = "tcp"
	}
	addr := withDefaultPort(upstream)
	conn, err := s.dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(queryTimeout))

	if tcp {
		out := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(out[:2], uint16(len(query)))
		copy(out[2:], query)
		if _, err := conn.Write(out); err != nil {
			return nil, err
		}
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, err
		}
		size := int(binary.BigEndian.Uint16(lenBuf[:]))
		resp := make([]byte, size)
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, err
		}
		return resp, nil
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// dial 通过隧道（若配置）或系统栈建立连接。
func (s *Server) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.opts.Dial != nil {
		return s.opts.Dial(ctx, network, addr)
	}
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// loadCache 读缓存。
func (s *Server) loadCache(key string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.cache[key]
	if !ok || time.Now().After(entry.expires) {
		delete(s.cache, key)
		return nil
	}
	return entry.msg
}

// withID 把缓存响应里的报文 ID 换成当前查询的 ID。
//
// 缓存的是完整报文，里面还带着上一次查询的 ID；客户端（dig、系统 resolver）
// 会按 ID 匹配响应，对不上直接丢弃，表现就是"第一次能解析，之后同样域名
// 全部超时"——这个坑极难从客户端现象上看出来，必须在出口处改 ID。
func withID(cached, query []byte) []byte {
	if len(cached) < 2 || len(query) < 2 {
		return cached
	}
	out := make([]byte, len(cached))
	copy(out, cached)
	copy(out[:2], query[:2])
	return out
}

// saveCache 写缓存。
func (s *Server) saveCache(key string, msg []byte) {
	ttl := responseTTL(msg)
	if ttl <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cache) >= maxCacheEntries {
		for k := range s.cache {
			delete(s.cache, k)
			break
		}
	}
	copied := make([]byte, len(msg))
	copy(copied, msg)
	s.cache[key] = cacheEntry{msg: copied, expires: time.Now().Add(ttl)}
}

// parseQuestion 解析出问题段的域名与类型。
func parseQuestion(query []byte) (dnsmessage.Question, error) {
	parser := dnsmessage.Parser{}
	if _, err := parser.Start(query); err != nil {
		return dnsmessage.Question{}, err
	}
	return parser.Question()
}

// cacheKey 生成缓存键。
func cacheKey(q dnsmessage.Question) string {
	return fmt.Sprintf("%s|%d|%d", strings.ToLower(q.Name.String()), q.Type, q.Class)
}

// responseTTL 取响应里最小的 TTL，限制在合理区间。
func responseTTL(msg []byte) time.Duration {
	parser := dnsmessage.Parser{}
	if _, err := parser.Start(msg); err != nil {
		return 0
	}
	if _, err := parser.AllQuestions(); err != nil {
		return 0
	}
	min := uint32(0)
	consider := func(ttl uint32) {
		if ttl == 0 {
			return
		}
		if min == 0 || ttl < min {
			min = ttl
		}
	}
	for {
		header, err := parser.AnswerHeader()
		if err != nil {
			break
		}
		consider(header.TTL)
		if err := parser.SkipAnswer(); err != nil {
			break
		}
	}
	parser = dnsmessage.Parser{}
	if _, err := parser.Start(msg); err != nil {
		return time.Duration(min) * time.Second
	}
	for {
		_, err := parser.AdditionalHeader()
		if err != nil {
			break
		}
		if err := parser.SkipAdditional(); err != nil {
			break
		}
	}
	ttl := time.Duration(min) * time.Second
	if ttl < minCacheTTL {
		ttl = minCacheTTL
	}
	if ttl > maxCacheTTL {
		ttl = maxCacheTTL
	}
	return ttl
}

// truncatedResponse 构造一个置了 TC 位的空响应，提示客户端改用 TCP。
func truncatedResponse(query []byte) []byte {
	question, err := parseQuestion(query)
	if err != nil {
		return nil
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 binary.BigEndian.Uint16(query[:2]),
		Response:           true,
		Truncated:          true,
		RecursionDesired:   true,
		RecursionAvailable: true,
	})
	if err := builder.StartQuestions(); err != nil {
		return nil
	}
	if err := builder.Question(question); err != nil {
		return nil
	}
	out, err := builder.Finish()
	if err != nil {
		return nil
	}
	return out
}

// withDefaultPort 给裸 IP 补 53 端口。
func withDefaultPort(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return addr
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "53")
}

// systemNameservers 读 /etc/resolv.conf 里的 nameserver。
func systemNameservers() []string {
	raw, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return []string{"223.5.5.5", "119.29.29.29"}
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "nameserver" {
			ip := fields[1]
			if strings.Contains(ip, ":") && !strings.Contains(ip, "]") {
				ip = "[" + ip + "]"
			}
			out = append(out, net.JoinHostPort(ip, "53"))
		}
	}
	if len(out) == 0 {
		return []string{"223.5.5.5:53", "119.29.29.29:53"}
	}
	return out
}

// tunnelUpstreams 返回当前隧道内 DNS（优先动态取值）。
func (s *Server) tunnelUpstreams() []string {
	if s.opts.UpstreamFunc != nil {
		return s.opts.UpstreamFunc()
	}
	return s.opts.Upstream
}

// splitDomains 返回当前内网域名后缀（优先动态取值）。
func (s *Server) splitDomains() []string {
	if s.opts.SplitFunc != nil {
		return s.opts.SplitFunc()
	}
	return s.opts.SplitDomains
}
