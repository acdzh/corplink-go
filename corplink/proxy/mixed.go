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
	"time"

	"github.com/acdzh/corplink-go/corplink/agent"
)

// 连接与握手参数。
const (
	// dialTimeout 是隧道内拨号超时。
	dialTimeout = 15 * time.Second
	// handshakeTimeout 是读取代理请求头的超时。
	handshakeTimeout = 20 * time.Second
)

// Server 是混合代理服务。
type Server struct {
	agent *agent.Agent
}

// New 构造混合代理。
func New(a *agent.Agent) *Server {
	return &Server{agent: a}
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
func (s *Server) resolve(tun tunLike, host string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr, nil
	}
	addrs, err := tun.LookupHost(host)
	if err != nil {
		return netip.Addr{}, err
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
