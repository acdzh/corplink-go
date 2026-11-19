// Package tunnel 用用户态 WireGuard 起隧道，并在 netstack 上暴露 SOCKS5。
//
// 数据面直接复用 PinkD/wireguard-go（与 corplink-rs 内嵌的是同一个 Go 实现），
// 它包含飞连特有的 Noise 标识与 TCP 传输；控制面（登录/签名/配置拉取）由本项目实现。
package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"

	socks5 "github.com/things-go/go-socks5"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// 协议常量与飞连节点上报的 protocol_mode 对应。
const (
	// ProtocolUDP 表示走 UDP 传输（protocol_mode=2）。
	ProtocolUDP = 0
	// ProtocolTCP 表示走 TCP 传输（protocol_mode=1）。
	ProtocolTCP = 1
)

// Config 是启动一条隧道所需的全部参数。
type Config struct {
	// PrivateKey 是本端 WireGuard 私钥（标准 base64）。
	PrivateKey string
	// PeerKey 是节点公钥（标准 base64）。
	PeerKey string
	// Endpoint 是节点 WireGuard 监听地址，形如 1.2.3.4:80。
	Endpoint string
	// Addresses 是本端隧道地址（不带掩码）。
	Addresses []string
	// DNS 是隧道内 DNS 服务器地址。
	DNS []string
	// AllowedIPs 是需要走隧道的网段。
	AllowedIPs []string
	// MTU 是隧道 MTU。
	MTU int
	// Protocol 是传输协议。
	Protocol int
	// SocksListen 是 SOCKS5 监听地址。
	SocksListen string
	// SocksUser 与 SocksPass 非空时启用 RFC1929 认证。
	SocksUser string
	SocksPass string
	// Verbose 打开 WireGuard 内部日志，便于排查握手问题。
	Verbose bool
}

// Tunnel 是一条已启动的隧道及其 SOCKS5 服务。
type Tunnel struct {
	dev    *device.Device
	net    *netstack.Net
	socks  *socks5.Server
	listen net.Listener
}

// Start 创建 netstack、启动 WireGuard 设备并对外提供 SOCKS5。
func Start(cfg Config) (*Tunnel, error) {
	addrs, err := parseAddrs(cfg.Addresses)
	if err != nil {
		return nil, err
	}
	dns, err := parseAddrs(cfg.DNS)
	if err != nil {
		return nil, err
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = device.DefaultMTU
	}
	tunDev, stack, err := netstack.CreateNetTUN(addrs, dns, mtu)
	if err != nil {
		return nil, fmt.Errorf("创建用户态网卡: %w", err)
	}
	var bind conn.Bind
	switch cfg.Protocol {
	case ProtocolTCP:
		bind = conn.NewTCPBind()
	default:
		bind = conn.NewDefaultBind()
	}
	level := device.LogLevelError
	if cfg.Verbose {
		level = device.LogLevelVerbose
	}
	logger := device.NewLogger(level, "corplink-go ")
	dev := device.NewDevice(tunDev, bind, logger)
	if err := dev.Up(); err != nil {
		return nil, fmt.Errorf("启动 WireGuard 设备: %w", err)
	}
	uapi, err := buildUAPI(cfg)
	if err != nil {
		return nil, err
	}
	if err := dev.IpcSet(uapi); err != nil {
		return nil, fmt.Errorf("下发 WireGuard 配置: %w", err)
	}

	opts := []socks5.Option{
		socks5.WithResolver(netstackResolver{net: stack}),
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return stack.DialContext(ctx, network, addr)
		}),
	}
	if cfg.SocksUser != "" {
		opts = append(opts, socks5.WithCredential(socks5.StaticCredentials{cfg.SocksUser: cfg.SocksPass}))
	}
	server := socks5.NewServer(opts...)
	ln, err := net.Listen("tcp", cfg.SocksListen)
	if err != nil {
		return nil, fmt.Errorf("监听 SOCKS5 %s: %w", cfg.SocksListen, err)
	}
	t := &Tunnel{dev: dev, net: stack, socks: server, listen: ln}
	go func() {
		if err := server.Serve(ln); err != nil {
			fmt.Printf("SOCKS5 服务退出: %v\n", err)
		}
	}()
	return t, nil
}

// DialContext 直接在隧道内发起连接，用于排查 SOCKS5 与 netstack 之间的问题。
func (t *Tunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return t.net.DialContext(ctx, network, addr)
}

// LookupHost 在隧道内解析域名，用于排查 DNS 是否可用。
func (t *Tunnel) LookupHost(host string) ([]string, error) {
	return t.net.LookupHost(host)
}

// Stats 返回 WireGuard UAPI 的设备状态，用于排查握手与流量。
func (t *Tunnel) Stats() (string, error) {
	var buf strings.Builder
	if err := t.dev.IpcGetOperation(&buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Close 停止 SOCKS5 与 WireGuard。
func (t *Tunnel) Close() {
	if t.listen != nil {
		_ = t.listen.Close()
	}
	if t.dev != nil {
		t.dev.Close()
	}
}

// netstackResolver 在隧道内解析域名，避免泄漏到本机 DNS。
type netstackResolver struct {
	net *netstack.Net
}

// Resolve 实现 socks5.NameResolver。
func (r netstackResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if ip := net.ParseIP(name); ip != nil {
		return ctx, ip, nil
	}
	addrs, err := r.net.LookupHost(name)
	if err != nil {
		return ctx, nil, err
	}
	// 优先 IPv4：部分服务端对隧道内 IPv6 支持不完整，先走 v4 成功率更高。
	var v6 net.IP
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			return ctx, ip, nil
		}
		if v6 == nil {
			v6 = ip
		}
	}
	if v6 != nil {
		return ctx, v6, nil
	}
	return ctx, nil, fmt.Errorf("解析 %s 失败：无地址", name)
}

// buildUAPI 生成 WireGuard UAPI 配置串。
func buildUAPI(cfg Config) (string, error) {
	priv, err := keyToHex(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("解析私钥: %w", err)
	}
	peer, err := keyToHex(cfg.PeerKey)
	if err != nil {
		return "", fmt.Errorf("解析节点公钥: %w", err)
	}
	var b strings.Builder
	b.WriteString("private_key=" + priv + "\n")
	b.WriteString("replace_peers=true\n")
	b.WriteString("public_key=" + peer + "\n")
	b.WriteString("replace_allowed_ips=true\n")
	b.WriteString("endpoint=" + cfg.Endpoint + "\n")
	b.WriteString("persistent_keepalive_interval=10\n")
	for _, route := range cfg.AllowedIPs {
		if strings.Contains(route, "/") {
			b.WriteString("allowed_ip=" + route + "\n")
			continue
		}
		suffix := "/32"
		if strings.Contains(route, ":") {
			suffix = "/128"
		}
		b.WriteString("allowed_ip=" + route + suffix + "\n")
	}
	b.WriteString("\n")
	return b.String(), nil
}

// keyToHex 把 base64 的 WireGuard 密钥转成 UAPI 需要的 hex。
func keyToHex(key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("密钥长度应为 32 字节，实际 %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// parseAddrs 解析地址列表，忽略空项。
func parseAddrs(values []string) ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if strings.Contains(v, "/") {
			prefix, err := netip.ParsePrefix(v)
			if err != nil {
				return nil, fmt.Errorf("非法地址 %q: %w", v, err)
			}
			out = append(out, prefix.Addr())
			continue
		}
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return nil, fmt.Errorf("非法地址 %q: %w", v, err)
		}
		out = append(out, addr)
	}
	return out, nil
}
