// Package tunnel 用用户态 WireGuard 建隧道，并在 netstack 上提供拨号能力。
//
// 数据面复用 PinkD/wireguard-go（与 corplink-rs 内嵌的同一份 Go 实现），
// 它包含飞连特有的 Noise 标识与 TCP 传输；控制面由本项目实现。
// 代理（SOCKS5/HTTP）在上层 internal/proxy 里，直接调用这里的拨号能力。
package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
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
	// Logger 接收 WireGuard 内部日志；为空时丢弃，不写标准输出。
	Logger *device.Logger
}

// ErrNoDialer 表示当前网卡没有用户态拨号能力：fd 直通时流量由系统路由接管。
var ErrNoDialer = errors.New("当前网卡不提供用户态拨号")

// Tunnel 是一条已启动的隧道。
type Tunnel struct {
	dev    *device.Device
	net    *netstack.Net
	routes []netip.Prefix
}

// Start 用内置 netstack 网卡启动隧道：数据面全在用户态，不需要系统 TUN 或 root。
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
	t, err := StartWith(cfg, tunDev)
	if err != nil {
		tunDev.Close()
		return nil, err
	}
	t.net = stack
	return t, nil
}

// StartWith 用调用方提供的网卡启动隧道，网卡的创建与关闭由调用方负责。
//
// Android 用 VpnService 的 fd 建网卡后走这条路径：地址、路由与 DNS 由系统按
// VpnService.Builder 的设置下发，这里只负责 WireGuard 协议本身。
func StartWith(cfg Config, tunDev tun.Device) (*Tunnel, error) {
	if tunDev == nil {
		return nil, fmt.Errorf("缺少网卡")
	}
	var bind conn.Bind
	switch cfg.Protocol {
	case ProtocolTCP:
		bind = conn.NewTCPBind()
	default:
		bind = conn.NewDefaultBind()
	}
	logger := cfg.Logger
	if logger == nil {
		logger = &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	}
	dev := device.NewDevice(tunDev, bind, logger)
	if err := dev.Up(); err != nil {
		return nil, fmt.Errorf("启动 WireGuard 设备: %w", err)
	}
	uapi, err := buildUAPI(cfg)
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("下发 WireGuard 配置: %w", err)
	}
	return &Tunnel{dev: dev, routes: parsePrefixes(cfg.AllowedIPs)}, nil
}

// Close 停止隧道。
func (t *Tunnel) Close() {
	if t == nil || t.dev == nil {
		return
	}
	t.dev.Close()
}

// Routes 返回隧道分流网段。
func (t *Tunnel) Routes() []string {
	out := make([]string, 0, len(t.routes))
	for _, p := range t.routes {
		out = append(out, p.String())
	}
	return out
}

// Allowed 判断地址是否落在分流网段内。
func (t *Tunnel) Allowed(addr netip.Addr) bool {
	for _, p := range t.routes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// DialContext 通过隧道拨号；只有 netstack 网卡具备该能力。
func (t *Tunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if t == nil || t.net == nil {
		return nil, ErrNoDialer
	}
	return t.net.DialContext(ctx, network, addr)
}

// LookupHost 用隧道内 DNS 解析域名；只有 netstack 网卡具备该能力。
func (t *Tunnel) LookupHost(host string) ([]string, error) {
	if t == nil || t.net == nil {
		return nil, ErrNoDialer
	}
	return t.net.LookupHost(host)
}

// Stats 返回 WireGuard UAPI 设备状态，用于排查握手与流量。
func (t *Tunnel) Stats() (string, error) {
	var buf strings.Builder
	if err := t.dev.IpcGetOperation(&buf); err != nil {
		return "", err
	}
	return buf.String(), nil
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
