package agent

import (
	"golang.zx2c4.com/wireguard/tun"

	"github.com/acdzh/corplink-go/corplink/tunnel"
)

// startTunnel 在有外部网卡时用该网卡启动隧道，否则回落到内置用户态网卡。
func startTunnel(cfg tunnel.Config, dev tun.Device) (*tunnel.Tunnel, error) {
	if dev == nil {
		return tunnel.Start(cfg)
	}
	return tunnel.StartWith(cfg, dev)
}
