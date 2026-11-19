package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/acdzh/corplink-go/internal/api"
	"github.com/acdzh/corplink-go/internal/config"
	"github.com/acdzh/corplink-go/internal/tunnel"
	"github.com/acdzh/corplink-go/internal/wgkey"
)

// proxyTimeout 是建立隧道前各步骤的超时。
const proxyTimeout = 30 * time.Second

// runProxy 建立隧道并对外提供 SOCKS5，直到收到中断信号。
func runProxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	cfgPath := fs.String("config", "./config.json", "配置文件路径")
	nodeName := fs.String("name", "", "指定节点 en_name，留空取第一个")
	listen := fs.String("listen", "", "SOCKS5 监听地址，默认取配置里的 socks5_listen")
	probe := fs.String("dial", "", "排障用：隧道建立后直接连这个地址并打印结果")
	lookup := fs.String("lookup", "", "排障用：隧道建立后在隧道内解析这个域名")
	verbose := fs.Bool("v", false, "打印请求与响应摘要")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	socksListen := *listen
	if socksListen == "" {
		socksListen = cfg.SocksListen
	}
	if socksListen == "" {
		socksListen = "127.0.0.1:1080"
	}

	ctx, cancel := context.WithTimeout(context.Background(), proxyTimeout)
	defer cancel()

	apiClient := mustClient(cfg, *verbose)
	if err := loadSession(apiClient, cfg); err != nil {
		return fmt.Errorf("读取会话: %w", err)
	}
	nodes, err := fetchNodes(ctx, apiClient)
	if err != nil {
		return err
	}
	node, err := pickNode(nodes, *nodeName)
	if err != nil {
		return err
	}
	fmt.Printf("节点: %s %s:%d protocol_mode=%d\n", node.EnName, node.IP, node.VPNPort, node.ProtocolMode)

	nodeClient, err := api.New(api.Options{
		Server:             fmt.Sprintf("https://%s:%d", node.IP, node.APIPort),
		DeviceID:           cfg.DeviceID,
		Language:           cfg.Language,
		Verbose:            *verbose,
		InsecureSkipVerify: true,
		Meta:               config.Meta(cfg),
	})
	if err != nil {
		return err
	}
	nodeClient.SetCookies(apiClient.Cookies())
	activate := cfg.ActivateCode
	if activate == "" {
		activate = cfg.CompanyName
	}
	nodeClient.SetSigner(signerFor(activate, cfg.DeviceID))

	pair, err := wgkey.Generate()
	if err != nil {
		return err
	}
	env, err := nodeClient.Do(ctx, api.EndpointVPNConn, nil, map[string]string{
		"public_key": pair.PublicKey,
		"otp":        "",
	})
	if err != nil {
		return err
	}
	if !env.OK() {
		return env.Error()
	}
	var info api.WgInfo
	if err := json.Unmarshal(env.Data, &info); err != nil {
		return fmt.Errorf("解析隧道配置: %w", err)
	}

	addresses := []string{info.IP}
	if info.IPv6 != "" {
		addresses = append(addresses, info.IPv6)
	}
	dns := []string{}
	for _, d := range []string{info.Setting.VpnDNS, info.Setting.VpnDNSBackup} {
		if d != "" {
			dns = append(dns, d)
		}
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
		SocksListen: socksListen,
		SocksUser:   cfg.SocksUser,
		SocksPass:   cfg.SocksPass,
	})
	if err != nil {
		return err
	}
	defer tun.Close()

	fmt.Printf("隧道就绪: %s/%s  MTU=%d  SOCKS5=%s\n", info.IP, info.IPMask, info.Setting.VpnMTU, socksListen)
	fmt.Printf("路由 %d 条，DNS %v\n", len(info.Setting.VpnRouteSplit), dns)
	if *lookup != "" {
		start := time.Now()
		addrs, err := tun.LookupHost(*lookup)
		if err != nil {
			fmt.Printf("隧道内解析 %s 失败（%v）: %v\n", *lookup, time.Since(start), err)
			return err
		}
		fmt.Printf("隧道内解析 %s 成功（%v）: %v\n", *lookup, time.Since(start), addrs)
		return nil
	}
	if *probe != "" {
		start := time.Now()
		conn, err := tun.DialContext(ctx, "tcp", *probe)
		if err != nil {
			fmt.Printf("隧道内连接 %s 失败: %v\n", *probe, err)
			return err
		}
		_ = conn.Close()
		fmt.Printf("隧道内连接 %s 成功，耗时 %v\n", *probe, time.Since(start))
		return nil
	}
	fmt.Println("按 Ctrl-C 结束")

	if *verbose {
		go func() {
			for i := 0; i < 6; i++ {
				time.Sleep(5 * time.Second)
				stats, err := tun.Stats()
				if err != nil {
					fmt.Printf("读取隧道状态失败: %v\n", err)
					continue
				}
				fmt.Printf("--- 隧道状态 ---\n%s\n", stats)
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	fmt.Println("\n正在关闭隧道...")
	return nil
}
