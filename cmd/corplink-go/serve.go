package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/acdzh/corplink-go/internal/agent"
	"github.com/acdzh/corplink-go/internal/config"
	"github.com/acdzh/corplink-go/internal/panel"
	"github.com/acdzh/corplink-go/internal/proxy"
)

// 启动阶段超时。
const startupTimeout = 30 * time.Second

// runServe 起守护进程：一个混合代理端口（SOCKS5 + HTTP）加一个控制面板。
func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "./config.json", "配置文件路径")
	proxyAddr := fs.String("proxy", "", "混合代理监听地址（SOCKS5 + HTTP），默认取配置 socks5_listen")
	panelAddr := fs.String("panel", "", "控制面板监听地址，默认取配置 panel_listen")
	nodeName := fs.String("name", "", "启动时自动连接的节点名，留空不自动连")
	keepalive := fs.Duration("keepalive", 30*time.Minute, "会话保活间隔，0 表示关闭")
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
	panelAddrValue := *panelAddr
	if panelAddrValue == "" {
		panelAddrValue = cfg.PanelListen
	}
	if panelAddrValue == "" {
		panelAddrValue = "127.0.0.1:8080"
	}
	token, err := ensureToken(cfg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := mustClient(cfg, *verbose)
	if err := loadSession(client, cfg); err != nil {
		fmt.Printf("警告: 读取会话失败（请先在面板或 CLI 登录）: %v\n", err)
	}
	startCtx, startCancel := context.WithTimeout(ctx, startupTimeout)
	defer startCancel()
	ag := agent.New(startCtx, cfg, client)
	if err := ag.LastError(); err != "" {
		fmt.Printf("警告: 拉取节点列表失败（可能是会话过期）: %s\n", err)
	}
	autoNode := *nodeName
	if autoNode == "" {
		autoNode = cfg.AutoNode
	}
	if autoNode != "" {
		if err := ag.Connect(startCtx, autoNode); err != nil {
			fmt.Printf("自动连接 %s 失败: %v\n", autoNode, err)
		}
	}

	proxyListen := *proxyAddr
	if proxyListen == "" {
		proxyListen = cfg.SocksListen
	}
	if proxyListen == "" {
		proxyListen = "127.0.0.1:3710"
	}
	keepaliveInterval := *keepalive
	if keepaliveInterval == 0 {
		if cfg.KeepaliveSeconds > 0 {
			keepaliveInterval = time.Duration(cfg.KeepaliveSeconds) * time.Second
		} else {
			keepaliveInterval = 30 * time.Minute
		}
	}
	if keepaliveInterval > 0 {
		go ag.Keepalive(ctx, keepaliveInterval)
	}

	proxyLn, err := net.Listen("tcp", proxyListen)
	if err != nil {
		return fmt.Errorf("监听代理端口 %s: %w", proxyListen, err)
	}
	go func() {
		if err := proxy.New(ag).Serve(proxyLn); err != nil && ctx.Err() == nil {
			fmt.Printf("代理服务退出: %v\n", err)
		}
	}()

	proxyHost, _, err := net.SplitHostPort(proxyListen)
	if err != nil || proxyHost == "" {
		proxyHost = "127.0.0.1"
	}
	proxyPort := proxyLn.Addr().(*net.TCPAddr).Port

	handler := panel.Handler(panel.Options{
		Agent:     ag,
		Config:    cfg,
		Token:     token,
		ProxyHost: proxyHost,
		ProxyPort: proxyPort,
		PanelHost: panelAddrValue,
	})
	server := &http.Server{Addr: panelAddrValue, Handler: handler}
	go func() {
		fmt.Printf("控制面板: http://%s\n", panelAddrValue)
		fmt.Printf("代理端口: %s（SOCKS5 + HTTP 混合，单端口）\n", proxyListen)
		fmt.Printf("订阅地址: http://%s/sub/%s\n", panelAddrValue, token)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("控制面板退出: %v\n", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	fmt.Println("\n正在关闭...")
	ag.Disconnect()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	return nil
}

// ensureToken 复用或生成订阅 token，并落盘保证地址稳定。
func ensureToken(cfg *config.Config) (string, error) {
	if cfg.SubToken != "" {
		return cfg.SubToken, nil
	}
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成订阅 token: %w", err)
	}
	cfg.SubToken = hex.EncodeToString(buf)
	if err := cfg.Save(); err != nil {
		fmt.Printf("保存订阅 token 失败（订阅地址每次会变）: %v\n", err)
	}
	return cfg.SubToken, nil
}
