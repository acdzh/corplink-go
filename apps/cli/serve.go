package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/acdzh/corplink-go/corplink"
	"github.com/acdzh/corplink-go/httpapi"
)

// panelURL 拼面板地址；配了令牌才带 token 参数。
func panelURL(listen, token string) string {
	if token == "" {
		return "http://" + listen + "/"
	}
	return "http://" + listen + "/?token=" + token
}

// subscriptionURL 拼 Clash 订阅地址；配了令牌才带 token 参数。
func subscriptionURL(listen, token string) string {
	if token == "" {
		return "http://" + listen + "/clash.yml"
	}
	return "http://" + listen + "/clash.yml?token=" + token
}

// defaultProxyListen 是 CLI 默认的混合代理监听地址。
const defaultProxyListen = "127.0.0.1:3710"

// runServe 起守护进程：库运行时（混合代理）+ 控制面板。
func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "配置文件路径，默认用户配置目录")
	proxyAddr := fs.String("proxy", "", "混合代理监听地址（SOCKS5 + HTTP），默认取配置")
	panelAddr := fs.String("panel", "", "控制面板监听地址，默认取配置")
	panelToken := fs.String("panel-token", "", "控制面板访问令牌；留空则不校验，直接开面板")
	nodeName := fs.String("name", "", "启动时自动连接的节点名，默认取配置")
	keepalive := fs.Duration("keepalive", 0, "会话保活间隔，默认取配置（缺省 30m）")
	verbose := fs.Bool("v", false, "打印请求与响应摘要")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	// 代理默认地址由端侧决定：库只在拿到地址时才开端口。
	listenProxy := *proxyAddr
	if listenProxy == "" {
		listenProxy = cfg.SocksListen
	}
	if listenProxy == "" {
		listenProxy = defaultProxyListen
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := corplink.New(ctx, corplink.Options{
		Config:      cfg,
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, nil)),
		ProxyListen: listenProxy,
		AutoNode:    *nodeName,
		Keepalive:   *keepalive,
		Verbose:     *verbose,
	})
	if err != nil {
		return err
	}
	if err := client.Start(ctx); err != nil {
		return err
	}
	defer func() {
		_ = client.Close(context.Background())
	}()

	listen := *panelAddr
	if listen == "" {
		listen = cfg.PanelListen
	}
	panel := &httpapi.Server{Token: *panelToken, PanelAddr: listen}
	go func() {
		if err := panel.Serve(ctx, listen, client); err != nil {
			fmt.Fprintf(os.Stderr, "控制面板退出: %v\n", err)
		}
	}()
	fmt.Printf("控制面板: %s\n", panelURL(listen, panel.AccessToken()))
	fmt.Printf("代理端口: %s（SOCKS5 + HTTP 混合）\n", client.ProxyAddr())
	fmt.Printf("订阅地址: %s\n", subscriptionURL(listen, panel.AccessToken()))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	fmt.Println("\n正在关闭...")
	cancel()
	return nil
}
