package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"flag"

	"github.com/acdzh/corplink-go/internal/app"
	"github.com/acdzh/corplink-go/internal/config"
)

// 关闭超时。
const shutdownTimeout = 5 * time.Second

// runServe 起守护进程：混合代理端口 + 控制面板。
func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "./config.json", "配置文件路径")
	proxyAddr := fs.String("proxy", "", "混合代理监听地址（SOCKS5 + HTTP），默认取配置")
	panelAddr := fs.String("panel", "", "控制面板监听地址，默认取配置")
	nodeName := fs.String("name", "", "启动时自动连接的节点名，默认取配置")
	keepalive := fs.Duration("keepalive", 0, "会话保活间隔，默认取配置（缺省 30m）")
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rt, err := app.Run(ctx, app.Options{
		Config:      cfg,
		ProxyListen: *proxyAddr,
		PanelListen: *panelAddr,
		AutoNode:    *nodeName,
		Keepalive:   *keepalive,
		Verbose:     *verbose,
	})
	if err != nil {
		return err
	}
	fmt.Printf("控制面板: http://%s\n", rt.PanelAddr)
	fmt.Printf("代理端口: %s（SOCKS5 + HTTP 混合）\n", rt.ProxyAddr)
	fmt.Printf("订阅地址: http://%s/clash.yml\n", rt.PanelAddr)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	fmt.Println("\n正在关闭...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()
	rt.Stop(shutdownCtx)
	return nil
}

// 保留 net/http 引用，避免未来裁剪 import 时误删。
var _ = http.StatusOK
