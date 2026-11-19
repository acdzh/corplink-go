// Package app 组装并启动运行时：登录、隧道、代理、控制面板。
//
// 纯二进制、Docker、桌面壳都走这里，保证三种形态行为一致。
package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/acdzh/corplink-go/internal/agent"
	"github.com/acdzh/corplink-go/internal/api"
	"github.com/acdzh/corplink-go/internal/config"
	"github.com/acdzh/corplink-go/internal/login"
	"github.com/acdzh/corplink-go/internal/panel"
	"github.com/acdzh/corplink-go/internal/proxy"
)

// 启动参数。
const (
	// defaultProxyListen 是默认代理监听地址。
	defaultProxyListen = "127.0.0.1:3710"
	// defaultPanelListen 是默认面板监听地址。
	defaultPanelListen = "127.0.0.1:13140"
	// defaultKeepalive 是默认会话保活间隔。
	defaultKeepalive = 30 * time.Minute
	// startupTimeout 是启动阶段请求超时。
	startupTimeout = 30 * time.Second
)

// Options 是运行时启动参数，零值字段回落到配置或默认值。
type Options struct {
	// Config 是已加载的配置。
	Config *config.Config
	// Client 是可选的已构造客户端（桌面壳需要共享时传入）。
	Client *api.Client
	// ProxyListen 覆盖配置里的代理监听地址。
	ProxyListen string
	// PanelListen 覆盖配置里的面板监听地址。
	PanelListen string
	// AutoNode 覆盖配置里的自动连接节点。
	AutoNode string
	// Keepalive 覆盖配置里的保活间隔。
	Keepalive time.Duration
	// Verbose 打开请求级日志。
	Verbose bool
}

// Runtime 是已启动的运行时。
type Runtime struct {
	// Agent 是隧道管理器。
	Agent *agent.Agent
	// Login 是登录服务。
	Login *login.Service
	// ProxyAddr 是实际代理监听地址。
	ProxyAddr string
	// PanelAddr 是实际面板监听地址。
	PanelAddr string
	// Client 是共享的 API 客户端。
	Client *api.Client

	server *http.Server
	cancel context.CancelFunc
}

// Run 启动运行时；调用方负责在退出时 Stop。
func Run(ctx context.Context, opts Options) (*Runtime, error) {
	cfg := opts.Config
	if cfg == nil {
		return nil, fmt.Errorf("缺少配置")
	}
	client := opts.Client
	if client == nil {
		var err error
		client, err = newClient(cfg, opts.Verbose)
		if err != nil {
			return nil, err
		}
	}
	if err := loadSession(client, cfg); err != nil {
		// 未登录不阻塞启动：面板可以完成登录。
		fmt.Printf("提示: %v\n", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	startCtx, startCancel := context.WithTimeout(runCtx, startupTimeout)
	defer startCancel()
	ag := agent.New(startCtx, cfg, client)

	autoNode := opts.AutoNode
	if autoNode == "" {
		autoNode = cfg.AutoNode
	}
	if autoNode != "" {
		if err := ag.Connect(startCtx, autoNode); err != nil {
			fmt.Printf("自动连接 %s 失败: %v\n", autoNode, err)
		}
	}

	keepalive := opts.Keepalive
	if keepalive == 0 {
		if cfg.KeepaliveSeconds > 0 {
			keepalive = time.Duration(cfg.KeepaliveSeconds) * time.Second
		} else {
			keepalive = defaultKeepalive
		}
	}
	if keepalive > 0 {
		go ag.Keepalive(runCtx, keepalive)
	}

	proxyListen := firstNonEmpty(opts.ProxyListen, cfg.SocksListen, defaultProxyListen)
	proxyLn, err := net.Listen("tcp", proxyListen)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("监听代理端口 %s: %w", proxyListen, err)
	}
	go func() {
		if err := proxy.New(ag).Serve(proxyLn); err != nil && runCtx.Err() == nil {
			fmt.Printf("代理服务退出: %v\n", err)
		}
	}()

	panelListen := firstNonEmpty(opts.PanelListen, cfg.PanelListen, defaultPanelListen)
	handler := panel.Handler(panel.Options{
		Agent:     ag,
		Login:     login.New(client, cfg, ag),
		Config:    cfg,
		ProxyHost: proxyLn.Addr().(*net.TCPAddr).IP.String(),
		ProxyPort: proxyLn.Addr().(*net.TCPAddr).Port,
		PanelHost: panelListen,
	})
	server := &http.Server{Addr: panelListen, Handler: handler}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("控制面板退出: %v\n", err)
		}
	}()

	return &Runtime{
		Agent:     ag,
		Login:     login.New(client, cfg, ag),
		ProxyAddr: proxyListen,
		PanelAddr: panelListen,
		Client:    client,
		server:    server,
		cancel:    cancel,
	}, nil
}

// Stop 关闭运行时。
func (r *Runtime) Stop(ctx context.Context) {
	if r == nil {
		return
	}
	r.Agent.Disconnect()
	if r.server != nil {
		_ = r.server.Shutdown(ctx)
	}
	if r.cancel != nil {
		r.cancel()
	}
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
