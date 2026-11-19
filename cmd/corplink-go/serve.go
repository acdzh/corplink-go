package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/acdzh/corplink-go/internal/api"
	"github.com/acdzh/corplink-go/internal/config"
	"github.com/acdzh/corplink-go/internal/sub"
	"github.com/acdzh/corplink-go/internal/vpn"
	"github.com/acdzh/corplink-go/internal/wgkey"
)

// serveTimeout 是启动阶段各请求的超时。
const serveTimeout = 30 * time.Second

// runServe 起订阅服务：一个订阅地址 + 每节点一个本地端口（懒建隧道）。
func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "./config.json", "配置文件路径")
	listen := fs.String("listen", "", "订阅服务监听地址，默认取配置 sub_listen")
	portBase := fs.Int("port-base", 12001, "节点端口起始值")
	maxTunnels := fs.Int("max-tunnels", 2, "同时存在的隧道上限")
	socksHost := fs.String("socks-host", "127.0.0.1", "订阅里填写的 SOCKS 服务地址")
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
	addr := *listen
	if addr == "" {
		addr = cfg.SubListen
	}
	if addr == "" {
		addr = "127.0.0.1:8081"
	}
	token := cfg.SubToken
	if token == "" {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("生成订阅 token: %w", err)
		}
		token = hex.EncodeToString(buf)
		// 落盘，保证重启后订阅地址不变。
		cfg.SubToken = token
		if err := cfg.Save(); err != nil {
			fmt.Printf("保存订阅 token 失败（订阅地址每次会变）: %v\n", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := mustClient(cfg, *verbose)
	if err := client.LoadCookies(cfg.SessionPath()); err != nil {
		return fmt.Errorf("读取会话: %w", err)
	}
	startCtx, startCancel := context.WithTimeout(ctx, serveTimeout)
	defer startCancel()
	nodes, err := fetchNodes(startCtx, client)
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		return fmt.Errorf("没有可用节点")
	}
	entries := vpn.Assign(nodes, *portBase)

	// 用第一个节点的配置生成分流规则；只做一次 API 调用，不起隧道。
	routes, domains, err := fetchSplitRules(startCtx, client, cfg, entries[0].Node)
	if err != nil {
		fmt.Printf("获取分流规则失败，订阅将只带域名规则: %v\n", err)
	}

	activate := cfg.ActivateCode
	if activate == "" {
		activate = cfg.CompanyName
	}
	manager := vpn.NewManager(client, config.Meta(cfg), activate, cfg.DeviceID, *maxTunnels, routes)
	defer manager.Close()
	go manager.Reap(ctx)

	for _, entry := range entries {
		entry := entry
		go func() {
			if err := manager.ServePort(ctx, entry); err != nil {
				fmt.Printf("端口 %d 监听失败: %v\n", entry.Port, err)
			}
		}()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/nodes", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		out := make([]map[string]any, 0, len(entries))
		for _, e := range entries {
			out = append(out, map[string]any{
				"name": e.Node.EnName,
				"ip":   e.Node.IP,
				"port": e.Port,
			})
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	yaml := sub.YAML(sub.Options{
		Entries:   entries,
		SocksHost: *socksHost,
		GroupName: "CORP",
		Routes:    routes,
		Domains:   domains,
		Username:  cfg.SocksUser,
		Password:  cfg.SocksPass,
	})
	mux.HandleFunc("/sub/"+token, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		_, _ = io.WriteString(w, yaml)
	})

	server := &http.Server{Addr: addr, Handler: mux}
	go func() {
		fmt.Printf("订阅地址: http://%s/sub/%s\n", addr, token)
		fmt.Printf("节点数: %d，端口 %d-%d，隧道上限 %d\n", len(entries), *portBase, *portBase+len(entries)-1, *maxTunnels)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("订阅服务退出: %v\n", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	fmt.Println("\n正在关闭...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	return nil
}

// fetchSplitRules 取一个节点的隧道配置，抽出分流网段与域名后缀。
func fetchSplitRules(ctx context.Context, client *api.Client, cfg *config.Config, node api.VpnInfo) ([]string, []string, error) {
	nodeClient, err := api.New(api.Options{
		Server:             fmt.Sprintf("https://%s:%d", node.IP, node.APIPort),
		DeviceID:           cfg.DeviceID,
		Language:           cfg.Language,
		InsecureSkipVerify: true,
		Meta:               config.Meta(cfg),
	})
	if err != nil {
		return nil, nil, err
	}
	nodeClient.SetCookies(client.Cookies())
	activate := cfg.ActivateCode
	if activate == "" {
		activate = cfg.CompanyName
	}
	nodeClient.SetSigner(signerFor(activate, cfg.DeviceID))

	pair, err := wgkey.Generate()
	if err != nil {
		return nil, nil, err
	}
	env, err := nodeClient.Do(ctx, api.EndpointVPNConn, nil, map[string]string{
		"public_key": pair.PublicKey,
		"otp":        "",
	})
	if err != nil {
		return nil, nil, err
	}
	if !env.OK() {
		return nil, nil, env.Error()
	}
	info, err := api.ParseWgInfo(env.Data)
	if err != nil {
		return nil, nil, err
	}
	return info.Setting.VpnRouteSplit, info.Setting.VpnDNSDomain, nil
}
