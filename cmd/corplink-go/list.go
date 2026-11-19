package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"github.com/acdzh/corplink-go/internal/api"
	"github.com/acdzh/corplink-go/internal/config"
)

// listTimeout 是节点列表请求的超时。
const listTimeout = 30 * time.Second

// runList 拉取并打印可用节点，用于验证会话与签名是否被服务端接受。
func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	cfgPath := fs.String("config", "./config.json", "配置文件路径")
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
	client := mustClient(cfg, *verbose)
	if err := loadSession(client, cfg); err != nil {
		return fmt.Errorf("读取会话: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), listTimeout)
	defer cancel()

	env, err := client.Do(ctx, api.EndpointVPNList, nil, nil)
	if err != nil {
		return err
	}
	if !env.OK() {
		return env.Error()
	}
	var nodes []api.VpnInfo
	if err := json.Unmarshal(env.Data, &nodes); err != nil {
		return fmt.Errorf("解析节点列表: %w（正文 %q）", err, string(env.Data)[:min(200, len(env.Data))])
	}
	fmt.Printf("共 %d 个节点\n", len(nodes))
	for _, n := range nodes {
		fmt.Printf("  %-14s %-16s vpn_port=%-5d api_port=%-5d protocol=%d\n",
			n.EnName, n.IP, n.VPNPort, n.APIPort, n.ProtocolMode)
	}
	return nil
}

// min 兼容老版本 Go 的 min 语义（数值取小）。
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
