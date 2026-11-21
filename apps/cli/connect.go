package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"github.com/acdzh/corplink-go/corplink/api"
	"github.com/acdzh/corplink-go/corplink/config"
	"github.com/acdzh/corplink-go/corplink/wgkey"
)

// connectTimeout 是取隧道配置的超时。
const connectTimeout = 30 * time.Second

// runConnect 选节点 -> 生成密钥对 -> 向节点请求 /vpn/conn，打印隧道参数。
func runConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "配置文件路径，默认用户配置目录")
	nodeName := fs.String("name", "", "指定节点 en_name，留空取第一个")
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
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
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
	fmt.Printf("选择节点: %s (%s:%d)\n", node.EnName, node.IP, node.APIPort)

	// 节点地址是自签证书，需要单独的客户端并非跳过校验。
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
	fmt.Printf("隧道地址: %s/%s  MTU=%d\n", info.IP, info.IPMask, info.Setting.VpnMTU)
	fmt.Printf("对端公钥: %s\n", info.PublicKey)
	fmt.Printf("DNS: %s（备用 %s）\n", info.Setting.VpnDNS, info.Setting.VpnDNSBackup)
	fmt.Printf("分流路由 %d 条 / 全量路由 %d 条\n", len(info.Setting.VpnRouteSplit), len(info.Setting.VpnRouteFull))
	fmt.Println("全量路由明细:", info.Setting.VpnRouteFull)
	for i, r := range info.Setting.VpnRouteSplit {
		if i >= 8 {
			fmt.Printf("  ... 其余 %d 条\n", len(info.Setting.VpnRouteSplit)-8)
			break
		}
		fmt.Println("  ", r)
	}
	return nil
}

// fetchNodes 拉取节点列表并刷新会话 Cookie（节点列表响应会下发 vpn-token）。
func fetchNodes(ctx context.Context, client *api.Client) ([]api.VpnInfo, error) {
	env, err := client.Do(ctx, api.EndpointVPNList, nil, nil)
	if err != nil {
		return nil, err
	}
	if !env.OK() {
		return nil, env.Error()
	}
	var nodes []api.VpnInfo
	if err := json.Unmarshal(env.Data, &nodes); err != nil {
		return nil, fmt.Errorf("解析节点列表: %w", err)
	}
	return nodes, nil
}

// pickNode 按名称选择节点，未指定时取第一个有余量的节点。
func pickNode(nodes []api.VpnInfo, name string) (*api.VpnInfo, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("没有可用节点")
	}
	if name == "" {
		return &nodes[0], nil
	}
	for i := range nodes {
		if nodes[i].EnName == name || nodes[i].Name == name {
			return &nodes[i], nil
		}
	}
	return nil, fmt.Errorf("找不到节点 %q", name)
}
