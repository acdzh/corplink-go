// corplink-go 是飞连（CorpLink）的非官方客户端与服务端化实现。
//
// 子命令：
//
//	probe     解析企业代码、打印登录配置与可用的第三方登录方式（无需扫码）
//	version   打印版本
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/acdzh/corplink-go/internal/api"
	"github.com/acdzh/corplink-go/internal/auth"
	"github.com/acdzh/corplink-go/internal/config"
)

// version 由构建时注入，未注入时为 dev。
var version = "dev"

// probeTimeout 是 probe 子命令的整体超时。
const probeTimeout = 60 * time.Second

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "probe":
		if err := runProbe(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "probe 失败:", err)
			os.Exit(1)
		}
	case "login":
		if err := runLogin(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "login 失败:", err)
			os.Exit(1)
		}
	case "list":
		if err := runList(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "list 失败:", err)
			os.Exit(1)
		}
	case "connect":
		if err := runConnect(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "connect 失败:", err)
			os.Exit(1)
		}
	case "paths":
		if err := runPaths(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "paths 失败:", err)
			os.Exit(1)
		}
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "serve 失败:", err)
			os.Exit(1)
		}
	case "version", "-v", "--version":
		fmt.Println("corplink-go", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令 %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `用法:
  corplink-go probe  [-config ./config.json] [-v]
  corplink-go login  [-config ./config.json] [-alias lark] [-callback <URL>] [-v]
  corplink-go list   [-config <path>] [-v]
  corplink-go paths  查看数据目录与端口
  corplink-go connect [-config ./config.json] [-v]
  corplink-go serve  [-config ./config.json] [-listen 127.0.0.1:8081] [-port-base 12001] [-max-tunnels 2]
  corplink-go version
`)
}

// runProbe 验证客户端与服务端的协议兼容性：
// 解析企业 -> 拉登录配置 -> 生成 PKCE -> 拉第三方登录方式。
func runProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "配置文件路径，默认用户配置目录")
	verbose := fs.Bool("v", false, "打印请求与响应摘要")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()

	if cfg.Server == "" {
		if cfg.CompanyName == "" {
			return fmt.Errorf("配置缺少 company_name")
		}
		info, err := api.MatchCompany(ctx, cfg.CompanyName)
		if err != nil {
			return fmt.Errorf("解析企业代码 %q: %w", cfg.CompanyName, err)
		}
		cfg.Server = info.Domain
		fmt.Printf("企业: %s (%s) 服务端: %s\n", info.ZhName, info.EnName, info.Domain)
		if err := cfg.Save(); err != nil {
			fmt.Fprintln(os.Stderr, "警告: 保存配置失败:", err)
		}
	}

	client, err := api.New(api.Options{
		Server:   cfg.Server,
		DeviceID: cfg.DeviceID,
		Language: cfg.Language,
		Verbose:  *verbose,
		Meta:     config.Meta(cfg),
	})
	if err != nil {
		return err
	}
	client.SetSigner(nil)

	svc := auth.NewService(client)

	setting, err := svc.Setting(ctx)
	if err != nil {
		return fmt.Errorf("拉取登录配置: %w", err)
	}
	printJSON("login-setting", setting)

	pkce, err := auth.NewPKCE()
	if err != nil {
		return err
	}
	fmt.Printf("pkce verifier=%s challenge=%s\n", pkce.Verifier, pkce.Challenge)

	for _, withOS := range []bool{true, false} {
		methods, err := svc.TPSLink(ctx, pkce.Challenge, withOS)
		if err != nil {
			fmt.Printf("tpslink(withOS=%v) 失败: %v\n", withOS, err)
			continue
		}
		label := "tpslink(os=Android)"
		if !withOS {
			label = "tpslink(纯 PKCE)"
		}
		fmt.Printf("%s: %d 个登录方式\n", label, len(methods))
		for _, m := range methods {
			fmt.Printf("  alias=%-10s token=%-5v url=%d 字节 %s\n",
				m.Alias, m.Token != "", len(m.LoginURL), truncate(m.LoginURL, 80))
		}
	}
	return nil
}

// printJSON 以缩进 JSON 打印任意值，便于对照服务端返回结构。
func printJSON(label string, v any) {
	payload, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Printf("%s: <序列化失败 %v>\n", label, err)
		return
	}
	fmt.Printf("%s:\n%s\n", label, payload)
}

// truncate 截断长 URL，避免刷屏。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
