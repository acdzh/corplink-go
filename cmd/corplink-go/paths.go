package main

import (
	"fmt"
	"os"

	"github.com/acdzh/corplink-go/internal/config"
)

// runPaths 打印 CLI 与桌面版使用的数据位置，便于排查"两边数据不一致"。
func runPaths(args []string) error {
	dir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("定位用户配置目录: %w", err)
	}
	cfg, err := config.LoadDir(dir + "/CorpLinkGo")
	if err != nil {
		return err
	}
	fmt.Printf("默认数据目录  %s\n", cfg.Dir())
	fmt.Printf("配置文件      %s\n", cfg.Path())
	fmt.Printf("会话文件      %s\n", cfg.SessionPath())
	fmt.Printf("代理端口      %s\n", fallback(cfg.SocksListen, "127.0.0.1:3710"))
	fmt.Printf("面板端口      %s\n", fallback(cfg.PanelListen, "127.0.0.1:13140"))
	return nil
}

// fallback 返回第一个非空值。
func fallback(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
