// Command corplink-desktop 是桌面壳：在进程内启动同一个运行时，
// 用 MyGo 的原生控件展示状态与操作入口，浏览器面板依然可用。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/acdzh/corplink-go/internal/app"
	"github.com/acdzh/corplink-go/internal/config"
)

func main() {
	cfgPath := flag.String("config", "", "配置文件路径，默认 <用户配置目录>/CorpLinkGo/config.json")
	flag.Parse()

	path := *cfgPath
	if path == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			log.Fatalf("定位用户配置目录: %v", err)
		}
		path = dir + "/CorpLinkGo/config.json"
	}
	cfg, err := config.Load(path)
	if err != nil {
		log.Fatalf("读取配置: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt, err := app.Run(ctx, app.Options{Config: cfg})
	if err != nil {
		log.Fatalf("启动运行时: %v", err)
	}

	// 收到中断信号时优雅退出。
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		cancel()
		rt.Stop(context.Background())
		mygo.App.Quit()
	}()

	view := func(c *ui.Context) {
		state := rt.Agent.State()
		ui.Column(c).Fill().Padding(18).Gap(12).Children(func() {
			title := "未连接"
			if state.Connected {
				title = fmt.Sprintf("已连接 %s · %s", state.Node, state.Address)
			}
			ui.Text(c, title).FontSize(16).Bold()
			ui.Text(c, fmt.Sprintf("代理 %s · 面板 http://%s", rt.ProxyAddr, rt.PanelAddr)).FontSize(12)
			if !rt.Agent.LoggedIn() {
				ui.Text(c, "未登录，请在浏览器面板完成登录").FontSize(12)
			}
			ui.Row(c).Gap(8).Children(func() {
				if ui.PrimaryButton(c, "连接").Clicked() {
					go func() {
						if err := rt.Agent.Connect(context.Background(), ""); err != nil {
							fmt.Println("连接失败:", err)
						}
					}()
				}
				if ui.Button(c, "断开").Clicked() {
					rt.Agent.Disconnect()
				}
			})
			ui.Text(c, fmt.Sprintf("可用节点 %d 个", len(rt.Agent.Nodes()))).FontSize(12)
		})
	}

	mygo.App.WhenReady(func() {
		mygo.NewWindow(mygo.WindowOptions{
			Title:   "CorpLink Go",
			Content: ui.View(view),
		})
	})
	if err := mygo.App.Run(); err != nil {
		log.Fatalf("运行窗口: %v", err)
	}
}
