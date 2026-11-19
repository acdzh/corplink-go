// Command corplink-desktop 是桌面壳：进程内启动同一运行时，
// 用 MyGo 原生控件操作，并常驻菜单栏托盘；浏览器面板依然可用。
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
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
	panelURL := "http://" + rt.PanelAddr

	// 收到中断信号时优雅退出。
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		cancel()
		rt.Stop(context.Background())
		mygo.App.Quit()
	}()

	openPanel := func() {
		if err := mygo.Shell.OpenExternal(panelURL); err != nil {
			fmt.Println("打开面板失败:", err)
		}
	}
	connect := func() {
		go func() {
			if err := rt.Agent.Connect(context.Background(), ""); err != nil {
				fmt.Println("连接失败:", err)
			}
		}()
	}

	view := func(c *ui.Context) {
		state := rt.Agent.State()
		ui.Column(c).Fill().Padding(18).Gap(12).Children(func() {
			title := "未连接"
			if state.Connected {
				title = fmt.Sprintf("已连接 %s · %s", state.Node, state.Address)
			}
			ui.Text(c, title).FontSize(16).Bold()
			ui.Text(c, fmt.Sprintf("代理 %s", rt.ProxyAddr)).FontSize(12)
			ui.Text(c, fmt.Sprintf("面板 %s", panelURL)).FontSize(12)
			if !rt.Agent.LoggedIn() {
				ui.Text(c, "未登录，请在面板完成登录").FontSize(12)
			}
			ui.Row(c).Gap(8).Children(func() {
				if ui.PrimaryButton(c, "连接").Clicked() {
					connect()
				}
				if ui.Button(c, "断开").Clicked() {
					rt.Agent.Disconnect()
				}
				if ui.Button(c, "打开面板").Clicked() {
					openPanel()
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
		// 菜单栏常驻图标：不用切换窗口就能连接/断开。
		if icon, err := trayIcon(); err == nil {
			if tray, err := mygo.NewTray(mygo.TrayOptions{
				ID:   "corplink-go",
				Icon: icon,
				Menu: mygo.NewMenu([]*mygo.MenuItem{
					{Label: "打开面板", Click: func(*mygo.MenuItem, *mygo.Window) { openPanel() }},
					mygo.Separator(),
					{Label: "连接", Click: func(*mygo.MenuItem, *mygo.Window) { connect() }},
					{Label: "断开", Click: func(*mygo.MenuItem, *mygo.Window) { rt.Agent.Disconnect() }},
					mygo.Separator(),
					{Label: "退出", Click: func(*mygo.MenuItem, *mygo.Window) { mygo.App.Quit() }},
				}),
			}); err == nil {
				_ = tray
			} else {
				fmt.Println("创建托盘失败:", err)
			}
		}
	})

	if err := mygo.App.Run(); err != nil {
		log.Fatalf("运行窗口: %v", err)
	}
}

// trayIcon 生成一个 16x16 的纯色图标，避免外部资源依赖。
func trayIcon() ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			img.Set(x, y, color.RGBA{R: 0x25, G: 0x63, B: 0xeb, A: 0xff})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
