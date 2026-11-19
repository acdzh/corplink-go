// Command corplink-desktop 是 macOS 桌面壳：进程内启动同一个运行时，
// 用 MyGo 原生控件提供状态、节点选择、流量与日志，并常驻菜单栏。
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
	"strings"
	"syscall"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/acdzh/corplink-go/internal/agent"
	"github.com/acdzh/corplink-go/internal/app"
	"github.com/acdzh/corplink-go/internal/config"
)

// uiState 是窗口本地状态。
type uiState struct {
	tab     int
	latency map[string]int64
	testing bool
}

var navItems = []string{"节点", "流量", "日志", "关于"}

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
	subURL := panelURL + "/clash.yml"

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		cancel()
		rt.Stop(context.Background())
		mygo.App.Quit()
	}()

	st := &uiState{latency: map[string]int64{}}
	var win *mygo.Window

	connect := func(name string) {
		go func() {
			if err := rt.Agent.Connect(context.Background(), name); err != nil {
				fmt.Println("连接失败:", err)
			}
			if win != nil {
				win.Invalidate()
			}
		}()
	}
	testAll := func() {
		if st.testing {
			return
		}
		st.testing = true
		go func() {
			st.latency = rt.Agent.LatencyAll(context.Background())
			st.testing = false
			if win != nil {
				win.Invalidate()
			}
		}()
	}

	// sidebar 画左侧栏：有系统材质时不铺底色，让毛玻璃透出来。
	sidebar := func(c *ui.Context, p palette, state agent.State) {
		side := ui.Column(c).Width(sidebarWidth).FillHeight().
			BorderWidth(0, 0, 0, 1).BorderColor(p.Border)
		if !c.Vibrancy() {
			side = side.Background(p.Sidebar)
		}
		side.Children(func() {
			ui.Column(c).Padding(16, 20, 8, 20).Gap(3).Children(func() {
				ui.Text(c, "Corplink Go").FontSize(fsH2).Bold().TextColor(p.Heading)
				ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
					tone, label := p.Faint, "未连接"
					if state.Connected {
						tone, label = p.Green, state.Node
					}
					ui.Box(c).Size(6, 6).Radius(3).Background(tone)
					ui.Text(c, label).FontSize(fsTiny).TextColor(p.Muted).Grow(1).SingleLine()
				})
			})
			ui.Column(c).Padding(4, 10).Gap(1).Children(func() {
				for i, label := range navItems {
					idx := i
					row := ui.Row(c).FillWidth().Radius(radiusRow).Padding(6, 10).AlignItems(ui.Center)
					if idx == st.tab {
						row = row.Background(p.AccentBg)
					}
					row.OnClick(func() { st.tab = idx }).Children(func() {
						ui.Text(c, label).FontSize(fsBody).
							TextColor(p.Text).Grow(1)
					})
				}
			})
			ui.Spacer(c)
			ui.Column(c).Padding(8, 20).Gap(2).Children(func() {
				ui.Text(c, "代理 "+rt.ProxyAddr).FontSize(fsTiny).TextColor(p.Faint).SingleLine()
				ui.Text(c, "面板 "+rt.PanelAddr).FontSize(fsTiny).TextColor(p.Faint).SingleLine()
			})
		})
	}

	view := func(c *ui.Context) {
		p := pal(c)
		state := rt.Agent.State()
		stats := rt.Agent.Stats()
		nodes := rt.Agent.Nodes()

		ui.Row(c).Fill().Children(func() {
			sidebar(c, p, state)

			ui.Column(c).Fill().Background(p.Bg).Padding(pagePadY, pagePadX).Gap(gapCard).Children(func() {
				// 标题行
				ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
					ui.Text(c, navItems[st.tab]).FontSize(fsH1).Bold().TextColor(p.Heading)
					ui.Spacer(c)
					if st.testing {
						ui.Spinner(c)
					}
					if rt.Agent.Auto() {
						ui.Text(c, "自动选择").FontSize(fsTiny).TextColor(p.Muted)
					}
				})

				switch st.tab {
				case 0:
					card(c, p, func() {
						ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
							if ui.Button(c, "连接").Clicked() {
								connect("")
							}
							if ui.Button(c, "断开").Clicked() {
								rt.Agent.Disconnect()
								c.Invalidate()
							}
							if ui.Button(c, "测速").Clicked() {
								testAll()
							}
							ui.Spacer(c)
							sub := "未建立隧道"
							if state.Connected {
								sub = state.Address + " · 路由 " + fmt.Sprint(state.Routes) + " 条"
							}
							ui.Text(c, sub).FontSize(fsTiny).TextColor(p.Faint)
						})
					})
					ui.Scroll(c).Grow(1).Children(func() {
						ui.Column(c).Gap(8).Children(func() {
							for _, n := range nodes {
								name := displayName(n.EnName, n.Name, n.IP)
								lat := ""
								if ms, ok := st.latency[name]; ok {
									if ms < 0 {
										lat = "超时"
									} else {
										lat = fmt.Sprintf("%d ms", ms)
									}
								}
								current := state.Connected && state.Node == name
								bg := p.Card
								if current {
									bg = p.OkBg
								}
								ui.Row(c).Key(name).FillWidth().Radius(radiusCard).Padding(10, 14).
									AlignItems(ui.Center).Background(bg).Border(1, p.Border).Children(func() {
									ui.Column(c).Gap(1).Grow(1).Children(func() {
										label := name
										if current {
											label = "✓ " + name
										}
										ui.Text(c, label).FontSize(fsBody).TextColor(p.Text).SingleLine()
										sub := protoName(n.ProtocolMode)
										if lat != "" {
											sub += " · " + lat
										}
										if n.TagName != "" {
											sub = n.TagName + " · " + sub
										}
										ui.Text(c, sub).FontSize(fsTiny).TextColor(p.Faint).SingleLine()
									})
									if !current {
										if ui.Button(c, "连接").Clicked() {
											connect(name)
										}
									}
								})
							}
							if len(nodes) == 0 {
								ui.Text(c, "没有节点，先在面板完成登录").FontSize(fsSmall).TextColor(p.Faint)
							}
						})
					})
				case 1:
					ui.Row(c).FillWidth().Gap(gapCard).Children(func() {
						statTile(c, p, "上行", humanBytes(stats.TxBytes))
						statTile(c, p, "下行", humanBytes(stats.RxBytes))
					})
					card(c, p, func() {
						line := func(k, v string) {
							ui.Row(c).FillWidth().Gap(10).Children(func() {
								ui.Text(c, k).FontSize(fsSmall).TextColor(p.Faint).Width(52)
								ui.Text(c, v).FontSize(fsSmall).TextColor(p.Muted).Grow(1).SingleLine()
							})
						}
						line("在线", humanDuration(stats.UptimeSeconds))
						line("隧道", state.Address)
						line("DNS", strings.Join(state.DNS, ", "))
					})
				case 2:
					card(c, p, func() {
						ui.Scroll(c).Height(320).Children(func() {
							ui.Column(c).Gap(5).Children(func() {
								events := rt.Agent.Events()
								for i := len(events) - 1; i >= 0; i-- {
									e := events[i]
									ui.Row(c).Gap(8).Children(func() {
										ui.Text(c, e.Time).FontSize(fsTiny).TextColor(p.Faint)
										ui.Text(c, e.Message).FontSize(fsSmall).TextColor(p.Muted)
									})
								}
								if len(events) == 0 {
									ui.Text(c, "暂无事件").FontSize(fsSmall).TextColor(p.Faint)
								}
							})
						})
					})
				case 3:
					card(c, p, func() {
						line := func(k, v string) {
							ui.Row(c).FillWidth().Gap(10).Children(func() {
								ui.Text(c, k).FontSize(fsSmall).TextColor(p.Faint).Width(52)
								ui.Text(c, v).FontSize(fsSmall).TextColor(p.Muted).Grow(1).SingleLine()
							})
						}
						line("订阅", subURL)
						line("配置", cfg.Path())
						line("设备", cfg.DeviceBrand+" "+cfg.DeviceModel+" · API "+cfg.OSVersion)
						ui.Row(c).Gap(8).Children(func() {
							if ui.Button(c, "打开面板").Clicked() {
								_ = mygo.Shell.OpenExternal(panelURL)
							}
							if ui.Button(c, "复制订阅").Clicked() {
								mygo.Clipboard.WriteText(subURL)
							}
						})
					})
				}
			})
		})
	}

	mygo.App.WhenReady(func() {
		win = mygo.NewWindow(mygo.WindowOptions{
			Title:       "Corplink Go",
			Width:       720,
			Height:      560,
			Transparent: true,
			Vibrancy:    mygo.VibrancySidebar,
			Content:     ui.View(view),
		})

		// 调试用：设置 CORPLINK_CAPTURE=<path> 时把窗口内容截图后退出。
		if out := os.Getenv("CORPLINK_CAPTURE"); out != "" {
			go func() {
				time.Sleep(3 * time.Second)
				data, err := win.CapturePage()
				if err != nil {
					fmt.Println("截图失败:", err)
				} else if err := os.WriteFile(out, data, 0o644); err != nil {
					fmt.Println("写入截图失败:", err)
				} else {
					fmt.Println("截图已保存:", out)
				}
				mygo.App.Quit()
			}()
		}

		trayIcon, _ := renderIcon()
		var tray *mygo.Tray
		if trayIcon != nil {
			t, err := mygo.NewTray(mygo.TrayOptions{ID: "corplink-go", Icon: trayIcon, ToolTip: "Corplink Go"})
			if err != nil {
				fmt.Println("创建托盘失败:", err)
			} else {
				tray = t
				tray.OnClick(func() {
					if win != nil {
						win.Focus()
					}
				})
			}
		}
		refreshTray := func() {
			if tray == nil {
				return
			}
			state := rt.Agent.State()
			header := "未连接"
			title := "○"
			if state.Connected {
				header = "已连接 " + state.Node
				title = "● " + state.Node
			}
			if rt.Agent.Auto() {
				header += "（自动）"
			}
			var nodeItems []*mygo.MenuItem
			for _, n := range rt.Agent.Nodes() {
				name := displayName(n.EnName, n.Name, n.IP)
				label := name
				if state.Connected && state.Node == name {
					label = "✓ " + name
				}
				node := name
				nodeItems = append(nodeItems, &mygo.MenuItem{
					Label: label,
					Click: func(*mygo.MenuItem, *mygo.Window) { connect(node) },
				})
			}
			items := []*mygo.MenuItem{
				{Label: header, Disabled: true},
				{Label: "自动选择（最快）", Click: func(*mygo.MenuItem, *mygo.Window) { connect("auto") }},
				{Label: "断开", Disabled: !state.Connected, Click: func(*mygo.MenuItem, *mygo.Window) {
					rt.Agent.Disconnect()
				}},
				mygo.Separator(),
				{Label: "选择节点", Submenu: nodeItems},
				mygo.Separator(),
				{Label: "打开面板", Click: func(*mygo.MenuItem, *mygo.Window) { _ = mygo.Shell.OpenExternal(panelURL) }},
				{Label: "复制订阅地址", Click: func(*mygo.MenuItem, *mygo.Window) { mygo.Clipboard.WriteText(subURL) }},
				{Label: "退出", Click: func(*mygo.MenuItem, *mygo.Window) { mygo.App.Quit() }},
			}
			tray.SetMenu(mygo.NewMenu(items))
			tray.SetTitle(title)
		}
		refreshTray()
		go func() {
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				refreshTray()
				if win != nil {
					win.Invalidate()
				}
			}
		}()
	})

	if err := mygo.App.Run(); err != nil {
		log.Fatalf("运行窗口: %v", err)
	}
}

// statTile 画一个指标卡片。
func statTile(c *ui.Context, p palette, label, value string) {
	ui.Column(c).Grow(1).Radius(radiusCard).Padding(padCard).Gap(4).
		Background(p.Card).Border(1, p.Border).Children(func() {
		ui.Text(c, label).FontSize(fsTiny).TextColor(p.Faint)
		ui.Text(c, value).FontSize(21).Bold().TextColor(p.Heading)
	})
}

// displayName 返回节点显示名。
func displayName(en, name, ip string) string {
	switch {
	case en != "":
		return en
	case name != "":
		return name
	default:
		return ip
	}
}

// protoName 把 protocol_mode 转成展示名。
func protoName(mode int) string {
	if mode == 1 {
		return "TCP"
	}
	return "UDP"
}

// humanBytes 把字节数转成可读单位。
func humanBytes(n int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	v := float64(n)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", v, units[i])
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// humanDuration 把秒转成 h/m/s。
func humanDuration(sec int64) string {
	if sec <= 0 {
		return "-"
	}
	h, m, s := sec/3600, (sec%3600)/60, sec%60
	out := ""
	if h > 0 {
		out += fmt.Sprintf("%dh ", h)
	}
	if m > 0 || h > 0 {
		out += fmt.Sprintf("%dm ", m)
	}
	return out + fmt.Sprintf("%ds", s)
}

// renderIcon 生成 16x16 托盘图标。
func renderIcon() ([]byte, error) {
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			img.Set(x, y, color.RGBA{0x30, 0x7a, 0x5a, 0xff})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
