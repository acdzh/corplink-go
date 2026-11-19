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

	"github.com/acdzh/corplink-go/internal/app"
	"github.com/acdzh/corplink-go/internal/config"
)

// 字号与圆角，保持层级差：H1 > H2 > 正文 > 小字。
const (
	fsH1       float32 = 18
	fsH2       float32 = 13
	fsBody     float32 = 13
	fsSmall    float32 = 12
	fsTiny     float32 = 11
	radiusCard float32 = 10
)

// palette 是浅色/深色两套配色：只用黑白灰，颜色仅用于状态。
type palette struct {
	Dark    bool
	Bg      ui.Color
	Content ui.Color
	Border  ui.Color
	Text    ui.Color
	Muted   ui.Color
	Faint   ui.Color
	Ok      ui.Color
	Bad     ui.Color
	Hover   ui.Color
}

func lightPalette() palette {
	return palette{
		Bg:      ui.Hex("#00000000"),
		Content: ui.Hex("#ffffff"),
		Border:  ui.Hex("#00000012"),
		Text:    ui.Hex("#111113"),
		Muted:   ui.Hex("#6b6b70"),
		Faint:   ui.Hex("#a0a0a6"),
		Ok:      ui.Hex("#3f9d5a"),
		Bad:     ui.Hex("#c0563f"),
		Hover:   ui.Hex("#00000008"),
	}
}

func darkPalette() palette {
	return palette{
		Bg:      ui.Hex("#00000000"),
		Content: ui.Hex("#1b1a1c"),
		Border:  ui.Hex("#ffffff14"),
		Text:    ui.Hex("#f2f2f4"),
		Muted:   ui.Hex("#a0a0a6"),
		Faint:   ui.Hex("#6f6f75"),
		Ok:      ui.Hex("#4ade80"),
		Bad:     ui.Hex("#f87171"),
		Hover:   ui.Hex("#ffffff0a"),
	}
}

func pal(c *ui.Context) palette {
	if c.Theme().Dark {
		return darkPalette()
	}
	return lightPalette()
}

// uiState 是窗口本地状态。
type uiState struct {
	tab     int
	latency map[string]int64
	testing bool
}

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

	navItems := []string{"节点", "流量", "日志", "关于"}

	view := func(c *ui.Context) {
		p := pal(c)
		state := rt.Agent.State()
		stats := rt.Agent.Stats()
		nodes := rt.Agent.Nodes()

		ui.Row(c).Fill().Children(func() {
			// 左侧栏：透明，交给系统毛玻璃
			ui.Column(c).Width(158).Fill().Padding(14, 12).Gap(3).Children(func() {
				ui.Text(c, "Corplink Go").FontSize(fsH2).Bold().TextColor(p.Text)
				ui.Row(c).Gap(5).AlignItems(ui.Center).Children(func() {
					tone := p.Faint
					label := "未连接"
					if state.Connected {
						tone = p.Ok
						label = state.Node
					}
					ui.Box(c).Size(6, 6).Radius(3).Background(tone)
					ui.Text(c, label).FontSize(fsTiny).TextColor(p.Muted).Grow(1).SingleLine()
				})
				ui.Spacer(c)
				ui.Text(c, "代理 "+rt.ProxyAddr).FontSize(fsTiny).TextColor(p.Faint).SingleLine()
				ui.Text(c, "面板 "+rt.PanelAddr).FontSize(fsTiny).TextColor(p.Faint).SingleLine()
			})

			// 分隔线：让透明侧栏与内容区有明确边界
			ui.Box(c).Width(1).FillHeight().Background(p.Border)

			// 右侧内容：不透明，与透明侧栏形成层次
			ui.Column(c).Fill().Background(p.Content).Padding(18, 16).Gap(12).Children(func() {
				ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
					ui.Tabs(c, &st.tab, navItems...)
					ui.Spacer(c)
					if st.testing {
						ui.Spinner(c)
					}
					if rt.Agent.Auto() {
						ui.Text(c, "自动").FontSize(fsTiny).TextColor(p.Muted)
					}
				})
				ui.Box(c).FillWidth().Height(1).Background(p.Border)

				switch st.tab {
				case 0:
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
					})
					ui.Scroll(c).Grow(1).Children(func() {
						ui.Column(c).Gap(0).Children(func() {
							for _, n := range nodes {
								name := displayName(n.EnName, n.Name, n.IP)
								lat := ""
								if ms, ok := st.latency[name]; ok {
									if ms < 0 {
										lat = " · 超时"
									} else {
										lat = fmt.Sprintf(" · %d ms", ms)
									}
								}
								current := state.Connected && state.Node == name
								ui.Row(c).Key(name).FillWidth().Padding(7, 0).AlignItems(ui.Center).Children(func() {
									ui.Column(c).Gap(1).Grow(1).Children(func() {
										label := name
										if current {
											label = "✓ " + name
										}
										ui.Text(c, label).FontSize(fsBody).TextColor(p.Text).SingleLine()
										sub := protoName(n.ProtocolMode) + lat
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
								ui.Box(c).FillWidth().Height(1).Background(p.Border)
							}
							if len(nodes) == 0 {
								ui.Text(c, "没有节点，先在面板完成登录").FontSize(fsSmall).TextColor(p.Faint)
							}
						})
					})
				case 1:
					ui.Row(c).FillWidth().Gap(32).Children(func() {
						metric(c, p, "上行", humanBytes(stats.TxBytes))
						metric(c, p, "下行", humanBytes(stats.RxBytes))
					})
					ui.Text(c, "在线 "+humanDuration(stats.UptimeSeconds)).FontSize(fsSmall).TextColor(p.Muted)
					if state.Connected {
						ui.Text(c, "隧道 "+state.Address+" · 路由 "+fmt.Sprint(state.Routes)+" 条").
							FontSize(fsSmall).TextColor(p.Muted)
						ui.Text(c, "DNS "+strings.Join(state.DNS, ", ")).FontSize(fsSmall).TextColor(p.Muted)
					}
				case 2:
					events := rt.Agent.Events()
					ui.Scroll(c).Grow(1).Children(func() {
						ui.Column(c).Gap(3).Children(func() {
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
				case 3:
					line := func(k, v string) {
						ui.Row(c).FillWidth().Gap(12).Children(func() {
							ui.Text(c, k).FontSize(fsSmall).TextColor(p.Faint).Width(44)
							ui.Text(c, v).FontSize(fsSmall).TextColor(p.Muted).Grow(1).SingleLine()
						})
					}
					line("订阅", subURL)
					line("配置", cfg.Path())
					line("设备", cfg.DeviceBrand+" "+cfg.DeviceModel+" · API "+cfg.OSVersion)
					ui.Box(c).FillWidth().Height(6)
					ui.Row(c).Gap(8).Children(func() {
						if ui.Button(c, "打开面板").Clicked() {
							_ = mygo.Shell.OpenExternal(panelURL)
						}
						if ui.Button(c, "复制订阅").Clicked() {
							mygo.Clipboard.WriteText(subURL)
						}
					})
				}
			})
		})
	}

	mygo.App.WhenReady(func() {
		win = mygo.NewWindow(mygo.WindowOptions{
			Title:       "Corplink Go",
			Width:       680,
			Height:      580,
			Transparent: true,
			Vibrancy:    mygo.VibrancySidebar,
			Content:     ui.View(view),
		})

		// 调试用：设置 CORPLINK_CAPTURE=<path> 时把窗口内容截图后退出，
		// 便于在无人值守环境检查界面渲染。
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

// metric 画一个指标块。
func metric(c *ui.Context, p palette, label, value string) {
	ui.Column(c).Gap(2).Children(func() {
		ui.Text(c, label).FontSize(fsTiny).TextColor(p.Faint)
		ui.Text(c, value).FontSize(20).Bold().TextColor(p.Text)
	})
}

// infoLine 画一行键值。
func infoLine(c *ui.Context, p palette, key, value string) {
	ui.Row(c).FillWidth().Gap(10).Children(func() {
		ui.Text(c, key).FontSize(fsSmall).TextColor(p.Faint).Width(40)
		ui.Text(c, value).FontSize(fsSmall).TextColor(p.Muted).Grow(1).SingleLine()
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
			img.Set(x, y, color.RGBA{0x25, 0x63, 0xeb, 0xff})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
