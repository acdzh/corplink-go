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
	fsH1       float32 = 19
	fsH2       float32 = 13.5
	fsBody     float32 = 13
	fsSmall    float32 = 12
	fsTiny     float32 = 11
	radiusCard float32 = 14
	radiusChip float32 = 6
)

// palette 是浅色/深色两套配色。
type palette struct {
	Dark      bool
	Bg        ui.Color
	Card      ui.Color
	Border    ui.Color
	Separator ui.Color
	Text      ui.Color
	Muted     ui.Color
	Faint     ui.Color
	Heading   ui.Color
	Green     ui.Color
	Red       ui.Color
	Yellow    ui.Color
	Blue      ui.Color
	OkBg      ui.Color
	BtnBg     ui.Color
}

func lightPalette() palette {
	return palette{
		Bg: ui.Hex("#fbf7f1"), Card: ui.Hex("#ffffff"), Border: ui.Hex("#00000014"),
		Separator: ui.Hex("#00000010"), Text: ui.Hex("#1d1d1f"), Muted: ui.Hex("#6b6b70"),
		Faint: ui.Hex("#9a9aa0"), Heading: ui.Hex("#111114"), Green: ui.Hex("#1f9d55"),
		Red: ui.Hex("#d64545"), Yellow: ui.Hex("#b7791f"), Blue: ui.Hex("#2563eb"),
		OkBg: ui.Hex("#e8f5ec"), BtnBg: ui.Hex("#f1ece4"),
	}
}

func darkPalette() palette {
	return palette{
		Dark: true,
		Bg:   ui.Hex("#141214"), Card: ui.Hex("#1e1b1e"), Border: ui.Hex("#ffffff1a"),
		Separator: ui.Hex("#ffffff12"), Text: ui.Hex("#f5f5f7"), Muted: ui.Hex("#a1a1a6"),
		Faint: ui.Hex("#77777c"), Heading: ui.Hex("#ffffff"), Green: ui.Hex("#4ade80"),
		Red: ui.Hex("#f87171"), Yellow: ui.Hex("#fbbf24"), Blue: ui.Hex("#60a5fa"),
		OkBg: ui.Hex("#16301f"), BtnBg: ui.Hex("#2a262a"),
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

	view := func(c *ui.Context) {
		p := pal(c)
		c.Root().Background(p.Bg)
		state := rt.Agent.State()
		stats := rt.Agent.Stats()
		nodes := rt.Agent.Nodes()

		ui.Column(c).Fill().Padding(16).Gap(12).Children(func() {
			// 标题栏
			ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
				ui.Text(c, "Corplink Go").FontSize(fsH1).Bold().TextColor(p.Heading)
				ui.Spacer(c)
				if state.Connected {
					ui.Text(c, "● 已连接").FontSize(fsSmall).TextColor(p.Green)
				} else {
					ui.Text(c, "○ 未连接").FontSize(fsSmall).TextColor(p.Faint)
				}
			})

			// 状态卡
			ui.Column(c).FillWidth().Radius(radiusCard).Padding(13, 14).Gap(8).
				Background(p.Card).Border(1, p.Border).Children(func() {
				title := "未建立隧道"
				if state.Connected {
					title = state.Node + " · " + state.Address
				}
				ui.Text(c, title).FontSize(fsBody).Bold().TextColor(p.Text)
				info := "未登录"
				if rt.Agent.LoggedIn() {
					info = "已登录 · 节点 " + fmt.Sprint(len(nodes)) + " 个"
				}
				if state.Connected {
					info += " · 路由 " + fmt.Sprint(state.Routes) + " 条"
				}
				ui.Text(c, info).FontSize(fsTiny).TextColor(p.Muted)
				ui.Row(c).Gap(8).Children(func() {
					if ui.PrimaryButton(c, "连接").Clicked() {
						connect("")
					}
					if ui.Button(c, "断开").Clicked() {
						rt.Agent.Disconnect()
						c.Invalidate()
					}
					if ui.Button(c, "打开面板").Clicked() {
						_ = mygo.Shell.OpenExternal(panelURL)
					}
					if st.testing {
						ui.Spinner(c)
					}
				})
			})

			ui.Tabs(c, &st.tab, "节点", "流量", "日志", "关于")

			switch st.tab {
			case 0:
				ui.Row(c).FillWidth().Gap(8).Children(func() {
					if ui.Button(c, "全部测速").Clicked() {
						testAll()
					}
					if ui.Button(c, "自动连最快").Clicked() {
						connect("auto")
					}
					ui.Spacer(c)
					if rt.Agent.Auto() {
						ui.Text(c, "自动模式").FontSize(fsTiny).TextColor(p.Blue)
					}
				})
				ui.Scroll(c).Grow(1).Children(func() {
					ui.Column(c).Gap(6).Children(func() {
						for _, n := range nodes {
							name := displayName(n.EnName, n.Name, n.IP)
							lat := "—"
							if ms, ok := st.latency[name]; ok {
								if ms < 0 {
									lat = "超时"
								} else {
									lat = fmt.Sprintf("%d ms", ms)
								}
							}
							current := state.Connected && state.Node == name
							rowBg := p.Card
							if current {
								rowBg = p.OkBg
							}
							ui.Row(c).Key(name).FillWidth().Radius(10).Padding(9, 11).
								AlignItems(ui.Center).Background(rowBg).Children(func() {
								ui.Column(c).Gap(2).Grow(1).Children(func() {
									ui.Text(c, name).FontSize(fsBody).TextColor(p.Text)
									sub := fmt.Sprintf("%s · %s", protoName(n.ProtocolMode), lat)
									if n.TagName != "" {
										sub = n.TagName + " · " + sub
									}
									ui.Text(c, sub).FontSize(fsTiny).TextColor(p.Faint)
								})
								if current {
									ui.Text(c, "使用中").FontSize(fsTiny).TextColor(p.Green)
								} else if ui.Button(c, "连接").Clicked() {
									connect(name)
								}
							})
						}
						if len(nodes) == 0 {
							ui.Text(c, "没有节点，先在面板完成登录").FontSize(fsSmall).TextColor(p.Faint)
						}
					})
				})
			case 1:
				ui.Column(c).FillWidth().Radius(radiusCard).Padding(13, 14).Gap(10).
					Background(p.Card).Border(1, p.Border).Children(func() {
					ui.Row(c).FillWidth().Gap(18).Children(func() {
						metric(c, p, "上行", humanBytes(stats.TxBytes))
						metric(c, p, "下行", humanBytes(stats.RxBytes))
					})
					ui.Text(c, "在线 "+humanDuration(stats.UptimeSeconds)).FontSize(fsTiny).TextColor(p.Muted)
					if state.Connected {
						ui.Text(c, "DNS "+strings.Join(state.DNS, ", ")).FontSize(fsTiny).TextColor(p.Muted)
					}
				})
			case 2:
				events := rt.Agent.Events()
				ui.Scroll(c).Grow(1).Children(func() {
					ui.Column(c).Gap(4).Children(func() {
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
				ui.Column(c).FillWidth().Radius(radiusCard).Padding(13, 14).Gap(6).
					Background(p.Card).Border(1, p.Border).Children(func() {
					infoLine(c, p, "代理", rt.ProxyAddr)
					infoLine(c, p, "面板", panelURL)
					infoLine(c, p, "订阅", subURL)
					infoLine(c, p, "配置", cfg.Path())
					infoLine(c, p, "设备", cfg.DeviceBrand+" "+cfg.DeviceModel+" · API "+cfg.OSVersion)
				})
			}
		})
	}

	mygo.App.WhenReady(func() {
		win = mygo.NewWindow(mygo.WindowOptions{
			Title:   "Corplink Go",
			Width:   560,
			Height:  680,
			Content: ui.View(view),
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
		ui.Text(c, value).FontSize(20).Bold().TextColor(p.Heading)
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
