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
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/acdzh/corplink-go/internal/agent"
	"github.com/acdzh/corplink-go/internal/api"
	"github.com/acdzh/corplink-go/internal/app"
	"github.com/acdzh/corplink-go/internal/config"
)

// uiState 是窗口本地状态。
//
// selected 只表示"列表里选中了谁"，与是否连接无关：
// 选中项决定点「连接」时连哪个，连接/断开由按钮控制。
type uiState struct {
	tab      int
	selected string
	// icons 是节点图标缓存，键为节点名；后台从 /api/icon 拉取。
	iconMu sync.Mutex
	icons  map[string]ui.ImageSource
}

// iconCount 返回已缓存图标数量。
func (s *uiState) iconCount() int {
	s.iconMu.Lock()
	defer s.iconMu.Unlock()
	return len(s.icons)
}

// iconOf 读取图标缓存。
func (s *uiState) iconOf(name string) ui.ImageSource {
	s.iconMu.Lock()
	defer s.iconMu.Unlock()
	return s.icons[name]
}

// setIcon 写入图标缓存。
func (s *uiState) setIcon(name string, src ui.ImageSource) {
	s.iconMu.Lock()
	defer s.iconMu.Unlock()
	s.icons[name] = src
}

var navItems = []string{"节点", "流量", "日志", "关于"}

// httpClient 用于拉取本地面板资源（节点图标）。
var httpClient = &http.Client{Timeout: 10 * time.Second}

func main() {
	cfgPath := flag.String("config", "", "配置文件路径，默认 <用户配置目录>/CorpLinkGo/config.json")
	flag.Parse()

	path := *cfgPath
	if path == "" {
		p, err := config.DefaultPath()
		if err != nil {
			log.Fatalf("定位配置路径: %v", err)
		}
		path = p
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

	st := &uiState{selected: cfg.Mode, icons: map[string]ui.ImageSource{}}
	var win *mygo.Window

	connect := func(name string) {
		if name == "__first__" {
			nodes := rt.Agent.Nodes()
			if len(nodes) == 0 {
				return
			}
			name = displayName(nodes[0].EnName, nodes[0].Name, nodes[0].IP)
		}
		if name == "" {
			return
		}
		go func() {
			if err := rt.Agent.Connect(context.Background(), name); err != nil {
				fmt.Println("连接失败:", err)
			}
			if win != nil {
				win.Invalidate()
			}
		}()
	}

	// loadIcons 后台拉取节点图标（面板 /api/icon 已带会话代理）。
	loadIcons := func(base string, nodes []api.VpnInfo) {
		for _, n := range nodes {
			if n.Icon == "" {
				continue
			}
			name := displayName(n.EnName, n.Name, n.IP)
			if st.iconOf(name) != nil {
				continue
			}
			icon := n.Icon
			go func(key, url string) {
				resp, err := httpClient.Get(base + "/api/icon?u=" + neturl.QueryEscape(url))
				if err != nil {
					return
				}
				defer resp.Body.Close()
				data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				if err != nil {
					return
				}
				bitmap, err := ui.DecodeBitmap(data)
				if err != nil {
					return
				}
				st.setIcon(key, bitmap)
				if win != nil {
					win.Invalidate()
				}
			}(name, icon)
		}
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
		latencies := rt.Agent.Latencies()

		ui.Row(c).Fill().Children(func() {
			sidebar(c, p, state)

			ui.Column(c).Fill().Background(p.Bg).Padding(pagePadY, pagePadX).Gap(gapCard).Children(func() {
				// 标题行
				ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
					ui.Text(c, navItems[st.tab]).FontSize(fsH1).Bold().TextColor(p.Heading)
					ui.Spacer(c)
				})

				if st.tab == 0 && st.iconCount() == 0 {
					loadIcons(panelURL, nodes)
				}
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
							// 列表只负责"选中"，连接由上方按钮控制。
							row := func(key, label, right string, icon ui.ImageSource, picked, connected bool, onClick func()) {
								ui.Row(c).Key(key).FillWidth().Radius(radiusRow).Height(34).
									Padding(0, 10).AlignItems(ui.Center).
									Background(pickBg(p, picked)).OnClick(onClick).Children(func() {
									// 无图标时占位，保证文字对齐
									if icon != nil {
										ui.Image(c, icon).Size(18, 13).Fit(ui.Contain)
									} else {
										ui.Box(c).Size(18, 13)
									}
									ui.Box(c).Width(9)
									ui.Text(c, label).FontSize(fsBody).TextColor(p.Text).Grow(1).SingleLine()
									if connected {
										ui.Text(c, "使用中").FontSize(fsTiny).TextColor(p.Green)
										ui.Box(c).Width(8)
									}
									ui.Text(c, right).FontSize(fsSmall).TextColor(p.Faint).Width(52)
								})
							}
							row("__auto__", mark(st.selected == "auto", "自动选择"), "", nil,
								st.selected == "auto", false, func() { st.selected = "auto" })
							for _, n := range nodes {
								name := displayName(n.EnName, n.Name, n.IP)
								ms, has := latencies[name]
								lat := "–"
								switch {
								case !has:
									lat = "–"
								case ms < 0:
									lat = "超时"
								default:
									lat = fmt.Sprintf("%d ms", ms)
								}
								node := name
								row(name, mark(st.selected == node, node), lat, st.iconOf(node),
									st.selected == node, state.Connected && state.Node == node,
									func() { st.selected = node })
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
			// 选择与连接解耦：子菜单只改选中项，连接由上面的「连接」按钮触发。
			selectOnly := func(name string) {
				st.selected = name
				if win != nil {
					win.Invalidate()
				}
			}
			autoLabel := "自动选择"
			if st.selected == "auto" {
				autoLabel = "✓ 自动选择"
			}
			nodeItems := []*mygo.MenuItem{{
				Label: autoLabel,
				Click: func(*mygo.MenuItem, *mygo.Window) { selectOnly("auto") },
			}, mygo.Separator()}
			for _, n := range rt.Agent.Nodes() {
				name := displayName(n.EnName, n.Name, n.IP)
				label := name
				if st.selected == name {
					label = "✓ " + name
				}
				node := name
				nodeItems = append(nodeItems, &mygo.MenuItem{
					Label: label,
					Click: func(*mygo.MenuItem, *mygo.Window) { selectOnly(node) },
				})
			}
			items := []*mygo.MenuItem{
				{Label: header, Disabled: true},
				{Label: "连接", Disabled: state.Connected, Click: func(*mygo.MenuItem, *mygo.Window) {
					connect(st.selected)
				}},
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

// mark 给选中项加勾。
func mark(picked bool, label string) string {
	if picked {
		return "✓ " + label
	}
	return label
}

// pickBg 返回选中行的背景色。
func pickBg(p palette, picked bool) ui.Color {
	if picked {
		return p.AccentBg
	}
	return p.Card
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
