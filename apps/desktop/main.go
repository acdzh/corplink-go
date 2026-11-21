// Command corplink-desktop 是 macOS 桌面壳：进程内启动同一个运行时，
// 用 MyGo 原生控件提供状态、节点选择、流量、令牌、设置与日志，并常驻菜单栏。
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
	"log/slog"
	"math"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/acdzh/corplink-go/corplink"
	"github.com/acdzh/corplink-go/corplink/config"
	"github.com/acdzh/corplink-go/httpapi"
)

// uiState 是窗口本地状态。
//
// selected 只表示"列表里选中了谁"，与是否连接无关：
// 选中项决定点「连接」时连哪个，连接/断开由按钮控制。
type uiState struct {
	tab      int
	selected string
	search   string

	connecting   bool
	pinging      bool
	refreshing   bool
	lifetimePact bool
	errMsg       string
	noticeMsg    string

	txRate       float64
	rxRate       float64
	lastTx       int64
	lastRx       int64
	lastSampleAt time.Time

	authURL       string
	callbackInput string
	mfaInput      string
	mfaRequired   bool
	loginBusy     bool
	loginTip      string

	setCompany      string
	setServer       string
	setProxy        string
	setPanel        string
	setAutoInterval string
	settingBusy     bool
	settingTip      string

	// icons 是节点图标缓存，键为节点名；后台从 /api/icon 拉取。
	iconMu   sync.Mutex
	icons    map[string]ui.ImageSource
	fetching map[string]bool
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

// beginFetch 原子检查并标记节点图标拉取状态，避免重复并发请求。
func (s *uiState) beginFetch(name string) bool {
	s.iconMu.Lock()
	defer s.iconMu.Unlock()
	if s.icons[name] != nil || s.fetching[name] {
		return false
	}
	s.fetching[name] = true
	return true
}

// endFetch 结束节点图标拉取标记。
func (s *uiState) endFetch(name string) {
	s.iconMu.Lock()
	defer s.iconMu.Unlock()
	delete(s.fetching, name)
}

var navItems = []string{"节点", "流量", "令牌", "设置", "日志"}

// 面板默认监听地址与图标拉取超时。
const (
	// defaultPanelListen 是控制面板默认监听地址。
	defaultPanelListen = "127.0.0.1:13140"
	// defaultProxyListen 是混合代理默认监听地址。
	defaultProxyListen = "127.0.0.1:3710"
	// iconTimeout 是单个节点图标的拉取上限。
	iconTimeout = 10 * time.Second
)

func main() {
	cfgPath := flag.String("config", "", "配置文件路径，默认 ~/.corplink-go/config.json")
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
	// 代理地址由端侧决定：库只在拿到地址时才开端口。
	proxyListenVal := cfg.SocksListen
	if proxyListenVal == "" {
		proxyListenVal = defaultProxyListen
	}
	rt, err := corplink.New(ctx, corplink.Options{
		Config:      cfg,
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, nil)),
		ProxyListen: proxyListenVal,
	})
	if err != nil {
		log.Fatalf("装配客户端: %v", err)
	}
	if err := rt.Start(ctx); err != nil {
		log.Fatalf("启动运行时: %v", err)
	}
	panelListen := cfg.PanelListen
	if panelListen == "" {
		panelListen = defaultPanelListen
	}
	panel := &httpapi.Server{PanelAddr: panelListen}
	go func() {
		if err := panel.Serve(ctx, panelListen, rt); err != nil {
			log.Printf("控制面板退出: %v", err)
		}
	}()
	panelBase := "http://" + panelListen
	panelURL := panelBase + "/?token=" + panel.AccessToken()
	subURL := panelBase + "/clash.yml?token=" + panel.AccessToken()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		cancel()
		rt.Close(context.Background())
		mygo.App.Quit()
	}()

	initialSelected := cfg.Mode
	if initialSelected == "" {
		initialSelected = "auto"
	}
	panelListenVal := panelListen
	autoIntervalVal := cfg.AutoModeIntervalSeconds
	if autoIntervalVal <= 0 {
		autoIntervalVal = 300
	}

	st := &uiState{
		selected:        initialSelected,
		setCompany:      cfg.CompanyName,
		setServer:       cfg.Server,
		setProxy:        proxyListenVal,
		setPanel:        panelListenVal,
		setAutoInterval: strconv.Itoa(autoIntervalVal),
		icons:           map[string]ui.ImageSource{},
		fetching:        map[string]bool{},
	}
	var win *mygo.Window
	var refreshTrayFn func()

	updateUI := func(fn func()) {
		if win != nil {
			win.Update(fn)
			return
		}
		fn()
	}

	connect := func(name string) {
		if name == "__first__" {
			nodes := rt.Nodes()
			if len(nodes) == 0 {
				updateUI(func() {
					st.errMsg = "节点列表为空，请先登录并刷新节点"
				})
				return
			}
			name = nodes[0].Name
		}
		if name == "" {
			name = st.selected
		}
		if name == "" {
			name = "auto"
		}
		updateUI(func() {
			if st.connecting {
				return
			}
			st.connecting = true
			st.selected = name
			st.errMsg = ""
			st.noticeMsg = ""
		})
		go func(target string) {
			err := rt.Connect(context.Background(), target)
			if err == nil {
				cfg.Mode = target
				if saveErr := cfg.Save(); saveErr != nil {
					fmt.Println("保存连接模式失败:", saveErr)
				}
			}
			updateUI(func() {
				st.connecting = false
				if err != nil {
					st.errMsg = "连接失败: " + err.Error()
				} else {
					st.errMsg = ""
					if st.lifetimePact {
						st.noticeMsg = "「一生、プロキシする。迷子でもプロキシ進め。」"
					} else if target == "auto" {
						st.noticeMsg = "已通过自动选路建立连接"
					} else {
						st.noticeMsg = "已连接到 " + target
					}
				}
			})
			if refreshTrayFn != nil {
				refreshTrayFn()
			}
		}(name)
	}

	disconnect := func() {
		rt.Disconnect()
		updateUI(func() {
			st.txRate = 0
			st.rxRate = 0
			st.lastSampleAt = time.Time{}
			if st.lifetimePact {
				st.lifetimePact = false
				st.noticeMsg = ""
				st.errMsg = "「なんでプロキシ切ったの！？」"
			} else {
				st.errMsg = ""
				st.noticeMsg = "已断开连接"
			}
		})
		if refreshTrayFn != nil {
			refreshTrayFn()
		}
	}

	pingAll := func() {
		updateUI(func() {
			if st.pinging {
				return
			}
			st.pinging = true
			st.errMsg = ""
		})
		go func() {
			pingCtx, pingCancel := context.WithTimeout(ctx, 20*time.Second)
			defer pingCancel()
			rt.PingAll(pingCtx)
			updateUI(func() {
				st.pinging = false
				st.noticeMsg = "节点测速已完成"
			})
			if refreshTrayFn != nil {
				refreshTrayFn()
			}
		}()
	}

	refreshNodes := func() {
		updateUI(func() {
			if st.refreshing {
				return
			}
			st.refreshing = true
			st.errMsg = ""
		})
		go func() {
			reqCtx, reqCancel := context.WithTimeout(ctx, 20*time.Second)
			defer reqCancel()
			err := rt.RefreshNodes(reqCtx)
			updateUI(func() {
				st.refreshing = false
				if err != nil {
					st.errMsg = "刷新节点失败: " + err.Error()
				} else {
					st.noticeMsg = fmt.Sprintf("已刷新节点，共 %d 个", len(rt.Nodes()))
				}
			})
			if refreshTrayFn != nil {
				refreshTrayFn()
			}
		}()
	}

	// loadIcons 后台按节点补齐图标：图标由库带会话代取，端侧不接触 Cookie。
	loadIcons := func(nodes []corplink.Node) {
		for _, n := range nodes {
			if n.Icon == "" {
				continue
			}
			name := n.Name
			if !st.beginFetch(name) {
				continue
			}
			icon := n.Icon
			go func(key, iconURL string) {
				defer st.endFetch(key)
				reqCtx, reqCancel := context.WithTimeout(ctx, iconTimeout)
				defer reqCancel()
				data, _, err := rt.FetchIcon(reqCtx, iconURL)
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
	sidebar := func(c *ui.Context, p palette, state corplink.State) {
		side := ui.Column(c).Width(sidebarWidth).FillHeight().
			BorderWidth(0, 0, 0, 1).BorderColor(p.Border)
		if !c.Vibrancy() {
			side = side.Background(p.Sidebar)
		}
		side.Children(func() {
			ui.Column(c).Padding(16, 20, 10, 20).Gap(4).Children(func() {
				ui.Text(c, "Corplink Go").FontSize(fsH2).Bold().TextColor(p.Heading)
				ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
					tone, label := p.Faint, "未连接"
					if st.connecting {
						tone, label = p.Yellow, "连接中..."
					} else if state.Connected {
						tone, label = p.Green, state.Node
					}
					ui.Box(c).Size(6, 6).Radius(3).Background(tone)
					ui.Text(c, label).FontSize(fsTiny).TextColor(p.Muted).Grow(1).SingleLine()
				})
				if rt.Auto() && state.Connected {
					ui.Text(c, "自动选路模式").FontSize(fsTiny).TextColor(p.Green)
				}
			})
			ui.Column(c).Padding(4, 10).Gap(2).Children(func() {
				for i, label := range navItems {
					idx := i
					row := ui.Row(c).FillWidth().Radius(radiusRow).Padding(7, 10).AlignItems(ui.Center)
					if idx == st.tab {
						row = row.Background(p.AccentBg)
					}
					row.OnClick(func() {
						st.tab = idx
					}).Children(func() {
						txtColor := p.Muted
						if idx == st.tab {
							txtColor = p.Heading
						}
						el := ui.Text(c, label).FontSize(fsBody).TextColor(txtColor).Grow(1)
						if idx == st.tab {
							el.Bold()
						}
					})
				}
			})
			ui.Spacer(c)
			if rt.HasTOTP() {
				if code, rem, err := rt.TOTPCode(); err == nil {
					remColor := p.Green
					if rem <= 5 {
						remColor = p.Red
					}
					ui.Column(c).Padding(8, 12).Margin(0, 12, 8, 12).Gap(2).Radius(radiusRow).
						Background(p.Card).Border(1, p.Border).
						OnClick(func() {
							mygo.Clipboard.WriteText(code)
							st.noticeMsg = "已复制动态码 " + code
						}).Children(func() {
						ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
							ui.Text(c, "动态码").FontSize(fsTiny).TextColor(p.Faint).Grow(1)
							ui.Text(c, fmt.Sprintf("%ds", rem)).FontSize(fsTiny).TextColor(remColor)
						})
						ui.Text(c, code[:3]+" "+code[3:]).FontSize(fsH2).Bold().TextColor(p.Heading)
					})
				}
			}
			ui.Column(c).Padding(8, 20, 14, 20).Gap(2).Children(func() {
				ui.Text(c, "代理 "+rt.ProxyAddr()).FontSize(fsTiny).TextColor(p.Faint).SingleLine()
				ui.Text(c, "面板 "+panelListen).FontSize(fsTiny).TextColor(p.Faint).SingleLine()
				easterText := "一生プロキシしてくれる？"
				if st.lifetimePact {
					easterText = "✦ 一生、プロキシする ✦"
				}
				ui.Text(c, easterText).FontSize(fsTiny).TextColor(p.Faint).SingleLine().
					OnClick(func() {
						st.lifetimePact = true
						st.errMsg = ""
						st.noticeMsg = "「一生、プロキシする。迷子でもプロキシ進め。」"
						if !state.Connected {
							connect(st.selected)
						}
					})
			})
		})
	}

	view := func(c *ui.Context) {
		p := pal(c)
		state := rt.State()
		stats := rt.Stats()
		nodes := rt.Nodes()
		latencies := rt.Latencies()
		loggedIn := rt.LoggedIn()

		if st.tab == 0 && len(nodes) > 0 {
			loadIcons(nodes)
		}

		ui.Row(c).Fill().Children(func() {
			sidebar(c, p, state)

			ui.Column(c).Fill().Background(p.Bg).Padding(pagePadY, pagePadX).Gap(gapCard).Children(func() {
				// 标题行
				ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(8).Children(func() {
					ui.Text(c, navItems[st.tab]).FontSize(fsH1).Bold().TextColor(p.Heading)
					if st.tab == 4 {
						ui.Spacer(c)
						if ui.Button(c, "清空日志").Clicked() {
							rt.ClearEvents()
						}
					} else {
						ui.Spacer(c)
						if loggedIn {
							badge(c, "已登录", p.Green, p.OkBg, p.OkBorder)
						} else {
							badge(c, "未登录", p.Yellow, p.WarnBg, p.WarnBorder)
						}
					}
				})

				if st.errMsg != "" {
					noticeBanner(c, st.errMsg, p.Red, p.AlertBg, p.AlertBorder, "关闭", func() {
						st.errMsg = ""
					})
				} else if st.noticeMsg != "" {
					noticeBanner(c, st.noticeMsg, p.Green, p.OkBg, p.OkBorder, "关闭", func() {
						st.noticeMsg = ""
					})
				}

				switch st.tab {
				case 0:
					card(c, p, func() {
						ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(8).Children(func() {
							connLabel := "未建立隧道"
							if st.connecting {
								connLabel = "正在建立隧道..."
							} else if state.Connected {
								connLabel = fmt.Sprintf("%s · %s · 路由 %d 条", state.Address, state.Protocol, state.Routes)
							}
							ui.Text(c, connLabel).FontSize(fsSmall).TextColor(p.Muted).Grow(1).SingleLine()
							if state.Connected && state.Tag != "" {
								badge(c, state.Tag, p.Green, p.OkBg, p.OkBorder)
							}
						})
						ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
							connectBtnLabel := "连接"
							if st.connecting {
								connectBtnLabel = "连接中..."
							} else if state.Connected && st.selected != "" && st.selected != "auto" && st.selected != state.Node {
								connectBtnLabel = "切换节点"
							} else if state.Connected {
								connectBtnLabel = "重连"
							}
							if ui.PrimaryButton(c, connectBtnLabel).Disabled(st.connecting).Clicked() {
								connect(st.selected)
							}
							if ui.Button(c, "断开").Disabled(!state.Connected || st.connecting).Clicked() {
								disconnect()
							}
							pingBtnLabel := "测速"
							if st.pinging {
								pingBtnLabel = "测速中..."
							}
							if ui.Button(c, pingBtnLabel).Disabled(st.pinging).Clicked() {
								pingAll()
							}
							refreshBtnLabel := "刷新"
							if st.refreshing {
								refreshBtnLabel = "刷新中..."
							}
							if ui.Button(c, refreshBtnLabel).Disabled(st.refreshing).Clicked() {
								refreshNodes()
							}
							ui.Spacer(c)
						})
					})

					ui.TextInput(c, &st.search).FillWidth().Placeholder("搜索节点名称、标签或 IP...")

					// 按延迟排序节点，便于快速挑选最优节点。
					sorted := make([]corplink.Node, len(nodes))
					copy(sorted, nodes)
					sort.SliceStable(sorted, func(i, j int) bool {
						ni := sorted[i].Name
						nj := sorted[j].Name
						li, okI := latencies[ni]
						lj, okJ := latencies[nj]
						vi := int64(math.MaxInt64)
						if okI && li >= 0 {
							vi = li
						}
						vj := int64(math.MaxInt64)
						if okJ && lj >= 0 {
							vj = lj
						}
						return vi < vj
					})

					var bestAutoMs int64 = -1
					for _, ms := range latencies {
						if ms >= 0 && (bestAutoMs < 0 || ms < bestAutoMs) {
							bestAutoMs = ms
						}
					}

					kw := strings.ToLower(strings.TrimSpace(st.search))

					ui.Scroll(c).Grow(1).Children(func() {
						ui.Column(c).Gap(6).Children(func() {
							// 列表支持单击选中、双击直连。
							row := func(key, label, tag, proto, latText string, latCol ui.Color, icon ui.ImageSource, picked, connected bool, onClick func(), onDouble func()) {
								r := ui.Row(c).Key(key).FillWidth().Radius(radiusRow).Height(36).
									Padding(0, 10).Gap(8).AlignItems(ui.Center).
									Background(pickBg(p, picked)).Border(1, pickBorder(p, picked)).
									OnClick(onClick)
								if r.DoubleClicked() && onDouble != nil {
									onDouble()
								}
								r.Children(func() {
									if icon != nil {
										ui.Image(c, icon).Size(18, 13).Fit(ui.Contain)
									} else {
										ui.Box(c).Size(18, 13)
									}
									ui.Text(c, label).FontSize(fsBody).TextColor(p.Text).Grow(1).SingleLine()
									if tag != "" {
										badge(c, tag, p.Muted, p.PillBg, p.Border)
									}
									if proto != "" {
										badge(c, proto, p.Faint, p.PillBg, p.Border)
									}
									if connected {
										badge(c, "使用中", p.Green, p.OkBg, p.OkBorder)
									}
									ui.Text(c, latText).FontSize(fsSmall).TextColor(latCol).Width(56)
								})
							}

							if kw == "" {
								autoLat := "–"
								autoCol := p.Faint
								if bestAutoMs >= 0 {
									autoLat = fmt.Sprintf("%d ms", bestAutoMs)
									autoCol = latencyColor(p, bestAutoMs)
								}
								row("__auto__", mark(st.selected == "auto", "自动选择"), "最快", "AUTO", autoLat, autoCol, nil,
									st.selected == "auto", rt.Auto() && state.Connected,
									func() { st.selected = "auto" },
									func() { connect("auto") })
							}

							matchedCount := 0
							for _, n := range sorted {
								name := n.Name
								if kw != "" {
									hay := strings.ToLower(name + " " + n.Name + " " + n.Tag + " " + n.IP + " " + n.InternalIP)
									if !strings.Contains(hay, kw) {
										continue
									}
								}
								matchedCount++
								ms, has := latencies[name]
								lat := "–"
								latCol := p.Faint
								switch {
								case !has:
									lat = "–"
								case ms < 0:
									lat = "超时"
									latCol = p.Red
								default:
									lat = fmt.Sprintf("%d ms", ms)
									latCol = latencyColor(p, ms)
								}
								node := name
								row(name, mark(st.selected == node, node), n.Tag, protoName(n.ProtocolMode),
									lat, latCol, st.iconOf(node),
									st.selected == node, state.Connected && state.Node == node,
									func() { st.selected = node },
									func() { connect(node) })
							}
							if len(nodes) == 0 {
								noticeBanner(c, "当前没有可用节点，请前往「令牌」页完成登录，或在「设置」页配置企业代码。", p.Muted, p.PillBg, p.Border, "去登录", func() {
									st.tab = 2
								})
							} else if kw != "" && matchedCount == 0 {
								ui.Text(c, "没有匹配的节点").FontSize(fsSmall).TextColor(p.Faint)
							}
						})
					})

				case 1:
					txRateText := "-"
					rxRateText := "-"
					if stats.Connected {
						txRateText = humanBytes(int64(st.txRate)) + "/s"
						rxRateText = humanBytes(int64(st.rxRate)) + "/s"
					}
					ui.Row(c).FillWidth().Gap(gapCard).Children(func() {
						statTile(c, p, "上行总计", humanBytes(stats.TxBytes))
						statTile(c, p, "下行总计", humanBytes(stats.RxBytes))
					})
					ui.Row(c).FillWidth().Gap(gapCard).Children(func() {
						statTile(c, p, "上行速率", txRateText)
						statTile(c, p, "下行速率", rxRateText)
					})
					card(c, p, func() {
						sectionTitle(c, p, "连接明细", "SOCKS5 + HTTP 混合代理")
						handshake := "-"
						if stats.LastHandshake > 0 {
							handshake = time.Unix(stats.LastHandshake, 0).Format("15:04:05")
						}
						kvRow(c, p, "在线时长", humanDuration(stats.UptimeSeconds))
						kvRow(c, p, "最近握手", handshake)
						kvRow(c, p, "隧道地址", state.Address)
						kvRow(c, p, "对端节点", state.Endpoint)
						kvRow(c, p, "传输协议", state.Protocol)
						kvRow(c, p, "隧道 DNS", strings.Join(state.DNS, ", "))
						kvRow(c, p, "分流规则", fmt.Sprintf("网段 %d 条 · 域名 %d 个", state.Routes, state.Domains))
						ui.Row(c).Gap(8).Children(func() {
							if ui.Button(c, "复制代理地址").Clicked() {
								mygo.Clipboard.WriteText(rt.ProxyAddr())
								st.noticeMsg = "已复制代理地址 " + rt.ProxyAddr()
							}
							if ui.Button(c, "复制终端命令").Clicked() {
								cmd := fmt.Sprintf("export https_proxy=http://%s http_proxy=http://%s all_proxy=socks5://%s", rt.ProxyAddr(), rt.ProxyAddr(), rt.ProxyAddr())
								mygo.Clipboard.WriteText(cmd)
								st.noticeMsg = "已复制终端环境变量命令"
							}
							if ui.Button(c, "复制订阅地址").Clicked() {
								mygo.Clipboard.WriteText(subURL)
								st.noticeMsg = "已复制 Clash 订阅地址"
							}
						})
					})
					routes := rt.Routes()
					domains := rt.Domains()
					if state.Connected && (len(routes) > 0 || len(domains) > 0) {
						card(c, p, func() {
							sectionTitle(c, p, "分流预览", fmt.Sprintf("%d 条网段 / %d 个域名", len(routes), len(domains)))
							ui.Scroll(c).Height(110).Children(func() {
								ui.Column(c).Gap(3).Children(func() {
									limit := 40
									for i, r := range routes {
										if i >= limit {
											ui.Text(c, fmt.Sprintf("... 还有 %d 条网段", len(routes)-limit)).FontSize(fsTiny).TextColor(p.Faint)
											break
										}
										ui.Text(c, "CIDR  "+r).FontSize(fsTiny).TextColor(p.Muted)
									}
									for i, d := range domains {
										if i >= limit {
											ui.Text(c, fmt.Sprintf("... 还有 %d 个域名", len(domains)-limit)).FontSize(fsTiny).TextColor(p.Faint)
											break
										}
										ui.Text(c, "DOMAIN  "+d).FontSize(fsTiny).TextColor(p.Muted)
									}
								})
							})
						})
					}

				case 2:
					card(c, p, func() {
						sectionTitle(c, p, "动态验证码 (TOTP)", "用于飞连二次认证")
						if !rt.HasTOTP() {
							ui.Text(c, "暂未绑定 TOTP 密钥；首次登录成功后将自动拉取并保存。").FontSize(fsSmall).TextColor(p.Faint)
						} else {
							code, rem, totpErr := rt.TOTPCode()
							if totpErr != nil {
								ui.Text(c, "生成动态码失败: "+totpErr.Error()).FontSize(fsSmall).TextColor(p.Red)
							} else {
								remColor := p.Green
								if rem <= 5 {
									remColor = p.Red
								}
								ui.Row(c).FillWidth().AlignItems(ui.Center).Gap(12).Children(func() {
									ui.Text(c, code[:3]+" "+code[3:]).FontSize(26).Bold().TextColor(p.Heading)
									ui.Text(c, fmt.Sprintf("剩余 %d 秒", rem)).FontSize(fsSmall).TextColor(remColor)
									ui.Spacer(c)
									if ui.PrimaryButton(c, "复制验证码").Clicked() {
										mygo.Clipboard.WriteText(code)
										st.noticeMsg = "已复制动态码 " + code
									}
								})
								ui.Progress(c, float64(rem)/30.0).FillWidth().TextColor(remColor)
							}
						}
					})

					card(c, p, func() {
						sectionTitle(c, p, "账号与登录", "SSO 授权与会话管理")
						kvRow(c, p, "当前状态", loginStateText(loggedIn, rt.LoginPending()))
						kvRow(c, p, "企业代码", cfg.CompanyName)
						kvRow(c, p, "服务端", cfg.Server)
						if st.loginTip != "" {
							ui.Text(c, st.loginTip).FontSize(fsSmall).TextColor(p.Muted)
						}
						ui.Row(c).Gap(8).Children(func() {
							authBtnLabel := "获取并打开授权链接"
							if st.loginBusy {
								authBtnLabel = "处理中..."
							}
							if ui.PrimaryButton(c, authBtnLabel).Disabled(st.loginBusy).Clicked() {
								updateUI(func() {
									st.loginBusy = true
									st.loginTip = "正在获取授权链接..."
								})
								go func() {
									reqCtx, reqCancel := context.WithTimeout(ctx, 20*time.Second)
									defer reqCancel()
									info, err := rt.LoginStart(reqCtx, "")
									updateUI(func() {
										st.loginBusy = false
										if err != nil {
											st.loginTip = "获取授权链接失败: " + err.Error()
											return
										}
										u, _ := info["url"].(string)
										st.authURL = u
										st.loginTip = "已在浏览器打开授权页，完成后请粘贴回调链接"
										if u != "" {
											_ = mygo.Shell.OpenExternal(u)
										}
									})
								}()
							}
							if ui.Button(c, "打开网页面板").Clicked() {
								_ = mygo.Shell.OpenExternal(panelURL)
							}
							if loggedIn {
								if ui.Button(c, "退出登录").Clicked() {
									if err := rt.LoginLogout(); err != nil {
										st.errMsg = "退出登录失败: " + err.Error()
									} else {
										st.authURL = ""
										st.callbackInput = ""
										st.mfaInput = ""
										st.mfaRequired = false
										st.loginTip = "已退出登录"
										if refreshTrayFn != nil {
											refreshTrayFn()
										}
									}
								}
							}
						})

						if st.authURL != "" {
							ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
								ui.TextInput(c, &st.callbackInput).Grow(1).Placeholder("粘贴 corplink://login/callback?... 回调地址")
								if ui.Button(c, "提交回调").Disabled(st.loginBusy).Clicked() {
									cb := strings.TrimSpace(st.callbackInput)
									if cb == "" {
										st.loginTip = "请先粘贴回调 URL"
									} else {
										updateUI(func() {
											st.loginBusy = true
											st.loginTip = "正在校验回调..."
										})
										go func(raw string) {
											reqCtx, reqCancel := context.WithTimeout(ctx, 20*time.Second)
											defer reqCancel()
											res, err := rt.LoginCallback(reqCtx, raw)
											updateUI(func() {
												st.loginBusy = false
												if err != nil {
													st.loginTip = "回调失败: " + err.Error()
													return
												}
												if mfa, _ := res["mfa_required"].(bool); mfa {
													st.mfaRequired = true
													st.loginTip = "需要二次验证，请输入验证码或直接留空用 TOTP 验证"
													return
												}
												st.authURL = ""
												st.callbackInput = ""
												st.mfaRequired = false
												st.loginTip = "登录成功"
												st.noticeMsg = "登录成功，节点已更新"
											})
											if refreshTrayFn != nil {
												refreshTrayFn()
											}
										}(cb)
									}
								}
							})
						}

						if st.mfaRequired || rt.LoginPending() {
							ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
								ui.TextInput(c, &st.mfaInput).Grow(1).Placeholder("2FA 验证码（已绑定 TOTP 可留空）")
								if ui.Button(c, "发送邮箱码").Disabled(st.loginBusy).Clicked() {
									updateUI(func() {
										st.loginBusy = true
									})
									go func() {
										reqCtx, reqCancel := context.WithTimeout(ctx, 15*time.Second)
										defer reqCancel()
										err := rt.LoginSendMFA(reqCtx, "email")
										updateUI(func() {
											st.loginBusy = false
											if err != nil {
												st.loginTip = "发送验证码失败: " + err.Error()
											} else {
												st.loginTip = "已请求发送邮箱验证码"
											}
										})
									}()
								}
								if ui.PrimaryButton(c, "提交验证").Disabled(st.loginBusy).Clicked() {
									code := strings.TrimSpace(st.mfaInput)
									updateUI(func() {
										st.loginBusy = true
										st.loginTip = "正在校验二次验证码..."
									})
									go func(mfaCode string) {
										reqCtx, reqCancel := context.WithTimeout(ctx, 20*time.Second)
										defer reqCancel()
										_, err := rt.LoginMFA(reqCtx, mfaCode)
										updateUI(func() {
											st.loginBusy = false
											if err != nil {
												st.loginTip = "二次验证失败: " + err.Error()
												return
											}
											st.authURL = ""
											st.callbackInput = ""
											st.mfaInput = ""
											st.mfaRequired = false
											st.loginTip = "登录成功"
											st.noticeMsg = "登录成功，节点已更新"
										})
										if refreshTrayFn != nil {
											refreshTrayFn()
										}
									}(code)
								}
							})
						}
					})

				case 3:
					card(c, p, func() {
						sectionTitle(c, p, "基础配置", "修改服务端支持即时生效，监听地址修改后需重启")
						fieldRow := func(label string, val *string, placeholder string) {
							ui.Row(c).FillWidth().Gap(10).AlignItems(ui.Center).Children(func() {
								ui.Text(c, label).FontSize(fsSmall).TextColor(p.Muted).Width(96)
								ui.TextInput(c, val).Grow(1).Placeholder(placeholder)
							})
						}
						fieldRow("企业代码", &st.setCompany, "例如 your-company")
						fieldRow("服务端地址", &st.setServer, "留空则由企业代码自动解析")
						fieldRow("代理监听", &st.setProxy, "127.0.0.1:3710")
						fieldRow("面板监听", &st.setPanel, "127.0.0.1:13140")
						fieldRow("测速间隔(秒)", &st.setAutoInterval, "300")
						if st.settingTip != "" {
							ui.Text(c, st.settingTip).FontSize(fsSmall).TextColor(p.Muted)
						}
						ui.Row(c).Gap(8).Children(func() {
							saveLabel := "保存设置"
							if st.settingBusy {
								saveLabel = "保存中..."
							}
							if ui.PrimaryButton(c, saveLabel).Disabled(st.settingBusy).Clicked() {
								company := strings.TrimSpace(st.setCompany)
								server := strings.TrimSpace(st.setServer)
								proxyAddr := strings.TrimSpace(st.setProxy)
								panelAddr := strings.TrimSpace(st.setPanel)
								intervalStr := strings.TrimSpace(st.setAutoInterval)

								updateUI(func() {
									st.settingBusy = true
									st.settingTip = ""
								})
								go func() {
									errMsg, restartList, resolvedServer := applyDesktopSettings(ctx, rt, cfg, company, server, proxyAddr, panelAddr, intervalStr)
									updateUI(func() {
										st.settingBusy = false
										if errMsg != "" {
											st.settingTip = errMsg
											st.errMsg = errMsg
											return
										}
										st.setServer = resolvedServer
										if len(restartList) > 0 {
											st.settingTip = "已保存，重启后生效: " + strings.Join(restartList, "、")
										} else {
											st.settingTip = "设置已保存并立即生效"
										}
										st.noticeMsg = st.settingTip
									})
								}()
							}
							if ui.Button(c, "在浏览器打开完整设置").Clicked() {
								_ = mygo.Shell.OpenExternal(panelURL)
							}
						})
					})
					card(c, p, func() {
						sectionTitle(c, p, "环境信息", "客户端伪装与文件位置")
						kvRow(c, p, "配置文件", cfg.Path())
						kvRow(c, p, "订阅地址", subURL)
						kvRow(c, p, "设备信息", cfg.DeviceBrand+" "+cfg.DeviceModel+" · Android "+cfg.OSVersion)
						ui.Row(c).Gap(8).Children(func() {
							if ui.Button(c, "复制订阅地址").Clicked() {
								mygo.Clipboard.WriteText(subURL)
								st.noticeMsg = "已复制 Clash 订阅地址"
							}
							if ui.Button(c, "复制配置路径").Clicked() {
								mygo.Clipboard.WriteText(cfg.Path())
								st.noticeMsg = "已复制配置文件路径"
							}
						})
					})

				case 4:
					card(c, p, func() {
						ui.Scroll(c).Height(420).Children(func() {
							ui.Column(c).Gap(6).Children(func() {
								events := rt.Events()
								for i := len(events) - 1; i >= 0; i-- {
									e := events[i]
									lvlColor := p.Green
									switch e.Level {
									case "warn":
										lvlColor = p.Yellow
									case "error":
										lvlColor = p.Red
									}
									ui.Row(c).FillWidth().Gap(8).AlignItems(ui.Center).Children(func() {
										ui.Text(c, e.Time).FontSize(fsTiny).TextColor(p.Faint).Width(54)
										ui.Text(c, strings.ToUpper(e.Level)).FontSize(fsTiny).Bold().TextColor(lvlColor).Width(42)
										ui.Text(c, e.Message).FontSize(fsSmall).TextColor(p.Muted).Grow(1)
									})
								}
								if len(events) == 0 {
									ui.Text(c, "暂无运行事件").FontSize(fsSmall).TextColor(p.Faint)
								}
							})
						})
					})
				}
			})
		})
	}

	mygo.App.WhenReady(func() {
		disconnectedIcon, _ := renderTrayIcon(false)
		connectedIcon, _ := renderTrayIcon(true)

		win = mygo.NewWindow(mygo.WindowOptions{
			Title:       "Corplink Go",
			Width:       780,
			Height:      600,
			MinWidth:    640,
			MinHeight:   480,
			StateKey:    "main",
			Transparent: true,
			Vibrancy:    mygo.VibrancySidebar,
			Content:     ui.View(view),
		})
		if connectedIcon != nil {
			_ = win.SetIcon(connectedIcon)
		}

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

		var tray *mygo.Tray
		if disconnectedIcon != nil {
			t, err := mygo.NewTray(mygo.TrayOptions{ID: "corplink-go", Icon: disconnectedIcon, ToolTip: "Corplink Go"})
			if err != nil {
				fmt.Println("创建托盘失败:", err)
			} else {
				tray = t
				tray.OnClick(func() {
					if win != nil {
						win.Show()
						win.Focus()
					}
				})
			}
		}

		var lastTrayState *bool
		refreshTray := func() {
			if tray == nil {
				return
			}
			state := rt.State()
			if lastTrayState == nil || *lastTrayState != state.Connected {
				v := state.Connected
				lastTrayState = &v
				if state.Connected && connectedIcon != nil {
					_ = tray.SetIcon(connectedIcon, false)
				} else if !state.Connected && disconnectedIcon != nil {
					_ = tray.SetIcon(disconnectedIcon, false)
				}
			}

			header := "未连接"
			title := "○"
			if state.Connected {
				header = "已连接 " + state.Node
				title = "● " + state.Node
			}
			if rt.Auto() {
				header += "（自动）"
			}

			latencies := rt.Latencies()
			autoLabel := "自动选择"
			if st.selected == "auto" {
				autoLabel = "✓ 自动选择"
			}
			nodeItems := []*mygo.MenuItem{{
				Label: autoLabel,
				Click: func(*mygo.MenuItem, *mygo.Window) {
					connect("auto")
				},
			}, mygo.Separator()}
			for _, n := range rt.Nodes() {
				name := n.Name
				label := name
				if ms, ok := latencies[name]; ok && ms >= 0 {
					label = fmt.Sprintf("%s (%d ms)", name, ms)
				}
				if (state.Connected && state.Node == name) || (!state.Connected && st.selected == name) {
					label = "✓ " + label
				}
				node := name
				nodeItems = append(nodeItems, &mygo.MenuItem{
					Label: label,
					Click: func(*mygo.MenuItem, *mygo.Window) {
						connect(node)
					},
				})
			}

			items := []*mygo.MenuItem{
				{Label: header, Disabled: true},
			}
			if rt.HasTOTP() {
				if code, rem, err := rt.TOTPCode(); err == nil {
					totpCode := code
					items = append(items, &mygo.MenuItem{
						Label: fmt.Sprintf("动态码: %s (%ds · 点击复制)", totpCode, rem),
						Click: func(*mygo.MenuItem, *mygo.Window) {
							mygo.Clipboard.WriteText(totpCode)
						},
					})
				}
			}
			items = append(items,
				mygo.Separator(),
				&mygo.MenuItem{Label: "连接", Disabled: state.Connected || st.connecting, Click: func(*mygo.MenuItem, *mygo.Window) {
					connect(st.selected)
				}},
				&mygo.MenuItem{Label: "断开", Disabled: !state.Connected, Click: func(*mygo.MenuItem, *mygo.Window) {
					disconnect()
				}},
				&mygo.MenuItem{Label: "立即测速", Click: func(*mygo.MenuItem, *mygo.Window) {
					pingAll()
				}},
				mygo.Separator(),
				&mygo.MenuItem{Label: "切换节点", Submenu: nodeItems},
				mygo.Separator(),
				&mygo.MenuItem{Label: "显示主窗口", Click: func(*mygo.MenuItem, *mygo.Window) {
					if win != nil {
						win.Show()
						win.Focus()
					}
				}},
				&mygo.MenuItem{Label: "打开网页面板", Click: func(*mygo.MenuItem, *mygo.Window) {
					_ = mygo.Shell.OpenExternal(panelURL)
				}},
				&mygo.MenuItem{Label: "复制代理地址", Click: func(*mygo.MenuItem, *mygo.Window) {
					mygo.Clipboard.WriteText(rt.ProxyAddr())
				}},
				&mygo.MenuItem{Label: "复制订阅地址", Click: func(*mygo.MenuItem, *mygo.Window) {
					mygo.Clipboard.WriteText(subURL)
				}},
				mygo.Separator(),
				&mygo.MenuItem{Label: "退出", Click: func(*mygo.MenuItem, *mygo.Window) {
					cancel()
					rt.Close(context.Background())
					mygo.App.Quit()
				}},
			)
			tray.SetMenu(mygo.NewMenu(items))
			tray.SetTitle(title)
		}
		refreshTrayFn = refreshTray
		refreshTray()

		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			tickCount := 0
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					tickCount++
					stats := rt.Stats()
					now := time.Now()
					updateUI(func() {
						if !stats.Connected {
							st.txRate = 0
							st.rxRate = 0
							st.lastSampleAt = time.Time{}
						} else {
							if !st.lastSampleAt.IsZero() {
								dt := now.Sub(st.lastSampleAt).Seconds()
								if dt > 0.4 {
									dTx := float64(stats.TxBytes-st.lastTx) / dt
									dRx := float64(stats.RxBytes-st.lastRx) / dt
									if dTx < 0 {
										dTx = 0
									}
									if dRx < 0 {
										dRx = 0
									}
									st.txRate = dTx
									st.rxRate = dRx
								}
							}
							st.lastTx = stats.TxBytes
							st.lastRx = stats.RxBytes
							st.lastSampleAt = now
						}
					})
					if tickCount%2 == 0 {
						refreshTray()
					}
				}
			}
		}()
	})

	if err := mygo.App.Run(); err != nil {
		log.Fatalf("运行窗口: %v", err)
	}
}

// applyDesktopSettings 校验并应用桌面端设置；服务端地址与签名器由库同步。
func applyDesktopSettings(ctx context.Context, rt *corplink.Client, cfg *config.Config, company, server, proxyAddr, panelAddr, intervalStr string) (string, []string, string) {
	interval := cfg.AutoModeIntervalSeconds
	if intervalStr != "" {
		v, err := strconv.Atoi(intervalStr)
		if err != nil || v < 0 {
			return "自动选路间隔必须是非负整数", nil, cfg.Server
		}
		interval = v
	}
	reqCtx, reqCancel := context.WithTimeout(ctx, 15*time.Second)
	defer reqCancel()
	restart, err := rt.UpdateSettings(reqCtx, corplink.Settings{
		CompanyName:             &company,
		Server:                  &server,
		ProxyListen:             &proxyAddr,
		PanelListen:             &panelAddr,
		AutoModeIntervalSeconds: &interval,
	})
	if err != nil {
		return err.Error(), nil, cfg.Server
	}
	return "", restartLabels(restart), rt.ServerURL()
}

// restartLabels 把库返回的字段名转成界面文案。
func restartLabels(fields []string) []string {
	if len(fields) == 0 {
		return nil
	}
	labels := make(map[string]string, len(fields))
	labels["proxy_listen"] = "代理监听"
	labels["panel_listen"] = "面板监听"
	labels["auto_mode_interval_seconds"] = "测速间隔"
	labels["keepalive_seconds"] = "保活间隔"
	labels["socks5_auth"] = "代理认证"
	labels["log_level"] = "日志级别"
	labels["device_model"] = "设备型号"
	labels["device_brand"] = "设备品牌"
	labels["os_version"] = "系统版本"
	labels["os_version_patch"] = "系统补丁"
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if label, ok := labels[f]; ok {
			out = append(out, label)
			continue
		}
		out = append(out, f)
	}
	return out
}

// loginStateText 生成可读登录状态文案。
func loginStateText(loggedIn, pending bool) string {
	if loggedIn && pending {
		return "等待二次验证"
	}
	if loggedIn {
		return "已登录"
	}
	return "未登录"
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

// pickBorder 返回选中行的边框色。
func pickBorder(p palette, picked bool) ui.Color {
	if picked {
		return p.OkBorder
	}
	return p.Border
}

// statTile 画一个指标卡片。
func statTile(c *ui.Context, p palette, label, value string) {
	ui.Column(c).Grow(1).Radius(radiusCard).Padding(padCard).Gap(4).
		Background(p.Card).Border(1, p.Border).Children(func() {
		ui.Text(c, label).FontSize(fsTiny).TextColor(p.Faint)
		ui.Text(c, value).FontSize(21).Bold().TextColor(p.Heading)
	})
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

// renderTrayIcon 生成 32x32 抗锯齿菜单栏徽章图标，按连接状态区分视觉。
func renderTrayIcon(connected bool) ([]byte, error) {
	const size = 32
	img := image.NewRGBA(image.Rect(0, 0, size, size))

	bg := color.RGBA{0x57, 0x60, 0x5c, 0xff}
	dotCol := color.RGBA{0xc8, 0xd0, 0xcc, 0xff}
	if connected {
		bg = color.RGBA{0x25, 0x63, 0xeb, 0xff}
		dotCol = color.RGBA{0x22, 0xc5, 0x5e, 0xff}
	}
	arcCol := color.RGBA{0xff, 0xff, 0xff, 0xf2}

	radius := float64(size) * 0.24
	const sub = 4
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			hits := 0
			for sy := 0; sy < sub; sy++ {
				for sx := 0; sx < sub; sx++ {
					px := float64(x) + (float64(sx)+0.5)/float64(sub)
					py := float64(y) + (float64(sy)+0.5)/float64(sub)
					if insideRoundedRect(px, py, size, radius) {
						hits++
					}
				}
			}
			if hits > 0 {
				a := uint8(float64(bg.A) * float64(hits) / float64(sub*sub))
				img.SetRGBA(x, y, color.RGBA{bg.R, bg.G, bg.B, a})
			}
		}
	}

	// 白色弧线通路：与 icon.svg 一致的从左下向右上延伸曲线。
	for i := 0; i <= 180; i++ {
		t := float64(i) / 180.0
		cx := (0.24 + 0.52*t) * float64(size)
		cy := (0.68 - 0.30*math.Sin(math.Pi*t*0.85)) * float64(size)
		blendDisc(img, cx, cy, float64(size)*0.068, arcCol)
	}
	// 右上角状态圆点。
	blendDisc(img, float64(size)*0.72, float64(size)*0.29, float64(size)*0.115, dotCol)

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// insideRoundedRect 判断采样点是否落在圆角矩形内部。
func insideRoundedRect(x, y, size, r float64) bool {
	if x < r && y < r {
		return math.Hypot(r-x, r-y) <= r
	}
	if x > size-r && y < r {
		return math.Hypot(x-(size-r), r-y) <= r
	}
	if x < r && y > size-r {
		return math.Hypot(r-x, y-(size-r)) <= r
	}
	if x > size-r && y > size-r {
		return math.Hypot(x-(size-r), y-(size-r)) <= r
	}
	return x >= 0 && x <= size && y >= 0 && y <= size
}

// blendDisc 使用边缘线性抗锯齿混合绘制实心圆点。
func blendDisc(img *image.RGBA, cx, cy, r float64, c color.RGBA) {
	minX := int(math.Floor(cx - r - 1))
	maxX := int(math.Ceil(cx + r + 1))
	minY := int(math.Floor(cy - r - 1))
	maxY := int(math.Ceil(cy + r + 1))
	b := img.Bounds()
	for y := minY; y <= maxY; y++ {
		for x := minX; x <= maxX; x++ {
			if x < 0 || y < 0 || x >= b.Dx() || y >= b.Dy() {
				continue
			}
			dist := math.Hypot(float64(x)+0.5-cx, float64(y)+0.5-cy)
			cov := math.Max(0, math.Min(1, r+0.5-dist))
			if cov <= 0 {
				continue
			}
			dst := img.RGBAAt(x, y)
			alpha := (float64(c.A) / 255.0) * cov
			outR := uint8(float64(c.R)*alpha + float64(dst.R)*(1-alpha))
			outG := uint8(float64(c.G)*alpha + float64(dst.G)*(1-alpha))
			outB := uint8(float64(c.B)*alpha + float64(dst.B)*(1-alpha))
			outA := dst.A
			if uint8(alpha*255) > outA {
				outA = uint8(math.Min(255, float64(dst.A)+alpha*255))
			}
			img.SetRGBA(x, y, color.RGBA{outR, outG, outB, outA})
		}
	}
}
