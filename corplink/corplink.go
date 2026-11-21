// Package corplink 是客户端库的入口：在进程内装配登录、隧道、代理与事件。
//
// 这里只提供原生 API，不含任何 HTTP 监听或界面代码：端侧（CLI / 桌面 / Android）
// 通过 Client 驱动全部能力，控制面板的 HTTP 契约在 httpapi 包里单独实现。
// 三种形态共用同一个数据面，行为不会漂移。
package corplink

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/acdzh/corplink-go/corplink/agent"
	"github.com/acdzh/corplink-go/corplink/api"
	"github.com/acdzh/corplink-go/corplink/config"
	"github.com/acdzh/corplink-go/corplink/login"
	"github.com/acdzh/corplink-go/corplink/proxy"
	"github.com/acdzh/corplink-go/corplink/sign"
	"github.com/acdzh/corplink-go/corplink/sub"
	"github.com/acdzh/corplink-go/corplink/totp"
	"github.com/acdzh/corplink-go/corplink/tunnel"
)

// 启动参数。
const (
	// defaultProxyListen 是默认代理监听地址。
	defaultProxyListen = "127.0.0.1:3710"
	// defaultKeepalive 是默认会话保活间隔。
	defaultKeepalive = 30 * time.Minute
	// startupTimeout 是启动阶段请求超时。
	startupTimeout = 30 * time.Second
	// watchdogInterval 是隧道健康检查间隔。
	watchdogInterval = 30 * time.Second
)

// 类型别名：端侧直接使用库里的状态结构，不重复定义一份。
type (
	// State 是当前活动连接的状态快照。
	State = agent.State
	// Stats 是隧道流量与握手状态。
	Stats = agent.Stats
	// Event 是一条运行事件。
	Event = agent.Event
	// Plan 是一次待建立的隧道参数。
	Plan = agent.Plan
)

// 分流模式：全局把全量路由送进隧道，分流只走内网网段。
const (
	// RouteFull 是全局模式。
	RouteFull = agent.RouteFull
	// RouteSplit 是分流模式。
	RouteSplit = agent.RouteSplit
)

// RouteMode 是隧道分流模式。
type RouteMode = agent.RouteMode

// TUNProvider 提供隧道使用的网卡；为空时使用内置 netstack 用户态网卡。
type TUNProvider interface {
	// TUN 按隧道参数返回网卡，返回的网卡交给 wireguard-go 托管。
	TUN(cfg tunnel.Config) (tun.Device, error)
}

// Options 是构造 Client 的参数，零值字段回落到配置或默认值。
type Options struct {
	// ConfigPath 是配置文件路径；为空时用用户配置目录下的默认路径。
	ConfigPath string
	// Config 是已加载的配置，非空时优先使用，端侧可以共享同一份实例读取展示字段。
	Config *config.Config
	// Logger 接收运行日志；为空时丢弃。
	Logger *slog.Logger
	// TUN 覆盖隧道网卡实现（Android 传 VpnService 的 fd）。
	TUN TUNProvider
	// TUNFD 大于 0 时按文件描述符建网卡，等价于传一个只会返回该 fd 的 TUNProvider。
	TUNFD int
	// ProxyListen 是混合代理监听地址；与配置都为空时不启动代理。
	ProxyListen string
	// AutoNode 是启动后自动连接的节点名，留空则不自动连接。
	AutoNode string
	// Keepalive 覆盖配置里的保活间隔。
	Keepalive time.Duration
	// Verbose 打开请求级日志。
	Verbose bool
}

// Client 是一个装配好的客户端：登录、隧道、代理共用同一份配置与会话。
type Client struct {
	cfg   *config.Config
	api   *api.Client
	agent *agent.Agent
	login *login.Service
	log   *slog.Logger
	opts  Options

	// proxyAddr 是实际代理监听地址，未启动代理时为空。
	proxyAddr string
	// proxyLn 是代理监听器，Close 时关闭。
	proxyLn net.Listener
	// cancel 停止后台循环。
	cancel context.CancelFunc
	// runCtx 是 Start 建立的后台循环上下文，代理日志用它判断是否已停止。
	runCtx context.Context
}

// New 加载配置、恢复会话并装配客户端。
//
// 构造阶段不联网、不监听、不建隧道：企业代码解析与所有后台循环都在 Start 里。
func New(ctx context.Context, opts Options) (*Client, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	cfg := opts.Config
	if cfg == nil {
		path := opts.ConfigPath
		if path == "" {
			p, err := config.DefaultPath()
			if err != nil {
				return nil, fmt.Errorf("定位配置路径: %w", err)
			}
			path = p
		}
		loaded, err := config.Load(path)
		if err != nil {
			return nil, err
		}
		cfg = loaded
	}
	if created, err := cfg.EnsureDeviceID(); err != nil {
		logger.Warn("生成 device_id 失败", "err", err)
	} else if created {
		logger.Info("已生成新的 device_id", "device_id", cfg.DeviceID)
	}

	apiClient, err := api.New(api.Options{
		Server:   cfg.Server,
		DeviceID: cfg.DeviceID,
		Language: cfg.Language,
		Verbose:  opts.Verbose,
		Meta:     config.Meta(cfg),
	})
	if err != nil {
		return nil, err
	}
	apiClient.SetSigner(sign.NewSigner(activateOf(cfg), cfg.DeviceID))
	if err := loadSession(apiClient, cfg); err != nil {
		// 未登录不阻塞启动：端侧可以完成登录。
		logger.Info("未加载会话", "reason", err)
	}

	provider := opts.TUN
	if provider == nil && opts.TUNFD > 0 {
		provider = fdProvider{fd: opts.TUNFD}
	}
	ag := agent.New(ctx, cfg, apiClient, agent.Options{
		TUN:          provider,
		Logger:       logger,
		DeviceLogger: newDeviceLogger(logger, opts.Verbose),
	})

	return &Client{
		cfg:   cfg,
		api:   apiClient,
		agent: ag,
		login: login.New(apiClient, cfg, ag),
		log:   logger,
		opts:  opts,
	}, nil
}

// Start 解析企业服务端、启动后台循环（测速、自动选路、保活、看门狗）与代理监听。
func (c *Client) Start(ctx context.Context) error {
	if err := c.resolveServer(ctx); err != nil {
		c.log.Warn("解析企业服务端失败", "err", err)
		c.agent.LogEvent("warn", "解析企业服务端失败: %v", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.runCtx = runCtx

	// 拉取一次节点列表：失败（未登录、会话过期）只记事件，不阻塞后续。
	if err := c.agent.RefreshNodes(runCtx); err != nil {
		c.log.Info("拉取节点列表失败", "err", err)
	}

	latencyInterval := time.Duration(c.cfg.AutoModeIntervalSeconds) * time.Second
	c.agent.PollLatency(runCtx, latencyInterval)
	// 只有显式指定节点时才在启动时连接：
	// 多出口场景（比如一条隧道走 CN、一条走海外）需要第二个实例自动连线。
	// 配置里的 mode 不触发连接，避免一开机就把代理建起来。
	if c.opts.AutoNode != "" {
		if err := c.agent.Connect(runCtx, c.opts.AutoNode); err != nil {
			c.log.Warn("自动连接节点失败", "node", c.opts.AutoNode, "err", err)
		}
	}
	if c.cfg.Mode == "auto" {
		c.agent.SetAuto(true)
	}
	go c.agent.AutoSelect(runCtx, latencyInterval)

	keepalive := c.opts.Keepalive
	if keepalive == 0 {
		if c.cfg.KeepaliveSeconds > 0 {
			keepalive = time.Duration(c.cfg.KeepaliveSeconds) * time.Second
		} else {
			keepalive = defaultKeepalive
		}
	}
	if keepalive > 0 {
		go c.agent.Keepalive(runCtx, keepalive)
	}
	go c.agent.Watchdog(runCtx, watchdogInterval)

	// 代理是可选能力：没有显式地址（选项或配置）就不开端口。
	proxyListen := firstNonEmpty(c.opts.ProxyListen, c.cfg.SocksListen)
	if proxyListen == "" {
		return nil
	}
	if err := c.StartProxy(proxyListen); err != nil {
		cancel()
		return err
	}
	return nil
}

// StartProxy 在 addr 上启动混合代理；已在运行时先关掉旧的。
func (c *Client) StartProxy(addr string) error {
	if addr == "" {
		return fmt.Errorf("缺少代理监听地址")
	}
	c.StopProxy()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("监听代理端口 %s: %w", addr, err)
	}
	c.proxyLn = ln
	c.proxyAddr = ln.Addr().String()
	runCtx := c.runCtx
	go func() {
		if err := proxy.New(c.agent).Serve(ln); err != nil && (runCtx == nil || runCtx.Err() == nil) {
			c.log.Warn("代理服务退出", "err", err)
		}
	}()
	return nil
}

// StopProxy 关闭混合代理。
func (c *Client) StopProxy() {
	if c.proxyLn != nil {
		_ = c.proxyLn.Close()
		c.proxyLn = nil
	}
	c.proxyAddr = ""
}

// Close 断开隧道并停止后台循环与代理监听。
func (c *Client) Close(_ context.Context) error {
	if c == nil {
		return nil
	}
	c.agent.Disconnect()
	c.StopProxy()
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

// ProxyAddr 返回实际代理监听地址；未启动代理时为空。
func (c *Client) ProxyAddr() string { return c.proxyAddr }

// ServerURL 返回当前企业服务端地址。
func (c *Client) ServerURL() string { return c.cfg.Server }

// ConfigPath 返回配置文件的落盘路径。
func (c *Client) ConfigPath() string { return c.cfg.Path() }

// Status 是端侧展示用的一次性状态快照。
type Status struct {
	// State 是活动连接状态。
	State State `json:"state"`
	// LoggedIn 表示会话是否有效。
	LoggedIn bool `json:"logged_in"`
	// Error 是最近一次失败原因。
	Error string `json:"error"`
	// MFAPending 表示登录流程正在等待二次验证码。
	MFAPending bool `json:"mfa_pending"`
	// Mode 是连接模式，auto 表示自动选路。
	Mode string `json:"mode"`
	// Auto 表示自动选路是否开启。
	Auto bool `json:"auto"`
	// CompanyName 是企业标识。
	CompanyName string `json:"company_name"`
	// Server 是企业服务端地址。
	Server string `json:"server"`
	// ProxyAddr 是混合代理监听地址。
	ProxyAddr string `json:"proxy_addr"`
	// HasTOTP 表示本地是否保存了 TOTP secret。
	HasTOTP bool `json:"has_totp"`
}

// Status 汇总当前状态。
func (c *Client) Status() Status {
	return Status{
		State:       c.agent.State(),
		LoggedIn:    c.agent.LoggedIn(),
		Error:       c.agent.LastError(),
		MFAPending:  c.login.Pending(),
		Mode:        c.agent.Mode(),
		Auto:        c.agent.Auto(),
		CompanyName: c.cfg.CompanyName,
		Server:      c.cfg.Server,
		ProxyAddr:   c.proxyAddr,
		HasTOTP:     c.cfg.Code != "",
	}
}

// Node 是节点列表的对外视图。
type Node struct {
	// Name 是展示名，按英文名、原名、IP 依次回落。
	Name string `json:"name"`
	// RawName 是服务端下发的原名。
	RawName string `json:"raw_name"`
	// IP 是节点公网地址。
	IP string `json:"ip"`
	// InternalIP 是节点内网地址。
	InternalIP string `json:"internal_ip"`
	// DomainName 是节点域名。
	DomainName string `json:"domain_name"`
	// Tag 是节点标签，用于筛选。
	Tag string `json:"tag"`
	// Type 是节点类型。
	Type string `json:"type"`
	// Icon 是节点图标地址，由库代取，不暴露会话。
	Icon string `json:"icon"`
	// ProtocolMode 是传输协议，1 为 TCP，其余为 UDP。
	ProtocolMode int `json:"protocol_mode"`
	// APIPort 是节点控制面端口。
	APIPort int `json:"api_port"`
	// VPNPort 是节点 WireGuard 端口。
	VPNPort int `json:"vpn_port"`
	// BackupIPs 是节点的备用地址，用于订阅里的直连规则。
	BackupIPs []string `json:"backup_ips,omitempty"`
}

// Nodes 返回当前节点列表的对外视图。
func (c *Client) Nodes() []Node {
	raw := c.agent.Nodes()
	out := make([]Node, 0, len(raw))
	for _, n := range raw {
		out = append(out, Node{
			Name:         displayName(n.EnName, n.Name, n.IP),
			RawName:      n.Name,
			IP:           n.IP,
			InternalIP:   n.InternalIP,
			DomainName:   n.DomainName,
			Tag:          n.TagName,
			Type:         n.Type,
			Icon:         n.Icon,
			ProtocolMode: n.ProtocolMode,
			APIPort:      n.APIPort,
			VPNPort:      n.VPNPort,
			BackupIPs:    n.BackupIPs,
		})
	}
	return out
}

// State 返回活动连接状态。
func (c *Client) State() State { return c.agent.State() }

// Stats 返回隧道流量与握手状态。
func (c *Client) Stats() Stats { return c.agent.Stats() }

// LoggedIn 表示当前是否持有有效会话。
func (c *Client) LoggedIn() bool { return c.agent.LoggedIn() }

// LastError 返回最近一次失败原因。
func (c *Client) LastError() string { return c.agent.LastError() }

// Mode 返回连接模式。
func (c *Client) Mode() string { return c.agent.Mode() }

// Auto 返回自动选路是否开启。
func (c *Client) Auto() bool { return c.agent.Auto() }

// SetAuto 开关自动选路。
func (c *Client) SetAuto(v bool) { c.agent.SetAuto(v) }

// Routes 返回隧道分流网段。
func (c *Client) Routes() []string { return c.agent.Routes() }

// Domains 返回服务端下发的分流域名。
func (c *Client) Domains() []string { return c.agent.Domains() }

// Latencies 返回最近一次测速结果。
func (c *Client) Latencies() map[string]int64 { return c.agent.Latencies() }

// RefreshNodes 重新拉取节点列表。
func (c *Client) RefreshNodes(ctx context.Context) error { return c.agent.RefreshNodes(ctx) }

// Connect 连接指定节点；成功后把节点名写回配置，重启后沿用。
func (c *Client) Connect(ctx context.Context, name string) error {
	if err := c.agent.Connect(ctx, name); err != nil {
		return err
	}
	c.cfg.Mode = name
	if err := c.cfg.Save(); err != nil {
		c.log.Warn("保存连接模式失败", "err", err)
	}
	return nil
}

// Disconnect 断开当前隧道。
func (c *Client) Disconnect() { c.agent.Disconnect() }

// Prepare 返回指定节点的隧道参数（地址、路由、DNS、MTU），不建立隧道。
//
// Android 先按它创建系统网卡，再把网卡描述符交给 Establish；
// mode 传 RouteSplit 只把内网网段送进隧道，传 RouteFull 走全量路由。
func (c *Client) Prepare(ctx context.Context, name string, mode RouteMode) (*Plan, error) {
	return c.agent.Prepare(ctx, name, mode)
}

// Establish 用文件描述符创建网卡并接入 plan 描述的隧道。
func (c *Client) Establish(ctx context.Context, plan *Plan, fd int) error {
	dev, err := tunFromFD(fd)
	if err != nil {
		return err
	}
	return c.agent.Establish(ctx, plan, dev)
}

// Ping 测单个节点的延迟。
func (c *Client) Ping(ctx context.Context, name string) (int64, error) {
	return c.agent.Ping(ctx, name)
}

// PingAll 全量测速。
func (c *Client) PingAll(ctx context.Context) map[string]int64 { return c.agent.PingAll(ctx) }

// Events 返回运行事件。
func (c *Client) Events() []Event { return c.agent.Events() }

// ClearEvents 清空运行事件。
func (c *Client) ClearEvents() { c.agent.ClearEvents() }

// LogEvent 追加一条运行事件。
func (c *Client) LogEvent(level, format string, args ...any) {
	c.agent.LogEvent(level, format, args...)
}

// LoginMethods 查询当前企业支持的第三方登录方式。
func (c *Client) LoginMethods(ctx context.Context) ([]api.ThirdPartyLogin, error) {
	return c.login.Methods(ctx)
}

// LoginStart 生成 PKCE 并返回授权链接、选中的登录方式与可用方式列表。
func (c *Client) LoginStart(ctx context.Context, alias string) (map[string]any, error) {
	return c.login.StartWithInfo(ctx, alias)
}

// LoginCallback 提交授权回调；需要二次验证时返回 mfa_required。
func (c *Client) LoginCallback(ctx context.Context, callback string) (map[string]any, error) {
	return c.login.Callback(ctx, callback)
}

// LoginSendMFA 请求下发二次验证码。
func (c *Client) LoginSendMFA(ctx context.Context, mfaType string) error {
	return c.login.SendMFA(ctx, strings.TrimSpace(mfaType))
}

// LoginMFA 提交二次验证码；留空且已绑定 TOTP 时自动生成。
func (c *Client) LoginMFA(ctx context.Context, code string) (map[string]any, error) {
	code = strings.TrimSpace(code)
	if code == "" && c.cfg.Code != "" {
		generated, _, err := totp.Code(c.cfg.Code, time.Now())
		if err != nil {
			return nil, fmt.Errorf("生成 TOTP: %w", err)
		}
		code = generated
	}
	return c.login.MFA(ctx, code)
}

// LoginPending 表示登录流程是否在等待二次验证码。
func (c *Client) LoginPending() bool { return c.login.Pending() }

// LoginLogout 清除会话并断开隧道。
func (c *Client) LoginLogout() error { return c.login.Logout() }

// TOTPCode 是当前动态码与剩余秒数。
type TOTPCode struct {
	// Bound 表示本地是否保存了 TOTP secret。
	Bound bool `json:"has_secret"`
	// Code 是动态码，未绑定时为空。
	Code string `json:"code,omitempty"`
	// Remaining 是本轮剩余秒数。
	Remaining int `json:"remaining,omitempty"`
}

// HasTOTP 表示本地是否保存了 TOTP secret。
func (c *Client) HasTOTP() bool { return c.cfg.Code != "" }

// TOTPCode 返回当前动态码与剩余秒数；未绑定 secret 时返回错误。
func (c *Client) TOTPCode() (string, int, error) {
	t, err := c.TOTP()
	if err != nil {
		return "", 0, err
	}
	if !t.Bound {
		return "", 0, fmt.Errorf("未绑定 TOTP 密钥")
	}
	return t.Code, t.Remaining, nil
}

// TOTP 生成当前动态码。
func (c *Client) TOTP() (TOTPCode, error) {
	if c.cfg.Code == "" {
		return TOTPCode{}, nil
	}
	code, remaining, err := totp.Code(c.cfg.Code, time.Now())
	if err != nil {
		return TOTPCode{}, err
	}
	return TOTPCode{Bound: true, Code: code, Remaining: remaining}, nil
}

// FetchIcon 用当前会话代取节点图标，避免把 Cookie 交给前端。
func (c *Client) FetchIcon(ctx context.Context, target string) ([]byte, string, error) {
	if target == "" {
		return nil, "", fmt.Errorf("缺少图标地址")
	}
	return c.api.GetRaw(ctx, target)
}

// ClashProfile 生成 Clash 订阅内容：防回环直连规则 + 服务端下发的分流规则。
func (c *Client) ClashProfile() string {
	var directDomains []string
	if u, err := url.Parse(c.cfg.Server); err == nil && u.Hostname() != "" {
		directDomains = append(directDomains, u.Hostname())
	}
	var nodeIPs []string
	for _, n := range c.agent.Nodes() {
		nodeIPs = append(nodeIPs, n.IP)
		nodeIPs = append(nodeIPs, n.BackupIPs...)
	}
	host, port := c.proxyHostPort()
	return sub.Clash(sub.Options{
		DirectDomains: directDomains,
		NodeIPs:       nodeIPs,
		Host:          host,
		Port:          port,
		Routes:        c.agent.Routes(),
		Domains:       c.agent.Domains(),
	})
}

// proxyHostPort 返回订阅里要写的代理地址。
func (c *Client) proxyHostPort() (string, int) {
	addr := firstNonEmpty(c.proxyAddr, c.cfg.SocksListen, defaultProxyListen)
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return "127.0.0.1", 3710
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return host, 3710
	}
	return host, port
}

// newDeviceLogger 把 slog 适配成 wireguard 的内部日志接口。
//
// wireguard-go 自带的 NewLogger 直接写标准输出，这里改走调用方的 logger；
// 未开启 Verbose 时只保留错误，Verbose 时把调试日志降级到 Debug。
func newDeviceLogger(logger *slog.Logger, verbose bool) *device.Logger {
	if !verbose {
		return &device.Logger{
			Verbosef: device.DiscardLogf,
			Errorf: func(format string, args ...any) {
				logger.Error(fmt.Sprintf(format, args...))
			},
		}
	}
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			logger.Debug(fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			logger.Error(fmt.Sprintf(format, args...))
		},
	}
}

// fdProvider 用外部交来的文件描述符建网卡。
type fdProvider struct {
	// fd 是已就绪的 TUN 文件描述符。
	fd int
}

// TUN 用文件描述符建网卡。
func (p fdProvider) TUN(tunnel.Config) (tun.Device, error) {
	return tunFromFD(p.fd)
}

// activateOf 返回签名用的租户标识。
func activateOf(cfg *config.Config) string {
	if cfg.ActivateCode != "" {
		return cfg.ActivateCode
	}
	return cfg.CompanyName
}

// resolveServer 在缺少服务端地址时按企业代码解析，内存模式下也不会落盘。
func (c *Client) resolveServer(ctx context.Context) error {
	if c.cfg.Server != "" || c.cfg.CompanyName == "" {
		return nil
	}
	reqCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	info, err := api.MatchCompany(reqCtx, c.cfg.CompanyName)
	if err != nil {
		return fmt.Errorf("解析企业代码 %q: %w", c.cfg.CompanyName, err)
	}
	c.cfg.Server = info.Domain
	if err := c.api.SetServer(info.Domain); err != nil {
		return err
	}
	if err := c.cfg.Save(); err != nil {
		c.log.Warn("保存企业服务端配置失败", "err", err)
	}
	return nil
}

// loadSession 读取会话文件；内存模式与文件缺失都直接跳过。
func loadSession(client *api.Client, cfg *config.Config) error {
	path := cfg.SessionPath()
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("会话文件 %s 不存在（请先登录）", path)
	}
	return client.LoadCookies(path)
}

// displayName 返回节点展示名，按英文名、原名、IP 依次回落。
func displayName(enName, name, ip string) string {
	if enName != "" {
		return enName
	}
	if name != "" {
		return name
	}
	return ip
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
