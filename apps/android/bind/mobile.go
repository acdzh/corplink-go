// Package mobile 是 Android 端的 gomobile 门面。
//
// 它只做三件事：持有唯一的 corplink.Client、把调用翻译成 JSON 字符串、
// 把 VpnService 的 fd 交给库。所有业务逻辑都在 corplink 库里，这里不放规则。
//
// 构建（需要 Android SDK + NDK）：
//
//	gomobile bind -target=android -androidapi 24 -o apps/android/app/libs/corplink.aar ./apps/android/bind
package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/acdzh/corplink-go/corplink"
)

// 进程内唯一的客户端与待接入的隧道参数。
var (
	mu sync.Mutex
	// client 是当前运行的库实例，未启动时为 nil。
	client *corplink.Client
	// cancel 停止库的后台循环。
	cancel context.CancelFunc
	// pending 是 Prepare 得到、等 VpnService 建好网卡后再接入的隧道参数。
	pending *corplink.Plan
)

// Start 按配置文件路径启动库：不建隧道、不监听代理，只跑控制面与后台循环。
func Start(configPath string) error {
	mu.Lock()
	defer mu.Unlock()
	if client != nil {
		return nil
	}
	ctx, stop := context.WithCancel(context.Background())
	c, err := corplink.New(ctx, corplink.Options{
		ConfigPath: configPath,
		Logger:     slog.New(slog.NewTextHandler(os.Stderr, nil)),
		// 不传 ProxyListen：Android 由系统路由接管，库里不开任何端口。
	})
	if err != nil {
		stop()
		return err
	}
	if err := c.Start(ctx); err != nil {
		stop()
		return err
	}
	client, cancel = c, stop
	return nil
}

// Stop 断开隧道并停止库。
func Stop() {
	mu.Lock()
	c, stop := client, cancel
	client, cancel, pending = nil, nil, nil
	mu.Unlock()
	if c == nil {
		return
	}
	if stop != nil {
		stop()
	}
	_ = c.Close(context.Background())
}

// Running 表示库是否已启动。
func Running() bool {
	mu.Lock()
	defer mu.Unlock()
	return client != nil
}

// Status 返回状态快照 JSON。
func Status() string { return encode(currentState(func(c *corplink.Client) any { return c.Status() })) }

// Stats 返回流量与握手状态 JSON。
func Stats() string { return encode(currentState(func(c *corplink.Client) any { return c.Stats() })) }

// Nodes 返回节点列表 JSON。
func Nodes() string { return encode(currentState(func(c *corplink.Client) any { return c.Nodes() })) }

// Events 返回运行事件 JSON。
func Events() string { return encode(currentState(func(c *corplink.Client) any { return c.Events() })) }

// Latencies 返回测速结果 JSON。
func Latencies() string {
	return encode(currentState(func(c *corplink.Client) any { return c.Latencies() }))
}

// Settings 返回可编辑配置 JSON。
func Settings() string {
	return encode(currentState(func(c *corplink.Client) any { return c.Settings() }))
}

// TOTP 返回动态码 JSON。
func TOTP() string {
	c := get()
	if c == nil {
		return encode(nil)
	}
	code, err := c.TOTP()
	if err != nil {
		return encode(map[string]string{"error": err.Error()})
	}
	return encode(code)
}

// Routes 返回分流网段 JSON。
func Routes() string { return encode(currentState(func(c *corplink.Client) any { return c.Routes() })) }

// ClashProfile 返回 Clash 订阅内容。
func ClashProfile() string {
	c := get()
	if c == nil {
		return ""
	}
	return c.ClashProfile()
}

// Connect 连接节点并直接用库内网卡建隧道（不经过 VpnService）。
func Connect(name string) error {
	c := get()
	if c == nil {
		return errNotStarted
	}
	return c.Connect(context.Background(), name)
}

// Disconnect 断开当前隧道。
func Disconnect() error {
	c := get()
	if c == nil {
		return errNotStarted
	}
	c.Disconnect()
	return nil
}

// RefreshNodes 重新拉取节点列表。
func RefreshNodes() error {
	c := get()
	if c == nil {
		return errNotStarted
	}
	return c.RefreshNodes(context.Background())
}

// PingAll 全量测速，返回 JSON。
func PingAll() string {
	c := get()
	if c == nil {
		return encode(nil)
	}
	return encode(c.PingAll(context.Background()))
}

// LoginMethods 返回可用登录方式 JSON。
func LoginMethods() (string, error) {
	c := get()
	if c == nil {
		return "", errNotStarted
	}
	methods, err := c.LoginMethods(context.Background())
	if err != nil {
		return "", err
	}
	return encode(methods), nil
}

// LoginStart 生成授权链接，返回 JSON。
func LoginStart(alias string) (string, error) {
	c := get()
	if c == nil {
		return "", errNotStarted
	}
	info, err := c.LoginStart(context.Background(), alias)
	if err != nil {
		return "", err
	}
	return encode(info), nil
}

// LoginCallback 提交授权回调，返回 JSON。
func LoginCallback(callback string) (string, error) {
	c := get()
	if c == nil {
		return "", errNotStarted
	}
	result, err := c.LoginCallback(context.Background(), callback)
	if err != nil {
		return "", err
	}
	return encode(result), nil
}

// LoginSendMFA 请求下发二次验证码。
func LoginSendMFA(mfaType string) error {
	c := get()
	if c == nil {
		return errNotStarted
	}
	return c.LoginSendMFA(context.Background(), mfaType)
}

// LoginMFA 提交二次验证码，返回 JSON。
func LoginMFA(code string) (string, error) {
	c := get()
	if c == nil {
		return "", errNotStarted
	}
	result, err := c.LoginMFA(context.Background(), code)
	if err != nil {
		return "", err
	}
	return encode(result), nil
}

// LoginLogout 清除会话。
func LoginLogout() error {
	c := get()
	if c == nil {
		return errNotStarted
	}
	return c.LoginLogout()
}

// UpdateSettings 应用配置并返回仍需重启的字段 JSON。
func UpdateSettings(payload string) (string, error) {
	c := get()
	if c == nil {
		return "", errNotStarted
	}
	var in corplink.Settings
	if err := json.Unmarshal([]byte(payload), &in); err != nil {
		return "", fmt.Errorf("解析设置: %w", err)
	}
	restart, err := c.UpdateSettings(context.Background(), in)
	if err != nil {
		return "", err
	}
	return encode(restart), nil
}

// planJSON 是 VpnService 建网卡需要的参数。
type planJSON struct {
	// Node 是节点展示名。
	Node string `json:"node"`
	// Addresses 是本端隧道地址（不带掩码）。
	Addresses []string `json:"addresses"`
	// Routes 是需要走隧道的网段。
	Routes []string `json:"routes"`
	// DNS 是隧道内 DNS。
	DNS []string `json:"dns"`
	// MTU 是隧道 MTU。
	MTU int `json:"mtu"`
}

// Plan 向节点申请隧道参数并缓存，返回 JSON；Kotlin 据此调用 VpnService.Builder。
func Plan(node string) (string, error) {
	c := get()
	if c == nil {
		return "", errNotStarted
	}
	p, err := c.Prepare(context.Background(), node)
	if err != nil {
		return "", err
	}
	mu.Lock()
	pending = p
	mu.Unlock()
	out := planJSON{
		Node:      p.Node(),
		Addresses: p.Addresses(),
		Routes:    p.Routes(),
		DNS:       p.DNS(),
		MTU:       p.MTU(),
	}
	return encode(out), nil
}

// Establish 用 VpnService 的 fd 建网卡并接入 Plan 缓存的隧道参数。
func Establish(fd int) error {
	c := get()
	if c == nil {
		return errNotStarted
	}
	mu.Lock()
	p := pending
	mu.Unlock()
	if p == nil {
		return fmt.Errorf("缺少隧道参数，请先调用 Plan")
	}
	return c.Establish(context.Background(), p, fd)
}

// errNotStarted 表示库尚未启动。
var errNotStarted = fmt.Errorf("库尚未启动，请先调用 Start")

// get 返回当前客户端。
func get() *corplink.Client {
	mu.Lock()
	defer mu.Unlock()
	return client
}

// currentState 在持有锁的情况下取客户端并执行读取，未启动时返回 nil。
func currentState(fn func(c *corplink.Client) any) any {
	c := get()
	if c == nil {
		return nil
	}
	return fn(c)
}

// encode 把任意值序列化成 JSON；失败时返回带错误信息的 JSON 字符串。
func encode(v any) string {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error())
	}
	return string(payload)
}
