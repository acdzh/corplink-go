// Package config 管理 corplink-go 的本地配置。
//
// 配置文件同时是持久化状态：device_id、WireGuard 密钥、activate_code、
// 上次选中的节点都写回同一份 JSON，避免多份状态失配。
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/acdzh/corplink-go/internal/api"
)

// Platform 表示飞连的登录方式。当前只实现 TPS（飞书/SSO 扫码）与密码。
type Platform string

const (
	// PlatformLark 走飞书第三方授权（PKCE）。
	PlatformLark Platform = "lark"
	// PlatformOIDC 走企业 SSO（OIDC 授权码 + PKCE）。
	PlatformOIDC Platform = "OIDC"
	// PlatformFeilian 走飞连账号密码。
	PlatformFeilian Platform = "feilian"
)

// Config 是磁盘上的配置与状态。
type Config struct {
	path string

	// CompanyName 是企业标识（飞连"公司代码"），用于解析服务端域名。
	CompanyName string `json:"company_name"`
	// Username 是登录账号。TPS 登录下仅用于日志与设备命名。
	Username string `json:"username"`
	// Password 仅密码登录使用。
	Password string `json:"password,omitempty"`

	// Server 是解析出来的企业服务端地址，首次运行后写回。
	Server string `json:"server,omitempty"`

	// DeviceID 是设备指纹，服务端用它做风控与设备绑定。必须稳定。
	DeviceID string `json:"device_id"`
	// DeviceName 是上报的设备名。
	DeviceName string `json:"device_name"`
	// DeviceModel 参与 User-Agent 构造，形如 XiaomiM2007J17C。
	DeviceModel string `json:"device_model"`
	// DeviceBrand 参与 User-Agent 构造，形如 Xiaomi。
	DeviceBrand string `json:"device_brand"`
	// OSVersion 是系统 API level，服务端按整数校验，shape 如 32。
	OSVersion string `json:"os_version"`
	// OSPatch 是系统安全补丁日期，服务端按 yyyy-mm-dd 校验。
	OSPatch string `json:"os_version_patch"`
	// AppVersion 上报的客户端版本号，需与租户允许的版本一致。
	AppVersion string `json:"app_version"`
	// BuildNumber 上报的客户端构建号。
	BuildNumber string `json:"build_number"`
	// Language 参与 User-Agent 与 Accept-Language 构造。
	Language string `json:"language"`

	// ActivateCode 是设备激活产物，用于派生请求签名密钥。
	ActivateCode string `json:"activate_code,omitempty"`
	// Code 是 TOTP secret（base32），登录后由服务端下发。
	Code string `json:"code,omitempty"`

	// ExtraSubscription 是可选机场订阅，用于把日本节点并入 Clash 配置。
	ExtraSubscription string `json:"extra_subscription,omitempty"`

	// Mode 是连接模式：auto 表示自动选最快节点，其它值为固定节点名。
	Mode string `json:"mode,omitempty"`
	// AutoModeIntervalSeconds 是自动选路的测速间隔（秒），0 表示默认 300。
	AutoModeIntervalSeconds int `json:"auto_mode_interval_seconds,omitempty"`
	// AutoNode 是启动时自动连接的节点名，留空则不自动连接。
	AutoNode string `json:"auto_node,omitempty"`
	// KeepaliveSeconds 是会话保活间隔（秒），0 表示使用默认 1800。
	KeepaliveSeconds int `json:"keepalive_seconds,omitempty"`
	// PanelListen 是控制面板监听地址。
	PanelListen string `json:"panel_listen,omitempty"`
	// SubListen 保留旧字段，等价于 panel_listen。
	SubListen string `json:"sub_listen,omitempty"`
	// HealthURL 是隧道内用于探测连通性的地址。
	HealthURL string `json:"health_url,omitempty"`
	// PreferNode 是优先节点名，留空按延迟自动选。
	PreferNode string `json:"prefer_node,omitempty"`
	// SocksListen 是用户态代理监听地址。
	SocksListen string `json:"socks5_listen,omitempty"`
	// SocksUser 与 SocksPass 非空时给 SOCKS5 启用 RFC1929 认证。
	SocksUser string `json:"socks5_username,omitempty"`
	SocksPass string `json:"socks5_password,omitempty"`

	// LogLevel 控制日志详细程度。
	LogLevel string `json:"log_level,omitempty"`
}

// Default 返回一份可直接使用的默认配置。
func Default() *Config {
	return &Config{
		DeviceName:  "corplink-go",
		DeviceModel: "Pixel 7",
		DeviceBrand: "google",
		OSVersion:   "33",
		OSPatch:     "2023-07-05",
		AppVersion:  "3.3.24",
		BuildNumber: "2485",
		Language:    "zh",
		PanelListen: "127.0.0.1:13140",
		LogLevel:    "info",
	}
}

// Load 读取配置；文件不存在时返回默认配置并记住目标路径，便于 Save 落盘。
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg := Default()
			cfg.path = path
			return cfg, nil
		}
		return nil, fmt.Errorf("读取配置 %s: %w", path, err)
	}
	cfg := Default()
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("解析配置 %s: %w", path, err)
	}
	cfg.path = path
	return cfg, nil
}

// Save 原子写回配置，避免中途崩溃导致文件损坏。
func (c *Config) Save() error {
	if c.path == "" {
		return errors.New("配置没有关联路径，无法保存")
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return fmt.Errorf("创建配置目录: %w", err)
	}
	payload, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置: %w", err)
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, append(payload, '\n'), 0o600); err != nil {
		return fmt.Errorf("写入临时配置: %w", err)
	}
	if err := os.Rename(tmp, c.path); err != nil {
		return fmt.Errorf("替换配置文件: %w", err)
	}
	return nil
}

// Path 返回配置文件路径。
func (c *Config) Path() string { return c.path }

// SessionPath 返回会话 Cookie 的落盘路径，与配置文件同目录，避免多份状态散落。
func (c *Config) SessionPath() string {
	if c.path == "" {
		return "session.json"
	}
	return filepath.Join(filepath.Dir(c.path), "session.json")
}

// EnsureDeviceID 保证配置里有 device_id。
//
// 官方客户端的取值顺序是：本地存储 -> SHA1(android_id) -> 随机 UUID。
// 我们没有 android_id，等价于客户端的兜底分支：生成一次随机 UUID（去掉横线），
// 落盘后一直复用，这样每个部署实例都有独立设备标识。
func (c *Config) EnsureDeviceID() (bool, error) {
	if c.DeviceID != "" {
		return false, nil
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return false, fmt.Errorf("生成 device_id: %w", err)
	}
	// RFC 4122 v4 变体位，保证是合法 UUID 形态，再去掉横线转小写。
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	c.DeviceID = hex.EncodeToString(buf)
	return true, c.Save()
}

// DefaultPath 返回用户级默认配置路径。
//
// CLI 与桌面版共用同一份数据，避免"命令里登录了、桌面版还说未登录"这类分裂。
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("定位用户目录: %w", err)
	}
	return filepath.Join(home, ".corplink-go", "config.json"), nil
}

// Dir 返回数据目录（配置文件所在目录）。
func (c *Config) Dir() string {
	if c.path == "" {
		return "."
	}
	return filepath.Dir(c.path)
}

// LoadDir 从数据目录加载配置，目录内固定使用 config.json。
//
// 数据目录布局：config.json（非敏感）、session.json（Cookie）、totp.json（可选）。
func LoadDir(dir string) (*Config, error) {
	if dir == "" {
		dir = "."
	}
	return Load(filepath.Join(dir, "config.json"))
}

// Meta 把配置里的客户端标识映射成请求参数；避免在多个包里重复拼装。
func Meta(c *Config) api.Meta {
	return api.Meta{
		OSVersion:   c.OSVersion,
		OSPatch:     c.OSPatch,
		AppVersion:  c.AppVersion,
		BuildNumber: c.BuildNumber,
		Model:       c.DeviceModel,
		Brand:       c.DeviceBrand,
		Language:    c.Language,
	}
}
