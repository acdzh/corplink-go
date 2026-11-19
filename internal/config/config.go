// Package config 管理 corplink-go 的本地配置。
//
// 配置文件同时是持久化状态：device_id、WireGuard 密钥、activate_code、
// 上次选中的节点都写回同一份 JSON，避免多份状态失配。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	// OSVersion 参与 User-Agent 构造，形如 12。
	OSVersion string `json:"os_version"`
	// Language 参与 User-Agent 与 Accept-Language 构造。
	Language string `json:"language"`

	// ActivateCode 是设备激活产物，用于派生请求签名密钥。
	ActivateCode string `json:"activate_code,omitempty"`
	// Code 是 TOTP secret（base32），登录后由服务端下发。
	Code string `json:"code,omitempty"`

	// SocksListen 是用户态代理监听地址；为空时走内核 TUN 模式（后续实现）。
	SocksListen string `json:"socks5_listen,omitempty"`

	// LogLevel 控制日志详细程度。
	LogLevel string `json:"log_level,omitempty"`
}

// Default 返回一份可直接使用的默认配置。
func Default() *Config {
	return &Config{
		DeviceName:  "corplink-go",
		DeviceModel: "M2007J17C",
		DeviceBrand: "Xiaomi",
		OSVersion:   "12",
		Language:    "zh-CN",
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
