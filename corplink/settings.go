package corplink

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/acdzh/corplink-go/corplink/api"
	"github.com/acdzh/corplink-go/corplink/sign"
)

// Settings 是可编辑配置的对外形态。
//
// 字段用指针：区分"没提交"和"提交了空值"，避免部分更新把其他项清空。
type Settings struct {
	// CompanyName 是企业标识，用于解析服务端地址。
	CompanyName *string `json:"company_name"`
	// Server 是企业服务端地址，留空可由企业代码自动解析。
	Server *string `json:"server"`
	// ActivateCode 是设备激活标识。
	ActivateCode *string `json:"activate_code"`
	// ProxyListen 是混合代理监听地址。
	ProxyListen *string `json:"proxy_listen"`
	// PanelListen 是控制面板监听地址。
	PanelListen *string `json:"panel_listen"`
	// AutoModeIntervalSeconds 是测速间隔（秒）。
	AutoModeIntervalSeconds *int `json:"auto_mode_interval_seconds"`
	// KeepaliveSeconds 是会话保活间隔（秒）。
	KeepaliveSeconds *int `json:"keepalive_seconds"`
	// LogLevel 是日志级别。
	LogLevel *string `json:"log_level"`
	// DeviceModel 与 DeviceBrand 影响 UA 与 query 上报。
	DeviceModel *string `json:"device_model"`
	DeviceBrand *string `json:"device_brand"`
	// OSVersion 与 OSPatch 是系统 API level 与补丁日期。
	OSVersion *string `json:"os_version"`
	OSPatch   *string `json:"os_version_patch"`
}

// Settings 返回可编辑的配置快照。
func (c *Client) Settings() Settings {
	proxyListen := c.cfg.SocksListen
	panelListen := c.cfg.PanelListen
	if proxyListen == "" {
		proxyListen = "127.0.0.1:3710"
	}
	if panelListen == "" {
		panelListen = "127.0.0.1:13140"
	}
	return Settings{
		CompanyName:             &c.cfg.CompanyName,
		Server:                  &c.cfg.Server,
		ActivateCode:            &c.cfg.ActivateCode,
		ProxyListen:             &proxyListen,
		PanelListen:             &panelListen,
		AutoModeIntervalSeconds: &c.cfg.AutoModeIntervalSeconds,
		KeepaliveSeconds:        &c.cfg.KeepaliveSeconds,
		LogLevel:                &c.cfg.LogLevel,
		DeviceModel:             &c.cfg.DeviceModel,
		DeviceBrand:             &c.cfg.DeviceBrand,
		OSVersion:               &c.cfg.OSVersion,
		OSPatch:                 &c.cfg.OSPatch,
	}
}

// UpdateSettings 校验并写入配置，返回需要重启进程才生效的字段名。
//
// 服务端地址与签名密钥在客户端上同步更新，其余字段落盘后由端侧决定何时重启。
func (c *Client) UpdateSettings(ctx context.Context, in Settings) ([]string, error) {
	cfg := c.cfg
	// 任何一步失败都把内存里的配置恢复原样，避免界面与服务端状态错位。
	backup := *cfg
	fail := func(err error) ([]string, error) {
		*cfg = backup
		return nil, err
	}
	restart := make([]string, 0, 4)
	oldCompany := cfg.CompanyName
	oldServer := cfg.Server
	oldActivate := cfg.ActivateCode

	if in.CompanyName != nil {
		cfg.CompanyName = strings.TrimSpace(*in.CompanyName)
	}
	if in.Server != nil {
		cfg.Server = strings.TrimSpace(*in.Server)
	}
	if in.ActivateCode != nil {
		cfg.ActivateCode = strings.TrimSpace(*in.ActivateCode)
	}
	companyChanged := cfg.CompanyName != oldCompany
	serverNotManuallyChanged := in.Server == nil || strings.TrimSpace(*in.Server) == oldServer
	if cfg.CompanyName != "" && (cfg.Server == "" || (companyChanged && serverNotManuallyChanged)) {
		info, err := api.MatchCompany(ctx, cfg.CompanyName)
		if err != nil {
			return fail(fmt.Errorf("解析企业代码 %q 失败: %w", cfg.CompanyName, err))
		}
		cfg.Server = info.Domain
	}
	if cfg.Server != oldServer {
		if err := c.api.SetServer(cfg.Server); err != nil {
			return fail(err)
		}
	}
	if cfg.ActivateCode != oldActivate || cfg.CompanyName != oldCompany {
		// 签名器与设备证明一起重挂，保证两条凭证始终指向同一份配置。
		c.dpop.Attach(c.api, sign.NewSigner(activateOf(cfg), cfg.DeviceID))
	}

	if in.ProxyListen != nil {
		v := strings.TrimSpace(*in.ProxyListen)
		if v != "" && v != cfg.SocksListen {
			if _, _, err := net.SplitHostPort(v); err != nil {
				return fail(fmt.Errorf("代理监听地址非法: %w", err))
			}
			cfg.SocksListen = v
			restart = append(restart, "proxy_listen")
		}
	}
	if in.PanelListen != nil {
		v := strings.TrimSpace(*in.PanelListen)
		if v != "" && v != cfg.PanelListen {
			if _, _, err := net.SplitHostPort(v); err != nil {
				return fail(fmt.Errorf("面板监听地址非法: %w", err))
			}
			cfg.PanelListen = v
			restart = append(restart, "panel_listen")
		}
	}
	if in.AutoModeIntervalSeconds != nil && *in.AutoModeIntervalSeconds != cfg.AutoModeIntervalSeconds {
		if *in.AutoModeIntervalSeconds < 0 {
			return fail(fmt.Errorf("自动选路间隔不能为负"))
		}
		cfg.AutoModeIntervalSeconds = *in.AutoModeIntervalSeconds
		restart = append(restart, "auto_mode_interval_seconds")
	}
	if in.KeepaliveSeconds != nil && *in.KeepaliveSeconds != cfg.KeepaliveSeconds {
		if *in.KeepaliveSeconds < 0 {
			return fail(fmt.Errorf("保活间隔不能为负"))
		}
		cfg.KeepaliveSeconds = *in.KeepaliveSeconds
		restart = append(restart, "keepalive_seconds")
	}
	if in.LogLevel != nil {
		v := strings.TrimSpace(*in.LogLevel)
		if v != "" && v != cfg.LogLevel {
			cfg.LogLevel = v
			restart = append(restart, "log_level")
		}
	}
	if in.DeviceModel != nil {
		v := strings.TrimSpace(*in.DeviceModel)
		if v != "" && v != cfg.DeviceModel {
			cfg.DeviceModel = v
			restart = append(restart, "device_model")
		}
	}
	if in.DeviceBrand != nil {
		v := strings.TrimSpace(*in.DeviceBrand)
		if v != "" && v != cfg.DeviceBrand {
			cfg.DeviceBrand = v
			restart = append(restart, "device_brand")
		}
	}
	if in.OSVersion != nil {
		v := strings.TrimSpace(*in.OSVersion)
		if v != "" && v != cfg.OSVersion {
			cfg.OSVersion = v
			restart = append(restart, "os_version")
		}
	}
	if in.OSPatch != nil {
		v := strings.TrimSpace(*in.OSPatch)
		if v != "" && v != cfg.OSPatch {
			cfg.OSPatch = v
			restart = append(restart, "os_version_patch")
		}
	}
	if err := cfg.Save(); err != nil {
		return fail(fmt.Errorf("保存配置: %w", err))
	}
	c.agent.LogEvent("info", "已保存系统配置")
	return restart, nil
}
