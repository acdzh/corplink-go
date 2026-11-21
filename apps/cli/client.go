package main

import (
	"fmt"
	"net/url"
	"os"

	"github.com/acdzh/corplink-go/corplink/api"
	"github.com/acdzh/corplink-go/corplink/config"
	"github.com/acdzh/corplink-go/corplink/dpop"
	"github.com/acdzh/corplink-go/corplink/sign"
)

// loadConfig 读取配置；path 为空时使用用户级默认路径。
func loadConfig(path string) (*config.Config, error) {
	if path == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	return config.Load(path)
}

// newClient 按配置构造客户端，并装配 v1 签名器。
func newClient(cfg *config.Config, verbose bool) (*api.Client, error) {
	client, err := api.New(api.Options{
		Server:   cfg.Server,
		DeviceID: cfg.DeviceID,
		Language: cfg.Language,
		Verbose:  verbose,
		Meta:     config.Meta(cfg),
	})
	if err != nil {
		return nil, err
	}
	dpopStore(cfg).Attach(client, signerFor(activateOf(cfg), cfg.DeviceID))
	return client, nil
}

// activateOf 返回签名用的 activate_code：缺失时按公司代码兜底。
func activateOf(cfg *config.Config) string {
	if cfg.ActivateCode != "" {
		return cfg.ActivateCode
	}
	return cfg.CompanyName
}

// dpopStore 打开设备密钥；失败时返回 nil，调用方据此退回无 DPoP 形态。
func dpopStore(cfg *config.Config) *dpop.Store {
	store, err := dpop.Open(cfg.DPoPKeyPath(), cfg.DeviceID)
	if err != nil {
		return nil
	}
	return store
}

// signerFor 生成绑定指定 activate_code 与 device_id 的签名器。
func signerFor(activateCode, deviceID string) api.Signer {
	return func(ep api.Endpoint, method string, u *url.URL, body []byte, cookie, csrf, jwt string) (string, error) {
		return sign.Header(ep.SigningInputParams, activateCode, deviceID, method, u, body, cookie, csrf, jwt)
	}
}

// mustClient 是 newClient 的便捷包装，便于命令里少写错误分支样板。
func mustClient(cfg *config.Config, verbose bool) *api.Client {
	client, err := newClient(cfg, verbose)
	if err != nil {
		panic(fmt.Sprintf("构造客户端失败: %v", err))
	}
	return client
}

// loadSession 读取会话文件；不存在直接报错，不做历史路径兼容。
func loadSession(client *api.Client, cfg *config.Config) error {
	path := cfg.SessionPath()
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("会话文件 %s 不存在（请先登录）", path)
	}
	return client.LoadCookies(path)
}
