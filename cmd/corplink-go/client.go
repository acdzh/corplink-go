package main

import (
	"fmt"
	"net/url"
	"os"

	"github.com/acdzh/corplink-go/internal/api"
	"github.com/acdzh/corplink-go/internal/config"
	"github.com/acdzh/corplink-go/internal/sign"
)

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
	activate := cfg.ActivateCode
	if activate == "" {
		// 该租户的 activate_code 与公司代码一致；缺失时按公司代码兜底。
		activate = cfg.CompanyName
	}
	client.SetSigner(signerFor(activate, cfg.DeviceID))
	return client, nil
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
