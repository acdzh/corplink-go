package main

import (
	"fmt"
	"net/url"

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
	client.SetSigner(func(ep api.Endpoint, method string, u *url.URL, body []byte, cookie, csrf, jwt string) (string, error) {
		return sign.Header(ep.SigningInputParams, activate, cfg.DeviceID, method, u, body, cookie, csrf, jwt)
	})
	return client, nil
}

// mustClient 是 newClient 的便捷包装，便于命令里少写错误分支样板。
func mustClient(cfg *config.Config, verbose bool) *api.Client {
	client, err := newClient(cfg, verbose)
	if err != nil {
		panic(fmt.Sprintf("构造客户端失败: %v", err))
	}
	return client
}
