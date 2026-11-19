package app

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"

	"github.com/acdzh/corplink-go/internal/api"
	"github.com/acdzh/corplink-go/internal/config"
	"github.com/acdzh/corplink-go/internal/sign"
)

// newClient 按配置构造客户端并装配签名器。
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
	client.SetSigner(sign.NewSigner(activateOf(cfg), cfg.DeviceID))
	return client, nil
}

// activateOf 返回签名用的租户标识。
func activateOf(cfg *config.Config) string {
	if cfg.ActivateCode != "" {
		return cfg.ActivateCode
	}
	return cfg.CompanyName
}

// loadSession 读取会话文件；不存在返回错误，由调用方决定是否忽略。
func loadSession(client *api.Client, cfg *config.Config) error {
	path := cfg.SessionPath()
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("会话文件 %s 不存在（请先登录）", path)
	}
	return client.LoadCookies(path)
}

// ensureToken 复用或生成订阅 token。
func ensureToken(cfg *config.Config) (string, error) {
	if cfg.SubToken != "" {
		return cfg.SubToken, nil
	}
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("生成订阅 token: %w", err)
	}
	cfg.SubToken = hex.EncodeToString(buf)
	if err := cfg.Save(); err != nil {
		fmt.Printf("保存订阅 token 失败: %v\n", err)
	}
	return cfg.SubToken, nil
}

// 确保 sign 与 url 被引用（签名器签名需要 url.URL 类型）。
var _ = url.URL{}
