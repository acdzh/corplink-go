package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/acdzh/corplink-go/internal/api"
)

// Service 封装登录相关的接口调用。
type Service struct {
	client *api.Client
}

// NewService 基于已构造的 HTTP 客户端创建登录服务。
func NewService(client *api.Client) *Service { return &Service{client: client} }

// Setting 拉取租户登录配置。
func (s *Service) Setting(ctx context.Context) (*api.LoginSetting, error) {
	env, err := s.client.Do(ctx, api.EndpointLoginSetting, loginQuery(), nil)
	if err != nil {
		return nil, err
	}
	if !env.OK() {
		return nil, env.Error()
	}
	out := &api.LoginSetting{}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return nil, fmt.Errorf("解析登录配置: %w", err)
	}
	return out, nil
}

// TPSLink 请求第三方登录方式列表。
//
// withOS 为真时附带 os/os_version 查询参数：服务端据此下发可轮询的 token 形态；
// 不带时是移动端 PKCE 形态（返回带 state_key 的 login_url）。
func (s *Service) TPSLink(ctx context.Context, challenge string, withOS bool) ([]api.ThirdPartyLogin, error) {
	q := url.Values{"code_challenge": {challenge}}
	if withOS {
		for k, v := range loginQuery() {
			q[k] = v
		}
	}
	env, err := s.client.Do(ctx, api.EndpointTPSLink, q, nil)
	if err != nil {
		return nil, err
	}
	if !env.OK() {
		return nil, env.Error()
	}
	if len(env.Data) == 0 {
		return nil, nil
	}
	var out []api.ThirdPartyLogin
	if err := json.Unmarshal(env.Data, &out); err != nil {
		return nil, fmt.Errorf("解析第三方登录方式: %w", err)
	}
	return out, nil
}

// TokenCheck 用第三方授权拿到的 token 换取会话（旧版 token 流程）。
func (s *Service) TokenCheck(ctx context.Context, token, verifier string) error {
	body := map[string]string{"token": token}
	if verifier != "" {
		body["code_verifier"] = verifier
	}
	env, err := s.client.Do(ctx, api.EndpointTPSToken, loginQuery(), body)
	if err != nil {
		return err
	}
	if !env.OK() {
		return env.Error()
	}
	return nil
}

// DeviceCallback 用授权码完成登录（移动端 PKCE 流程）。
func (s *Service) DeviceCallback(ctx context.Context, aliasKey, code, state, verifier string) error {
	body := map[string]string{
		"alias_key":     aliasKey,
		"code":          code,
		"state":         state,
		"code_verifier": verifier,
	}
	env, err := s.client.Do(ctx, api.EndpointTPSDevice, loginQuery(), body)
	if err != nil {
		return err
	}
	if !env.OK() {
		return env.Error()
	}
	return nil
}

// OTP 拉取 TOTP 绑定信息（url 里带 secret），供二次验证自动生成验证码。
func (s *Service) OTP(ctx context.Context) (*api.OtpInfo, error) {
	env, err := s.client.Do(ctx, api.EndpointOTP, loginQuery(), map[string]string{})
	if err != nil {
		return nil, err
	}
	if !env.OK() {
		return nil, env.Error()
	}
	out := &api.OtpInfo{}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return nil, fmt.Errorf("解析 OTP 信息: %w", err)
	}
	return out, nil
}

// loginQuery 与 api 包的登录查询参数保持一致，避免重复拼接逻辑。
func loginQuery() url.Values {
	return url.Values{"os": {api.LoginOS}, "os_version": {api.LoginOSVersion}}
}
