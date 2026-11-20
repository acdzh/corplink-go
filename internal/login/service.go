// Package login 在进程内维护一次登录流程，供控制面板调用。
//
// PKCE 的 verifier 必须和发起授权时一致，所以整条流程的状态放在内存里：
// Start 生成 verifier 与授权链接，Callback 提交回调，必要时再走 MFA，最后落盘会话。
package login

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/acdzh/corplink-go/internal/agent"
	"github.com/acdzh/corplink-go/internal/api"
	"github.com/acdzh/corplink-go/internal/auth"
	"github.com/acdzh/corplink-go/internal/config"
	"github.com/acdzh/corplink-go/internal/sign"
)

// 流程参数。
const (
	// defaultAlias 是默认登录方式。
	defaultAlias = "bytedance_sso"
	// flowTTL 是单次登录流程的有效期。
	flowTTL = 10 * time.Minute
	// mfaScene 与 mfaType 来自客户端源码与抓包：登录二次认证固定用 feilian + email，
	// account 传空串由服务端按会话定位。
	mfaScene = "feilian"
	mfaType  = "email"
)

// flow 是一次进行中的登录。
type flow struct {
	verifier  string
	alias     string
	startedAt time.Time
	mfa       bool
	authList  []string
}

// Service 维护登录流程。
type Service struct {
	auth   *auth.Service
	client *api.Client
	cfg    *config.Config
	agent  *agent.Agent

	mu      sync.Mutex
	current *flow
}

// New 构造登录服务。
func New(client *api.Client, cfg *config.Config, ag *agent.Agent) *Service {
	return &Service{auth: auth.NewService(client), client: client, cfg: cfg, agent: ag}
}

// ensureServer 在服务端地址未配置时尝试按企业代码解析并写回配置。
func (s *Service) ensureServer(ctx context.Context) error {
	if s.cfg.Server != "" {
		return nil
	}
	if s.cfg.CompanyName == "" {
		return fmt.Errorf("请先在设置中配置企业代码或服务端地址")
	}
	info, err := api.MatchCompany(ctx, s.cfg.CompanyName)
	if err != nil {
		return fmt.Errorf("解析企业代码 %q: %w", s.cfg.CompanyName, err)
	}
	s.cfg.Server = info.Domain
	if err := s.client.SetServer(info.Domain); err != nil {
		return err
	}
	activate := s.cfg.ActivateCode
	if activate == "" {
		activate = s.cfg.CompanyName
	}
	s.client.SetSigner(sign.NewSigner(activate, s.cfg.DeviceID))
	_ = s.cfg.Save()
	s.agent.LogEvent("info", "已解析企业 %s 服务端: %s", s.cfg.CompanyName, info.Domain)
	return nil
}

// Methods 查询当前企业支持的第三方登录方式列表。
func (s *Service) Methods(ctx context.Context) ([]api.ThirdPartyLogin, error) {
	if err := s.ensureServer(ctx); err != nil {
		return nil, err
	}
	pkce, err := auth.NewPKCE()
	if err != nil {
		return nil, err
	}
	return s.auth.TPSLink(ctx, pkce.Challenge, true)
}

// Start 生成 PKCE 并返回授权链接。
func (s *Service) Start(ctx context.Context, alias string) (string, error) {
	info, err := s.StartWithInfo(ctx, alias)
	if err != nil {
		return "", err
	}
	u, _ := info["url"].(string)
	return u, nil
}

// StartWithInfo 生成 PKCE 并返回授权链接、选中的登录方式与可用登录方式列表。
func (s *Service) StartWithInfo(ctx context.Context, alias string) (map[string]any, error) {
	if err := s.ensureServer(ctx); err != nil {
		return nil, err
	}
	pkce, err := auth.NewPKCE()
	if err != nil {
		return nil, err
	}
	methods, err := s.auth.TPSLink(ctx, pkce.Challenge, true)
	if err != nil {
		return nil, err
	}
	chosen, err := chooseLoginMethod(methods, alias)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.current = &flow{verifier: pkce.Verifier, alias: chosen.Alias, startedAt: time.Now()}
	s.mu.Unlock()
	s.agent.LogEvent("info", "已发起第三方授权登录（%s）", chosen.Alias)
	return map[string]any{
		"url":        chosen.LoginURL,
		"alias":      chosen.Alias,
		"full_title": chosen.FullTitle,
		"methods":    methods,
	}, nil
}

// chooseLoginMethod 选择登录方式：显式指定时精确匹配，未指定时按常见优先级回退到首个可用方式。
func chooseLoginMethod(methods []api.ThirdPartyLogin, alias string) (*api.ThirdPartyLogin, error) {
	if len(methods) == 0 {
		return nil, fmt.Errorf("服务端未返回可用的第三方登录方式")
	}
	if alias != "" {
		for i := range methods {
			if methods[i].Alias == alias || methods[i].AliasKey == alias {
				return &methods[i], nil
			}
		}
		return nil, fmt.Errorf("登录方式 %s 不可用（可用: %v）", alias, aliases(methods))
	}
	for _, preferred := range []string{defaultAlias, "lark"} {
		for i := range methods {
			if methods[i].Alias == preferred || methods[i].AliasKey == preferred {
				return &methods[i], nil
			}
		}
	}
	return &methods[0], nil
}

// Callback 提交授权回调；若服务端要求二次验证则返回 mfa_required。
func (s *Service) Callback(ctx context.Context, raw string) (map[string]any, error) {
	s.mu.Lock()
	current := s.current
	s.mu.Unlock()
	if current == nil || time.Since(current.startedAt) > flowTTL {
		return nil, fmt.Errorf("没有进行中的登录，请重新获取授权链接")
	}
	parsed, err := auth.ParseCallback(raw)
	if err != nil {
		return nil, err
	}
	data, err := s.auth.DeviceCallback(ctx, parsed.AliasKey, parsed.Code, parsed.State, current.verifier)
	if err != nil {
		return nil, err
	}
	action, list, _ := parseNext(data)
	if action == "2FA" {
		s.mu.Lock()
		s.current.mfa = true
		s.current.authList = list
		s.mu.Unlock()
		s.agent.LogEvent("info", "授权回调成功，等待二次验证")
		return map[string]any{
			"mfa_required": true,
			"auth_list":    list,
			"has_totp":     s.cfg.Code != "",
		}, nil
	}
	if action != "" {
		return nil, fmt.Errorf("服务端要求暂不支持的步骤: %s", action)
	}
	return s.finish(ctx)
}

// SendMFA 在等待二次验证阶段主动下发邮箱或短信验证码。
func (s *Service) SendMFA(ctx context.Context, mfaType string) error {
	s.mu.Lock()
	current := s.current
	s.mu.Unlock()
	if current == nil || !current.mfa {
		return fmt.Errorf("当前没有等待验证码的登录")
	}
	if mfaType == "" {
		mfaType = mfaTypeEmail()
	}
	if _, err := s.auth.MfaSend(ctx, mfaScene, mfaType, ""); err != nil {
		return err
	}
	s.agent.LogEvent("info", "已请求下发二次验证码（%s）", mfaType)
	return nil
}

// mfaTypeEmail 返回默认的 MFA 验证码下发类型。
func mfaTypeEmail() string {
	return mfaType
}

// MFA 提交二次验证码；TOTP secret 存在时调用方可以自动生成。
func (s *Service) MFA(ctx context.Context, code string) (map[string]any, error) {
	s.mu.Lock()
	current := s.current
	s.mu.Unlock()
	if current == nil || !current.mfa {
		return nil, fmt.Errorf("当前没有等待验证码的登录")
	}
	data, err := s.auth.MfaVerify(ctx, mfaScene, mfaType, "", code)
	if err != nil {
		return nil, err
	}
	if action, _, _ := parseNext(data); action != "" && action != "GoToLink" {
		return nil, fmt.Errorf("二次验证后仍有步骤: %s", action)
	}
	return s.finish(ctx)
}

// finish 收尾：拉 TOTP secret、落盘会话、刷新节点。
func (s *Service) finish(ctx context.Context) (map[string]any, error) {
	otpSaved := false
	if otp, err := s.auth.OTP(ctx); err == nil {
		if secret, err := auth.OtpSecret(otp.URL); err == nil {
			s.cfg.Code = secret
			otpSaved = s.cfg.Save() == nil
		}
	}
	if err := s.client.SaveCookies(s.cfg.SessionPath()); err != nil {
		return nil, fmt.Errorf("保存会话: %w", err)
	}
	s.mu.Lock()
	s.current = nil
	s.mu.Unlock()
	s.agent.Warmup(ctx)
	if err := s.agent.RefreshNodes(ctx); err != nil {
		return map[string]any{"logged_in": true, "otp_saved": otpSaved, "warning": err.Error()}, nil
	}
	s.agent.LogEvent("info", "登录成功，节点 %d 个", len(s.agent.Nodes()))
	return map[string]any{"logged_in": true, "otp_saved": otpSaved, "nodes": len(s.agent.Nodes())}, nil
}

// Logout 清除会话并断开隧道。
func (s *Service) Logout() error {
	s.agent.Disconnect()
	s.client.ClearCookies()
	s.mu.Lock()
	s.current = nil
	s.mu.Unlock()
	if err := os.Remove(s.cfg.SessionPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除会话文件: %w", err)
	}
	s.agent.LogEvent("info", "已退出登录并清除本地会话")
	return nil
}

// Pending 返回是否有等待验证码的登录。
func (s *Service) Pending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current != nil && s.current.mfa
}

// parseNext 解析 LoginV2Result 的下一步动作与可用认证方式。
func parseNext(data []byte) (string, []string, string) {
	var parsed struct {
		Result string `json:"result"`
		Next   struct {
			Action   string   `json:"action"`
			AuthList []string `json:"auth_list"`
			Email    string   `json:"email"`
		} `json:"next"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", nil, ""
	}
	return parsed.Next.Action, parsed.Next.AuthList, parsed.Next.Email
}

// aliases 提取可用登录方式，便于报错提示。
func aliases(methods []api.ThirdPartyLogin) []string {
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		out = append(out, m.Alias)
	}
	return out
}
