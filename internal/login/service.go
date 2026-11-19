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

// Start 生成 PKCE 并返回授权链接。
func (s *Service) Start(ctx context.Context, alias string) (string, error) {
	if alias == "" {
		alias = defaultAlias
	}
	pkce, err := auth.NewPKCE()
	if err != nil {
		return "", err
	}
	methods, err := s.auth.TPSLink(ctx, pkce.Challenge, true)
	if err != nil {
		return "", err
	}
	url := ""
	for _, m := range methods {
		if m.Alias == alias {
			url = m.LoginURL
			break
		}
	}
	if url == "" {
		return "", fmt.Errorf("登录方式 %s 不可用（可用: %v）", alias, aliases(methods))
	}
	s.mu.Lock()
	s.current = &flow{verifier: pkce.Verifier, alias: alias, startedAt: time.Now()}
	s.mu.Unlock()
	return url, nil
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
		return map[string]any{"mfa_required": true, "auth_list": list}, nil
	}
	if action != "" {
		return nil, fmt.Errorf("服务端要求暂不支持的步骤: %s", action)
	}
	return s.finish(ctx)
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
	if err := s.agent.RefreshNodes(ctx); err != nil {
		return map[string]any{"logged_in": true, "otp_saved": otpSaved, "warning": err.Error()}, nil
	}
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
