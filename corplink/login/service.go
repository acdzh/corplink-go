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
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/acdzh/corplink-go/corplink/agent"
	"github.com/acdzh/corplink-go/corplink/api"
	"github.com/acdzh/corplink-go/corplink/auth"
	"github.com/acdzh/corplink-go/corplink/clock"
	"github.com/acdzh/corplink-go/corplink/config"
	"github.com/acdzh/corplink-go/corplink/dpop"
	"github.com/acdzh/corplink-go/corplink/sign"
	"github.com/acdzh/corplink-go/corplink/totp"
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
	// mfaTypeMobile 是手机短信二次认证。
	mfaTypeMobile = "mobile"
	// dpopScene 是设备密钥登记用的 MFA scene（DpopMfaPurpose.DEVICE_KEY_REGISTRATION）。
	dpopScene = "device_key"
	// codeTypeOTP 是 TOTP 认证方式的名字。
	codeTypeOTP = "otp"
)

// loginMfaPreference 是无人值守时自动选二次认证方式的顺序。
//
// 官方客户端（LoginV2MfaActivity）把服务端 auth_list 原样列给用户点，默认第一项；
// 我们把列表也给面板点，但"默认值"必须按能否确定送达来定：email 一定收得到，
// otp 依赖本地 secret，mobile 依赖账号绑过手机号——本租户的 type 就是 mobile，
// 账号没绑手机时选它等于登录卡死（验证码永远不会到）。
var loginMfaPreference = []string{mfaType, codeTypeOTP, mfaTypeMobile}

// supportedLoginAuth 是官方 isAuthNotSupport 的白名单：
// 服务端可能下发客户端并不支持的认证方式，官方会先把它们剔掉再展示。
var supportedLoginAuth = map[string]bool{
	"email":    true,
	"mobile":   true,
	"otp":      true,
	"password": true,
	"passkey":  true,
}

// flow 是一次进行中的登录。
type flow struct {
	verifier  string
	alias     string
	startedAt time.Time
	mfa       bool
	authList  []string
	// mfaType 是本次登录实际使用的验证码方式，下发与校验必须一致。
	mfaType string
	// email / mobile 是服务端给的回显账号（已脱敏），供面板提示"码发到哪"。
	email  string
	mobile string
}

// dpopState 是设备密钥登记的当前状态，供面板展示。
type dpopState struct {
	// keyID 是本地 device_key_id。
	keyID string
	// bound 表示服务端已接受该公钥。
	bound bool
	// needCode 表示登记卡在验证码上，等人工输入。
	needCode bool
	// codeType 是待输入的验证码类型（otp / email / mobile）。
	codeType string
	// lastErr 是最近一次登记失败的原因。
	lastErr string
}

// Service 维护登录流程。
type Service struct {
	auth   *auth.Service
	client *api.Client
	cfg    *config.Config
	agent  *agent.Agent
	dpop   *dpop.Store

	mu      sync.Mutex
	current *flow
	device  dpopState
	// kicked / kickReason 记录会话被服务端终止的状态。
	kicked     bool
	kickReason string
}

// New 构造登录服务。
func New(client *api.Client, cfg *config.Config, ag *agent.Agent, store *dpop.Store) *Service {
	return &Service{auth: auth.NewService(client), client: client, cfg: cfg, agent: ag, dpop: store}
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
	next := parseNext(data)
	if next.Action == "2FA" {
		options := supportedAuthTypes(next.AuthList)
		chosen := s.pickLoginMfaType(ctx, options)
		s.mu.Lock()
		s.current.mfa = true
		s.current.authList = options
		s.current.mfaType = chosen
		s.current.email = next.Email
		s.current.mobile = next.Mobile
		s.mu.Unlock()
		s.agent.LogEvent("info", "授权回调成功，等待二次验证（默认 %s，可用 %s）", chosen, strings.Join(options, "/"))
		return map[string]any{
			"mfa_required": true,
			"auth_list":    options,
			"mfa_type":     chosen,
			"email":        next.Email,
			"mobile":       next.Mobile,
			"has_totp":     s.cfg.Code != "",
		}, nil
	}
	if next.Action != "" {
		return nil, fmt.Errorf("服务端要求暂不支持的步骤: %s", next.Action)
	}
	return s.finish(ctx)
}

// SendMFA 在等待二次验证阶段下发验证码，返回实际使用的方式。
//
// mfaType 为空时用流程里已选定的方式（见 pickMfaType 的排序）。
func (s *Service) SendMFA(ctx context.Context, mfaType string) (string, error) {
	s.mu.Lock()
	current := s.current
	s.mu.Unlock()
	if current == nil || !current.mfa {
		return "", fmt.Errorf("当前没有等待验证码的登录")
	}
	if mfaType == "" {
		mfaType = current.mfaType
	}
	if mfaType == "" {
		mfaType = s.pickLoginMfaType(ctx, current.authList)
	}
	if !mfaTypeAllowed(mfaType, current.authList) {
		return "", fmt.Errorf("本租户不支持 %s 认证（可用: %s）", mfaType, strings.Join(current.authList, "/"))
	}
	s.setFlowMfaType(mfaType)
	if _, err := s.auth.MfaSend(ctx, mfaScene, mfaType, ""); err != nil {
		return mfaType, err
	}
	s.agent.LogEvent("info", "已请求下发二次验证码（%s）", mfaType)
	return mfaType, nil
}

// mfaTypeEmail 返回默认的 MFA 验证码下发类型。
func mfaTypeEmail() string {
	return mfaType
}

// MFA 提交二次验证码并完成登录。
//
// mfaType 为空时用流程里已选定的方式：下发与校验必须是同一个 mfa_type，
// 否则服务端会按"验证码不属于该方式"直接拒绝。同一个码在不同方式间乱试
// 只会把真正的失败原因（发码失败 / 没绑手机 / 码过期）盖掉，所以这里不再回退。
func (s *Service) MFA(ctx context.Context, code, mfaType string) (map[string]any, error) {
	s.mu.Lock()
	current := s.current
	s.mu.Unlock()
	if current == nil || !current.mfa {
		return nil, fmt.Errorf("当前没有等待验证码的登录")
	}
	if mfaType == "" {
		mfaType = current.mfaType
	}
	if mfaType == "" {
		mfaType = s.pickLoginMfaType(ctx, current.authList)
	}
	// 只有服务端确实支持 otp 时才用本地 TOTP 兜底：feilian 场景通常只给
	// mobile/email，用 TOTP 去校验必然失败。
	if code == "" && mfaType == codeTypeOTP && s.cfg.Code != "" {
		generated, _, err := totp.Code(s.cfg.Code, clock.Now())
		if err != nil {
			return nil, fmt.Errorf("生成 TOTP: %w", err)
		}
		code = generated
	}
	if code == "" {
		return nil, fmt.Errorf("请先输入 %s 验证码", mfaType)
	}
	s.setFlowMfaType(mfaType)
	data, err := s.auth.MfaVerify(ctx, mfaScene, mfaType, "", code)
	if err != nil {
		return nil, fmt.Errorf("二次验证失败（方式 %s%s）: %w", mfaType, optionHint(current.authList), err)
	}
	if next := parseNext(data); next.Action != "" && next.Action != "GoToLink" {
		return nil, fmt.Errorf("二次验证后仍有步骤: %s", next.Action)
	}
	return s.finish(ctx)
}

// pickLoginMfaType 选一个可用的登录 MFA 方式。
//
// auth_list 优先；为空时向服务端协商（/api/mfa/type），再退回 email。
func (s *Service) pickLoginMfaType(ctx context.Context, authList []string) string {
	available := supportedAuthTypes(authList)
	// 回调已经给出 auth_list 时不再多打一次接口：这一步是登录最敏感的位置，
	// 少一个失败点比省一行代码重要。
	if len(available) > 0 {
		return pickMfaType(available, "")
	}
	fallback := ""
	if typ, err := s.auth.MfaType(ctx, mfaScene); err == nil && typ != nil {
		fallback = typ.Type
		available = typ.Types
		if len(available) == 0 && typ.Type != "" {
			available = []string{typ.Type}
		}
	}
	return pickMfaType(supportedAuthTypes(available), fallback)
}

// pickMfaType 按 loginMfaPreference 选默认的验证码方式。
//
// 排序理由见 loginMfaPreference：email 一定收得到，otp 要有本地 secret，
// mobile 要账号绑过手机号。列表里没有偏好项时退回服务端顺序第一项，
// 再退回 /api/mfa/type 的 type，最后退回 email。用户显式指定时不会走到这里。
func pickMfaType(available []string, fallback string) string {
	for _, want := range loginMfaPreference {
		for _, got := range available {
			if got == want {
				return want
			}
		}
	}
	if len(available) > 0 {
		return available[0]
	}
	if fallback != "" {
		return fallback
	}
	return mfaTypeEmail()
}

// supportedAuthTypes 剔掉客户端不支持的认证方式，保持服务端顺序。
func supportedAuthTypes(list []string) []string {
	out := make([]string, 0, len(list))
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item == "" || !supportedLoginAuth[item] {
			continue
		}
		if !containsType(out, item) {
			out = append(out, item)
		}
	}
	return out
}

// containsType 判断列表里是否已有该方式。
func containsType(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// mfaTypeAllowed 判断该方式是否在服务端给出的可用列表里（列表为空时不拦）。
func mfaTypeAllowed(typ string, available []string) bool {
	return len(available) == 0 || containsType(available, typ)
}

// optionHint 生成"（可用: email/mobile）"后缀，便于定位失败原因。
func optionHint(available []string) string {
	if len(available) == 0 {
		return ""
	}
	return "，可用: " + strings.Join(available, "/")
}

// setFlowMfaType 把选定的 MFA 方式记回当前流程。
func (s *Service) setFlowMfaType(mfaType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil {
		s.current.mfaType = mfaType
	}
}

// SolveVPNMFA 完成连接期二次认证（服务端返回 20210002 时调用）。
//
// 官方把 conn 请求挂起，等 MFA 完成后用同一个 body 续跑；这里等价的实现是：
// 取 vpn 场景可用方式 → 本地 TOTP 生成验证码 → /api/mfa/code/verify。
// 没有 TOTP secret 时返回可操作的错误，由调用方提示用户。
func (s *Service) SolveVPNMFA(ctx context.Context) error {
	typ, err := s.auth.VPNMfaType(ctx)
	if err != nil {
		return fmt.Errorf("查询连接认证方式: %w", err)
	}
	codeType := codeTypeOTP
	if typ != nil && typ.Type != "" && s.cfg.Code == "" {
		codeType = typ.Type
	}
	if codeType != codeTypeOTP {
		return fmt.Errorf("连接需要 %s 验证码，请先在面板完成一次验证", codeType)
	}
	if s.cfg.Code == "" {
		return fmt.Errorf("连接需要动态码，但本地没有 TOTP secret")
	}
	code, _, err := totp.Code(s.cfg.Code, clock.Now())
	if err != nil {
		return fmt.Errorf("生成 TOTP: %w", err)
	}
	if err := s.auth.VerifyMfaCode(ctx, "vpn", codeTypeOTP, code, nil); err != nil {
		return fmt.Errorf("校验连接动态码: %w", err)
	}
	s.agent.LogEvent("info", "连接期二次认证通过")
	return nil
}

// finish 收尾：拉 TOTP secret、落盘会话、登记设备密钥、刷新节点。
func (s *Service) finish(ctx context.Context) (map[string]any, error) {
	otpSaved := false
	if otp, err := s.auth.OTP(ctx); err == nil {
		if secret, err := auth.OtpSecret(otp.URL); err == nil {
			s.cfg.Code = secret
			otpSaved = s.cfg.Save() == nil
		}
	}
	if path := s.cfg.SessionPath(); path != "" {
		if err := s.client.SaveCookies(path); err != nil {
			return nil, fmt.Errorf("保存会话: %w", err)
		}
	}
	s.mu.Lock()
	s.current = nil
	s.mu.Unlock()

	// 未签协议会让"登录成功但拉不到节点"，先补签再做后面的登记与刷新。
	s.ensureAgreement(ctx)

	// 设备上报必须早于任何连接尝试：服务端设备表里没有这台设备时，
	// /vpn/conn 只会回 3015「Session 无效」（实测：报完立刻就能连上）。
	if err := s.auth.ReportDevice(ctx, true, config.Meta(s.cfg), s.cfg.DeviceName, s.cfg.DeviceModel, s.cfg.DeviceBrand); err != nil {
		s.agent.LogEvent("warn", "设备上报失败: %v", err)
	}

	// 设备密钥登记要在会话有效期内做完：服务端只给"会话 + 已登记公钥"
	// 的组合签发 vpn-token，没有 vpn-token 时 /vpn/conn 必然 3015。
	dpopInfo, dpopErr := s.RegisterDeviceKey(ctx, "", "")
	if dpopErr != nil {
		s.agent.LogEvent("warn", "设备密钥登记失败: %v", dpopErr)
	} else if vpnToken, ok := dpopInfo["vpn_token"].(bool); ok && !vpnToken {
		s.agent.LogEvent("warn", "会话仍未拿到 vpn-token，连接可能失败（3015）")
	}

	s.agent.Warmup(ctx)
	result := map[string]any{"logged_in": true, "otp_saved": otpSaved}
	if dpopInfo != nil {
		for k, v := range dpopInfo {
			result[k] = v
		}
	}
	// 拉列表本身也会触发服务端续签 vpn-token，成功后再存一次会话。
	if err := s.agent.RefreshNodes(ctx); err != nil {
		s.saveCookies("登录收尾")
		result["warning"] = err.Error()
		return result, nil
	}
	s.saveCookies("登录收尾")
	s.agent.LogEvent("info", "登录成功，节点 %d 个", len(s.agent.Nodes()))
	result["nodes"] = len(s.agent.Nodes())
	result["vpn_token"] = s.HasVPNToken()
	return result, nil
}

// saveCookies 落盘会话；失败只记事件，不影响登录结果。
//
// 被踢之后禁止再写：此时 cookie jar 已经被清空，写回去会留下一个
// "文件存在但没有会话"的残废状态，重启后看不出到底发生过什么。
func (s *Service) saveCookies(stage string) {
	path := s.cfg.SessionPath()
	if path == "" {
		return
	}
	s.mu.Lock()
	kicked := s.kicked
	s.mu.Unlock()
	if kicked {
		return
	}
	if err := s.client.SaveCookies(path); err != nil {
		s.agent.LogEvent("warn", "保存会话失败（%s）: %v", stage, err)
	}
}

// HasVPNToken 判断会话里是否已有 vpn-token。
func (s *Service) HasVPNToken() bool {
	for _, ck := range s.client.Cookies() {
		if ck.Name == "vpn-token" && ck.Value != "" {
			return true
		}
	}
	return false
}

// RefreshVPNToken 主动续签 vpn-token，供保活循环与连接自愈调用。
func (s *Service) RefreshVPNToken(ctx context.Context) error {
	_, err := s.refreshVPNToken(ctx)
	return err
}

// refreshVPNToken 请求一次节点列表，让服务端按已登记的设备密钥签发 vpn-token。
//
// 这是整套 DPoP 的引导点：绑定成功的会话带上有效的 DPoP 证明（ath 覆盖 session）
// 请求 /api/vpn/list，服务端才会 Set-Cookie 下发带 cnf.jwk 的 vpn-token。
func (s *Service) refreshVPNToken(ctx context.Context) (bool, error) {
	env, err := s.client.Do(ctx, api.EndpointVPNList, nil, nil)
	if err != nil {
		return false, err
	}
	if !env.OK() {
		return false, env.Error()
	}
	s.saveCookies("设备密钥登记后刷新")
	return s.HasVPNToken(), nil
}

// DeviceKey 返回本地设备密钥，必要时创建一对新的。
func (s *Service) DeviceKey() (*dpop.Key, error) {
	if s.dpop == nil {
		return nil, fmt.Errorf("未启用设备密钥")
	}
	return s.dpop.Key()
}

// DpopInfo 返回本地设备密钥与登记状态，供面板展示。
func (s *Service) DpopInfo(ctx context.Context) (map[string]any, error) {
	key, err := s.DeviceKey()
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"device_key_id": key.ID(),
		"bound":         key.Bound(),
		"protection":    "software_protected",
		"key_path":      s.dpop.Path(),
	}
	status, err := s.auth.DpopStatus(ctx)
	if err != nil {
		out["error"] = err.Error()
		return out, nil
	}
	out["registered"] = status.Registered
	out["enabled"] = status.Enabled
	out["device_key_status"] = status.DeviceKeyStatus
	out["server_device_key_id"] = status.DeviceKeyID
	if status.RegistrationNotice != nil {
		out["mfa_type"] = status.RegistrationNotice.MFAType
		out["backup_mfa_type"] = status.RegistrationNotice.BackupMFAType
	}
	s.mu.Lock()
	state := s.device
	s.mu.Unlock()
	out["need_code"] = state.needCode
	out["pending_code_type"] = state.codeType
	if state.lastErr != "" {
		out["last_error"] = state.lastErr
	}
	return out, nil
}

// DeviceKeyState 返回面板需要的设备密钥状态快照。
func (s *Service) DeviceKeyState() (keyID string, bound bool, needCode bool, codeType string) {
	if s.dpop != nil {
		if key, err := s.dpop.Key(); err == nil {
			keyID = key.ID()
			bound = key.Bound()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.device.keyID != "" {
		keyID = s.device.keyID
	}
	bound = bound || s.device.bound
	return keyID, bound, s.device.needCode, s.device.codeType
}

// RegisterDeviceKey 完成一次设备密钥登记。
//
// codeType 为空时按"有 TOTP secret 就用 otp，否则用服务端引导里的方式"选择；
// code 为空且需要人工输入时返回 need_code=true，调用方拿到验证码后再调一次。
func (s *Service) RegisterDeviceKey(ctx context.Context, codeType, code string) (map[string]any, error) {
	if s.dpop == nil {
		return nil, fmt.Errorf("未启用设备密钥")
	}
	key, err := s.dpop.Key()
	if err != nil {
		return nil, err
	}
	status, err := s.auth.DpopStatus(ctx)
	if err != nil {
		// 未登记设备查不了这个接口（服务端回 40001），按未绑定继续走注册流程。
		s.agent.LogEvent("warn", "查询设备密钥状态失败，按未登记继续: %v", err)
		status = &api.DpopStatus{}
	}
	s.setDeviceState(key.ID(), status.Bound(key.ID()), false, "")
	if status.Bound(key.ID()) {
		if err := s.dpop.MarkBound(true); err != nil {
			return nil, err
		}
		s.agent.LogEvent("info", "设备密钥已登记: %s", key.ID())
		vpnToken, err := s.refreshVPNToken(ctx)
		if err != nil {
			s.agent.LogEvent("warn", "刷新 vpn-token 失败: %v", err)
		}
		return map[string]any{"dpop_bound": true, "device_key_id": key.ID(), "vpn_token": vpnToken}, nil
	}
	// 服务端记的是另一把密钥时，本地这把必须重新登记（登记会覆盖旧公钥）。
	if status.DeviceKeyID != "" && status.DeviceKeyID != key.ID() {
		s.agent.LogEvent("warn", "服务端已有其他设备密钥 %s，按本地密钥重新登记", status.DeviceKeyID)
	}
	if err := s.dpop.MarkBound(false); err != nil {
		return nil, err
	}

	if codeType == "" {
		codeType = s.pickCodeType(status)
	}
	if code == "" {
		// otp 是本地生成的动态码，服务端不为它下发消息：官方客户端在
		// 选到 otp 时直接进校验，调用 send 会被回 3021「无效的二次认证方法」。
		if codeType != codeTypeOTP {
			if err := s.auth.MfaCodeSendExtra(ctx, dpopScene, codeType, nil); err != nil {
				s.setDeviceState(key.ID(), false, false, codeType, err.Error())
				return nil, fmt.Errorf("下发设备密钥登记验证码: %w", err)
			}
		}
		if codeType != codeTypeOTP || s.cfg.Code == "" {
			s.setDeviceState(key.ID(), false, true, codeType, "")
			s.agent.LogEvent("warn", "设备密钥登记需要验证码（%s）", codeType)
			return map[string]any{
				"dpop_bound":     false,
				"dpop_need_code": true,
				"code_type":      codeType,
				"device_key_id":  key.ID(),
			}, nil
		}
		generated, _, err := totp.Code(s.cfg.Code, clock.Now())
		if err != nil {
			s.setDeviceState(key.ID(), false, true, codeType, err.Error())
			return nil, fmt.Errorf("生成 TOTP: %w", err)
		}
		code = generated
	}

	if _, err := s.auth.MfaCodeVerifyExtra(ctx, dpopScene, codeType, code, key.LoginFields()); err != nil {
		s.setDeviceState(key.ID(), false, false, codeType, err.Error())
		return nil, fmt.Errorf("校验设备密钥登记验证码: %w", err)
	}
	// 校验通过后重新确认服务端状态，避免"请求成功但公钥没落地"。
	confirmed, err := s.auth.DpopStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("确认设备密钥状态: %w", err)
	}
	if !confirmed.Bound(key.ID()) {
		s.setDeviceState(key.ID(), false, false, codeType, "服务端未确认登记")
		return map[string]any{
			"dpop_bound":    false,
			"device_key_id": key.ID(),
			"registered":    confirmed.Registered,
			"server_status": confirmed.DeviceKeyStatus,
		}, nil
	}
	if err := s.dpop.MarkBound(true); err != nil {
		return nil, err
	}
	s.setDeviceState(key.ID(), true, false, "")
	s.agent.LogEvent("info", "设备密钥登记成功: %s", key.ID())
	vpnToken, err := s.refreshVPNToken(ctx)
	if err != nil {
		s.agent.LogEvent("warn", "刷新 vpn-token 失败: %v", err)
	}
	return map[string]any{"dpop_bound": true, "device_key_id": key.ID(), "vpn_token": vpnToken}, nil
}

// pickCodeType 决定用哪种方式验证设备密钥登记。
func (s *Service) pickCodeType(status *api.DpopStatus) string {
	if s.cfg.Code != "" {
		return codeTypeOTP
	}
	if status != nil && status.RegistrationNotice != nil && status.RegistrationNotice.MFAType != "" {
		return status.RegistrationNotice.MFAType
	}
	return mfaTypeEmail()
}

// setDeviceState 更新设备密钥状态快照。
func (s *Service) setDeviceState(keyID string, bound, needCode bool, codeType string, lastErr ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.device.keyID = keyID
	s.device.bound = bound
	s.device.needCode = needCode
	s.device.codeType = codeType
	if len(lastErr) > 0 {
		s.device.lastErr = lastErr[0]
	} else if !needCode {
		s.device.lastErr = ""
	}
}

// MarkKicked 在会话被服务端终止时清理本地状态。
//
// 与主动登出不同：这里不请求 /api/logout（会话已经没了），直接清 cookie 与
// session 文件，并在状态里留下原因，供面板提示"请重新登录"。
func (s *Service) MarkKicked(reason string) {
	// 先把状态置为"被踢"，后面的 saveCookies 才不会把空 cookie 写回去。
	s.mu.Lock()
	s.current = nil
	s.kicked = true
	s.kickReason = reason
	s.mu.Unlock()

	s.agent.Disconnect()
	s.client.ClearCookies()
	if path := s.cfg.SessionPath(); path != "" {
		archiveSessionFile(path)
	}
	s.agent.LogEvent("warn", "会话已失效，请重新登录（%s）", reason)
}

// archiveSessionFile 把失效的会话文件改名留档，而不是直接删掉。
//
// 直接删会让人误以为"session.json 被吞了/被重写了"，也丢掉唯一的现场
// （里面能看出是哪台设备、哪次登录的会话）。只保留最近 3 份，避免堆垃圾。
func archiveSessionFile(path string) {
	if _, err := os.Stat(path); err != nil {
		return
	}
	stamp := time.Now().Format("20060102-150405")
	_ = os.Rename(path, path+".kicked-"+stamp)
	pruneSessionArchives(path, 3)
}

// pruneSessionArchives 只保留最近 keep 份失效会话存档。
func pruneSessionArchives(path string, keep int) {
	matches, err := filepath.Glob(path + ".kicked-*")
	if err != nil || len(matches) <= keep {
		return
	}
	sort.Strings(matches)
	for _, old := range matches[:len(matches)-keep] {
		_ = os.Remove(old)
	}
}

// Kicked 返回是否处于"被服务端终止"状态。
func (s *Service) Kicked() (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kicked, s.kickReason
}

// ensureAgreement 检查并补签协议条款。
//
// 未签状态下服务端会让登录"成功但节点列表为空"，所以放在登录收尾里做。
func (s *Service) ensureAgreement(ctx context.Context) {
	pending, err := s.auth.AgreementPending(ctx)
	if err != nil || len(pending) == 0 {
		return
	}
	if err := s.auth.SignAgreement(ctx, pending); err != nil {
		s.agent.LogEvent("warn", "协议签署失败: %v", err)
		return
	}
	s.agent.LogEvent("info", "已补签协议 %d 项", len(pending))
}

// Logout 清除会话并断开隧道。
func (s *Service) Logout() error {
	s.agent.Disconnect()
	// 先让服务端注销会话：残留会话会导致"退出后立刻重登被反踢"。
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := s.auth.Logout(ctx, false); err != nil {
		s.agent.LogEvent("warn", "注销服务端会话失败: %v", err)
	}
	cancel()
	s.client.ClearCookies()
	s.mu.Lock()
	s.current = nil
	s.mu.Unlock()
	if path := s.cfg.SessionPath(); path != "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("删除会话文件: %w", err)
		}
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

// MfaState 返回二次验证阶段的当前状态，供面板渲染可选项与提示。
func (s *Service) MfaState() (pending bool, mfaType string, options []string, email, mobile string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil || !s.current.mfa {
		return false, "", nil, "", ""
	}
	return true, s.current.mfaType, append([]string(nil), s.current.authList...), s.current.email, s.current.mobile
}

// loginNext 是 LoginV2Result.next 的子集（字段名与官方 bean 一致）。
type loginNext struct {
	// Action 是下一步动作，2FA / GoToLink / OpenWebview / ChangeInitPassword 等。
	Action string
	// AuthList 是可用的二次认证方式。
	AuthList []string
	// Email / Mobile 是服务端回显的脱敏账号。
	Email  string
	Mobile string
}

// parseNext 解析 LoginV2Result 的下一步动作与可用认证方式。
func parseNext(data []byte) loginNext {
	var parsed struct {
		Result string `json:"result"`
		Next   struct {
			Action   string   `json:"action"`
			AuthList []string `json:"auth_list"`
			Email    string   `json:"email"`
			Mobile   string   `json:"mobile"`
		} `json:"next"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return loginNext{}
	}
	return loginNext{
		Action:   parsed.Next.Action,
		AuthList: parsed.Next.AuthList,
		Email:    parsed.Next.Email,
		Mobile:   parsed.Next.Mobile,
	}
}

// aliases 提取可用登录方式，便于报错提示。
func aliases(methods []api.ThirdPartyLogin) []string {
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		out = append(out, m.Alias)
	}
	return out
}
