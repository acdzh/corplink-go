package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/acdzh/corplink-go/corplink/api"
)

// Service 封装登录相关的接口调用。
type Service struct {
	client *api.Client
}

// NewService 基于已构造的 HTTP 客户端创建登录服务。
func NewService(client *api.Client) *Service { return &Service{client: client} }

// Setting 拉取租户登录配置。
func (s *Service) Setting(ctx context.Context) (*api.LoginSetting, error) {
	env, err := s.client.Do(ctx, api.EndpointLoginSetting, nil, nil)
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
	// 服务端按 query 里的 os/os_version 判断下发哪种形态：带上下文是移动端 PKCE。
	// 元信息由 api.Client 统一拼在 query 上，这里只需要挑战码；withOS 仅影响
	// 调用方语义（探测时两种形态都试），不再重复拼参数。
	q := url.Values{"code_challenge": {challenge}}
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
	env, err := s.client.Do(ctx, api.EndpointTPSToken, nil, body)
	if err != nil {
		return err
	}
	if !env.OK() {
		return env.Error()
	}
	return nil
}

// DeviceCallback 用授权码完成登录（移动端 PKCE 流程）。
// 返回原始 data，便于上层判断服务端是否要求追加步骤（如 2FA）。
func (s *Service) DeviceCallback(ctx context.Context, aliasKey, code, state, verifier string) (json.RawMessage, error) {
	body := map[string]string{
		"alias_key":     aliasKey,
		"code":          code,
		"state":         state,
		"code_verifier": verifier,
	}
	env, err := s.client.Do(ctx, api.EndpointTPSDevice, nil, body)
	if err != nil {
		return nil, err
	}
	if !env.OK() {
		return nil, env.Error()
	}
	return env.Data, nil
}

// MfaType 查询某个 mfa_scene 下可用的二次认证方式。
func (s *Service) MfaType(ctx context.Context, scene string) (*api.MfaType, error) {
	env, err := s.client.Do(ctx, api.EndpointMFAType, url.Values{"mfa_scene": {scene}}, nil)
	if err != nil {
		return nil, err
	}
	if !env.OK() {
		return nil, env.Error()
	}
	out := &api.MfaType{}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return nil, fmt.Errorf("解析 MFA 方式: %w", err)
	}
	return out, nil
}

// MfaCodeSend 用 MFA v2 接口下发验证码。
func (s *Service) MfaCodeSend(ctx context.Context, scene, codeType string) error {
	return s.MfaCodeSendExtra(ctx, scene, codeType, nil)
}

// MfaCodeSendExtra 在下发验证码时附带额外字段。
//
// 设备密钥登记走的就是这套接口（scene=device_key），官方客户端在这里
// 只发 mfa_scene + code_type，设备字段留到校验时才带。
func (s *Service) MfaCodeSendExtra(ctx context.Context, scene, codeType string, extra map[string]any) error {
	body := map[string]any{"mfa_scene": scene, "code_type": codeType}
	for k, v := range extra {
		body[k] = v
	}
	env, err := s.client.Do(ctx, api.EndpointMFACodeSend, nil, body)
	if err != nil {
		return err
	}
	if !env.OK() {
		return env.Error()
	}
	return nil
}

// MfaCodeVerify 用 MFA v2 接口校验验证码，成功后登录态才有效。
func (s *Service) MfaCodeVerify(ctx context.Context, scene, codeType, code string) (json.RawMessage, error) {
	return s.MfaCodeVerifyExtra(ctx, scene, codeType, code, nil)
}

// MfaCodeVerifyExtra 在校验验证码时附带额外字段。
//
// 官方客户端的请求体固定为
//
//	{mfa_scene, code_type, action: <同一个 scene>, code, device_key_id,
//	 device_key_protected_level, device_public_key}
//
// action 与 mfa_scene 取同值是设备密钥登记能落地的关键。
func (s *Service) MfaCodeVerifyExtra(ctx context.Context, scene, codeType, code string, extra map[string]any) (json.RawMessage, error) {
	body := map[string]any{
		"mfa_scene": scene,
		"code_type": codeType,
		"code":      code,
	}
	if scene != "" {
		body["action"] = scene
	}
	for k, v := range extra {
		body[k] = v
	}
	env, err := s.client.Do(ctx, api.EndpointMFACodeVerify, nil, body)
	if err != nil {
		return nil, err
	}
	if !env.OK() {
		return nil, env.Error()
	}
	return env.Data, nil
}

// DpopStatus 查询本设备的密钥登记状态。
func (s *Service) DpopStatus(ctx context.Context) (*api.DpopStatus, error) {
	env, err := s.client.Do(ctx, api.EndpointDpopStatus, nil, nil)
	if err != nil {
		return nil, err
	}
	if !env.OK() {
		return nil, env.Error()
	}
	out := &api.DpopStatus{}
	if len(env.Data) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return nil, fmt.Errorf("解析设备密钥状态: %w", err)
	}
	return out, nil
}

// MfaSend 触发一次登录 MFA 验证码下发。loginScene 一般是 feilian，mfaType 为 email 或 mobile。
func (s *Service) MfaSend(ctx context.Context, loginScene, mfaType, account string) (json.RawMessage, error) {
	body := map[string]string{"login_scene": loginScene, "mfa_type": mfaType, "account": account}
	env, err := s.client.Do(ctx, api.EndpointMFASend, nil, body)
	if err != nil {
		return nil, err
	}
	if !env.OK() {
		return nil, env.Error()
	}
	return env.Data, nil
}

// MfaVerify 提交 MFA 验证码，成功后登录态才真正建立。
func (s *Service) MfaVerify(ctx context.Context, loginScene, mfaType, account, code string) (json.RawMessage, error) {
	body := map[string]string{"login_scene": loginScene, "mfa_type": mfaType, "account": account, "code": code}
	env, err := s.client.Do(ctx, api.EndpointMFAVerify, nil, body)
	if err != nil {
		return nil, err
	}
	if !env.OK() {
		return nil, env.Error()
	}
	return env.Data, nil
}

// OTP 拉取 TOTP 绑定信息（url 里带 secret），供二次验证自动生成验证码。
func (s *Service) OTP(ctx context.Context) (*api.OtpInfo, error) {
	env, err := s.client.Do(ctx, api.EndpointOTP, nil, map[string]string{})
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

// Logout 通知服务端注销当前会话。
//
// 不调它的代价是服务端会话残留：退出后立刻重登可能被 self_kick_out 反踢，
// 多设备场景还会占满并发名额（s1.java:63、tf0.java:35）。
func (s *Service) Logout(ctx context.Context, all bool) error {
	q := url.Values{}
	if all {
		q.Set("logout_all", "true")
	}
	env, err := s.client.Do(ctx, api.EndpointLogout, q, nil)
	if err != nil {
		return err
	}
	if !env.OK() && !env.LoggedOut() {
		return env.Error()
	}
	return nil
}

// Agreement 返回当前租户的协议条款与签署状态。
func (s *Service) Agreement(ctx context.Context) (*api.AgreementConfig, error) {
	env, err := s.client.Do(ctx, api.EndpointAgreement, nil, nil)
	if err != nil {
		return nil, err
	}
	if !env.OK() {
		return nil, env.Error()
	}
	out := &api.AgreementConfig{}
	if len(env.Data) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return nil, fmt.Errorf("解析协议条款: %w", err)
	}
	return out, nil
}

// AgreementPending 返回尚未签署的协议标识。
func (s *Service) AgreementPending(ctx context.Context) ([]string, error) {
	cfg, err := s.Agreement(ctx)
	if err != nil {
		return nil, err
	}
	if !cfg.EmployeeAgreementEnable && !cfg.GuestAgreementEnable {
		return nil, nil
	}
	keys := make([]string, 0, len(cfg.AgreementList))
	for _, item := range cfg.AgreementList {
		if item.IsRequired && !item.Signed {
			keys = append(keys, strconv.Itoa(item.ID))
		}
	}
	return keys, nil
}

// SignAgreement 批量签署协议；keys 为空表示全部。
func (s *Service) SignAgreement(ctx context.Context, keys []string) error {
	body := map[string]any{"keys": keys}
	env, err := s.client.Do(ctx, api.EndpointAgreementSign, nil, body)
	if err != nil {
		return err
	}
	if !env.OK() {
		return env.Error()
	}
	return nil
}

// ReportDevice 上报本机设备信息（/api/device/report）。
//
// 官方客户端在登录成功后用 newLogin=true 报一次，运行期再周期上报。
// 这台设备在服务端的设备表里存在之后，节点才会认这个会话：
// 少了这一步，/vpn/conn 会回 3015「Session 无效」，报完立刻就能连。
func (s *Service) ReportDevice(ctx context.Context, newLogin bool, meta api.Meta, name, model, brand string) error {
	payload := map[string]any{"new_login": newLogin, "items": deviceReportItems(meta, name, model, brand)}
	env, err := s.client.Do(ctx, api.EndpointDeviceReport, nil, payload)
	if err != nil {
		return err
	}
	if !env.OK() {
		return env.Error()
	}
	return nil
}

// deviceReportItems 生成设备上报的 items。
//
// 官方客户端报的是本机真实的内存/磁盘/CPU/网卡，我们只对齐字段形状，
// 填固定的合理值：服务端要的是"这台设备存在且有画像"，不是精确读数。
// device_name / model / brand 额外带上，控制台"登录设备"里才有名字可显示，
// 否则只会看到一排 "Android"（官方客户端由系统给出设备名）。
func deviceReportItems(meta api.Meta, name, model, brand string) []map[string]any {
	if model == "" {
		model = meta.Model
	}
	if brand == "" {
		brand = meta.Brand
	}
	name = reportDeviceName(name, model)
	return []map[string]any{
		{"key": "device_name", "value": name},
		{"key": "model", "value": model},
		{"key": "brand", "value": brand},
		{"key": "memory_total", "value": 8},
		{"key": "memory_available", "value": 4},
		{"key": "disk_total", "value": 256},
		{"key": "disk_available", "value": 128},
		{"key": "cpu_model", "value": "Tensor G2"},
		{"key": "os_model", "value": "android"},
		{"key": "os_detail_version", "value": meta.OSVersion},
		{"key": "nic_detail_list", "value": map[string]any{
			"wlan0": map[string]any{
				"mac_addr":   "3c:5a:b4:1a:2b:3c",
				"active":     true,
				"ipv4":       "192.168.1.100",
				"ipv6":       []string{},
				"dns":        []string{"192.168.1.1"},
				"is_virtual": false,
			},
		}},
	}
}

// reportDeviceName 返回可以外发的设备名。
//
// 设备名会显示在租户控制台的"登录设备"里，属于对外暴露面：绝不能带本项目
// 的痕迹（corplink-go / corplink 等），否则一眼就能看出不是官方客户端。
// 名字缺失或命中黑名单时退回机型名（如 Pixel 7），这是官方客户端也会显示的值。
func reportDeviceName(name, model string) string {
	trimmed := strings.TrimSpace(name)
	lower := strings.ToLower(trimmed)
	if trimmed == "" || strings.Contains(lower, "corplink") {
		trimmed = strings.TrimSpace(model)
	}
	if trimmed == "" {
		trimmed = "Android Device"
	}
	return trimmed
}

// VPNMfaType 查询连接（vpn）场景可用的二次认证方式。
func (s *Service) VPNMfaType(ctx context.Context) (*api.MfaType, error) {
	return s.MfaType(ctx, "vpn")
}

// VerifyMfaCode 用 MFA v2 接口校验任意场景的验证码（连接期认证也走这里）。
func (s *Service) VerifyMfaCode(ctx context.Context, scene, codeType, code string, extra map[string]any) error {
	_, err := s.MfaCodeVerifyExtra(ctx, scene, codeType, code, extra)
	return err
}
