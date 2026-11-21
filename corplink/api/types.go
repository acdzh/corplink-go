// Package api 封装飞连服务端的 HTTP 协议：地址模板、请求头、Cookie 与签名。
package api

import (
	"encoding/json"
	"fmt"
)

// Envelope 是所有飞连接口的统一响应外壳。
type Envelope struct {
	Code    int             `json:"code"`
	Action  string          `json:"action"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
	// LogoutReason 只在会话失效时出现，用于区分"需要重新登录"与其他错误。
	LogoutReason json.RawMessage `json:"logout_reason,omitempty"`
}

// OK 表示业务成功。
func (e Envelope) OK() bool { return e.Code == 0 }

// LoggedOut 判断这次响应是否表示"会话被服务端作废"。
//
// 官方客户端认两种信号：action=logout（lb.java:880-882），以及 101
// 「登录已过期」。两者都会带着 logout_reason 说明原因。
func (e Envelope) LoggedOut() bool {
	if e.Code == 0 {
		return false
	}
	return e.Action == "logout" || e.Code == CodeSessionExpired || len(e.LogoutReason) > 0
}

// KickedError 把"被踢/会话失效"包装成可判定的错误，避免调用方只能比字符串。
func (e Envelope) KickedError() error {
	reason := KickReason{}
	_ = json.Unmarshal(e.LogoutReason, &reason)
	return &KickedError{Code: e.Code, Message: e.Message, Reason: reason.Reason, Scene: reason.Scene}
}

// KickReason 是服务端下发的下线原因（LogoutReason.java:11-15）。
type KickReason struct {
	// Reason 是给人看的原因描述。
	Reason string `json:"reason"`
	// Scene 是下线场景，决定要清到什么程度。
	Scene string `json:"scene"`
}

// KickedError 表示会话已被服务端终止。
type KickedError struct {
	// Code 是业务码（常见 101）。
	Code int
	// Message 是服务端文案。
	Message string
	// Reason 是下线原因。
	Reason string
	// Scene 是下线场景，取值见 KickScene*。
	Scene string
}

// Error 实现 error。
func (e *KickedError) Error() string {
	if e.Message != "" {
		return "会话已失效: " + e.Message
	}
	return "会话已失效（被服务端终止）"
}

// NeedFullClean 判断是否需要连设备密钥绑定一起清（LogoutReason.isNeedLogoutCas 的六个场景）。
func (e *KickedError) NeedFullClean() bool {
	switch e.Scene {
	case KickSceneLogout, KickSceneXiaomiCAS, KickSceneAdmin, KickSceneAPI, KickSceneSelf, KickSceneDynamicControl:
		return true
	}
	return false
}

// 会话终止场景，对应 LogoutReason.java 的六个 kick_out 取值。
const (
	// KickSceneLogout 是正常登出。
	KickSceneLogout = "logout"
	// KickSceneXiaomiCAS 是小米 CAS 踢线。
	KickSceneXiaomiCAS = "xiaomi_cas_kick_out"
	// KickSceneAdmin 是管理员踢线。
	KickSceneAdmin = "admin_kick_out"
	// KickSceneAPI 是接口侧踢线。
	KickSceneAPI = "api_kick_out"
	// KickSceneSelf 是其它端登录把自己顶掉。
	KickSceneSelf = "self_kick_out"
	// KickSceneDynamicControl 是风控踢线。
	KickSceneDynamicControl = "dynamic_control_kick_out"
)

// CodeSessionExpired 是飞连的"登录已过期"业务码。
const CodeSessionExpired = 101

// Error 把业务错误码与消息拼成可读错误。
func (e Envelope) Error() error {
	return &BusinessError{Code: e.Code, Message: e.Message, Action: e.Action}
}

// BusinessError 是服务端返回的业务错误。
type BusinessError struct {
	Code    int
	Message string
	Action  string
}

func (e *BusinessError) Error() string {
	return "飞连接口返回错误 " + itoa(e.Code) + ": " + e.Message
}

// itoa 避免为了一个格式化引入 strconv 之外的依赖链。
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// DpopStatus 是 /api/v1/device/dpop 返回的设备密钥登记状态。
//
// 线上样例（2026-11-22）：
//
//	{"registered":true,"enabled":true,"device_key_status":1,
//	 "device_key_id":"<device_id>_<uuid>","device_key_registered_at":1793464649,
//	 "device_public_key":{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","x":"..","y":".."},
//	 "registration_notice":{"mfa_type":"otp","backup_mfa_type":["mobile","email"],"allow_skip":true,...}}
type DpopStatus struct {
	// Registered 表示该 device_key_id 已在服务端登记。
	Registered bool `json:"registered"`
	// Enabled 表示租户开启了这个能力；关掉时服务端不会下发 vpn-token。
	Enabled bool `json:"enabled"`
	// DeviceKeyID 是服务端记录的 device_key_id，与本地密钥不一致说明密钥被换过。
	DeviceKeyID string `json:"device_key_id"`
	// DeviceKeyStatus 是登记状态机：1 正常，2/3 需要重新登记。
	DeviceKeyStatus int `json:"device_key_status"`
	// DeviceKeyRegisteredAt 是登记时间（unix 秒）。
	DeviceKeyRegisteredAt int64 `json:"device_key_registered_at"`
	// Email 是脱敏后的账号邮箱。
	Email string `json:"email"`
	// DevicePublicKey 是服务端存的公钥，用于核对本地密钥是否仍然有效。
	DevicePublicKey DpopPublicKey `json:"device_public_key"`
	// RegistrationNotice 是登记引导（何时弹窗、用哪种 MFA）。
	RegistrationNotice *DpopNotice `json:"registration_notice"`
}

// Bound 判断服务端是否已经接受该设备公钥。
func (s DpopStatus) Bound(keyID string) bool {
	if !s.Registered || !s.Enabled {
		return false
	}
	if s.DeviceKeyStatus == 2 || s.DeviceKeyStatus == 3 {
		return false
	}
	return s.DeviceKeyID == "" || s.DeviceKeyID == keyID
}

// DpopPublicKey 是服务端返回的设备公钥 JWK。
type DpopPublicKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// DpopNotice 是设备密钥登记的引导配置。
type DpopNotice struct {
	// Enabled 表示是否需要引导用户去登记。
	Enabled bool `json:"enabled"`
	// AllowSkip 表示用户可以跳过。
	AllowSkip bool `json:"allow_skip"`
	// IntervalSeconds 是两次引导之间的最小间隔。
	IntervalSeconds int `json:"interval_seconds"`
	// MaxCount 是引导次数上限。
	MaxCount int `json:"max_count"`
	// MFAType 是主用二次认证方式（otp / mobile / email）。
	MFAType string `json:"mfa_type"`
	// BackupMFAType 是备用认证方式。
	BackupMFAType []string `json:"backup_mfa_type"`
	// DeviceTypes 是适用的端类型。
	DeviceTypes []string `json:"device_types"`
	// Dialog 是引导弹窗文案。
	Dialog *DpopNoticeDialog `json:"dialog"`
}

// DpopNoticeDialog 是引导弹窗的文案。
type DpopNoticeDialog struct {
	Title           string `json:"title"`
	Content         string `json:"content"`
	PrimaryButton   string `json:"primary_button"`
	SecondaryButton string `json:"secondary_button"`
}

// CompanyInfo 是 /api/match 返回的企业信息。
type CompanyInfo struct {
	Name    string `json:"name"`
	ZhName  string `json:"zh_name"`
	EnName  string `json:"en_name"`
	Domain  string `json:"domain"`
	SelfSSL bool   `json:"enable_self_signed"`
}

// LoginSetting 是 /api/login/setting 的关键字段。
type LoginSetting struct {
	LoginVersion     string   `json:"login_version"`
	ServerVersion    int      `json:"server_version"`
	LoginOrders      []string `json:"login_orders"`
	LoginEnable      bool     `json:"login_enable"`
	PasswordEncrypt  bool     `json:"password_encrypted"`
	AccountTypes     []string `json:"login_account"`
	OTPEnabled       bool     `json:"-"`
	LocalServerPort  int      `json:"local_server_http_port"`
	MobileAuthEnable bool     `json:"mobile_auth_enabled"`
}

// ThirdPartyLogin 是 /api/tpslogin/link 返回的单个登录方式。
type ThirdPartyLogin struct {
	Alias     string `json:"alias"`
	AliasKey  string `json:"alias_key"`
	LoginURL  string `json:"login_url"`
	FullTitle string `json:"full_title"`
	Token     string `json:"token"`
}

// OtpInfo 是 /api/v2/p/otp 返回的 TOTP 绑定信息，url 里带 secret。
type OtpInfo struct {
	URL  string `json:"url"`
	Code string `json:"code"`
}

// MfaType 是 /api/mfa/type 的返回，描述某个场景可用的二次认证方式。
type MfaType struct {
	MfaScene string   `json:"mfa_scene"`
	Type     string   `json:"type"`
	Types    []string `json:"types"`
	Email    string   `json:"email"`
	Mobile   string   `json:"mobile"`
}

// VpnInfo 是 /api/vpn/list 返回的单个节点。
type VpnInfo struct {
	ID int `json:"id"`
	// ExportID 是节点的出口编号，连接时要回传给服务端（多出口租户按它选出口）。
	ExportID     int      `json:"export_id"`
	Type         string   `json:"type"`
	Name         string   `json:"name"`
	EnName       string   `json:"en_name"`
	TagName      string   `json:"tag_name"`
	Icon         string   `json:"icon"`
	IP           string   `json:"ip"`
	InternalIP   string   `json:"internal_ip"`
	DomainName   string   `json:"domain_name"`
	BackupIPs    []string `json:"backup_ips"`
	APIPort      int      `json:"api_port"`
	VPNPort      int      `json:"vpn_port"`
	ProtocolMode int      `json:"protocol_mode"`
	Timeout      int      `json:"timeout"`
	// Dedicated 表示服务端把节点标为专属节点：只授权给特定人群使用，
	// 官方客户端把它排在列表最后，自动选路也不会连它。
	Dedicated bool `json:"dedicated"`
}

// WgSetting 是隧道附加配置。
//
// 字段清单对齐官方 VpnConfigModel.java:130-210 的解析范围；服务端不下发的
// 字段保持零值，使用方按空值跳过。
type WgSetting struct {
	VpnMTU        uint32   `json:"vpn_mtu"`
	VpnDNS        string   `json:"vpn_dns"`
	VpnDNSBackup  string   `json:"vpn_dns_backup"`
	VpnDNSDomain  []string `json:"vpn_dns_domain_split"`
	VpnRouteFull  []string `json:"vpn_route_full"`
	VpnRouteSplit []string `json:"vpn_route_split"`
	V6RouteFull   []string `json:"v6_route_full"`
	V6RouteSplit  []string `json:"v6_route_split"`
	// DynamicDomain 是需要走隧道/内网解析的域名清单（数组形态，线上实测有值）。
	DynamicDomain []string `json:"dynamic_domain"`
	// DynamicDomainRouteSplit 是动态域名路由规则（对象形态，按需展开）。
	DynamicDomainRouteSplit map[string]any `json:"vpn_dynamic_domain_route_split"`
	// WildcardDynamicDomainRouteSplit 是通配域名规则。
	WildcardDynamicDomainRouteSplit map[string]any `json:"vpn_wildcard_dynamic_domain_route_split"`
	// SuffixWildcardDynamicDomainRouteSplit 是后缀通配规则（服务端可能下发 null）。
	SuffixWildcardDynamicDomainRouteSplit any `json:"suffix_wildcard_dynamic_domain_route_split"`
	// CentralDNS 是内网 DNS 的 dnat vip 配置。
	CentralDNS CentralDNS `json:"central_dns"`
	// IPNats 是 NAT 后需要额外加路由的地址段。
	IPNats []IPNat `json:"ip_nats"`
	// SearchDomain 是解析搜索域（官方客户端未使用，保留取值）。
	SearchDomain []string `json:"search_domain"`
	// ExcludeRoute 是不进隧道的网段。
	ExcludeRoute []string `json:"exclude_route"`
	// ExcludeStaticDomain 是静态排除域名：这些域名不走公司 DNS。
	ExcludeStaticDomain []string `json:"exclude_static_domain"`
	// ExcludeDynamicDomain 是动态排除域名（对象形态，键即域名）。
	ExcludeDynamicDomain map[string]any `json:"exclude_dynamic_domain"`
	// VpnGlobalExclude 是全局排除项。
	VpnGlobalExclude VpnGlobalExclude `json:"vpn_global_exclude"`
}

// CentralDNS 是内网 DNS 配置。
type CentralDNS struct {
	// DNS 是内网 DNS 地址列表。
	DNS []string `json:"dns"`
	// Vip 是内网 DNS 的 dnat 网段，官方缺省按 30.100.0.0/14 处理。
	Vip string `json:"vip"`
}

// VpnGlobalExclude 是全局排除的域名与网段。
type VpnGlobalExclude struct {
	// Domains 是不走公司 DNS 的域名。
	Domains []string `json:"domains"`
	// IPs 是不走隧道的地址。
	IPs []string `json:"ips"`
}

// IPNat 是一条 NAT 映射。
type IPNat struct {
	// IPs 是 NAT 之后需要加路由的地址。
	IPs []string `json:"ips"`
}

// WgInfo 是 /vpn/conn 返回的隧道参数。
type WgInfo struct {
	IP        string    `json:"ip"`
	IPv6      string    `json:"ipv6"`
	IPMask    string    `json:"ip_mask"`
	PublicKey string    `json:"public_key"`
	Setting   WgSetting `json:"setting"`
	Mode      uint32    `json:"mode"`
	// PresharedKey 是日常 PSK：服务端下发时必须写进 WireGuard，否则握手全失败。
	PresharedKey string `json:"preshared_key"`
	// SignToken 是重连凭据：重发 /vpn/conn 时带上，服务端才认作同一会话。
	SignToken string `json:"sign_token"`
	// Identities 是会话身份串，同样用于重连与原地址复用。
	Identities string `json:"identities"`
	// ProtocolVersion 是服务端声明的协议版本（线上是字符串形态）。
	ProtocolVersion string `json:"protocol_version"`
}

// ParseWgInfo 解析 /vpn/conn 的返回。
func ParseWgInfo(raw []byte) (*WgInfo, error) {
	out := &WgInfo{}
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, fmt.Errorf("解析隧道配置: %w", err)
	}
	return out, nil
}

// AgreementConfig 是协议条款与签署状态（/api/v1/config/agreement）。
type AgreementConfig struct {
	// EmployeeAgreementEnable 表示员工登录需要签署协议。
	EmployeeAgreementEnable bool `json:"employee_auth_agreement_enable"`
	// GuestAgreementEnable 表示访客需要签署协议。
	GuestAgreementEnable bool `json:"guest_auth_agreement_enable"`
	// AgreementList 是条款列表。
	AgreementList []AgreementItem `json:"agreement_list"`
}

// AgreementItem 是一条协议。
type AgreementItem struct {
	// ID 是协议编号。
	ID int `json:"id"`
	// IsRequired 表示必须签署。
	IsRequired bool `json:"is_required"`
	// Signed 表示本账号是否已签。
	Signed bool `json:"signed"`
	// Link 是协议正文链接。
	Link string `json:"link"`
}
