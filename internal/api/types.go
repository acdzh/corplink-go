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
	IP           string `json:"ip"`
	APIPort      int    `json:"api_port"`
	VPNPort      int    `json:"vpn_port"`
	ProtocolMode int    `json:"protocol_mode"`
	Name         string `json:"name"`
	EnName       string `json:"en_name"`
	ID           int    `json:"id"`
	Timeout      int    `json:"timeout"`
}

// WgSetting 是隧道附加配置。
type WgSetting struct {
	VpnMTU        uint32   `json:"vpn_mtu"`
	VpnDNS        string   `json:"vpn_dns"`
	VpnDNSBackup  string   `json:"vpn_dns_backup"`
	VpnDNSDomain  []string `json:"vpn_dns_domain_split"`
	VpnRouteFull  []string `json:"vpn_route_full"`
	VpnRouteSplit []string `json:"vpn_route_split"`
	V6RouteFull   []string `json:"v6_route_full"`
	V6RouteSplit  []string `json:"v6_route_split"`
}

// WgInfo 是 /vpn/conn 返回的隧道参数。
type WgInfo struct {
	IP        string    `json:"ip"`
	IPv6      string    `json:"ipv6"`
	IPMask    string    `json:"ip_mask"`
	PublicKey string    `json:"public_key"`
	Setting   WgSetting `json:"setting"`
	Mode      uint32    `json:"mode"`
}

// ParseWgInfo 解析 /vpn/conn 的返回。
func ParseWgInfo(raw []byte) (*WgInfo, error) {
	out := &WgInfo{}
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, fmt.Errorf("解析隧道配置: %w", err)
	}
	return out, nil
}
