package api

import "net/url"

// 客户端伪装参数：与官方 Android 客户端保持一致的版本号。
const (
	// AppVersion 是上报的飞连客户端版本。
	AppVersion = "3.3.24"
	// BuildNumber 是上报的内部构建号，取自官方客户端的版本串。
	BuildNumber = "332400"
	// LoginOS 与 LoginOSVersion 是登录类接口使用的平台参数。
	// 服务端只在 Android 平台下发 TOTP secret，这是沿用官方移动端路径的原因。
	LoginOS        = "Android"
	LoginOSVersion = "2"
	// VPNOS 是节点列表/连接接口上报的平台。
	VPNOS = "Linux"
)

// Endpoint 描述一个接口的地址模板与需要携带的签名规则。
type Endpoint struct {
	// Path 是接口路径，不含查询串。
	Path string
	// SigningInputParams 为 0 表示不需要签名；否则是服务端下发的位掩码。
	SigningInputParams uint64
}

// 登录相关接口。
var (
	EndpointCompanyMatch = Endpoint{Path: "/api/match"}
	EndpointLoginSetting = Endpoint{Path: "/api/login/setting"}
	EndpointTPSLink      = Endpoint{Path: "/api/tpslogin/link"}
	EndpointTPSToken     = Endpoint{Path: "/api/tpslogin/token/check"}
	EndpointTPSDevice    = Endpoint{Path: "/api/tpslogin/device/callback"}
	EndpointOTP          = Endpoint{Path: "/api/v2/p/otp"}
)

// 隧道相关接口，签名参数取自服务端 http_sign_config。
var (
	EndpointVPNList   = Endpoint{Path: "/api/vpn/list", SigningInputParams: 510}
	EndpointVPNConn   = Endpoint{Path: "/vpn/conn", SigningInputParams: 542}
	EndpointVPNReport = Endpoint{Path: "/vpn/report"}
)

// loginQuery 构造登录类接口的公共查询参数。
func loginQuery() url.Values {
	return url.Values{"os": {LoginOS}, "os_version": {LoginOSVersion}}
}

// vpnQuery 构造节点类接口的公共查询参数。
func vpnQuery() url.Values {
	q := url.Values{
		"app_version":   {AppVersion},
		"build_number":  {BuildNumber},
		"client_source": {"FeiLian"},
		"language":      {"zh-CN"},
		"os":            {VPNOS},
		"os_release":    {"Linux"},
		"os_version":    {"Linux"},
		"soc":           {"aarch64"},
	}
	return q
}
