package api

import (
	"net/url"
	"strconv"
	"time"
)

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
	EndpointCompanyMatch  = Endpoint{Path: "/api/match"}
	EndpointLoginSetting  = Endpoint{Path: "/api/login/setting"}
	EndpointTPSLink       = Endpoint{Path: "/api/tpslogin/link"}
	EndpointTPSToken      = Endpoint{Path: "/api/tpslogin/token/check"}
	EndpointTPSDevice     = Endpoint{Path: "/api/tpslogin/device/callback"}
	EndpointOTP           = Endpoint{Path: "/api/v2/p/otp"}
	EndpointInfoMe        = Endpoint{Path: "/api/info/me"}
	EndpointMFAType       = Endpoint{Path: "/api/mfa/type"}
	EndpointMFACodeSend   = Endpoint{Path: "/api/mfa/code/send"}
	EndpointMFACodeVerify = Endpoint{Path: "/api/mfa/code/verify"}
	EndpointMFASend       = Endpoint{Path: "/api/v1/login/mfa/send"}
	EndpointMFAVerify     = Endpoint{Path: "/api/v1/login/mfa/verify"}
)

// 隧道相关接口，签名参数取自服务端 http_sign_config。
var (
	EndpointVPNList   = Endpoint{Path: "/api/vpn/list", SigningInputParams: 510}
	EndpointVPNConn   = Endpoint{Path: "/vpn/conn", SigningInputParams: 542}
	EndpointVPNReport = Endpoint{Path: "/vpn/report"}
)

// Meta 是随每个请求上报的客户端元信息。
//
// 官方客户端把这些字段放在 query 里（而不是 header），服务端据此校验客户端版本
// 与设备环境；缺字段时登录 MFA 会返回 3019 "没有可用的二次认证方法"。
type Meta struct {
	// OS 是平台名，登录类接口固定 Android。
	OS string
	// OSVersion 是系统 API level（整数），例如 Android 12 的 32。
	OSVersion string
	// OSPatch 是系统安全补丁日期。
	OSPatch string
	// AppVersion 是客户端版本号。
	AppVersion string
	// BuildNumber 是客户端构建号。
	BuildNumber string
	// Model 是设备型号。
	Model string
	// Brand 是设备厂商。
	Brand string
	// Language 是语言标签，官方客户端用 zh 而非 zh-CN。
	Language string
	// ClientSource 固定为 FeiLian。
	ClientSource string
}

// Query 生成通用请求参数，timestamp 由调用时刻决定。
func (m Meta) Query() url.Values {
	return url.Values{
		"os":               {m.OS},
		"os_version":       {m.OSVersion},
		"os_version_patch": {m.OSPatch},
		"app_version":      {m.AppVersion},
		"build_number":     {m.BuildNumber},
		"model":            {m.Model},
		"brand":            {m.Brand},
		"language":         {m.Language},
		"client_source":    {m.ClientSource},
		"timestamp":        {strconv.FormatInt(time.Now().Unix(), 10)},
	}
}
