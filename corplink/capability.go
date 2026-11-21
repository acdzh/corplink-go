package corplink

// 租户能力探测。
//
// 有两类租户开关会让 WireGuard 这条路径直接失效，而且失败时服务端不会
// 给出可读原因：
//   - 强制 ZTNA（ZtnaSettingBean.proxy_enable / default_vpn_mode）：官方改走
//     TGW 通道（ZtnaModeResolver.java:16-24），我们只支持 WireGuard；
//   - need_trusted（DeviceTrustedConfig.java:11）：设备未登记时节点列表可能为空。
//
// 所以启动时各查一次，把结论写进事件日志，避免"登录成功但连不上"的黑盒。

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/acdzh/corplink-go/corplink/api"
)

// 租户能力探测用到的接口（官方 ZtnaApi.java、ew.java）。
var (
	// endpointZTNASetting 返回零信任接入配置。
	endpointZTNASetting = api.Endpoint{Path: "/api/network/v1/ztna/setting"}
	// endpointTrustedCheck 返回设备信任要求。
	endpointTrustedCheck = api.Endpoint{Path: "/api/emgr/v1/trusted_device/trusted_check"}
)

// ztnaSetting 是 ZTNA 配置里我们关心的字段。
type ztnaSetting struct {
	ProxyEnable    bool `json:"proxy_enable"`
	DefaultVPNMode int  `json:"default_vpn_mode"`
}

// trustedCheck 是设备信任要求。
type trustedCheck struct {
	NeedTrusted bool `json:"need_trusted"`
}

// probeTenantCapabilities 探测租户级开关并写事件。
func (c *Client) probeTenantCapabilities(ctx context.Context) {
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if env, err := c.api.Do(probeCtx, endpointZTNASetting, url.Values{}, nil); err == nil && env.OK() {
		setting := ztnaSetting{}
		_ = json.Unmarshal(env.Data, &setting)
		// default_vpn_mode=1 表示默认走 TGW（ZtnaModeResolver.java:12-13）。
		if setting.ProxyEnable || setting.DefaultVPNMode == 1 {
			c.agent.LogEvent("warn", "该租户启用了零信任接入（ZTNA），当前实现只支持 WireGuard，连接可能失败")
		}
	}

	if env, err := c.api.Do(probeCtx, endpointTrustedCheck, url.Values{}, nil); err == nil && env.OK() {
		check := trustedCheck{}
		_ = json.Unmarshal(env.Data, &check)
		if check.NeedTrusted {
			c.agent.LogEvent("info", "租户要求设备登记（need_trusted）；未登记时节点列表可能为空，可用 corplink dpop 与官方客户端确认")
		}
	}
}
