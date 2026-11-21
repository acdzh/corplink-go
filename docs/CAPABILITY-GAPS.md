# corplink-go 能力缺口清单（官方客户端 vs Go 复刻）

> 2026-11-22 全量审计。证据来自 reference/jadx-sources/（jadx 反编译）与 Go 源码实测行号。
> 5 个领域并行审计：数据面 / 会话 / 合规 / 路由 / 运行期，原始表见 .ai-tmp/gap3/。

## 结论

主链路（登录 → 节点 → 隧道 → 代理，含 DPoP）可用。剩余 **4 条 P0、20 条 P1**，集中于：
换租户就炸的隐性协议项 > 时钟与凭证正确性 > 弱网建连成功率 > 分流规则完整性。

## P0（不补会直接连不上 / 零流量）

| # | 缺口 | 官方证据 | Go 现状 | 影响 |
| --- | --- | --- | --- | --- |
| P0-1 | **WireGuard PSK 未支持** | VpnConfigModel.java:143 解析 preshared_key；ServerOperator.java:133 | tunnel.go:32-56 无 PSK 字段，buildUAPI（tunnel.go:179-208）不写 preshared_key | 开 PSK 的租户：隧道建起来但握手全失败 → connected:true 却零流量，日志只有握手超时。本租户未返回该字段，属换租户必炸 |
| P0-2 | **连接期二次认证 20210002 未处理** | VpnConfigModel.java:130-132（3002→20210002）、ServerOperator.java:99-102 暂停、:217-232 resumeMfa 重发同一 body | agent.go:1004-1012 只走 recoverConn，其余码直接返回错误 | 账号开「连接需二次认证」时永远连不上，且只有一句「连接失败」 |
| P0-3 | **时钟偏差未校正（TOTP + DPoP iat）** | MainActivity.java:2399-2401 / k31.java:31-33 存 otp_time_diff；yk0.java:428 TOTP 叠加；zr.java:25-28 + hz.java:28 proof 的 iat 叠加；OtpSyncHelper.java:26-33 / aq.java:36 用 Date 头兜底 | totp.go:32、dpop.go:167,195、endpoints.go:107 全是 time.Now()；types.go 未建模 timestamp | 偏差 ≤30s 安全、30~60s 概率失败、≥60s 恒定失败（设备密钥登记挂 → 3015）；DPoP 窗口 ±300s，超了拿不到节点列表 |
| P0-4 | **租户强制 ZTNA 时静默失败** | ZtnaApi.java:18-31、ZtnaSettingBean.java:12-22（proxy_enable / default_vpn_mode）、ZtnaModeResolver.java:16-24 | 全树 ztna 零命中，仍按 WireGuard 拨号 | 开零信任接入的租户：登录成功、连接建不起来且无提示。短期不必实现 ZTNA，但必须检测并明确报错 |

## P1 —— 连接建立

| # | 缺口 | 官方证据 | Go 现状 | 影响 |
| --- | --- | --- | --- | --- |
| 1 | 节点重试阶梯缺失 | ServerOperator.java:43-45（Auto=3 dot / 手动=1）、:81（每 dot retry<3）、:103（仅 1010 重试）、:144-189（dot 只选一次） | agent.go:1000-1012 单发一次 | 弱网或节点抖动即整体失败；官方一次点击内最多 3×3 自愈 |
| 2 | 协议探测缺失（UDP 被封不切 TCP） | VpnManagerImpl.java:1527-1533、:1047-1062（switchToUdp/Tcp + reHandshake）、:833,946 | agent.go:1029-1032 按 node.ProtocolMode 静态选；Watchdog（agent.go:1158-1169）同协议无限重连 | UDP 被运营商封时形成重连死循环，永不恢复 |
| 3 | MTU 探测缺失 | VpnManagerImpl.java:1452-1461 | agent.go:1033 直接用 vpn_mtu，tunnel.go:74-76 仅在 ≤0 时兜底 1420 | PPPoE 链路下发 1500 时大包黑洞：ping 通、TLS 卡死、网页转圈 |
| 4 | mode / export_id / not_auto / sign_token / identities 未发送 | VpnConfigModel.java:73-80、ServerOperator.java:92 | agent.go:996-999 只发 public_key + otp；recoverConn（agent.go:923）重发首建 body | 多出口租户走错出口、被 ACL 拒；重连被当新会话（丢 sign_token/identities）→ 会话数翻倍、分配 IP 变化 |
| 5 | IPv6 路由未生效 | VpnConfigModel.java:199-208 | types.go:212-213 有字段，agent.go:1036-1043 选路由从不用 | 双栈租户：分到 v6 地址却无 v6 路由，v6 内网不可达 |

## P1 —— 分流路由

| # | 缺口 | 官方证据 | Go 现状 | 影响 |
| --- | --- | --- | --- | --- |
| 6 | 内网域名 DNS 分流未实现 | VpnConfigModel.java:150-155（内网 DNS 后缀表）、WgaOperator.java:323-327 | agent.go:1019-1023 只取全局 DNS；sub.go:107-113 把域名降级为 DOMAIN-SUFFIX，sub.go:62 硬编码 223.5.5.5 | Clash 模式下内网域名 NXDOMAIN：「连上了但公司站点打不开」 |
| 7 | 四类动态域名规则整段缺失 | VpnConfigModel.java:156-159（4 个 optString 规则文本） | types.go:205-213 无对应 tag，反序列化静默丢弃 | 后端 IP 动态变化的租户：目标不在 allowed_ip → 内网接口超时 |
| 8 | ip_nats / central_dns.vip 未解析 | ServerOperator.java:315-333、:23（DEFAULT_VIPS 30.100.0.0/14）、:302-312 | 全树零命中 | NAT 后服务地址与内网 DNS dnat vip 不在路由表 → 解析超时、服务不可达 |
| 9 | 分流网段命中控制面 API IP 时未减除 | VpnConfigModel.java:180-198（网段减 apiIp/32） | agent.go:1037-1058 直接用 routesSplit | 下发 10.0.0.0/8 且 API 在 10.x：请求被塞进隧道 →「能连上但一分钟就掉」 |
| 10 | AllowedIPs 混入域名会炸隧道（防御缺失） | ServerOperator.java:268-272（域名是 String 通道，与 IP 列表两套） | tunnel.go:195-204 对不含 / 的条目无条件补 /32 | 一旦把规则文本接进路由，UAPI 解析失败、建隧道报错且看不出原因 |
| 11 | Clash 订阅规则来源不完整 | VpnConfigModel.java:150-210 全量 setting | corplink.go:615-634、sub.go:44-118 只有 IP-CIDR / DOMAIN-SUFFIX / MATCH | 订阅用户公司 NAT 网段与内网域名全走直连 |

## P1 —— 会话与凭证

| # | 缺口 | 官方证据 | Go 现状 | 影响 |
| --- | --- | --- | --- | --- |
| 12 | 被踢线未识别（logout_reason 丢弃） | BaseResponse.java:21-22、lb.java:880-882、LogoutReason.java:11-15,31-69 | types.go:16 声明零引用；BusinessError 丢字段；agent.go:442-444 一律塞 lastErr | 后台踢下线后隧道不断、仍显示「已连接」，但所有请求 401 |
| 13 | 被踢后的清理分级缺失 | LogoutReason.isNeedLogoutCas 六值白名单、v9.java:75-84 | 无 | 只删 session 不清设备密钥绑定 → 重登卡在 DPoP 登记 |
| 14 | 主动登出不调 /api/logout | tf0.java:35-36、s1.java:63-64 | login/service.go:531-544 只清本地 | 退出后立刻重登可能被 self_kick_out 反踢；服务端会话占额 |
| 15 | /vpn/report 从未调用（也是唯一踢线信号） | VpnReportOperator.java:44（type=100）/ :80（type=101）、VpnManagerImpl.java:1355-1371（60s 周期）、VpnReportOperator.java:51-53（响应 code=1000 表示被踢） | endpoints.go:61 定义但零调用 | 服务端无在线记录、无法感知下线；被踢只能等看门狗按握手超时猜 |
| 16 | 协议签署缺失 | eo.java:19,25、tf0.java:56、MainActivity.java:2496,2512 | 无端点；service.go:210-211 未知 action 直接抛错 | 开启后：登录中断，或登录成功但节点列表为空 |
| 17 | MFA 类型写死 email | v21.java:17-24、MfaViewModel.java:465-467、DpopRegistrationStatusBean.java:161,179 | auth/login.go:99-112 已实现但零调用；service.go:30-33,247 写死 | 租户关邮箱只留 TOTP/短信：「没有可用的二次认证方法」，登录卡死 |

## P1 —— 租户特性

| # | 缺口 | 官方证据 | Go 现状 | 影响 |
| --- | --- | --- | --- | --- |
| 18 | 设备信任 trusted_check / create_cert 缺失 | ew.java:54-58、DeviceTrustedConfig.java:11-12、MainActivity.java:2163、DeviceRegisterActivity.java:612,630 | 无 | 开 need_trusted 的租户：节点列表空 / 403，无提示与修复入口 |
| 19 | /api/device/report 循环上报缺失 | ew.java:36-37、MainActivity.java:3349,3351、kw.java:120-185 | agent.go:529-540 无 | 服务端设备画像缺失，异常登录/次数限制策略误判 |
| 20 | ws 长连接缺失（MFA 推送审批） | bz1.java:72（端点）、:71（20s ping）、:100-113（message_received 回执）、az1.java:41-50（重试 3 次） | 全树零命中 | 开推送审批的租户：OTP/验证码都对但进不去主界面（等不到推送确认）；踢线/策略变更无法即时到达 |

## P2 / NO

| 项 | 判断 |
| --- | --- |
| not_auto、ip_nats（连接参数）、上报失败落盘重放 | P2，补 P1 时顺手 |
| 安全检测 /api/security/config 解析 + /report 上报 | P2：level 只影响 UI 配色（SecurityCheckActivity.java:385-411），不阻断连接 |
| trusted / untrusted 审批流、本地证书校验 | P2 |
| client_monitor(APM)、feature_flag、ws 事件枚举 | P2（ws 事件表需 smali 或真机抓帧补全） |
| 面板显示时钟偏差、Status.Kicked 字段 | P2 |
| **safemode** | NO：Android 崩溃保活（k40.java:87-105），Go 常驻进程无等价场景 |
| **log_collection** | NO：缺上报载体，收益低 |
| **client.p12 / WiFi 802.1x** | NO：p12 用于 BYOD 设备证书 + WiFi EAP-TLS（DeviceRegisterActivity.java:539），对 /vpn/conn 无作用，设备身份已由 DPoP 承担 |
| **search_domain** | NO：官方自己也没解析（ServerOperator.java:281 恒 null） |
| **MMKV 跨进程 timeDiff** | NO：Go 单进程，复刻双通道只会引入不一致 |
| 推送式配置热更新 | NO：改为 connect/订阅时重新拉 /vpn/conn |
| WiFi 认证、投屏、工单、反馈、banner | NO：与连内网无关 |
| RADIUS / LDAP / passkey / 验证码登录 | NO：本租户 login_orders=[mobile_auth,lark,bytedance_sso]，已覆盖 |

## 三条纠偏（之前判断错的）

1. **need_trusted 不是隧道门槛**：base/vpn/ 与 source/ 全树零引用，连接链路不检查信任状态。它只是设备台账/证书/审批开关，表现为「节点列表空」而非「拒绝连接」。
2. **client.p12 对隧道无用**：p12 是 WiFi EAP-TLS 用的，/vpn/conn 只验 DPoP。之前担心的「证书参与握手」可以彻底放下。
3. **AllowedIPs 里绝不能混域名**：官方把域名规则放在 String 通道、IP 路由放在 List 通道；混用会让 wireguard-go UAPI 直接解析失败。要加防御性校验。

## 施工批次（按性价比）

- **A 批｜换租户就炸的隐性坑（约 120 行）**：P0-1 PSK + #5 v6 路由 + #4 conn 补字段（含重连凭据）+ #10 路由防御校验
- **B 批｜时钟与凭证（约 100 行）**：P0-3 统一时间源（登录 timestamp / Date 头兜底 → TOTP 与 DPoP iat）
- **C 批｜建连成功率（约 200 行）**：P0-2 连接期 MFA + #1 重试阶梯 + #2 协议探测 + #3 MTU 探测
- **D 批｜会话正确性（约 180 行）**：#12/#13 被踢 + #14 登出 + #15 report（含 60s 周期与踢线信号）+ #17 MFA 协商
- **E 批｜分流完整性（约 250 行）**：#6 域名 DNS 分流 + #7 四类规则 + #8 NAT/central_dns + #9 排除段 + #11 订阅补齐
- **F 批｜租户特性（按需）**：P0-4 ZTNA 检测与明示 + #18/#19 信任与上报 + #20 ws 推送

> A+B 合计约 220 行、纯增量、不改现有调用契约；C 批动连接流程，需要配套回归。
