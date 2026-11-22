# 141 部署与维护（corplink + mihomo + 路由器 DNS）

## 拓扑

```
设备（手机 / Mac）
   │ ① DNS：corp 域名 → 路由器 dnsmasq（同网段直连，不经过 141）
   ▼
路由器 10.0.0.1（ImmortalWrt，dnsmasq）
   │ ② 只把 corp 域名转发给 141:5335；其它域名保持原样
   ▼
141 · mihomo（host 网络，端口 7890 混合代理 / 5335 DNS / 9090 控制面）
   │ ③ DNS：corp 域名 → 127.0.0.1:10053；其它 → DoH
   │ ④ 路由：RULE-SET(corp) → CorpLink(SOCKS5 127.0.0.1:3710)；其它 → 机场节点
   ▼
141 · corplink 容器（ghcr.io/acdzh/corplink-go）
   │ ⑤ 本地 DNS 127.0.0.1:10053 → 隧道内 10.8.8.18
   ▼
公司内网
```

**关键**：手机到路由器的 DNS 是同网段直连，不经过 141，所以 DNS 只能在路由器上做；
141 上的 tproxy/redirect 规则对这类查询无效（已删）。

## 域名怎么加（没有脚本，直接改三处）

公司域名很少，写死即可。加一个域名需要改：

| # | 文件 | 改什么 | 生效方式 |
|---|---|---|---|
| 1 | 141:`/mnt/d/docker/stacks/mihomo/config/ruleset/corp.yaml` | `payload:` 下加 `- '+.example.com'` | 见下方重载 |
| 2 | 141:`/mnt/d/docker/stacks/mihomo/config/config.yaml` | `nameserver-policy` 的 `corplink corp dns` 块里加 `+.example.com: *corplinkdns` | 见下方重载 |
| 3 | 路由器`/etc/config/dhcp` | 加 `list server '/example.com/10.0.0.141#5335'` | `/etc/init.d/dnsmasq restart` |

重载 mihomo：

```bash
curl -s -X PUT 'http://127.0.0.1:9090/configs?force=true' \
  -H 'Authorization: Bearer 123456' -H 'Content-Type: application/json' \
  -d '{"path":"/root/.config/mihomo/config.yaml"}'
```

当前 corp 域名清单见 `deploy/corp/corp-domains.txt`（只是清单，供对照，不参与任何自动化）。

## 设备怎么接（两种，互不影响）

| 设备 | 接法 | 说明 |
|---|---|---|
| 手机 / 平板 | 路由器 DNS 转发（已在用） | 设备侧零改动；流量由路由器原有 tproxy 规则送进 141 |
| Mac / Windows | 系统代理 → `10.0.0.141:7890`（HTTP/HTTPS/SOCKS 同端口） | 已在本机设好：Wi-Fi 服务的 SOCKS + HTTP + HTTPS 全指向 141:7890 |

iOS/Android 没法手动设网关，只能靠路由器的 DNS 转发/策略；Mac 用系统代理最省事，不依赖路由。

## 验证

```bash
# 141 上
ssh admin@10.0.0.141 'dig @127.0.0.1 -p 10053 code.byted.org +short'   # 期望 10.8.7.149
ssh admin@10.0.0.141 'dig @127.0.0.1 -p 5335  code.byted.org +short'   # 期望 198.18.0.x（fake-ip）
ssh admin@10.0.0.141 'curl -s -o /dev/null -w "%{http_code}\n" -x 127.0.0.1:7890 https://code.byted.org/'   # 302

# 路由器上
ssh root@10.0.0.1 'nslookup code.byted.org 127.0.0.1'                   # 期望 198.18.0.x

# Mac 上（系统代理已开）
curl -s -o /dev/null -w "%{http_code}\n" -x 10.0.0.141:7890 https://code.byted.org/   # 302
```

## 已知限制

- mihomo 对 corp 域名返回 **fake-ip（198.18.x.x）**。所以：不是走 141 的设备，即使解析到 corp 域名也连不上（连 198.18.x.x 会直接超时）。这是“没有代理就别想访问内网”的正常表现。
- 路由器 → 141 的 DNS 转发依赖 141 在线；141 挂了，corp 域名解析失败，其它域名不受影响。
- **UDP 节点（CN-LF5 / CN-HL9）经常“握手超时”并被服务端 `report 1000` 终止**；141 固定用 TCP 节点（CN-LF-TCP）。

## 回滚

```bash
# 路由器
ssh root@10.0.0.1 'cp /etc/config/dhcp.bak.<时间> /etc/config/dhcp && /etc/init.d/dnsmasq restart'
# 141 mihomo
ssh admin@10.0.0.141 'cd /mnt/d/docker/stacks/mihomo/config && cp config.yaml.bak.<时间> config.yaml'
# Mac 系统代理
sudo networksetup -setwebproxystate Wi-Fi off && sudo networksetup -setsecurewebproxystate Wi-Fi off && sudo networksetup -setsocksfirewallproxystate Wi-Fi off
```

## 相关位置

| 位置 | 内容 |
|---|---|
| 141:`/mnt/d/docker/stacks/corplink/` | 容器、compose、数据（config.json / session.json / dpop） |
| 141:`/mnt/d/docker/stacks/mihomo/config/` | mihomo 配置、ruleset/corp.yaml |
| 路由器`/etc/config/dhcp` | dnsmasq 的 corp 域名转发 |
| `deploy/corp/corp-domains.txt` | corp 域名清单（对照用） |
