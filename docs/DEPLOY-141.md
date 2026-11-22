# 141 部署与维护（corplink + mihomo + 路由器 DNS）

## 拓扑

```
手机 / 需要走公司的设备
   │ ① DNS：corp 域名问路由器（同网段直连，不经过 141）
   ▼
路由器 10.0.0.1（ImmortalWrt，dnsmasq）
   │ ② 只把 corp 域名转发给 141:5335，其它域名保持原样
   ▼
141 · mihomo（host 网络）
   │ ③ DNS 分流：corp 域名 → 127.0.0.1:10053；其它 → DoH
   │ ④ 流量分流：RULE-SET(corp) → CorpLink(SOCKS5 127.0.0.1:3710)，其它 → 机场节点
   ▼
141 · corplink（容器 ghcr.io/acdzh/corplink-go）
   │ ⑤ 本地 DNS 10053 → 隧道内 10.8.8.18
   ▼
公司内网
```

关键点：**手机到路由器的 DNS 是同网段直连，永远不经过 141**，所以 DNS 这一步只能在路由器上做；
141 上的 tproxy/redirect 规则对这类查询无效（已删除，避免误解）。

## 唯一真源

`deploy/corp/corp-domains.txt` —— 只放公司内网域名。公网域名（google / x.com / anthropic …）不要加。

改域名只需两步：

```bash
./deploy/corp/sync-141.sh      # 写 mihomo 的 ruleset/corp.yaml + nameserver-policy，并热重载
./deploy/corp/sync-router.sh   # 写路由器 dnsmasq 的 server=/域名/10.0.0.141#5335，并重启 dnsmasq
```

两个脚本都幂等，重复执行不会产生重复条目；都会自动备份（141：`config.yaml.bak.*`，路由器：`/etc/config/dhcp.bak.*`）。

## 验证（三条）

```bash
# 1) 141 上：corp DNS 与代理
ssh admin@10.0.0.141 'dig @127.0.0.1 -p 10053 code.byted.org +short'
ssh admin@10.0.0.141 'curl -s -o /dev/null -w "%{http_code}\n" -x 127.0.0.1:7890 https://code.byted.org/'   # 期望 302

# 2) 路由器上：corp 域名拿到 141 的回答（fake-ip 198.18.x.x）
ssh root@10.0.0.1 'nslookup code.byted.org 127.0.0.1'

# 3) 141 上：mihomo 是否正确分流
ssh admin@10.0.0.141 'docker logs --tail 50 mihomo 2>&1 | grep byted'
# 期望：code.byted.org:443 match RuleSet(corp) using CorpLink
```

## 已知限制

- 路由器到 141 的转发依赖 141 在线：141 挂了，corp 域名解析会失败（其它域名不受影响）。
- mihomo 对 corp 域名返回 fake-ip（198.18.x.x），设备必须把流量交给 141 才能还原域名；不走代理的设备拿到 fake-ip 也连不上 corp（本来也连不上）。
- **UDP 节点（CN-LF5 / CN-HL9）经常“握手超时”并被服务端 `report 1000` 终止**，141 建议固定用 TCP 节点（如 CN-LF-TCP）。
- 路由器 dnsmasq 的改法只影响 DNS；流量是否进 141 由路由器原有 tproxy 规则决定。

## 回滚

```bash
# 路由器
ssh root@10.0.0.1 'cp /etc/config/dhcp.bak.<时间> /etc/config/dhcp && /etc/init.d/dnsmasq restart'
# 141 mihomo
ssh admin@10.0.0.141 'cd /mnt/d/docker/stacks/mihomo/config && cp config.yaml.bak.<时间> config.yaml'
ssh admin@10.0.0.141 'curl -s -X PUT "http://127.0.0.1:9090/configs?force=true" -H "Authorization: Bearer 123456" -H "Content-Type: application/json" -d "{\"path\":\"/root/.config/mihomo/config.yaml\"}"'
```

## 相关文件

| 位置 | 内容 |
|---|---|
| `deploy/corp/corp-domains.txt` | corp 域名唯一真源 |
| `deploy/corp/sync-141.sh` | 写 mihomo（ruleset + nameserver-policy）并重载 |
| `deploy/corp/sync-router.sh` | 写路由器 dnsmasq 转发并重启 |
| 141:`/mnt/d/docker/stacks/corplink/` | corplink 容器、compose、数据（config.json / session.json / dpop） |
| 141:`/mnt/d/docker/stacks/mihomo/config/` | mihomo 配置、ruleset/corp.yaml |
