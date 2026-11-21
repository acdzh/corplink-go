# Corplink Go

用 Go 重新实现飞连（CorpLink）客户端协议，提供一个本地混合代理、Web 控制面板与 macOS 原生桌面端。
不需要安装官方客户端，也不需要 TUN/root：数据面跑在用户态 WireGuard + gVisor netstack 上。

仓库分成三层，依赖单向：

```
apps/*     端侧（CLI / 桌面 / Android）—— 只调库，不复制业务逻辑
httpapi    HTTP 契约（JSON API + 控制面板页面）—— 只依赖库
corplink/  库：登录、签名、隧道、代理、订阅、TOTP —— 只依赖标准库与 wireguard-go
```

## 它能做什么

- **登录与保活**：PKCE 第三方授权（SSO / 飞书）+ 二次验证（邮箱 / 短信 / 自动 TOTP），会话自动保存与保活
- **协议与隧道**：按服务端规则对请求签名（HKDF + HMAC + protobuf 头 + DPoP 设备证明），拉取节点并建立 WireGuard 隧道（支持 UDP 与 TCP 分帧）
- **混合代理**：本机单端口同时提供 SOCKS5 与 HTTP 代理，不设用户名密码
- **本地 DNS**：在 127.0.0.1:10053 提供解析服务，内网域名走隧道内 DNS、其余走系统 DNS（官方客户端对应 53 端口）
- **Web 控制面板**：连接/断开/自动选路/单节点与全量测速/节点搜索与标签筛选/分流规则校验/TOTP 倒计时与复制/实时流量速率与峰值/登录向导/运行日志/动态配置
- **Clash 订阅**：生成防回环的 Clash 配置，分流规则由服务端下发并交给 Clash 执行
- **桌面客户端**：MyGo 原生窗口（节点、流量、令牌、设置、日志）+ 菜单栏动态状态图标、节点直连切换与一键复制动态码

## 快速开始

```bash
# 构建 CLI
go build -o corplink ./apps/cli

# 启动（代理 3710，面板 13140，默认数据目录 ~/.corplink-go）
./corplink serve
```

也可以预先准备配置文件（如指定自定义路径 `-config ./data/config.json`）：

```bash
mkdir -p ./data
cat > ./data/config.json <<'EOF'
{
  "company_name": "your-company",
  "device_model": "M2007J17C",
  "device_brand": "Redmi",
  "os_version": "32",
  "os_version_patch": "2023-07-05",
  "app_version": "3.3.24",
  "build_number": "2485",
  "language": "zh"
}
EOF

./corplink serve -config ./data/config.json
```

面板不做任何鉴权，直接打开 `http://127.0.0.1:13140/` 即可。谁能连到这个端口，谁就能用面板，
所以不想给局域网用就别把 `-panel` 绑到 `0.0.0.0`。

打开面板：

1. 若未配置企业服务端，可在「系统设置」填入企业代码（或服务端地址），保存后立即生效
2. 在「账号登录」点击「获取授权链接」，在浏览器完成 SSO 授权并把回调地址粘回面板提交
3. 若要求二次验证：已绑定 TOTP 时留空即可自动填码，也可点击发送邮箱验证码手动填写
4. 在「节点列表」选择节点（或直接连接「自动选择」），连接成功后即可使用代理

代理使用示例：

```bash
curl --socks5 127.0.0.1:3710 http://internal.example.com
curl -x http://127.0.0.1:3710 http://internal.example.com
```

## Clash

面板里的订阅地址：

```
http://127.0.0.1:13140/clash.yml
```


导入 Clash Verge 后保持「规则」模式即可。配置里包含控制面域名与节点公网 IP 的防回环直连规则，
企业内网分流规则来自服务端 `/vpn/conn` 下发的网段与域名后缀，未命中走 `MATCH,DIRECT`。
DNS 使用 fake-ip，内网域名不依赖本机 DNS。

## 命令

| 命令 | 说明 |
| --- | --- |
| `corplink login` | 命令行完成一次登录（面板登录之外的兜底方式） |
| `corplink list` | 拉取可用节点列表 |
| `corplink connect` | 打印指定节点的隧道参数，便于排障 |
| `corplink serve` | 启动守护进程：混合代理 + Web 控制面板 |
| `corplink probe` | 探测企业信息与登录配置 |
| `corplink dpop` | 查看设备密钥登记状态；`-register` 补做一次登记并换取 vpn-token |

## 配置与数据

全部状态放在同一个数据目录里：

```
<data-dir>/（默认 ~/.corplink-go）
├── config.json        非敏感配置、设备标识与运行选项
├── session.json       Cookie 与登录态（0600，切勿提交）
└── dpop/
    └── device_key.json  ES256 设备私钥（0600，单独存放，切勿提交）
```

设备私钥刻意不放进 `config.json` / `session.json`：那两份是明文 JSON，
混进去等于把长寿命私钥直接暴露；分开存放也让"换个会话继续用同一把设备密钥"成立。

TOTP secret 存在 `config.json` 的 `code` 字段（登录成功后自动写入）。
本地 DNS 监听地址存在 `dns_listen` 字段（默认 `127.0.0.1:10053`，留空即关闭）。
Docker 下默认数据目录为 `/data`。

## 本地 DNS

官方客户端启动后会在本机 53 端口提供解析服务；我们在 **127.0.0.1:10053** 提供同样的能力，
避免和系统解析器抢端口：

```bash
# 默认随 serve 一起启动，监听 127.0.0.1:10053
corplink serve

# 改地址 / 关掉
corplink serve -dns 127.0.0.1:10053
corplink serve -dns ""
```

分流规则：

| 查询 | 上游 | 说明 |
| --- | --- | --- |
| 命中 `vpn_dns_domain_split` 或 `dynamic_domain` 的后缀 | 隧道内 DNS（`vpn_dns`/`vpn_dns_backup`，经 WireGuard） | 公司域名解析不泄漏给本地运营商 |
| 其余域名 | 系统 DNS（读 /etc/resolv.conf），隧道 DNS 作为兜底 | 公网域名照常用本地解析 |
| 上游不可用 | 自动切备用（先主后备，最后系统） | |

实现细节：UDP + TCP 双栈（大响应按 TC 位让客户端改用 TCP）、按 qname+qtype 缓存
（TTL 取响应最小值，限制在 5s–10min）、单查询 4 秒超时。

```bash
dig +short @127.0.0.1 -p 10053 www.bytedance.net     # 内网：走隧道
dig +short @127.0.0.1 -p 10053 www.apple.com         # 公网：走系统 DNS
dig +tcp +short @127.0.0.1 -p 10053 www.bytedance.net
```

面板 `/api/status` 里的 `dns_addr` 会显示实际监听地址；Docker 镜像已暴露 10053/tcp 与 10053/udp。

## 设备证明（DPoP）

飞连 2026 年起给部分租户启用了设备证明：服务端只给"能证明自己持有某对 ES256
设备私钥"的会话签发 `vpn-token`，token 的 `val` 段里带
`auth_scheme=device-pop-es256-v1` 与 `cnf.jwk`（设备公钥）。没有 `vpn-token`
时 `/vpn/conn` 固定失败在 `3015`（"Session 无效"）。

完整链路（全部按官方 Android 客户端反编译实现，见 `corplink/dpop`）：

1. **生成并持久化 ES256（P-256）密钥**，`device_key_id = <device_id>_<uuid>`，
   uuid 由客户端生成；私钥落在 `<data-dir>/dpop/device_key.json`（0600）。
2. **登记公钥**：登录成功后用 `mfa_scene=device_key` 做一次二次认证，
   校验请求体带上
   `device_key_id` / `device_key_protected_level` / `device_public_key`。
   otp 是本地动态码，**不需要**先调 `/api/mfa/code/send`（调了会回 3021）。
3. **换取 vpn-token**：绑定成功后带一份 DPoP 证明请求 `/api/vpn/list`，
   服务端这时才 `Set-Cookie` 下发带 `cnf.jwk` 的 `vpn-token`。
4. **带证明连接**：`/vpn/conn` 除 `sign` 与 `jwt-token` 外再带 `DPoP` 头。

证明是一份 ES256 紧凑 JWT，header 固定
`{"typ":"dpop+jwt","alg":"ES256","kid":"<device_key_id>"}`，两类 claim：

| 接口 | claim | 说明 |
| --- | --- | --- |
| `GET /api/vpn/list` | `htm` `iat` `jti` `ath` `htu` `query_hash` `body_hash` | `ath` 覆盖 **session** cookie；`htu` 去掉 query；`query_hash` 按 key 排序归一化后取哈希 |
| `POST /vpn/conn` | `htm` `iat` `jti` `ath` `ver` `htp` `wgh` `body_hash` | `ath` 覆盖 **vpn-token**；`ver=vpn-pop-es256-v1`；`wgh` 是本次 WireGuard 公钥原文的 SHA-256 |

### 自动续期与自愈

- **vpn-token**（14 天）：只在请求 `/api/vpn/list` 时续签。保活循环每轮检查余量，
  剩余不足 48 小时就换一张并落盘；启动、登录、手动刷新节点时也会顺手续签。
- **连接失败自愈**：`/vpn/conn` 返回 `3015` / `10220018` / `10420003~10420006`
  时自动换票后重试一次；返回 `10220021`（服务端记的公钥与本机不一致）时先重新登记
  设备密钥、再换票重试。对应官方客户端的 `DpopVpnRecovery`。
- **session cookie**：飞连没有 refresh token，只有保活请求能让它保持活跃；服务端判定
  过期（`101 登录已过期`）后必须重新走一次登录，这一步库不会替你完成 SSO。

排障：

```bash
corplink dpop              # 本地 device_key_id / 服务端登记状态 / 是否已绑定
corplink dpop -register    # 补做登记（本地有 TOTP secret 时全自动，无需手工输码）
corplink dpop -json        # 机器可读
curl "http://127.0.0.1:13140/api/dpop"   # 面板同款视图
```

## Docker

```bash
docker build -t corplink-go .
docker run -d --name corp-link \
  -p 3710:3710 -p 13140:13140 \
  -v $PWD/data:/data \
  corplink-go
```

或使用 `docker compose up -d`。

多架构构建（linux/amd64 + linux/arm64，需要 buildx）：

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t corplink-go . --load
```

Dockerfile 用 `--platform=$BUILDPLATFORM` 编译、按 `TARGETOS/TARGETARCH` 交叉出二进制，
运行时是 distroless（无 shell、非 root），数据目录挂 `/data`。

容器怎么跑：

```
ENTRYPOINT corplink
CMD      serve -config /data/config.json -proxy 0.0.0.0:3710 -panel 0.0.0.0:13140
```

也就是容器内跑的就是 CLI 的 `serve`：混合代理在 3710，面板在 13140，状态落在 `/data`
（`config.json` + `session.json`）。面板监听 `0.0.0.0` 且默认不校验令牌，
同网段能连到 13140 的人都能直接打开面板 —— 只想本机用就把 `-panel` 改成 `127.0.0.1:13140`，
只想本机用就别绑 `0.0.0.0`：

```bash
docker run -d --name corp-link \
  -p 3710:3710 -p 13140:13140 \
  -v "$PWD/data:/data" \
  corplink-go:latest \
  serve -config /data/config.json -proxy 0.0.0.0:3710 -panel 0.0.0.0:13140
```

> 本机实测：Docker Hub 直连不可达，daemon 的 `registry-mirrors` 指向 `mirrors.byted.org`
> 又解析不了（NXDOMAIN）。镜像改成 daocloud / dockerproxy.net 才能拉得动。
> 原配置备份在 `~/.docker/daemon.json.bak-*`。

## 桌面版

```bash
CGO_ENABLED=0 go build -o corplink-desktop ./apps/desktop
./corplink-desktop
```

原生窗口（节点、流量、令牌、设置、日志）+ 托盘状态图标，内部运行同一套核心运行时，Web 控制面板照常可用。

| 平台 | 状态 | 说明 |
| --- | --- | --- |
| macOS 11+ | 支持 | 菜单栏托盘，发布产物是二进制；用 `scripts/macos-app.sh` 包成 .app |
| Windows 10+ | 支持 | 发布产物是 GUI 子系统（`-H=windowsgui`），双击不弹控制台；未签名会被 SmartScreen 拦 |
| Linux | 需系统库 | 运行时 dlopen GTK3 栈，缺库直接起不来，见下 |

Linux 依赖（Debian/Ubuntu）：

```bash
sudo apt install libgtk-3-0 libgtk-layer-shell0 libayatana-appindicator3-1 \
  libcairo2 libharfbuzz0b libepoxy0 libfontconfig1 libglib2.0-0
# 托盘图标另外需要 libayatana-appindicator3 或 libappindicator3
```

macOS 打成 .app：

```bash
VERSION=$(git describe --tags --always) scripts/macos-app.sh corplink-desktop "Corplink Go.app"
open "Corplink Go.app"
```

发布产物命名（goreleaser）：

```
corplink-go_<version>_<os>_<arch>.tar.gz            CLI
corplink-go-desktop_<version>_<os>_<arch>.tar.gz    桌面端（Windows 为 .zip）
checksums.txt
```

## 平台支持

| 目标 | 状态 | 说明 |
| --- | --- | --- |
| 库 `corplink/` | 全平台 | 纯 Go，无 cgo；darwin/linux/windows 的 amd64+arm64 与 android 各 ABI 均编译通过 |
| CLI `apps/cli` | 全平台 | darwin/linux/windows amd64+arm64，另验过 linux/armv7 |
| 桌面 `apps/desktop` | macOS / Windows / Linux | 纯 Go（mygo 用 purego 调系统 API）；Linux 需 GTK3 系统库 |
| Docker | linux/amd64 + linux/arm64 | buildx 多架构，镜像内跑 CLI + 面板 |
| Android `apps/android` | 可用 | Compose 界面 + VpnService；支持全局/分流切换与本地代理；发版流水线出四 ABI 的 APK |
| iOS | 未做 | 库已与平台解耦，后续接 c-archive 即可 |

## 开发

```bash
go test ./...     # sign / sub / totp 的单元测试
go vet ./...

# 交叉编译（CI 里跑的就是这些）
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ./apps/desktop
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build ./apps/desktop
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build ./apps/android/bind
```

目录结构：

```
corplink/corplink.go     库门面：New / Start / Close / Status / Nodes / Connect / Login / TOTP
corplink/settings.go     配置读写（Settings / UpdateSettings）
corplink/agent           单隧道管理、测速、自动选路、看门狗、事件日志
corplink/tunnel          wireguard-go 封装；Start 用 netstack，StartWith 用外部网卡
corplink/proxy           SOCKS5 + HTTP 混合代理
corplink/api             飞连 HTTP 协议与签名钩子
corplink/auth            PKCE / 2FA / OTP
corplink/login           登录流程编排
corplink/sign            v1 请求签名
corplink/sub             Clash 订阅生成
corplink/totp            TOTP 动态码
corplink/wgkey           X25519 密钥
corplink/config          配置与设备标识
httpapi                  JSON API + 控制面板页面
apps/cli                 CLI 与服务入口
apps/desktop             MyGo 原生桌面端
apps/android             Android 端（gomobile 门面 + VpnService + Compose，含全局/分流与本地代理）
```

库不含任何监听与序列化：`httpapi` 才提供 HTTP 契约，端侧按需启动。
Android 端只启用库与 VpnService，不起代理与面板，构建方式见 [apps/android/README.md](apps/android/README.md)。

## 发版

版本号是日期，不用手写：

- 触发：仓库 Actions → `release` → `Run workflow`（也可以自己打 tag，形如 `v2026.11.21`）
- 版本号 = 当天日期 `v2026.11.22`；同一天发第二次自动变 `v2026.11.22-2`（goreleaser 只认三段式 semver，四段会被判非法）
- 产物：goreleaser 出 6 个平台的 CLI 包 + 桌面端包，ghcr 出 `corplink-go:2026.11.21` 与 `latest`（linux/amd64 + linux/arm64）
- Android 的 `versionName` 用同一个字符串，`versionCode` 由它派生（`2026.11.21` → `20261121`）

本地想先看产物：

```bash
goreleaser release --snapshot --clean     # 不发布，只在本地产出 dist/
```

## 作为库使用

`corplink` 收参数、返回对象，不假设运行环境：

```go
// 纯内存：不读配置文件、不写任何文件、不开端口
client, err := corplink.New(ctx, corplink.Options{
	Config:  config.Default(),
	Logger:  slog.New(slog.NewTextHandler(os.Stderr, nil)),
	TUNFD:   fd,        // Android：VpnService.establish() 的 fd；不传则用内置 netstack
	Verbose: false,
})
if err == nil {
	err = client.Start(ctx)   // 这里才解析企业服务端、起后台循环
}
defer client.Close(ctx)

st, _ := client.TOTP()        // 状态、节点、动态码、订阅都是普通返回值
```

约定：

| 能力 | 触发条件 |
| --- | --- |
| 联网 | `Start` 之后；`New` 只做装配，不发请求 |
| 监听端口 | 传了 `Options.ProxyListen` 或配置里有 `socks5_listen`，否则不开代理 |
| 落盘 | 只有先 `config.Load(path)` 或传 `Options.ConfigPath` 才会写；`config.Default()` 下 `Save` 是空操作 |
| 隧道网卡 | `Options.TUN` / `Options.TUNFD`，或先 `Prepare` 拿参数、再用 `Establish(fd)` 接入 |
| 日志 | 全部走 `Options.Logger`（含 wireguard 内部日志，默认只留错误） |

## 注意

- 本项目只做协议复刻，用于个人在自有设备上连接公司内网；请遵守所在公司的安全与合规要求。
- `config.json` 里的 `device_id`、`code`（TOTP）以及 `session.json` 都属于凭据，不要提交到仓库。
- 服务端策略变更可能导致协议失效，需要重新对齐客户端行为。
