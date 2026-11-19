# Corplink Go

用 Go 重新实现飞连（CorpLink）客户端协议，提供一个本地混合代理与网页控制面板。
不需要安装官方客户端，也不需要 TUN/root：数据面跑在用户态 WireGuard + gVisor netstack 上。

## 它能做什么

- PKCE 登录 + 登录二次验证（邮箱/短信/TOTP），会话自动保存与保活
- 按服务端规则对请求签名（HKDF + HMAC + protobuf 头）
- 拉取节点列表，建立 WireGuard 隧道（含 TCP 分帧传输）
- 在本机开一个端口，同时提供 SOCKS5 与 HTTP 代理
- 网页面板：连接/断开/切换节点/自动选路/测速/TOTP/日志/设置/登录
- 生成 Clash 订阅（分流规则由服务端下发，交给 Clash 执行）
- 桌面版（MyGo 原生窗口 + 菜单栏托盘）、Docker 部署、多平台二进制

## 快速开始

```bash
# 1. 构建
go build -o corplink ./cmd/corplink-go

# 2. 准备配置（首次可直接用面板完成登录，配置会自动落盘）
mkdir -p ./data
cat > ./data/config.json <<'EOF'
{
  "company_name": "your-company",
  "server": "https://sealsuite.example.com:443",
  "device_id": "替换为客户端设备 ID",
  "device_model": "M2007J17C",
  "device_brand": "Redmi",
  "os_version": "32",
  "os_version_patch": "2023-07-05",
  "app_version": "3.3.24",
  "build_number": "2485",
  "language": "zh"
}
EOF

# 3. 启动（代理 3710，面板 13140）
./corplink serve -config ./data/config.json
```

打开 <http://127.0.0.1:13140>：

1. 点「获取授权链接」，在浏览器完成 SSO 授权
2. 把回调地址粘回面板，提交
3. 若要求二次验证：留空即可用已保存的 TOTP 自动填，或手动输入验证码
4. 在「节点」里选节点（或直接选「自动选择」），点连接

然后代理就能用了：

```bash
curl --socks5 127.0.0.1:3710 http://internal.example.com
curl -x http://127.0.0.1:3710 http://internal.example.com
```

## Clash

面板里的订阅地址：

```
http://127.0.0.1:13140/clash.yml
```

导入 Clash Verge 后保持「规则」模式即可。配置里只有一个代理与本机端口，
分流规则来自服务端 `/vpn/conn` 下发的网段与域名后缀，未命中走 `MATCH,DIRECT`。
DNS 使用 fake-ip，内网域名不依赖本机 DNS。

## 命令

| 命令 | 说明 |
| --- | --- |
| `corplink login` | 命令行完成一次登录（面板登录失败时的兜底） |
| `corplink list` | 拉取节点列表 |
| `corplink connect` | 打印某个节点的隧道参数，便于排障 |
| `corplink serve` | 启动守护进程：混合代理 + 控制面板 |
| `corplink probe` | 探测企业信息与登录配置 |

## 配置与数据

全部状态放在同一个数据目录里：

```
<data-dir>/（默认 ~/.corplink-go）
├── config.json   非敏感配置（租户、设备标识、端口、模式）
└── session.json  Cookie 与登录态（0600，切勿提交）
```

TOTP secret 存在 `config.json` 的 `code` 字段（登录成功后自动写入）。
Docker 下数据目录是 `/data`。

## Docker

```bash
docker build -t corplink-go .
docker run -d --name corp-link \
  -p 3710:3710 -p 13140:13140 \
  -v $PWD/data:/data \
  corplink-go
```

或 `docker compose up -d`。

## 桌面版

```bash
go build -o corplink-desktop ./cmd/corplink-desktop
./corplink-desktop
```

原生窗口 + 菜单栏托盘，内部跑同一套运行时，浏览器面板照常可用。
配置默认放在用户配置目录（`~/.corplink-go`）。

## 开发

```bash
go test ./...     # sign / sub / totp 的单元测试
go vet ./...
```

目录结构：

```
cmd/corplink-go          CLI 与服务入口
cmd/corplink-desktop     MyGo 桌面壳
internal/app             运行时装配
internal/agent           单隧道管理、测速、自动选路、看门狗
internal/proxy           SOCKS5 + HTTP 混合代理
internal/tunnel          wireguard-go + netstack 封装
internal/panel           控制面板（JSON API + 静态页面）
internal/api             飞连 HTTP 协议与签名钩子
internal/auth            PKCE / 2FA / OTP
internal/sign            v1 请求签名
internal/sub             Clash 订阅生成
internal/totp            TOTP
internal/wgkey           X25519 密钥
```

## 注意

- 本项目只做协议复刻，用于个人在自有设备上连接公司内网；请遵守所在公司的安全与合规要求。
- `config.json` 里的 `device_id`、`code`（TOTP）以及 `session.json` 都属于凭据，不要提交到仓库。
- 服务端策略变更可能导致协议失效，需要重新对齐客户端行为。
