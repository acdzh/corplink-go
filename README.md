# Corplink Go

用 Go 重新实现飞连（CorpLink）客户端协议，提供一个本地混合代理、Web 控制面板与 macOS 原生桌面端。
不需要安装官方客户端，也不需要 TUN/root：数据面跑在用户态 WireGuard + gVisor netstack 上。

## 它能做什么

- **登录与保活**：PKCE 第三方授权（SSO / 飞书）+ 二次验证（邮箱 / 短信 / 自动 TOTP），会话自动保存与保活
- **协议与隧道**：按服务端规则对请求签名（HKDF + HMAC + protobuf 头），拉取节点并建立 WireGuard 隧道（支持 UDP 与 TCP 分帧）
- **混合代理与认证**：本机单端口同时提供 SOCKS5 与 HTTP 代理，支持 RFC 1929 与 Basic 认证
- **Web 控制面板**：连接/断开/自动选路/单节点与全量测速/节点搜索与标签筛选/分流规则校验/TOTP 倒计时与复制/实时流量速率与峰值/登录向导/运行日志/动态配置
- **Clash 订阅**：生成防回环的 Clash 配置，分流规则由服务端下发并交给 Clash 执行
- **桌面客户端**：MyGo 原生窗口（节点、流量、令牌、设置、日志）+ 菜单栏动态状态图标、节点直连切换与一键复制动态码

## 快速开始

```bash
# 构建 CLI
go build -o corplink ./cmd/corplink-go

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

打开 <http://127.0.0.1:13140>：

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

## 配置与数据

全部状态放在同一个数据目录里：

```
<data-dir>/（默认 ~/.corplink-go）
├── config.json   非敏感配置、设备标识与运行选项
└── session.json  Cookie 与登录态（0600，切勿提交）
```

TOTP secret 存在 `config.json` 的 `code` 字段（登录成功后自动写入）。
Docker 下默认数据目录为 `/data`。

## Docker

```bash
docker build -t corplink-go .
docker run -d --name corp-link \
  -p 3710:3710 -p 13140:13140 \
  -v $PWD/data:/data \
  corplink-go
```

或使用 `docker compose up -d`。

## 桌面版

```bash
go build -o corplink-desktop ./cmd/corplink-desktop
./corplink-desktop
```

macOS 原生窗口（节点、流量、令牌、设置、日志）+ 菜单栏常驻托盘，内部运行同一套核心运行时，Web 控制面板照常可用。
点击菜单栏图标可快速切换节点直连、查看并一键复制当前 TOTP 动态码、复制代理地址或订阅链接。

## 开发

```bash
go test ./...     # sign / sub / totp 的单元测试
go vet ./...
```

目录结构：

```
cmd/corplink-go          CLI 与服务入口
cmd/corplink-desktop     MyGo 原生桌面端
internal/app             运行时装配
internal/agent           单隧道管理、测速、自动选路、看门狗、事件日志
internal/proxy           SOCKS5 + HTTP 混合代理（含认证）
internal/tunnel          wireguard-go + netstack 封装
internal/panel           控制面板（JSON API + 静态页面）
internal/api             飞连 HTTP 协议与签名钩子
internal/auth            PKCE / 2FA / OTP
internal/login           登录流程编排
internal/sign            v1 请求签名
internal/sub             Clash 订阅生成
internal/totp            TOTP 动态码
internal/wgkey           X25519 密钥
```

## 注意

- 本项目只做协议复刻，用于个人在自有设备上连接公司内网；请遵守所在公司的安全与合规要求。
- `config.json` 里的 `device_id`、`code`（TOTP）以及 `session.json` 都属于凭据，不要提交到仓库。
- 服务端策略变更可能导致协议失效，需要重新对齐客户端行为。
