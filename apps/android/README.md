# Android 端

库（`corplink/`）在 Android 上只出二进制能力，界面与 VpnService 都在这层。

## 结构

```
apps/android
├── bind/                 gomobile 门面（package mobile）
│   └── mobile.go         唯一 Go 入口：Start / Plan / Establish / 代理开关 / 登录，全部 JSON
└── app/                  Android 应用（Gradle + Compose）
    └── src/main
        ├── AndroidManifest.xml
        ├── res/drawable/ic_stat_vpn.xml
        └── java/dev/corplink/android
            ├── MainActivity.kt          界面：状态、模式开关、本地代理、登录、节点
            ├── CorplinkVpnService.kt    VpnService：建网卡 → fd 交给库
            └── Bridge.kt                JSON → 数据类
```

## 数据流

```
Compose ──(JSON)──▶ mobile.Mobile ──▶ corplink.Client ──▶ WireGuard
   ▲                                        │
   └──────── 每秒轮询 Status/Nodes ◀─────────┘

VpnService.establish() ──fd──▶ mobile.Establish ──▶ tun.CreateUnmonitoredTUNFromFD
```

建隧道分两步，因为系统网卡必须先于隧道存在：

1. `mobile.Plan(node, full)` 向节点申请参数（地址 / 路由 / DNS / MTU），不建隧道；
   `full=true` 走服务端下发的全量路由（全局），`false` 只走内网网段（分流）。
2. Kotlin 按参数调用 `VpnService.Builder` 并 `establish()`，把 fd 交给 `mobile.Establish(fd)`。

切换模式会重建网卡（断开重连，几百毫秒），因为 `addRoute` 只能在 `establish()` 之前设置。

## 功能

- 登录：浏览器授权 → 粘贴回调 → 二次验证（留空自动用 TOTP）
- 节点列表 + 测速 + 连接 / 断开
- 全局 / 分流切换（持久化在 SharedPreferences）
- 本地混合代理开关：在 `127.0.0.1:3710` 提供 SOCKS5 + HTTP，给其它 App / Termux 用
- 前台服务通知；VPN 授权被系统回收时自动断开

## 构建

需要 JDK 17+、Android SDK（platform 35、build-tools 35）与 NDK 27。

```bash
# 1. 生成 AAR（改库或改 bind 后都要重跑）
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
gomobile bind -target=android -androidapi 24 \
  -o apps/android/app/libs/corplink.aar ./apps/android/bind

# 2. 打包 APK
cd apps/android
./gradlew assembleDebug -PcorplinkVersion=2026.11.22-3
# 产物：app/build/outputs/apk/debug/app-debug.apk
```

`gomobile` 依赖 `go.mod` 里的 `tool golang.org/x/mobile/cmd/gobind`（已加好），
网络受限时带着 `GOPROXY=https://goproxy.cn,direct` 执行。

## 发布产物

发版流水线会在 GitHub Release 上挂一个 `corplink-go_<版本>_android.apk`（debug 签名，四 ABI）。

## 注意

- `addDisallowedApplication(packageName)` 把自身流量排除在 VPN 外，避免 WireGuard
  握手被自己的隧道捕获；Android 不支持按 socket 调 `protect()`，这是等价做法。
- 库的 HTTP 面板在 Android 上不启用，本机端口不是安全边界。
- `config.json` 里有 TOTP secret 与 device_id，落在 `filesDir`，不要导出到外部存储。
