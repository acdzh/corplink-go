# Android 端

库（`corplink/`）在 Android 上只出二进制能力，界面与 VpnService 都在这层。

## 结构

```
apps/android
├── bind/                 gomobile 门面（package mobile）
│   └── mobile.go         唯一的 Go 入口：Start/Plan/Establish/Status…全部返回 JSON
└── app/                  Android 应用
    ├── build.gradle.kts
    └── src/main
        ├── AndroidManifest.xml
        └── java/dev/corplink/android
            ├── MainActivity.kt          Compose 界面，只读库快照
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

1. `mobile.Plan(node)` 向节点申请隧道参数（地址 / 路由 / DNS / MTU），不建隧道；
2. Kotlin 按参数调用 `VpnService.Builder` 并 `establish()`，把 fd 交给 `mobile.Establish(fd)`。

## 构建

需要 Android SDK、NDK 与 JDK（`ANDROID_HOME` / `ANDROID_NDK_HOME` 指向它们）。

```bash
# 1. 生成 AAR（每次改库或改 bind 都要重跑）
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
gomobile bind -target=android -androidapi 24 \
  -o apps/android/app/libs/corplink.aar ./apps/android/bind

# 2. 打包 APK
cd apps/android
./gradlew assembleDebug
```

## 已做与未做

已做：库启动、登录（授权链接 + 回调 + 二次验证）、节点列表与测速、连接 / 断开、
VpnService 建网卡、前台服务通知、TOTP 动态码。

未做：开机自启、快捷开关磁贴、按应用分流（`addAllowedApplication`）、
订阅导出界面、Keystore 加密 `config.json`（当前为应用私有目录明文）。

## 注意

- `addDisallowedApplication(packageName)` 把自身流量排除在 VPN 外，避免 WireGuard
  握手被自己的隧道捕获；Android 不支持按 socket 调 `protect()`，这是等价做法。
- 库的 HTTP 面板在 Android 上不启用（`DisableProxy: true`，也不起 `httpapi`）：
  本机端口在 Android 上不是安全边界。
- `config.json` 里有 TOTP secret 与 device_id，落在 `filesDir`，不要导出到外部存储。
