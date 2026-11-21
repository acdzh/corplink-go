package dev.corplink.android

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import mobile.Mobile

// CorplinkVpnService 建系统网卡，再把网卡交给库里的 WireGuard 设备。
//
// 地址、路由与 DNS 来自库的 Plan（服务端下发的隧道参数），这里不做任何策略判断。
class CorplinkVpnService : VpnService() {

    companion object {
        // ACTION_CONNECT 用指定节点建隧道。
        const val ACTION_CONNECT = "dev.corplink.android.action.CONNECT"
        // ACTION_DISCONNECT 断开隧道并收起通知。
        const val ACTION_DISCONNECT = "dev.corplink.android.action.DISCONNECT"
        // EXTRA_NODE 是节点展示名。
        const val EXTRA_NODE = "node"
        // CHANNEL_ID 是前台服务通知渠道。
        private const val CHANNEL_ID = "corplink-tunnel"
        // NOTIFICATION_ID 是前台服务通知 id。
        private const val NOTIFICATION_ID = 1
    }

    // tunnel 是系统网卡，交给库之后只用于关闭。
    private var tunnel: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                startForeground(NOTIFICATION_ID, buildNotification())
                val node = intent.getStringExtra(EXTRA_NODE).orEmpty()
                runCatching { connect(node) }.onFailure {
                    Mobile.disconnect()
                    closeTunnel()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
            ACTION_DISCONNECT -> {
                Mobile.disconnect()
                closeTunnel()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        Mobile.disconnect()
        closeTunnel()
        stopSelf()
        super.onRevoke()
    }

    // connect 按 Plan 建网卡，把 fd 交给库。
    private fun connect(node: String) {
        if (tunnel != null) {
            return
        }
        val plan = Bridge.plan(node)
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(plan.mtu)
            .setBlocking(false)
            // 把自己的出站排除在 VPN 之外：WireGuard 握手必须走底层网络，否则会回环。
            .addDisallowedApplication(packageName)
        plan.addresses.forEach { builder.addAddress(it.host(), it.prefix(32)) }
        plan.routes.forEach { builder.addRoute(it.host(), it.prefix(32)) }
        plan.dns.forEach { builder.addDnsServer(it) }
        val pfd = builder.establish() ?: error("establish 失败：未授权或已有其它 VPN")
        tunnel = pfd
        Mobile.establish(pfd.fd)
    }

    // closeTunnel 关闭系统网卡，忽略库已关闭同一 fd 的情况。
    private fun closeTunnel() {
        runCatching { tunnel?.close() }
        tunnel = null
    }

    // buildNotification 构造前台服务通知。
    private fun buildNotification(): android.app.Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.notification_channel),
                    NotificationManager.IMPORTANCE_LOW,
                )
            )
        }
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setSmallIcon(android.R.drawable.stat_sys_vpn_ic)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }
}

// host 去掉 CIDR 的掩码部分。
private fun String.host(): String = substringBefore('/')

// prefix 取 CIDR 掩码；IPv6 缺省 128。
private fun String.prefix(default: Int): Int {
    val text = substringAfter('/', "")
    if (text.isNotEmpty()) {
        return text.toIntOrNull() ?: default
    }
    return if (contains(':')) 128 else default
}
