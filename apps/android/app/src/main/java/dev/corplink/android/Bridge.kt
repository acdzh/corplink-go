package dev.corplink.android

import mobile.Mobile
import org.json.JSONArray
import org.json.JSONObject

// NodeInfo 是节点列表里的一项。
data class NodeInfo(
    val name: String = "",
    val tag: String = "",
    val protocolMode: Int = 0,
    val latencyMs: Long = -1,
)

// StatusInfo 是状态快照，字段来自库的 Status 与 Stats。
data class StatusInfo(
    val connected: Boolean = false,
    val node: String = "",
    val address: String = "",
    val loggedIn: Boolean = false,
    val mfaPending: Boolean = false,
    val hasTotp: Boolean = false,
    val txBytes: Long = 0,
    val rxBytes: Long = 0,
    val company: String = "",
    val server: String = "",
    val error: String = "",
)

// VpnPlan 是 VpnService.Builder 建网卡需要的参数。
//
// routes 已经按模式选好；routesFull / routesSplit 是两套原样路由，方便界面展示。
data class VpnPlan(
    val node: String = "",
    val addresses: List<String> = emptyList(),
    val routes: List<String> = emptyList(),
    val routesFull: List<String> = emptyList(),
    val routesSplit: List<String> = emptyList(),
    val dns: List<String> = emptyList(),
    val mtu: Int = 1420,
    val mode: String = "full",
)

// Bridge 把库返回的 JSON 翻译成数据类，界面不直接解析 JSON。
object Bridge {
    // status 读状态与流量。
    fun status(): StatusInfo {
        val status = JSONObject(Mobile.status())
        val state = status.optJSONObject("state") ?: JSONObject()
        val stats = runCatching { JSONObject(Mobile.stats()) }.getOrDefault(JSONObject())
        return StatusInfo(
            connected = state.optBoolean("connected"),
            node = state.optString("node"),
            address = state.optString("address"),
            loggedIn = status.optBoolean("logged_in"),
            mfaPending = status.optBoolean("mfa_pending"),
            hasTotp = status.optBoolean("has_totp"),
            txBytes = stats.optLong("tx_bytes"),
            rxBytes = stats.optLong("rx_bytes"),
            company = status.optString("company_name"),
            server = status.optString("server"),
            error = status.optString("error"),
        )
    }

    // nodes 读节点列表，并把测速结果贴到对应节点上。
    fun nodes(): List<NodeInfo> {
        val array = runCatching { JSONArray(Mobile.nodes()) }.getOrNull() ?: return emptyList()
        val latencies = runCatching { JSONObject(Mobile.latencies()) }.getOrDefault(JSONObject())
        val out = ArrayList<NodeInfo>(array.length())
        for (i in 0 until array.length()) {
            val item = array.optJSONObject(i) ?: continue
            val name = item.optString("name")
            out += NodeInfo(
                name = name,
                tag = item.optString("tag"),
                protocolMode = item.optInt("protocol_mode"),
                latencyMs = latencies.optLong(name, -1L),
            )
        }
        return out
    }

    // plan 申请隧道参数，供 VpnService 建网卡；full 为真走全局，否则只走内网。
    fun plan(node: String, full: Boolean): VpnPlan {
        val json = JSONObject(Mobile.plan(node, full))
        return VpnPlan(
            node = json.optString("node"),
            addresses = json.optJSONArray("addresses").toStringList(),
            routes = json.optJSONArray("routes").toStringList(),
            routesFull = json.optJSONArray("routes_full").toStringList(),
            routesSplit = json.optJSONArray("routes_split").toStringList(),
            dns = json.optJSONArray("dns").toStringList(),
            mtu = json.optInt("mtu", 1420),
            mode = json.optString("mode", "full"),
        )
    }

    // totp 读当前动态码。
    fun totp(): String {
        val json = runCatching { JSONObject(Mobile.totp()) }.getOrDefault(JSONObject())
        return if (json.optBoolean("has_secret")) json.optString("code") else ""
    }

    // authURL 发起登录并返回授权链接。
    fun authURL(alias: String): String {
        val json = JSONObject(Mobile.loginStart(alias))
        return json.optString("url")
    }

    // submitCallback 提交授权回调，返回需要二次验证时的提示。
    fun submitCallback(callback: String): String {
        val json = JSONObject(Mobile.loginCallback(callback))
        return if (json.optBoolean("mfa_required")) "需要二次验证" else "登录成功"
    }

    // submitMFA 提交二次验证码。
    fun submitMFA(code: String): String {
        JSONObject(Mobile.loginMFA(code))
        return "登录成功"
    }

    // startProxy 在 addr 上开本地混合代理。
    fun startProxy(addr: String): String {
        Mobile.startProxy(addr)
        return Mobile.proxyAddr()
    }

    // stopProxy 关掉本地混合代理。
    fun stopProxy() {
        Mobile.stopProxy()
    }

    // proxyAddr 返回当前代理监听地址，未启动时为空。
    fun proxyAddr(): String = runCatching { Mobile.proxyAddr() }.getOrDefault("")
}

// toStringList 把 JSON 数组转成字符串列表，忽略空值。
private fun JSONArray?.toStringList(): List<String> {
    if (this == null) {
        return emptyList()
    }
    val out = ArrayList<String>(length())
    for (i in 0 until length()) {
        val value = optString(i, "")
        if (value.isNotEmpty()) {
            out += value
        }
    }
    return out
}
