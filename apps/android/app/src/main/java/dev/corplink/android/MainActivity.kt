package dev.corplink.android

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import mobile.Mobile
import java.io.File

// MainActivity 是 Android 端的壳：申请 VPN 授权、启动前台服务、展示库快照。
class MainActivity : ComponentActivity() {

    // pendingNode 是等待授权的节点名。
    private var pendingNode = ""
    // message 是最近一次操作的提示。
    private var message by mutableStateOf("")

    // consent 处理系统 VPN 授权结果。
    private val consent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val node = pendingNode
        pendingNode = ""
        if (result.resultCode == Activity.RESULT_OK && node.isNotEmpty()) {
            launchService(CorplinkVpnService.ACTION_CONNECT, node)
        } else {
            message = "未授予 VPN 权限"
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val configPath = File(filesDir, "config.json").absolutePath
        runCatching { Mobile.start(configPath) }.onFailure { message = it.message ?: "初始化失败" }
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    Screen(
                        message = message,
                        onNotice = { message = it },
                        onOpenUrl = { url -> startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) },
                        onConnect = ::requestVpn,
                        onDisconnect = { launchService(CorplinkVpnService.ACTION_DISCONNECT, "") },
                    )
                }
            }
        }
    }

    // requestVpn 先拿系统授权，再启动前台服务。
    private fun requestVpn(node: String) {
        pendingNode = node
        val intent = VpnService.prepare(this)
        if (intent != null) {
            consent.launch(intent)
            return
        }
        launchService(CorplinkVpnService.ACTION_CONNECT, node)
    }

    // launchService 启动 VPN 前台服务。
    private fun launchService(action: String, node: String) {
        val intent = Intent(this, CorplinkVpnService::class.java).setAction(action)
        if (node.isNotEmpty()) {
            intent.putExtra(CorplinkVpnService.EXTRA_NODE, node)
        }
        ContextCompat.startForegroundService(this, intent)
    }
}

// Screen 是唯一界面：状态、登录、节点都从库的 JSON 快照读。
@Composable
private fun Screen(
    message: String,
    onNotice: (String) -> Unit,
    onOpenUrl: (String) -> Unit,
    onConnect: (String) -> Unit,
    onDisconnect: () -> Unit,
) {
    var status by remember { mutableStateOf(StatusInfo()) }
    var nodes by remember { mutableStateOf(emptyList<NodeInfo>()) }
    var totp by remember { mutableStateOf("") }
    var callback by remember { mutableStateOf("") }
    var mfaCode by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()

    // 每秒刷新一次快照：库内部已经维护状态，界面只读。
    LaunchedEffect(Unit) {
        while (true) {
            withContext(Dispatchers.IO) {
                status = runCatching { Bridge.status() }.getOrDefault(StatusInfo())
                nodes = runCatching { Bridge.nodes() }.getOrDefault(emptyList())
                totp = runCatching { Bridge.totp() }.getOrDefault("")
            }
            delay(1000)
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text(text = "Corplink Go", style = MaterialTheme.typography.headlineSmall)
        }
        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        text = if (status.connected) "已连接 ${status.node}" else "未连接",
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text(text = "企业: ${status.company}", style = MaterialTheme.typography.bodySmall)
                    Text(text = "服务端: ${status.server}", style = MaterialTheme.typography.bodySmall)
                    if (status.address.isNotEmpty()) {
                        Text(text = "隧道地址: ${status.address}", style = MaterialTheme.typography.bodySmall)
                    }
                    Text(
                        text = "流量 下行 ${status.rxBytes / 1024} KB / 上行 ${status.txBytes / 1024} KB",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    if (status.error.isNotEmpty()) {
                        Text(text = "错误: ${status.error}", style = MaterialTheme.typography.bodySmall)
                    }
                    if (message.isNotEmpty()) {
                        Text(text = message, style = MaterialTheme.typography.bodySmall)
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = onDisconnect) { Text("断开") }
                        Button(onClick = {
                            scope.launch(Dispatchers.IO) {
                                runCatching { Mobile.refreshNodes() }
                                    .onFailure { onNotice(it.message ?: "刷新失败") }
                            }
                        }) { Text("刷新节点") }
                        if (totp.isNotEmpty()) {
                            OutlinedButton(onClick = { onNotice("动态码 $totp") }) { Text("动态码") }
                        }
                    }
                }
            }
        }
        item {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "账号", style = MaterialTheme.typography.titleMedium)
                    Text(
                        text = if (status.loggedIn) "已登录" else "未登录",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    OutlinedButton(onClick = {
                        scope.launch(Dispatchers.IO) {
                            runCatching { Bridge.authURL("") }
                                .onSuccess { url -> withContext(Dispatchers.Main) { onOpenUrl(url) } }
                                .onFailure { onNotice(it.message ?: "获取授权链接失败") }
                        }
                    }) { Text("浏览器授权") }
                    OutlinedTextField(
                        value = callback,
                        onValueChange = { callback = it },
                        label = { Text("回调地址") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                    )
                    OutlinedButton(onClick = {
                        scope.launch(Dispatchers.IO) {
                            runCatching { Bridge.submitCallback(callback) }
                                .onSuccess { onNotice(it) }
                                .onFailure { onNotice(it.message ?: "提交失败") }
                        }
                    }) { Text("提交回调") }
                    OutlinedTextField(
                        value = mfaCode,
                        onValueChange = { mfaCode = it },
                        label = { Text("二次验证码（留空用 TOTP）") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = {
                            scope.launch(Dispatchers.IO) {
                                runCatching { Mobile.loginSendMFA("email") }
                                    .onSuccess { onNotice("已请求邮箱验证码") }
                                    .onFailure { onNotice(it.message ?: "下发失败") }
                            }
                        }) { Text("发送邮箱码") }
                        Button(onClick = {
                            scope.launch(Dispatchers.IO) {
                                runCatching { Bridge.submitMFA(mfaCode) }
                                    .onSuccess { onNotice(it) }
                                    .onFailure { onNotice(it.message ?: "验证失败") }
                            }
                        }) { Text("提交验证") }
                    }
                }
            }
        }
        item { HorizontalDivider() }
        item {
            Text(text = "节点 ${nodes.size}", style = MaterialTheme.typography.titleMedium)
        }
        items(nodes) { node ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column {
                        Text(text = node.name, style = MaterialTheme.typography.bodyLarge)
                        Text(
                            text = listOf(
                                node.tag,
                                if (node.protocolMode == 1) "TCP" else "UDP",
                                if (node.latencyMs >= 0) "${node.latencyMs} ms" else "未测速",
                            ).filter { it.isNotEmpty() }.joinToString(" · "),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    Button(onClick = { onConnect(node.name) }) { Text("连接") }
                }
            }
        }
    }
}
