package agent

// 连接上报（/vpn/report）。
//
// 官方客户端连上后立刻发 type=100，之后每 60 秒重发一次；断开发 type=101。
// 这个接口同时是唯一的"被踢线"信号：响应 code=1000 表示服务端已把本端下线
// （VpnReportOperator.java:51-53、VpnManagerImpl.java:1355-1371、:1230）。

import (
	"context"
	"fmt"
	"time"

	"github.com/acdzh/corplink-go/corplink/api"
)

// 上报类型。
const (
	// reportConnect 表示连接成功。
	reportConnect = "100"
	// reportDisconnect 表示断开。
	reportDisconnect = "101"
	// reportInterval 是连接期间的周期重报间隔。
	reportInterval = 60 * time.Second
	// codeReportKicked 是服务端用来通知"你已被顶下线"的业务码。
	codeReportKicked = 1000
)

// startReport 启动连接上报循环。
func (a *Agent) startReport(plan *Plan) {
	if plan == nil {
		return
	}
	a.stopReport(false)
	a.mu.Lock()
	stop := make(chan struct{})
	a.reportStop = stop
	a.reportNode = plan.node
	a.reportIP = plan.cfg.Addresses[0]
	a.reportPubKey = plan.publicKey
	a.reportMode = plan.mode.connMode()
	a.mu.Unlock()

	a.sendReport(reportConnect)
	go func() {
		ticker := time.NewTicker(reportInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				a.sendReport(reportConnect)
			}
		}
	}()
}

// stopReport 停止上报循环，必要时补一条断开上报。
func (a *Agent) stopReport(sendDisconnect bool) {
	a.mu.Lock()
	stop := a.reportStop
	a.reportStop = nil
	a.mu.Unlock()
	if stop == nil {
		return
	}
	close(stop)
	if sendDisconnect {
		a.sendReport(reportDisconnect)
	}
}

// stopReportLoopOnly 停掉周期上报但不再补发 101（避免与断开的处理互相触发）。
func (a *Agent) stopReportLoopOnly() {
	a.mu.Lock()
	stop := a.reportStop
	a.reportStop = nil
	a.mu.Unlock()
	if stop != nil {
		close(stop)
	}
}

// sendReport 发一次上报；响应 code=1000 表示连接被服务端终止（不是登录失效）。
func (a *Agent) sendReport(typ string) {
	a.mu.RLock()
	node := a.reportNode
	ip := a.reportIP
	pub := a.reportPubKey
	mode := a.reportMode
	a.mu.RUnlock()
	if node.IP == "" {
		return
	}
	client, err := api.New(api.Options{
		Server:             fmt.Sprintf("https://%s:%d", node.IP, node.APIPort),
		DeviceID:           a.cfg.DeviceID,
		Language:           a.cfg.Language,
		InsecureSkipVerify: true,
		Meta:               a.meta,
		Verbose:            a.verbose,
	})
	if err != nil {
		return
	}
	client.SetCookies(a.client.Cookies())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	env, err := client.Do(ctx, api.EndpointVPNReport, nil, map[string]string{
		"type":       typ,
		"ip":         ip,
		"public_key": pub,
		"mode":       mode,
	})
	if err != nil {
		a.addEvent("warn", "连接上报失败（%s）: %v", typ, err)
		return
	}
	if env.Code == codeReportKicked {
		// code=1000 只代表"这条隧道连接被服务端终止"，与登录态无关。
		// 这里绝不能走 handleKicked：那会清 cookie、删 session.json，把一次
		// 可以自愈的连接抖动升级成"必须重新扫码/收验证码登录"。
		a.addEvent("warn", "服务端终止了本端连接（report code=1000），保留登录态")
		a.stopReportLoopOnly()
		a.Disconnect()
		// 服务端踢掉的只是这条隧道连接：断开立刻用上次保存的 sign_token/identities
		// 续连同一个节点，续不上再退化为一次新建连接。
		a.resumeKickedConnection()
		return
	}
	// 上报成功说明这条连接是健康的，把连续续连计数清零。
	a.markReportHealthy()
}
