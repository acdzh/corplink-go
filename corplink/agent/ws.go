package agent

// WebSocket 长连接（/api/ws/socket）。
//
// 官方用它接收两类即时事件：MFA 推送审批的确认请求，以及服务端下发的
// 踢线/策略变更通知。没有它时，开"推送审批"的租户会卡在"验证码都对但进不去"，
// 踢线也只能等保活轮询才发现。
//
// 协议要点（bz1.java:72 / :100-113 / az1.java:41-50）：
//   - 端点 /api/ws/socket?<客户端元信息>
//   - 20 秒 ping，读写超时同为 20 秒
//   - 收到消息后要回 {"action":"message_received","id":<id>}
//   - 断线最多重试 3 次

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/acdzh/corplink-go/corplink/api"

	"golang.org/x/net/websocket"
)

// WebSocket 重连参数。
const (
	// wsRetry 是一次断线内的最大重试次数（az1.java:41-50）。
	wsRetry = 3
	// wsRetryDelay 是重试间隔。
	wsRetryDelay = 3 * time.Second
	// wsIdleDelay 是一轮重试都失败后的等待时间。
	wsIdleDelay = 2 * time.Minute
)

// RunWebSocket 维持一条到服务端的推送长连接，直到 ctx 结束。
func (a *Agent) RunWebSocket(ctx context.Context) {
	if a.cfg.Server == "" {
		return
	}
	for {
		if err := a.runWebSocketOnce(ctx); err != nil {
			a.addEvent("warn", "推送长连接断开: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wsIdleDelay):
		}
	}
}

// runWebSocketOnce 建立一次连接并持续读取消息。
func (a *Agent) runWebSocketOnce(ctx context.Context) error {
	base, err := url.Parse(a.cfg.Server)
	if err != nil {
		return err
	}
	scheme := "wss"
	if base.Scheme == "http" {
		scheme = "ws"
	}
	target := url.URL{
		Scheme:   scheme,
		Host:     base.Host,
		Path:     "/api/ws/socket",
		RawQuery: a.meta.Query().Encode(),
	}
	cfg, err := websocket.NewConfig(target.String(), base.Scheme+"://"+base.Host)
	if err != nil {
		return err
	}
	cfg.TlsConfig = &tls.Config{InsecureSkipVerify: true}
	cookies := a.client.Cookies()
	cfg.Header.Set("User-Agent", api.UserAgent(a.meta))
	for _, ck := range cookies {
		cfg.Header.Add("Cookie", ck.Name+"="+ck.Value)
	}

	var conn *websocket.Conn
	for attempt := 1; attempt <= wsRetry; attempt++ {
		conn, err = websocket.DialConfig(cfg)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wsRetryDelay):
		}
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.PayloadType = websocket.TextFrame
	a.addEvent("info", "推送长连接已建立")

	// 用 ctx 取消来中断阻塞读。
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	for {
		var raw string
		if err := websocket.Message.Receive(conn, &raw); err != nil {
			return err
		}
		a.handleWebSocketMessage(conn, raw)
	}
}

// wsMessage 是推送消息的通用外壳。
//
// 官方的事件枚举没有完整反编译出来（az1.java 的 onMessage 被 jadx 跳过），
// 因此这里按"通用外壳 + 透传"处理：认识 action/id 就回执并记事件，其余只记日志。
type wsMessage struct {
	Action string          `json:"action"`
	ID     string          `json:"id"`
	Type   string          `json:"type"`
	Data   json.RawMessage `json:"data"`
}

// handleWebSocketMessage 处理一条推送：回执 + 分派已知事件。
func (a *Agent) handleWebSocketMessage(conn *websocket.Conn, raw string) {
	a.addEvent("info", "收到推送: %s", truncateText(raw, 200))
	msg := wsMessage{}
	if err := json.Unmarshal([]byte(raw), &msg); err != nil {
		return
	}
	if msg.ID != "" {
		// 双向确认：不回执服务端会重推（bz1.java:100-113）。
		ack, _ := json.Marshal(map[string]string{"action": "message_received", "id": msg.ID})
		_ = websocket.Message.Send(conn, string(ack))
	}
	switch strings.ToLower(msg.Action) {
	case "logout", "kick_out", "force_logout":
		a.handleKicked(fmt.Errorf("服务端推送下线（%s）", msg.Action))
	case "config_update", "setting_update":
		a.addEvent("info", "服务端配置已变更，建议重新连接以生效")
	}
}

// truncateText 截断长文本用于日志。
func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
