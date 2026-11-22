package agent

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/acdzh/corplink-go/corplink/tunnel"
)

// 官方 VpnHandshakeOperate：TCP 6 秒、UDP 9 秒、其余 15 秒。
func TestHandshakeBudget(t *testing.T) {
	cases := []struct {
		protocol int
		want     time.Duration
	}{
		{tunnel.ProtocolTCP, 6 * time.Second},
		{tunnel.ProtocolUDP, 9 * time.Second},
		{2, 15 * time.Second},
	}
	for _, c := range cases {
		if got := handshakeBudget(c.protocol); got != c.want {
			t.Fatalf("protocol=%d 预算应为 %s，实际 %s", c.protocol, c.want, got)
		}
	}
}

func TestHandshakeAtParsesUAPI(t *testing.T) {
	raw := "private_key=aa\npublic_key=bb\nlast_handshake_time_sec=1763770000\nlast_handshake_time_nsec=0\n"
	if got := handshakeAt(raw); got.Unix() != 1763770000 {
		t.Fatalf("应解析出 1763770000，实际 %v", got)
	}
	if got := handshakeAt("public_key=bb\n"); !got.IsZero() {
		t.Fatalf("没有握手行时应返回零值，实际 %v", got)
	}
}

// 握手一到位就立刻返回，不必等满预算。
func TestWaitHandshakeReturnsOnComplete(t *testing.T) {
	since := time.Now()
	stats := func() (string, error) {
		return "last_handshake_time_sec=" + itoa(since.Unix()+1) + "\n", nil
	}
	start := time.Now()
	if err := waitHandshakeWith(stats, since, 5*time.Second); err != nil {
		t.Fatalf("握手成功时不应报错: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("握手成功应立即返回，实际等了 %s", elapsed)
	}
}

// 始终没有握手 → 必须是 errHandshakeTimeout，调用方据此换协议/换节点。
func TestWaitHandshakeTimeout(t *testing.T) {
	stats := func() (string, error) { return "public_key=bb\n", nil }
	err := waitHandshakeWith(stats, time.Now(), 300*time.Millisecond)
	if !errors.Is(err, errHandshakeTimeout) {
		t.Fatalf("应返回 errHandshakeTimeout，实际 %v", err)
	}
}

// 上一次连接遗留的握手时间戳不能当成这次的成功。
func TestWaitHandshakeIgnoresStaleHandshake(t *testing.T) {
	since := time.Now()
	stats := func() (string, error) {
		return "last_handshake_time_sec=" + itoa(since.Unix()-600) + "\n", nil
	}
	err := waitHandshakeWith(stats, since, 300*time.Millisecond)
	if !errors.Is(err, errHandshakeTimeout) {
		t.Fatalf("陈旧的握手时间戳应判超时，实际 %v", err)
	}
}

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}
