package dnsserver

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// buildQueryWithID 构造指定报文 ID 的 A 查询。
func buildQueryWithID(name string, id uint16) ([]byte, error) {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name + "."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	return builder.Finish()
}

// rawQuery 发一条查询，返回原始响应。
func rawQuery(t *testing.T, server, name string, id uint16) []byte {
	t.Helper()
	msg, err := buildQueryWithID(name, id)
	if err != nil {
		t.Fatalf("构造查询: %v", err)
	}
	conn, err := net.DialTimeout("udp", server, 2*time.Second)
	if err != nil {
		t.Fatalf("拨号: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("发送: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("读取响应: %v", err)
	}
	return buf[:n]
}

// TestCacheHitKeepsQueryID 校验缓存命中时响应 ID 与本次查询一致。
//
// 回归点：缓存存的是完整报文，直接回出去会带着上一次查询的 ID，
// 客户端按 ID 匹配失败后丢弃响应，表现为"首次解析正常、之后同域名全部超时"。
func TestCacheHitKeepsQueryID(t *testing.T) {
	var hits int
	upstream, stop := fakeUpstreamCounting(t, "10.0.0.9", &hits)
	defer stop()
	server := New(Options{Listen: "127.0.0.1:0", Upstream: []string{upstream}, SystemUpstream: []string{upstream}})
	if err := server.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	defer server.Close()
	addr := server.Addr()

	_ = rawQuery(t, addr, "b.corp.local", 1)
	before := hits
	resp := rawQuery(t, addr, "b.corp.local", 4242)
	if hits != before {
		t.Fatalf("第二次应命中缓存，上游命中数 %d -> %d", before, hits)
	}
	if got := binary.BigEndian.Uint16(resp[:2]); got != 4242 {
		t.Fatalf("缓存响应 ID = %d，应为 4242（否则客户端会丢弃）", got)
	}
}
