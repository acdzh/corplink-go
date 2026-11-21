package dnsserver

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeUpstream 起一个只回固定 A 记录的 UDP+TCP DNS。
func fakeUpstream(t *testing.T, ip string) (string, func()) {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("解析地址: %v", err)
	}
	udp, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("监听: %v", err)
	}
	stop := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = udp.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, remote, err := udp.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			resp := buildAnswer(t, buf[:n], ip)
			if resp != nil {
				_, _ = udp.WriteToUDP(resp, remote)
			}
		}
	}()
	return udp.LocalAddr().String(), func() {
		close(stop)
		_ = udp.Close()
	}
}

// buildAnswer 把查询包成一条 A 记录响应。
func buildAnswer(t *testing.T, query []byte, ip string) []byte {
	parser := dnsmessage.Parser{}
	header, err := parser.Start(query)
	if err != nil {
		return nil
	}
	question, err := parser.Question()
	if err != nil {
		return nil
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		RecursionDesired:   header.RecursionDesired,
		RecursionAvailable: true,
	})
	if err := builder.StartQuestions(); err != nil {
		return nil
	}
	if err := builder.Question(question); err != nil {
		return nil
	}
	if err := builder.StartAnswers(); err != nil {
		return nil
	}
	addr := net.ParseIP(ip).To4()
	if addr == nil {
		return nil
	}
	var a [4]byte
	copy(a[:], addr)
	if err := builder.AResource(dnsmessage.ResourceHeader{
		Name:  question.Name,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
		TTL:   60,
	}, dnsmessage.AResource{A: a}); err != nil {
		return nil
	}
	out, err := builder.Finish()
	if err != nil {
		return nil
	}
	return out
}

// queryA 构造一条 A 查询并解析出 IP。
func queryA(t *testing.T, server, name string) (string, error) {
	t.Helper()
	msg, err := buildQuery(name)
	if err != nil {
		return "", err
	}
	conn, err := net.DialTimeout("udp", server, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		return "", err
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	parser := dnsmessage.Parser{}
	if _, err := parser.Start(buf[:n]); err != nil {
		return "", err
	}
	if _, err := parser.AllQuestions(); err != nil {
		return "", err
	}
	for {
		h, err := parser.AnswerHeader()
		if err != nil {
			break
		}
		if h.Type == dnsmessage.TypeA {
			res, err := parser.AResource()
			if err != nil {
				break
			}
			return net.IP(res.A[:]).String(), nil
		}
		if err := parser.SkipAnswer(); err != nil {
			break
		}
	}
	return "", nil
}

// buildQuery 构造 A 查询。
func buildQuery(name string) ([]byte, error) {
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
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

// TestAllQueriesGoToTunnel 覆盖默认形态：连上隧道后所有查询都发给公司 DNS。
func TestAllQueriesGoToTunnel(t *testing.T) {
	tunnelAddr, stopTunnel := fakeUpstream(t, "10.88.128.53")
	defer stopTunnel()
	systemAddr, stopSystem := fakeUpstream(t, "1.2.3.4")
	defer stopSystem()

	server := New(Options{
		Listen:         "127.0.0.1:0",
		Upstream:       []string{tunnelAddr},
		SystemUpstream: []string{systemAddr},
	})
	if err := server.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	defer server.Close()
	addr := server.Addr()
	for _, name := range []string{"www.bytedance.net", "example.com"} {
		if got, err := queryA(t, addr, name); err != nil || got != "10.88.128.53" {
			t.Fatalf("%s 应走公司 DNS，得到 %q / %v", name, got, err)
		}
	}
}

// TestExcludeGoesPhysical 覆盖排除表：命中排除表的域名走物理网络 DNS。
func TestExcludeGoesPhysical(t *testing.T) {
	tunnelAddr, stopTunnel := fakeUpstream(t, "10.88.128.53")
	defer stopTunnel()
	systemAddr, stopSystem := fakeUpstream(t, "1.2.3.4")
	defer stopSystem()

	server := New(Options{
		Listen:         "127.0.0.1:0",
		Upstream:       []string{tunnelAddr},
		SystemUpstream: []string{systemAddr},
		ExcludeFunc:    func() []string { return []string{"bytedance.com", "*.corp.example"} },
	})
	if err := server.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	defer server.Close()
	addr := server.Addr()
	if got, err := queryA(t, addr, "www.bytedance.net"); err != nil || got != "10.88.128.53" {
		t.Fatalf("未命中排除表应走公司 DNS，得到 %q / %v", got, err)
	}
	if got, err := queryA(t, addr, "hr.bytedance.com"); err != nil || got != "1.2.3.4" {
		t.Fatalf("命中排除表应走物理 DNS，得到 %q / %v", got, err)
	}
}

// TestSplitModeFollowsDomains 覆盖可选的分流模式。
func TestSplitModeFollowsDomains(t *testing.T) {
	tunnelAddr, stopTunnel := fakeUpstream(t, "10.88.128.53")
	defer stopTunnel()
	systemAddr, stopSystem := fakeUpstream(t, "1.2.3.4")
	defer stopSystem()

	server := New(Options{
		Listen:         "127.0.0.1:0",
		Upstream:       []string{tunnelAddr},
		SystemUpstream: []string{systemAddr},
		SplitDomains:   []string{"bytedance.net"},
		SplitMode:      true,
	})
	if err := server.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	defer server.Close()
	addr := server.Addr()
	if got, err := queryA(t, addr, "www.bytedance.net"); err != nil || got != "10.88.128.53" {
		t.Fatalf("分流模式下内网域名应走公司 DNS，得到 %q / %v", got, err)
	}
	if got, err := queryA(t, addr, "example.com"); err != nil || got != "1.2.3.4" {
		t.Fatalf("分流模式下公网域名应走物理 DNS，得到 %q / %v", got, err)
	}
}

// TestCache 覆盖缓存命中后不再访问上游。
func TestCache(t *testing.T) {
	var hits int
	tunnelAddr, stop := fakeUpstreamCounting(t, "10.0.0.9", &hits)
	defer stop()
	server := New(Options{Listen: "127.0.0.1:0", Upstream: []string{tunnelAddr}, SystemUpstream: []string{tunnelAddr}, SplitDomains: []string{"corp.local"}})
	if err := server.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	defer server.Close()
	if _, err := queryA(t, server.Addr(), "a.corp.local"); err != nil {
		t.Fatalf("首次查询: %v", err)
	}
	first := hits
	if _, err := queryA(t, server.Addr(), "a.corp.local"); err != nil {
		t.Fatalf("二次查询: %v", err)
	}
	if hits != first {
		t.Fatalf("第二次应命中缓存，上游命中数 %d -> %d", first, hits)
	}
}

// fakeUpstreamCounting 计数版上游。
func fakeUpstreamCounting(t *testing.T, ip string, hits *int) (string, func()) {
	t.Helper()
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udp, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("监听: %v", err)
	}
	stop := make(chan struct{})
	go func() {
		buf := make([]byte, 2048)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = udp.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, remote, err := udp.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			*hits++
			if resp := buildAnswer(t, buf[:n], ip); resp != nil {
				_, _ = udp.WriteToUDP(resp, remote)
			}
		}
	}()
	return udp.LocalAddr().String(), func() { close(stop); _ = udp.Close() }
}

// TestUpstreamFallback 覆盖主 DNS 不可用时切备用。
func TestUpstreamFallback(t *testing.T) {
	good, stop := fakeUpstream(t, "10.9.9.9")
	defer stop()
	server := New(Options{
		Listen:         "127.0.0.1:0",
		Upstream:       []string{"127.0.0.1:1", good},
		SystemUpstream: []string{"127.0.0.1:1", good},
		SplitDomains:   []string{"corp.local"},
	})
	if err := server.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	defer server.Close()
	if got, err := queryA(t, server.Addr(), "x.corp.local"); err != nil || got != "10.9.9.9" {
		t.Fatalf("应回落到备用 DNS，得到 %q / %v", got, err)
	}
}

var _ = context.Background
