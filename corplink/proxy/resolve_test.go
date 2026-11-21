package proxy

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// fakeTun 是可计数的假隧道解析器。
type fakeTun struct {
	calls int32
	addrs []string
	delay time.Duration
}

func (f *fakeTun) LookupHost(host string) ([]string, error) {
	atomic.AddInt32(&f.calls, 1)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return f.addrs, nil
}

// TestResolveCachesResult 校验同一域名只解析一次。
func TestResolveCachesResult(t *testing.T) {
	s := New(nil)
	tun := &fakeTun{addrs: []string{"10.8.7.149"}}
	for i := 0; i < 3; i++ {
		addr, err := s.resolve(tun, "code.byted.org")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if addr != netip.MustParseAddr("10.8.7.149") {
			t.Fatalf("addr = %v", addr)
		}
	}
	if got := atomic.LoadInt32(&tun.calls); got != 1 {
		t.Fatalf("应只解析 1 次，实际 %d 次", got)
	}
}

// TestResolveTimesOutFast 校验解析卡住时会快速失败，而不是拖死握手。
func TestResolveTimesOutFast(t *testing.T) {
	s := New(nil)
	tun := &fakeTun{addrs: []string{"10.0.0.1"}, delay: resolveTimeout * 3}
	start := time.Now()
	if _, err := s.resolve(tun, "slow.example.com"); err == nil {
		t.Fatal("应返回超时错误")
	}
	if elapsed := time.Since(start); elapsed > resolveTimeout+time.Second {
		t.Fatalf("超时未生效，耗时 %v", elapsed)
	}
}

// TestResetCache 校验清缓存后会重新解析。
func TestResetCache(t *testing.T) {
	s := New(nil)
	tun := &fakeTun{addrs: []string{"10.0.0.2"}}
	_, _ = s.resolve(tun, "a.example.com")
	s.ResetCache()
	_, _ = s.resolve(tun, "a.example.com")
	if got := atomic.LoadInt32(&tun.calls); got != 2 {
		t.Fatalf("清缓存后应重新解析，实际调用 %d 次", got)
	}
}
