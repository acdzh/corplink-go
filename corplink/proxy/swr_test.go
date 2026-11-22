package proxy

import (
	"net/netip"
	"testing"
	"time"
)

// 缓存过期后仍应返回旧地址（stale-while-revalidate），而不是让调用方去等冷解析。
func TestLoadCachedReturnsStaleEntry(t *testing.T) {
	s := &Server{cache: map[string]resolveEntry{}}
	addr := netip.MustParseAddr("10.8.7.149")
	s.cache["code.byted.org"] = resolveEntry{addr: addr, expires: time.Now().Add(-time.Minute)}

	got, ok := s.loadCached("code.byted.org")
	if !ok {
		t.Fatal("过期条目应仍然命中（stale）")
	}
	if got != addr {
		t.Fatalf("应返回旧地址 %s，实际 %s", addr, got)
	}
}

// 没有缓存时不应该命中。
func TestLoadCachedMiss(t *testing.T) {
	s := &Server{cache: map[string]resolveEntry{}}
	if _, ok := s.loadCached("nope.example"); ok {
		t.Fatal("无缓存时不应命中")
	}
}
