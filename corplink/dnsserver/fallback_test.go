package dnsserver

import "testing"

// TestPhysicalFallback 校验隧道上游失败时会兜底物理 DNS，且不与主上游重复。
func TestPhysicalFallback(t *testing.T) {
	s := New(Options{Listen: "127.0.0.1:0", Upstream: []string{"10.8.8.18:53"}, SystemUpstream: []string{"127.0.0.53:53", "10.8.8.18:53"}})
	got := s.physicalFallback([]string{"10.8.8.18:53"})
	if len(got) != 1 || got[0] != "127.0.0.53:53" {
		t.Fatalf("兜底候选 = %v，应只保留物理 DNS", got)
	}
}

// TestPhysicalFallbackSameAsPrimary 校验物理 DNS 与主上游相同时不产生兜底候选。
func TestPhysicalFallbackSameAsPrimary(t *testing.T) {
	s := New(Options{Listen: "127.0.0.1:0", SystemUpstream: []string{"10.8.8.18:53"}})
	if got := s.physicalFallback([]string{"10.8.8.18:53"}); len(got) != 0 {
		t.Fatalf("应无兜底候选，实际 %v", got)
	}
}
