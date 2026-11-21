package clock

import (
	"net/http"
	"testing"
	"time"
)

// TestSyncFromDate 覆盖用 Date 头校准偏移。
func TestSyncFromDate(t *testing.T) {
	Reset()
	defer Reset()
	future := time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat)
	if !SyncFromDate(future) {
		t.Fatal("偏差 90 秒应触发校准")
	}
	if got := Offset(); got < 85*time.Second || got > 95*time.Second {
		t.Fatalf("偏移 = %v，应在 90s 附近", got)
	}
	// 偏差小于 2 秒不处理
	Reset()
	near := time.Now().UTC().Format(http.TimeFormat)
	if SyncFromDate(near) {
		t.Fatal("秒级噪声不应触发校准")
	}
}

// TestSyncFromUnix 覆盖用业务体 timestamp 校准。
func TestSyncFromUnix(t *testing.T) {
	Reset()
	defer Reset()
	if !SyncFromUnix(time.Now().Add(-120 * time.Second).Unix()) {
		t.Fatal("偏差 -120 秒应触发校准")
	}
	if got := Offset(); got > -110*time.Second || got < -130*time.Second {
		t.Fatalf("偏移 = %v", got)
	}
	if SyncFromUnix(0) {
		t.Fatal("非法 timestamp 不应校准")
	}
}

// TestNowAppliesOffset 覆盖 Now() 叠加偏移。
func TestNowAppliesOffset(t *testing.T) {
	Reset()
	defer Reset()
	SetOffset(30 * time.Second)
	diff := time.Until(Now().Add(-30 * time.Second))
	if diff > 2*time.Second || diff < -2*time.Second {
		t.Fatalf("Now() 未叠加偏移，差值 %v", diff)
	}
}
