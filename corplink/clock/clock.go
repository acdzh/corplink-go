// Package clock 提供与服务端对齐的时间源。
//
// 飞连客户端里有两处对时间敏感：TOTP（30 秒步长，服务端只认 ±1 步）与
// DPoP 证明的 iat（服务端容忍窗口较小）。官方客户端用 otp_time_diff 把
// 「服务端时间 - 本机时间」记下来，TOTP 与 proof 都叠加这个偏移。
//
// 本包就是那个偏移的唯一来源：api 层在每次响应里用 Date 头（以及业务体里的
// timestamp 字段）校准，其余模块一律用 Now() 取时间。
package clock

import (
	"net/http"
	"sync/atomic"
	"time"
)

// offsetMS 是「服务端时间 - 本机时间」的毫秒数。
var offsetMS atomic.Int64

// lastSync 是最近一次校准的 unix 纳秒，避免高频请求反复写盘。
var lastSync atomic.Int64

// syncInterval 是校准的最小间隔：Date 头只有秒级精度，太频繁没有意义。
const syncInterval = 10 * time.Minute

// Now 返回对齐后的当前时间。
func Now() time.Time {
	return time.Now().Add(Offset())
}

// Offset 返回当前偏移。
func Offset() time.Duration {
	return time.Duration(offsetMS.Load()) * time.Millisecond
}

// SetOffset 直接设置偏移（从配置恢复时使用）。
func SetOffset(d time.Duration) {
	offsetMS.Store(int64(d / time.Millisecond))
}

// SetOffsetMS 用毫秒数设置偏移（配置落盘用）。
func SetOffsetMS(ms int64) {
	offsetMS.Store(ms)
}

// OffsetMS 返回偏移的毫秒数。
func OffsetMS() int64 {
	return offsetMS.Load()
}

// ShouldSync 判断是否该做一次网络校准。
func ShouldSync() bool {
	last := lastSync.Load()
	if last == 0 {
		return true
	}
	return time.Since(time.Unix(0, last)) > syncInterval
}

// SyncFromDate 用 HTTP Date 头校准；无法解析或偏差为 0 时不动。
//
// 返回是否发生了有效校准，调用方据此决定要不要落盘。
func SyncFromDate(value string) bool {
	if value == "" {
		return false
	}
	server, err := http.ParseTime(value)
	if err != nil {
		return false
	}
	return syncTo(server)
}

// SyncFromUnix 用业务体里的 timestamp（秒）校准。
func SyncFromUnix(seconds int64) bool {
	if seconds <= 0 {
		return false
	}
	return syncTo(time.Unix(seconds, 0))
}

// syncTo 记录偏移；小于 2 秒的差异不处理（Date 头本身只有秒级精度）。
func syncTo(server time.Time) bool {
	diff := time.Until(server) // 服务端时间 - 本机时间
	if diff < 2*time.Second && diff > -2*time.Second {
		lastSync.Store(time.Now().UnixNano())
		return false
	}
	offsetMS.Store(int64(diff / time.Millisecond))
	lastSync.Store(time.Now().UnixNano())
	return true
}

// Reset 清零偏移（测试用）。
func Reset() {
	offsetMS.Store(0)
	lastSync.Store(0)
}
