package dpop

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// TokenExpiry 解析 vpn-token（JWT）的 exp，返回绝对时间。
//
// 只读 payload，不验签：这个值只用于本地决定"该不该提前续签"，
// 真正是否有效仍由服务端判定。
func TokenExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || claims.Exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}
