package auth

import (
	"fmt"
	"net/url"
	"strings"
)

// Callback 是第三方授权完成后回调携带的参数。
type Callback struct {
	AliasKey string
	Code     string
	State    string
}

// ParseCallback 解析 corplink://login/callback?alias_key=..&code=..&state=..
//
// 允许三种输入形态，便于手工从浏览器地址栏或代理抓包结果里粘贴：
//   - 完整 URL（corplink:// 或 https://）
//   - 仅查询串（alias_key=..&code=..&state=..）
func ParseCallback(raw string) (*Callback, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil, fmt.Errorf("回调内容为空")
	}
	if !strings.Contains(text, "?") && !strings.Contains(text, "://") {
		text = "corplink://login/callback?" + text
	}
	u, err := url.Parse(text)
	if err != nil {
		return nil, fmt.Errorf("解析回调 URL: %w", err)
	}
	q := u.Query()
	out := &Callback{
		AliasKey: q.Get("alias_key"),
		Code:     q.Get("code"),
		State:    q.Get("state"),
	}
	if out.AliasKey == "" || out.Code == "" || out.State == "" {
		return nil, fmt.Errorf("回调缺少参数（alias_key=%q code=%q state=%q）", out.AliasKey, out.Code, out.State)
	}
	return out, nil
}
