package auth

import (
	"fmt"
	"net/url"
	"strings"
)

// OtpSecret 从 otpauth URI 里取出 TOTP secret。
// 服务端下发的 URI 形如 otpauth://totp/CorpLink:user?secret=XXXX&issuer=...
func OtpSecret(otpURI string) (string, error) {
	if otpURI == "" {
		return "", fmt.Errorf("服务端未下发 OTP 绑定信息")
	}
	u, err := url.Parse(otpURI)
	if err != nil {
		return "", fmt.Errorf("解析 otpauth URI: %w", err)
	}
	secret := strings.TrimSpace(u.Query().Get("secret"))
	if secret == "" {
		return "", fmt.Errorf("otpauth URI 里没有 secret")
	}
	return secret, nil
}
