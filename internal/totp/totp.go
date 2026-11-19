// Package totp 生成登录二次验证用的 TOTP 验证码。
//
// 登录成功后我们会从 /api/v2/p/otp 拿到 otpauth URI 并保存其中的 secret，
// 有了它就能在面板上直接看到动态码，无需再等短信或邮件。
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// 标准参数。
const (
	// digits 是验证码位数。
	digits = 6
	// period 是验证码有效期。
	period = 30
)

// Code 生成当前时间片的验证码，并返回剩余有效秒数。
func Code(secret string, now time.Time) (string, int, error) {
	raw, err := decodeSecret(secret)
	if err != nil {
		return "", 0, err
	}
	counter := uint64(now.Unix() / period)
	remaining := period - int(now.Unix()%period)

	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(sha1.New, raw)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	code := value % 1_000_000
	return fmt.Sprintf("%06d", code), remaining, nil
}

// decodeSecret 解码 base32 secret，兼容空格、小写与缺省填充。
func decodeSecret(secret string) ([]byte, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	if normalized == "" {
		return nil, fmt.Errorf("TOTP secret 为空")
	}
	if pad := len(normalized) % 8; pad != 0 {
		normalized += strings.Repeat("=", 8-pad)
	}
	raw, err := base32.StdEncoding.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("解析 TOTP secret: %w", err)
	}
	return raw, nil
}
