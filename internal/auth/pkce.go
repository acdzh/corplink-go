// Package auth 实现飞连的登录流程：PKCE 参数、第三方授权与设备回调。
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// verifierBytes 与官方客户端一致：code_verifier 是一把 X25519 私钥（32 字节）。
const verifierBytes = 32

// PKCE 是一组一次性授权参数。
type PKCE struct {
	// Verifier 是原始随机串，回调时上送。
	Verifier string
	// Challenge 是 verifier 的 SHA-256（base64url 无填充），授权时上送。
	Challenge string
}

// NewPKCE 生成一组新的授权参数。
// verifier 采用标准 base64（含填充），与官方客户端 Wireguard.generatePrivateKey 的字符串形态一致。
func NewPKCE() (*PKCE, error) {
	buf := make([]byte, verifierBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("生成随机数: %w", err)
	}
	verifier := base64.StdEncoding.EncodeToString(buf)
	return &PKCE{Verifier: verifier, Challenge: challengeOf(verifier)}, nil
}

// challengeOf 计算 SHA-256 后做 base64url 无填充编码，即 RFC 7636 的 S256。
func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
