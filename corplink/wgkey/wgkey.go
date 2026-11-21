// Package wgkey 生成 WireGuard 所需的 X25519 密钥对。
package wgkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Pair 是一对 base64 编码的 WireGuard 密钥。
type Pair struct {
	// PrivateKey 是 32 字节私钥的标准 base64。
	PrivateKey string
	// PublicKey 是 X25519 公钥的标准 base64。
	PublicKey string
}

// Generate 生成新的密钥对。
func Generate() (*Pair, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成 X25519 私钥: %w", err)
	}
	pub := priv.PublicKey()
	return &Pair{
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Bytes()),
		PublicKey:  base64.StdEncoding.EncodeToString(pub.Bytes()),
	}, nil
}
