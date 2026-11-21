// Package sign 实现飞连的 v1 请求签名。
//
// 算法来自官方客户端：服务端下发 http_sign_config（哪些 URL、用哪套字段位掩码），
// 客户端用 HKDF 派生密钥后对选定字段做 HMAC-SHA256，最后以 protobuf 结构放进 sign 头。
// 密钥 = HKDF-SHA256(ikm=固定串, info="<activate_code>|<device_id>")，已用设备端
// Wireguard.generateHttpSignKey 的真实输出反证。
package sign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/acdzh/corplink-go/corplink/api"
)

// secret 是官方客户端内置的 HKDF 输入密钥（不是设备密钥）。
const secret = "TOK@@AoNfRIX+3bla%"

// rootKeyVersion 是 sign 头 protobuf 里的版本字段。
const rootKeyVersion = 1

// keyLen 是派生密钥长度。
const keyLen = 32

// key 派生签名密钥。
func key(activateCode, deviceID string) []byte {
	info := activateCode + "|" + deviceID
	return hkdfSHA256([]byte(secret), nil, []byte(info), keyLen)
}

// Header 生成 sign 头。
//
// mask 来自服务端配置（例如 /api/vpn/list 是 510、/vpn/conn 是 542）；
// 每个 bit 对应一个参与签名的字段，字段顺序固定，见 canonical。
func Header(mask uint64, activateCode, deviceID, method string, u *url.URL, body []byte, cookie, csrf, jwt string) (string, error) {
	if mask == 0 {
		return "", nil
	}
	if deviceID == "" {
		return "", fmt.Errorf("缺少 device_id，无法签名")
	}
	var bodyHash []byte
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		bodyHash = sum[:]
	}
	query := ""
	if u.RawQuery != "" {
		query = u.RawQuery
	}
	// 索引与位掩码一一对应：1 method、2 path、3 query、4 body hash、5 cookie、7 csrf、9 jwt。
	fields := [10][]byte{
		nil,
		[]byte(method),
		[]byte(u.Path),
		[]byte(query),
		bodyHash,
		[]byte(cookie),
		nil,
		[]byte(csrf),
		nil,
		[]byte(jwt),
	}
	var canonical []byte
	for i := 1; i < len(fields); i++ {
		if mask&(1<<uint(i)) != 0 {
			canonical = append(canonical, fields[i]...)
		}
	}
	mac := hmac.New(sha256.New, key(activateCode, deviceID))
	mac.Write(canonical)
	digest := mac.Sum(nil)
	return encodeHeader(mask, digest), nil
}

// encodeHeader 把签名结果封装成 protobuf + "v1;" 前缀。
func encodeHeader(mask uint64, digest []byte) string {
	var buf []byte
	buf = appendVarintField(buf, 1, rootKeyVersion)
	buf = appendVarintField(buf, 3, mask)
	buf = appendBytesField(buf, 4, digest)
	return "v1;" + base64.StdEncoding.EncodeToString(buf)
}

// hkdfSHA256 是标准 HKDF（RFC 5869），salt 为空时按 32 字节零值处理。
func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)

	var okm, previous []byte
	for counter := byte(1); len(okm) < length; counter++ {
		mac = hmac.New(sha256.New, prk)
		mac.Write(previous)
		mac.Write(info)
		mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		okm = append(okm, previous...)
	}
	return okm[:length]
}

// appendVarintField 写入 protobuf varint 字段。
func appendVarintField(dst []byte, field, value uint64) []byte {
	dst = appendVarint(dst, field<<3)
	return appendVarint(dst, value)
}

// appendBytesField 写入 protobuf length-delimited 字段。
func appendBytesField(dst []byte, field uint64, value []byte) []byte {
	dst = appendVarint(dst, (field<<3)|2)
	dst = appendVarint(dst, uint64(len(value)))
	return append(dst, value...)
}

// appendVarint 写入 protobuf varint 编码。
func appendVarint(dst []byte, value uint64) []byte {
	for value >= 0x80 {
		dst = append(dst, byte(value)|0x80)
		value >>= 7
	}
	return append(dst, byte(value))
}

// NewSigner 返回绑定指定租户与设备的签名器，供 api.Client 使用。
func NewSigner(activateCode, deviceID string) api.Signer {
	return func(ep api.Endpoint, method string, u *url.URL, body []byte, cookie, csrf, jwt string) (string, error) {
		return Header(ep.SigningInputParams, activateCode, deviceID, method, u, body, cookie, csrf, jwt)
	}
}
