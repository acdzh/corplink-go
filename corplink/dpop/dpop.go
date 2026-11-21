// Package dpop 实现飞连的设备证明（DPoP）。
//
// 服务端只给"能证明自己持有某对 ES256 设备私钥"的会话签发 vpn-token，
// token 的 val 段里带 auth_scheme=device-pop-es256-v1 与 cnf.jwk（设备公钥）；
// 之后 /api/vpn/list、/vpn/conn 要带一份用该私钥签名的 DPoP 证明。
//
// 协议细节全部来自官方 Android 客户端反编译：
//
//	com.bytedance.topgo.base.dpop.*   枚举与状态机
//	defpackage.hz                     证明（JWT）构造
//	defpackage.zy                     okhttp 拦截器：哪两个路径要证明、怎么算字段
//	defpackage.fz / u01.D             登录体里的设备公钥字段
//	defpackage.xy                     required 语义：只有已绑定密钥才签名
//
// 与服务端对话的可观测事实（2026-11-22 线上 /api/v1/device/dpop）：
//
//	device_key_id = <device_id>_<uuid>，uuid 由客户端生成
//	device_public_key = {"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","x":..,"y":..}
package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/acdzh/corplink-go/corplink/clock"

	"github.com/acdzh/corplink-go/corplink/api"
)

// 协议常量。取值必须与官方客户端逐字节一致，服务端会按字面校验。
const (
	// headerTyp 是 DPoP 证明 JWT 的 typ。
	headerTyp = "dpop+jwt"
	// algES256 是设备密钥算法，私钥固定 P-256。
	algES256 = "ES256"
	// curveP256 是 JWK 的 crv 字段。
	curveP256 = "P-256"
	// verVPNPop 是 /vpn/conn 证明的协议版本，服务端据此选校验分支。
	verVPNPop = "vpn-pop-es256-v1"
	// pathConn 是带 DPoP 证明的连接路径。
	pathConn = "/vpn/conn"
	// protectionLevel 是设备密钥的保护级别：Go 端只有软件保护。
	protectionLevel = "software_protected"
	// keyFileVersion 是本地密钥文件格式版本。
	keyFileVersion = 1
	// KeyFileName 是数据目录里密钥文件的文件名。
	KeyFileName = "device_key.json"
)

// JWK 是设备公钥的 JSON 表示，字段顺序与官方客户端一致。
type JWK struct {
	// Kty 固定 EC。
	Kty string `json:"kty"`
	// Crv 固定 P-256。
	Crv string `json:"crv"`
	// Alg 固定 ES256。
	Alg string `json:"alg"`
	// Use 固定 sig。
	Use string `json:"use"`
	// X 是 32 字节横坐标的 base64url（无填充）。
	X string `json:"x"`
	// Y 是 32 字节纵坐标的 base64url（无填充）。
	Y string `json:"y"`
}

// Key 是一份设备密钥快照。
type Key struct {
	deviceID  string
	uuid      string
	priv      *ecdsa.PrivateKey
	bound     bool
	createdAt int64
}

// ID 返回服务端认识的 device_key_id：<device_id>_<uuid>。
func (k *Key) ID() string {
	if k == nil {
		return ""
	}
	return k.deviceID + "_" + k.uuid
}

// UUID 返回密钥引用里的 uuid 部分。
func (k *Key) UUID() string {
	if k == nil {
		return ""
	}
	return k.uuid
}

// DeviceID 返回绑定的 device_id。
func (k *Key) DeviceID() string {
	if k == nil {
		return ""
	}
	return k.deviceID
}

// Bound 表示服务端已登记该公钥，可以开始签名。
func (k *Key) Bound() bool {
	if k == nil {
		return false
	}
	return k.bound
}

// CreatedAt 返回密钥生成时间（unix 秒）。
func (k *Key) CreatedAt() int64 {
	if k == nil {
		return 0
	}
	return k.createdAt
}

// PublicJWK 返回公钥 JWK。
func (k *Key) PublicJWK() JWK {
	if k == nil || k.priv == nil {
		return JWK{}
	}
	return JWK{
		Kty: "EC",
		Crv: curveP256,
		Alg: algES256,
		Use: "sig",
		X:   b64url(pad32(k.priv.PublicKey.X)),
		Y:   b64url(pad32(k.priv.PublicKey.Y)),
	}
}

// LoginFields 返回登录 / 注册请求体里必须携带的设备字段。
//
// 官方客户端把它们塞进任何"带身份"的请求体（登录、MFA 校验），
// 服务端据此把会话与设备公钥关联，并在 vpn-token 里写 cnf.jwk。
func (k *Key) LoginFields() map[string]any {
	if k == nil {
		return nil
	}
	return map[string]any{
		"device_key_id":              k.ID(),
		"device_key_protected_level": protectionLevel,
		"device_public_key":          k.PublicJWK(),
	}
}

// ProofList 生成 GET /api/vpn/list 的 DPoP 证明。
//
// 该分支的 ath 覆盖 session cookie（官方客户端用的是 d.aw = "session"），
// 也就是说它证明的是"会话 + 设备私钥"同时在手。
func (k *Key) ProofList(u *url.URL, session string, now time.Time) (string, error) {
	if k == nil || k.priv == nil {
		return "", fmt.Errorf("设备密钥不可用")
	}
	claims := map[string]any{
		"htm":        "GET",
		"iat":        now.Unix(),
		"jti":        newUUID(),
		"ath":        hashB64(session),
		"htu":        hashTarget(u),
		"query_hash": queryHash(u.RawQuery),
		"body_hash":  hashB64(""),
	}
	return k.sign(claims)
}

// ProofConn 生成 POST /vpn/conn 的 DPoP 证明。
//
// 与 list 分支的差别：ath 覆盖 vpn-token；用 ver + htp 取代 htu；
// 额外用 wgh 绑定本次申请隧道用的 WireGuard 公钥（body.public_key）。
func (k *Key) ProofConn(body []byte, vpnToken string, now time.Time) (string, error) {
	if k == nil || k.priv == nil {
		return "", fmt.Errorf("设备密钥不可用")
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("生成 jti: %w", err)
	}
	wgh, err := wireguardHash(body)
	if err != nil {
		return "", err
	}
	claims := map[string]any{
		"htm":       "POST",
		"iat":       now.Unix(),
		"jti":       b64url(jti),
		"ath":       hashB64(vpnToken),
		"ver":       verVPNPop,
		"htp":       pathConn,
		"wgh":       wgh,
		"body_hash": hashB64(string(body)),
	}
	return k.sign(claims)
}

// sign 把 claims 组装成 ES256 签名的紧凑 JWT。
func (k *Key) sign(claims map[string]any) (string, error) {
	headJSON, err := json.Marshal(orderedHeader{Typ: headerTyp, Alg: algES256, Kid: k.ID()})
	if err != nil {
		return "", err
	}
	payloadJSON, err := marshalOrdered(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64url(headJSON) + "." + b64url(payloadJSON)
	sig, err := signES256(k.priv, []byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64url(sig), nil
}

// orderedHeader 固定 header 的字段顺序，便于与抓包逐字节比对。
type orderedHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// claimOrder 是两类证明的 claim 顺序，与官方客户端 JSONObject 的插入顺序一致。
var claimOrder = []string{
	"htm", "iat", "jti", "ath", "ver", "htp", "htu", "query_hash", "wgh", "body_hash",
}

// marshalOrdered 按 claimOrder 输出 JSON，避免 map 的随机顺序导致抓包对不上。
func marshalOrdered(claims map[string]any) ([]byte, error) {
	var buf strings.Builder
	buf.WriteByte('{')
	first := true
	for _, name := range claimOrder {
		value, ok := claims[name]
		if !ok {
			continue
		}
		if !first {
			buf.WriteByte(',')
		}
		first = false
		keyJSON, err := json.Marshal(name)
		if err != nil {
			return nil, err
		}
		valueJSON, err := marshalClaimValue(value)
		if err != nil {
			return nil, err
		}
		buf.Write(keyJSON)
		buf.WriteByte(':')
		buf.Write(valueJSON)
	}
	// 兜底：claimOrder 之外新增的字段按字典序追加，避免静默丢字段。
	rest := make([]string, 0, len(claims))
	for name := range claims {
		known := false
		for _, ordered := range claimOrder {
			if ordered == name {
				known = true
				break
			}
		}
		if !known {
			rest = append(rest, name)
		}
	}
	sort.Strings(rest)
	for _, name := range rest {
		if !first {
			buf.WriteByte(',')
		}
		first = false
		keyJSON, err := json.Marshal(name)
		if err != nil {
			return nil, err
		}
		valueJSON, err := marshalClaimValue(claims[name])
		if err != nil {
			return nil, err
		}
		buf.Write(keyJSON)
		buf.WriteByte(':')
		buf.Write(valueJSON)
	}
	buf.WriteByte('}')
	return []byte(buf.String()), nil
}

// marshalClaimValue 序列化单个 claim 值，避免 HTML 转义。
func marshalClaimValue(v any) ([]byte, error) {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(sb.String(), "\n")), nil
}

// signES256 用 P-256 私钥签名，输出 JOSE 要求的 64 字节 r||s。
func signES256(priv *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, fmt.Errorf("ES256 签名: %w", err)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// Verify 校验一份 DPoP 证明的签名与 kid，供自检与测试使用。
func (k *Key) Verify(proof string) error {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return fmt.Errorf("证明不是三段式 JWT")
	}
	var head struct {
		Typ string `json:"typ"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	rawHead, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("解码 header: %w", err)
	}
	if err := json.Unmarshal(rawHead, &head); err != nil {
		return fmt.Errorf("解析 header: %w", err)
	}
	if head.Typ != headerTyp || head.Alg != algES256 || head.Kid != k.ID() {
		return fmt.Errorf("header 不符: %+v", head)
	}
	rawSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("解码签名: %w", err)
	}
	if len(rawSig) != 64 {
		return fmt.Errorf("签名长度 %d，应为 64", len(rawSig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(rawSig[:32])
	s := new(big.Int).SetBytes(rawSig[32:])
	if !ecdsa.Verify(&k.priv.PublicKey, digest[:], r, s) {
		return fmt.Errorf("签名校验失败")
	}
	return nil
}

// Claims 解码证明的 header 与 payload，返回两个泛型 map，便于测试断言。
func Claims(proof string) (map[string]any, map[string]any, error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("证明不是三段式 JWT")
	}
	head := map[string]any{}
	payload := map[string]any{}
	rawHead, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(rawHead, &head); err != nil {
		return nil, nil, err
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil, nil, err
	}
	return head, payload, nil
}

// Store 管理一份持久化的设备密钥。
//
// 私钥单独放在 <数据目录>/dpop/device_key.json，绝不写进 session.json 或 config.json。
type Store struct {
	path     string
	deviceID string

	mu  sync.Mutex
	key *Key
}

// Open 打开（必要时创建）设备密钥存储；path 为空时密钥只在内存里。
func Open(path, deviceID string) (*Store, error) {
	s := &Store{path: path, deviceID: deviceID}
	if path == "" {
		return s, nil
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Path 返回密钥文件路径。
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// SetDeviceID 在 device_id 变化时刷新：旧密钥不能复用，需要重新生成并登记。
func (s *Store) SetDeviceID(id string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deviceID == id {
		return
	}
	s.deviceID = id
	if s.key != nil && s.key.deviceID != id {
		s.key = nil
	}
}

// DeviceID 返回当前 device_id。
func (s *Store) DeviceID() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deviceID
}

// load 读取密钥文件；文件不存在视为"还没生成"。
func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("读取设备密钥 %s: %w", s.path, err)
	}
	var rec keyRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return fmt.Errorf("解析设备密钥 %s: %w", s.path, err)
	}
	der, err := base64.StdEncoding.DecodeString(rec.PrivateKey)
	if err != nil {
		return fmt.Errorf("解base64 设备私钥: %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return fmt.Errorf("解析设备私钥: %w", err)
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return fmt.Errorf("设备私钥不是 P-256")
	}
	s.key = &Key{
		deviceID:  rec.DeviceID,
		uuid:      rec.UUID,
		priv:      priv,
		bound:     rec.Bound,
		createdAt: rec.CreatedAt,
	}
	return nil
}

// Key 返回当前密钥，必要时生成并落盘。
func (s *Store) Key() (*Key, error) {
	if s == nil {
		return nil, fmt.Errorf("未启用设备密钥")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		// device_id 对不上时绝不能"顺手换一把新钥匙"：那会覆盖掉服务端已经
		// 登记的那把，当前会话立刻失去设备证明，服务端只会回一个含糊的
		// 3015「Session 无效」，看起来像登录状态坏了。换钥匙必须走 Reset()。
		if s.key.deviceID != s.deviceID {
			return nil, fmt.Errorf("设备密钥属于 %s，与当前 device_id %s 不一致；请删除 %s 后重新登录",
				s.key.deviceID, s.deviceID, s.path)
		}
		return s.key, nil
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成 ES256 设备密钥: %w", err)
	}
	key := &Key{
		deviceID:  s.deviceID,
		uuid:      newUUID(),
		priv:      priv,
		createdAt: time.Now().Unix(),
	}
	s.key = key
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return key, nil
}

// MarkBound 记录服务端是否已登记该公钥，并落盘。
func (s *Store) MarkBound(bound bool) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil || s.key.bound == bound {
		return nil
	}
	s.key.bound = bound
	return s.saveLocked()
}

// Reset 丢弃当前密钥并生成新的一对（服务端要求重新登记时使用）。
func (s *Store) Reset() (*Key, error) {
	if s == nil {
		return nil, fmt.Errorf("未启用设备密钥")
	}
	s.mu.Lock()
	s.key = nil
	s.mu.Unlock()
	return s.Key()
}

// saveLocked 原子写回密钥文件，权限 0600。
func (s *Store) saveLocked() error {
	if s.path == "" || s.key == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("创建设备密钥目录: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(s.key.priv)
	if err != nil {
		return fmt.Errorf("序列化设备私钥: %w", err)
	}
	rec := keyRecord{
		Version:        keyFileVersion,
		DeviceID:       s.key.deviceID,
		DeviceKeyID:    s.key.ID(),
		UUID:           s.key.uuid,
		PrivateKey:     base64.StdEncoding.EncodeToString(der),
		PublicJWK:      s.key.PublicJWK(),
		ProtectedLevel: protectionLevel,
		Bound:          s.key.bound,
		CreatedAt:      s.key.createdAt,
	}
	payload, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化设备密钥记录: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(payload, 10), 0o600); err != nil {
		return fmt.Errorf("写入设备密钥: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("替换设备密钥: %w", err)
	}
	return nil
}

// keyRecord 是 device_key.json 的结构。
type keyRecord struct {
	Version        int    `json:"version"`
	DeviceID       string `json:"device_id"`
	DeviceKeyID    string `json:"device_key_id"`
	UUID           string `json:"uuid"`
	PrivateKey     string `json:"private_key_pkcs8"`
	PublicJWK      JWK    `json:"public_jwk"`
	ProtectedLevel string `json:"protected_level"`
	Bound          bool   `json:"bound"`
	CreatedAt      int64  `json:"created_at"`
}

// Prover 返回挂到 api.Client 上的证明器。
//
// 官方客户端的语义是"只有已绑定密钥才签名"（DpopSigningSession.required），
// 未绑定时返回空串，让请求保持无证明形态。
func (s *Store) Prover() api.DPoPProver {
	if s == nil {
		return nil
	}
	return func(ep api.Endpoint, method string, u *url.URL, body []byte, session, vpnToken string) (string, error) {
		key, err := s.Key()
		if err != nil || !key.Bound() {
			return "", nil
		}
		if ep.Path == pathConn {
			return key.ProofConn(body, vpnToken, clock.Now())
		}
		return key.ProofList(u, session, clock.Now())
	}
}

// Attach 把设备密钥与 v1 签名器一起挂到 api 客户端上。
func (s *Store) Attach(c *api.Client, signer api.Signer) {
	if c == nil {
		return
	}
	c.SetSigner(signer)
	if s != nil {
		c.SetDPoP(s.Prover())
	}
}

// b64url 做无填充的 base64url 编码。
func b64url(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

// hashB64 返回 SHA-256 摘要的 base64url 形态。
func hashB64(text string) string {
	sum := sha256.Sum256([]byte(text))
	return b64url(sum[:])
}

// hashTarget 返回去掉 query 与 fragment 的绝对 URL，对应证明里的 htu。
func hashTarget(u *url.URL) string {
	if u == nil {
		return ""
	}
	copied := *u
	copied.RawQuery = ""
	copied.ForceQuery = false
	copied.Fragment = ""
	return copied.String()
}

// queryHash 归一化查询串后取哈希。
//
// 官方实现：按 '&' 切分，每个片段按第一个 '=' 拆成 key/value，
// 两者都做 RFC 3986 百分号解码再编码，key 必须非空且唯一，按 key 排序后
// 用 '&' 拼回再 SHA-256。这样 query 顺序变化不会导致证明失效。
func queryHash(encodedQuery string) string {
	if encodedQuery == "" {
		return hashB64("")
	}
	type pair struct {
		key   string
		value string
	}
	pairs := make([]pair, 0, 8)
	seen := make(map[string]bool, 8)
	for _, segment := range strings.Split(encodedQuery, "&") {
		if segment == "" {
			continue
		}
		key, value, _ := strings.Cut(segment, "=")
		decodedKey, err := url.PathUnescape(key)
		if err != nil {
			decodedKey = key
		}
		decodedValue, err := url.PathUnescape(value)
		if err != nil {
			decodedValue = value
		}
		if decodedKey == "" || seen[decodedKey] {
			continue
		}
		seen[decodedKey] = true
		pairs = append(pairs, pair{key: escapeRFC3986(decodedKey), value: escapeRFC3986(decodedValue)})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].key < pairs[j].key })
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, p.key+"="+p.value)
	}
	return hashB64(strings.Join(parts, "&"))
}

// escapeRFC3986 只保留 A-Z a-z 0-9 - . _ ~，其余按 %XX 大写转义。
func escapeRFC3986(text string) string {
	const hex = "0123456789ABCDEF"
	var sb strings.Builder
	for i := 0; i < len(text); i++ {
		c := text[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			sb.WriteByte(c)
			continue
		}
		sb.WriteByte('%')
		sb.WriteByte(hex[c>>4])
		sb.WriteByte(hex[c&0x0f])
	}
	return sb.String()
}

// wireguardHash 从连接请求体里取出 public_key 并对其 32 字节原文取哈希。
func wireguardHash(body []byte) (string, error) {
	if len(body) == 0 {
		return "", fmt.Errorf("连接请求体为空")
	}
	var probe struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return "", fmt.Errorf("解析连接请求体: %w", err)
	}
	if probe.PublicKey == "" {
		return "", fmt.Errorf("连接请求体缺少 public_key")
	}
	raw, err := base64.StdEncoding.DecodeString(probe.PublicKey)
	if err != nil {
		return "", fmt.Errorf("解码 public_key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("public_key 长度 %d，应为 32", len(raw))
	}
	sum := sha256.Sum256(raw)
	return b64url(sum[:]), nil
}

// pad32 把大整数补成 32 字节定长表示。
func pad32(v *big.Int) []byte {
	out := make([]byte, 32)
	if v == nil {
		return out
	}
	v.FillBytes(out)
	return out
}

// newUUID 生成 RFC 4122 v4 UUID 字符串（小写、带横线）。
func newUUID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand 不可用时退回时间戳拼装，保证仍能产生唯一 id。
		now := time.Now().UnixNano()
		for i := 0; i < 16; i++ {
			buf[i] = byte(now >> uint(8*(i%8)))
		}
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}
