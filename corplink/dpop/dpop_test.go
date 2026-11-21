package dpop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/acdzh/corplink-go/corplink/api"
)

// newTestStore 在临时目录里造一个未绑定的密钥。
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "dpop", KeyFileName), "6a35386c3b47e140103c61d2c74ca645")
	if err != nil {
		t.Fatalf("打开密钥存储: %v", err)
	}
	if _, err := store.Key(); err != nil {
		t.Fatalf("生成密钥: %v", err)
	}
	return store
}

// TestKeyPersistAndReload 覆盖密钥落盘、权限、device_key_id 形状与公钥坐标长度。
func TestKeyPersistAndReload(t *testing.T) {
	store := newTestStore(t)
	key, err := store.Key()
	if err != nil {
		t.Fatalf("取密钥: %v", err)
	}
	wantPrefix := "6a35386c3b47e140103c61d2c74ca645_"
	if !strings.HasPrefix(key.ID(), wantPrefix) {
		t.Fatalf("device_key_id = %q，应以 %q 开头", key.ID(), wantPrefix)
	}
	if len(key.UUID()) != 36 || strings.Count(key.UUID(), "-") != 4 {
		t.Fatalf("uuid 形状不对: %q", key.UUID())
	}
	jwk := key.PublicJWK()
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.Alg != "ES256" || jwk.Use != "sig" {
		t.Fatalf("JWK 常量字段不对: %+v", jwk)
	}
	if len(jwk.X) != 43 || len(jwk.Y) != 43 {
		t.Fatalf("JWK 坐标应为 43 字符 base64url，实为 %d/%d", len(jwk.X), len(jwk.Y))
	}
	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatalf("密钥文件不存在: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("密钥文件权限 = %o，应为 600", perm)
	}

	reopened, err := Open(store.Path(), "6a35386c3b47e140103c61d2c74ca645")
	if err != nil {
		t.Fatalf("重新打开: %v", err)
	}
	again, err := reopened.Key()
	if err != nil {
		t.Fatalf("重新取密钥: %v", err)
	}
	if again.ID() != key.ID() || again.PublicJWK() != key.PublicJWK() {
		t.Fatalf("重新加载后的密钥不一致: %+v vs %+v", again.PublicJWK(), key.PublicJWK())
	}
}

// TestMarkBoundPersisted 覆盖 bound 状态落盘。
func TestMarkBoundPersisted(t *testing.T) {
	store := newTestStore(t)
	if err := store.MarkBound(true); err != nil {
		t.Fatalf("标记绑定: %v", err)
	}
	reopened, err := Open(store.Path(), "6a35386c3b47e140103c61d2c74ca645")
	if err != nil {
		t.Fatalf("重新打开: %v", err)
	}
	key, err := reopened.Key()
	if err != nil {
		t.Fatalf("重新取密钥: %v", err)
	}
	if !key.Bound() {
		t.Fatal("bound 状态没落盘")
	}
}

// TestProofListClaims 校验 /api/vpn/list 分支的 claim 集与取值。
func TestProofListClaims(t *testing.T) {
	store := newTestStore(t)
	key, _ := store.Key()
	u, err := url.Parse("https://sealsuite.example.com:443/api/vpn/list?os=Android&timestamp=1700000000&language=zh")
	if err != nil {
		t.Fatalf("解析 URL: %v", err)
	}
	proof, err := key.ProofList(u, "SESSION-VALUE", time.Unix(1700000123, 0))
	if err != nil {
		t.Fatalf("生成证明: %v", err)
	}
	if err := key.Verify(proof); err != nil {
		t.Fatalf("证明自校验失败: %v", err)
	}
	head, claims, err := Claims(proof)
	if err != nil {
		t.Fatalf("解码证明: %v", err)
	}
	if head["typ"] != "dpop+jwt" || head["alg"] != "ES256" || head["kid"] != key.ID() {
		t.Fatalf("header 不对: %+v", head)
	}
	if claims["htm"] != "GET" {
		t.Fatalf("htm = %v", claims["htm"])
	}
	if claims["iat"].(float64) != 1700000123 {
		t.Fatalf("iat = %v", claims["iat"])
	}
	if claims["ath"] != hashB64("SESSION-VALUE") {
		t.Fatalf("ath 应覆盖 session，实际 %v", claims["ath"])
	}
	if claims["htu"] != "https://sealsuite.example.com:443/api/vpn/list" {
		t.Fatalf("htu 应去掉 query，实际 %v", claims["htu"])
	}
	if claims["body_hash"] != hashB64("") {
		t.Fatalf("body_hash 应为空体哈希，实际 %v", claims["body_hash"])
	}
	if _, ok := claims["query_hash"]; !ok {
		t.Fatal("缺少 query_hash")
	}
	if _, ok := claims["jti"]; !ok {
		t.Fatal("缺少 jti")
	}
}

// TestQueryHashOrderIndependent 覆盖 query 顺序无关性。
func TestQueryHashOrderIndependent(t *testing.T) {
	a := queryHash("os=Android&language=zh&timestamp=1")
	b := queryHash("language=zh&timestamp=1&os=Android")
	if a != b {
		t.Fatalf("query_hash 应忽略顺序: %s vs %s", a, b)
	}
	want := hashB64("language=zh&os=Android&timestamp=1")
	if a != want {
		t.Fatalf("query_hash = %s，应为 %s", a, want)
	}
	if queryHash("") != hashB64("") {
		t.Fatal("空 query 应是空串哈希")
	}
	got := queryHash("model=Pixel%207&brand=go%2Dogle")
	wantEscaped := hashB64("brand=go-ogle&model=Pixel%207")
	if got != wantEscaped {
		t.Fatalf("转义后 query_hash = %s，应为 %s", got, wantEscaped)
	}
}

// TestProofConnClaims 校验 /vpn/conn 分支：ver / htp / wgh / body_hash。
func TestProofConnClaims(t *testing.T) {
	store := newTestStore(t)
	key, _ := store.Key()
	wgRaw := make([]byte, 32)
	for i := range wgRaw {
		wgRaw[i] = byte(i)
	}
	body, err := json.Marshal(map[string]string{"public_key": base64.StdEncoding.EncodeToString(wgRaw), "otp": "123456"})
	if err != nil {
		t.Fatalf("序列化请求体: %v", err)
	}
	proof, err := key.ProofConn(body, "VPN-TOKEN-VALUE", time.Unix(1700000999, 0))
	if err != nil {
		t.Fatalf("生成证明: %v", err)
	}
	if err := key.Verify(proof); err != nil {
		t.Fatalf("证明自校验失败: %v", err)
	}
	_, claims, err := Claims(proof)
	if err != nil {
		t.Fatalf("解码证明: %v", err)
	}
	if claims["htm"] != "POST" || claims["ver"] != "vpn-pop-es256-v1" || claims["htp"] != "/vpn/conn" {
		t.Fatalf("conn 分支固定字段不对: %+v", claims)
	}
	wantWgh := hashB64(string(wgRaw))
	if claims["wgh"] != wantWgh {
		t.Fatalf("wgh = %v，应为 %v", claims["wgh"], wantWgh)
	}
	if claims["body_hash"] != hashB64(string(body)) {
		t.Fatalf("body_hash 应覆盖完整请求体")
	}
	if claims["ath"] != hashB64("VPN-TOKEN-VALUE") {
		t.Fatalf("ath 应覆盖 vpn-token")
	}
	jti, _ := claims["jti"].(string)
	raw, err := base64.RawURLEncoding.DecodeString(jti)
	if err != nil || len(raw) != 16 {
		t.Fatalf("jti 应为 16 字节 base64url，实际 %q", jti)
	}
	if _, ok := claims["htu"]; ok {
		t.Fatal("conn 分支不应带 htu")
	}
}

// TestProverRespectsBound 覆盖 required 语义：未绑定不签名。
func TestProverRespectsBound(t *testing.T) {
	store := newTestStore(t)
	prover := store.Prover()
	u, _ := url.Parse("https://example.com/api/vpn/list?os=Android")
	proof, err := prover(api.EndpointVPNList, "GET", u, nil, "sess", "")
	if err != nil || proof != "" {
		t.Fatalf("未绑定时应跳过签名，得到 %q / %v", proof, err)
	}
	if err := store.MarkBound(true); err != nil {
		t.Fatalf("标记绑定: %v", err)
	}
	proof, err = prover(api.EndpointVPNList, "GET", u, nil, "sess", "")
	if err != nil || proof == "" {
		t.Fatalf("已绑定时应签名，得到 %q / %v", proof, err)
	}
	body, _ := json.Marshal(map[string]string{"public_key": base64.StdEncoding.EncodeToString(make([]byte, 32))})
	proof, err = prover(api.EndpointVPNConn, "POST", u, body, "sess", "vpn")
	if err != nil || proof == "" {
		t.Fatalf("conn 已绑定时应签名，得到 %q / %v", proof, err)
	}
}

// TestProofRejectsTamper 覆盖签名校验：改动 payload 必须验签失败。
func TestProofRejectsTamper(t *testing.T) {
	store := newTestStore(t)
	key, _ := store.Key()
	u, _ := url.Parse("https://example.com/api/vpn/list")
	proof, err := key.ProofList(u, "sess", time.Now())
	if err != nil {
		t.Fatalf("生成证明: %v", err)
	}
	parts := strings.Split(proof, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte("{\"htm\":\"POST\"}")) + "." + parts[2]
	if err := key.Verify(tampered); err == nil {
		t.Fatal("被篡改的证明不应通过校验")
	}
}

// TestLoginFields 校验登录体里的设备字段形状。
func TestLoginFields(t *testing.T) {
	store := newTestStore(t)
	key, _ := store.Key()
	fields := key.LoginFields()
	if fields["device_key_id"] != key.ID() {
		t.Fatalf("device_key_id 不符: %v", fields["device_key_id"])
	}
	if fields["device_key_protected_level"] != "software_protected" {
		t.Fatalf("保护级别不对: %v", fields["device_key_protected_level"])
	}
	raw, err := json.Marshal(fields["device_public_key"])
	if err != nil {
		t.Fatalf("序列化公钥: %v", err)
	}
	for _, want := range []string{"\"kty\":\"EC\"", "\"crv\":\"P-256\"", "\"alg\":\"ES256\"", "\"use\":\"sig\""} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("公钥缺失 %s: %s", want, raw)
		}
	}
}

// TestWireguardHashMatchesAndroid 校验 wgh 的取值口径：公钥原文（32 字节）的 SHA-256。
func TestWireguardHashMatchesAndroid(t *testing.T) {
	raw := []byte(strings.Repeat("a", 32))
	body, _ := json.Marshal(map[string]string{"public_key": base64.StdEncoding.EncodeToString(raw)})
	got, err := wireguardHash(body)
	if err != nil {
		t.Fatalf("计算 wgh: %v", err)
	}
	sum := sha256.Sum256(raw)
	if got != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatalf("wgh 口径不对: %s", got)
	}
	if _, err := wireguardHash([]byte("{\"public_key\":\"short\"}")); err == nil {
		t.Fatal("非 32 字节公钥应报错")
	}
}

// TestSetDeviceIDRotatesKey 覆盖 device_id 变化时换钥：device_key_id 必须跟着变。
func TestSetDeviceIDRotatesKey(t *testing.T) {
	store := newTestStore(t)
	before, err := store.Key()
	if err != nil {
		t.Fatalf("取密钥: %v", err)
	}
	store.SetDeviceID("ffffffffffffffffffffffffffffffff")
	after, err := store.Key()
	if err != nil {
		t.Fatalf("换 device_id 后取密钥: %v", err)
	}
	if after.DeviceID() != "ffffffffffffffffffffffffffffffff" {
		t.Fatalf("device_id 未切换: %s", after.DeviceID())
	}
	if after.ID() == before.ID() {
		t.Fatal("换 device_id 后应生成新密钥")
	}
	if !strings.HasPrefix(after.ID(), "ffffffffffffffffffffffffffffffff_") {
		t.Fatalf("device_key_id 前缀不对: %s", after.ID())
	}
}
