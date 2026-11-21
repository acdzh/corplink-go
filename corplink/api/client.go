package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/acdzh/corplink-go/corplink/clock"
)

// matchBaseURL 是公司代码解析服务，与具体企业的服务端地址无关。
const matchBaseURL = "https://corplink.volcengine.cn"

// requestTimeout 是单次接口调用的超时。
const requestTimeout = 20 * time.Second

// maxBodyBytes 限制读取的响应体大小，避免异常响应打爆内存。
const maxBodyBytes = 4 << 20

// errNoServer 表示客户端尚未配置企业服务端地址。
const errNoServer = "未配置服务端地址，请先在设置中配置企业代码或服务端地址"

// Signer 为需要签名的接口生成 sign 头。返回空串表示不添加该头。
type Signer func(ep Endpoint, method string, u *url.URL, body []byte, cookie, csrf, jwt string) (string, error)

// DPoPProver 为需要设备证明的接口生成 DPoP 头。
//
// session 与 vpnToken 分别是会话 cookie 与 vpn-token 的原文：
// /api/vpn/list 的证明覆盖 session，/vpn/conn 的证明覆盖 vpn-token。
// 返回空串表示本次不带证明（设备密钥尚未登记时官方客户端也这么做）。
type DPoPProver func(ep Endpoint, method string, u *url.URL, body []byte, session, vpnToken string) (string, error)

// Client 是飞连服务端的 HTTP 客户端，负责地址拼接、请求头、Cookie 与签名。
type Client struct {
	mu      sync.RWMutex
	base    *url.URL
	http    *http.Client
	ua      string
	lang    string
	device  string
	meta    Meta
	signer  Signer
	prover  DPoPProver
	verbose bool
}

// Options 是构造 Client 的可选项。
type Options struct {
	// Server 是企业服务端地址，形如 https://sealsuite.example.com。
	Server string
	// DeviceID 是设备指纹，会以 cookie 形式随请求发送。
	DeviceID string
	// UserAgent 为空时按官方 Android 客户端格式自动生成。
	UserAgent string
	// Language 用于 Accept-Language，默认 zh-CN。
	Language string
	// InsecureSkipVerify 允许企业使用自签证书（对应 enable_self_signed）。
	InsecureSkipVerify bool
	// Verbose 打开请求级日志。
	Verbose bool
	// Meta 是随请求上报的客户端元信息；零值字段会被默认值填充。
	Meta Meta
}

// New 构造客户端并初始化 Cookie 容器；Server 为空时允许延后通过 SetServer 配置。
func New(opts Options) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("初始化 cookie 容器: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if opts.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	meta := opts.Meta
	meta = withMetaDefaults(meta)
	ua := opts.UserAgent
	if ua == "" {
		ua = UserAgent(meta)
	}
	lang := opts.Language
	if lang == "" {
		lang = "zh"
	}
	c := &Client{
		http:    &http.Client{Jar: jar, Transport: transport, Timeout: requestTimeout},
		ua:      ua,
		lang:    lang,
		device:  opts.DeviceID,
		meta:    meta,
		verbose: opts.Verbose,
	}
	if strings.TrimSpace(opts.Server) != "" {
		if err := c.SetServer(opts.Server); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// SetServer 动态更新企业服务端地址，并同步写入 device_id Cookie。
func (c *Client) SetServer(server string) error {
	trimmed := strings.TrimSpace(strings.TrimRight(server, "/"))
	if trimmed == "" {
		c.mu.Lock()
		c.base = nil
		c.mu.Unlock()
		return nil
	}
	base, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("解析服务端地址 %q: %w", server, err)
	}
	if base.Scheme == "" || base.Host == "" {
		return fmt.Errorf("服务端地址不完整: %q", server)
	}
	c.mu.Lock()
	c.base = base
	c.mu.Unlock()
	// device_id 以 cookie 形式参与风控，必须先于任何请求写入。
	if c.device != "" {
		c.http.Jar.SetCookies(base, []*http.Cookie{{Name: "device_id", Value: c.device, Path: "/"}})
	}
	return nil
}

// UserAgent 返回本客户端对外使用的 User-Agent。
//
// 所有发往企业服务端/节点的请求都必须带上它：Go 的默认 UA
// （Go-http-client/1.1）会直接把"这不是官方客户端"写在脸上。
func (c *Client) UserAgent() string { return c.ua }

// DefaultUserAgent 返回不依赖配置的官方 UA，供企业解析等裸请求使用。
func DefaultUserAgent() string { return UserAgent(withMetaDefaults(Meta{})) }

// Server 返回当前配置的服务端地址，未配置时返回空串。
func (c *Client) Server() string {
	return c.Base()
}

// UserAgent 按官方客户端格式拼出 User-Agent：
//
//	CorpLink/<version> (<brand><model>; Android <release>; <language>)
//
// 注意括号里是 Android 的 **release 版本号**（Build.VERSION.RELEASE，如 13），
// 不是 SDK level（33）。query 里的 os_version 才是 SDK level，两者不能混用，
// 混了等于自己举报"不是真机"。
func UserAgent(m Meta) string {
	return fmt.Sprintf("CorpLink/%s (%s%s; Android %s; %s)", m.AppVersion, m.Brand, m.Model, AndroidRelease(m.OSVersion), m.Language)
}

// androidReleases 是 SDK level → Android release 的对照表（Build.VERSION.RELEASE）。
var androidReleases = map[string]string{
	"21": "5.0", "22": "5.1", "23": "6.0", "24": "7.0", "25": "7.1",
	"26": "8.0", "27": "8.1", "28": "9", "29": "10", "30": "11",
	"31": "12", "32": "12L", "33": "13", "34": "14", "35": "15", "36": "16",
}

// AndroidRelease 把 SDK level 翻成 UA 里用的 release 版本；未知值原样返回。
func AndroidRelease(sdk string) string {
	if release, ok := androidReleases[sdk]; ok {
		return release
	}
	return sdk
}

// withMetaDefaults 为未显式指定的元信息补默认值，保证请求参数齐全。
func withMetaDefaults(m Meta) Meta {
	if m.OS == "" {
		m.OS = LoginOS
	}
	if m.AppVersion == "" {
		m.AppVersion = AppVersion
	}
	if m.BuildNumber == "" {
		m.BuildNumber = BuildNumber
	}
	if m.Language == "" {
		m.Language = "zh"
	}
	if m.ClientSource == "" {
		m.ClientSource = "FeiLian"
	}
	// 机型/品牌也要有默认值：MatchCompany 这类不经过配置的请求同样要伪装成
	// 官方 Android 客户端，否则会漏出 Go 的默认 UA（Go-http-client/1.1）。
	if m.Model == "" {
		m.Model = "Pixel 7"
	}
	if m.Brand == "" {
		m.Brand = "google"
	}
	// SDK level 与补丁日期也要有默认值：UA 里要有 "Android 13"，
	// 空着会拼出 "Android ; zh" 这种一眼假的串。
	if m.OSVersion == "" {
		m.OSVersion = "33"
	}
	if m.OSPatch == "" {
		m.OSPatch = "2023-07-05"
	}
	return m
}

// GetRaw 以当前会话拉取一个原始资源（如图片），仅允许本企业域名。
func (c *Client) GetRaw(ctx context.Context, target string) ([]byte, string, error) {
	base := c.currentBase()
	if base == nil || base.Host == "" {
		return nil, "", fmt.Errorf(errNoServer)
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, "", err
	}
	// 比较主机名（忽略端口），base 里通常带 :443。
	if !strings.EqualFold(u.Hostname(), base.Hostname()) {
		return nil, "", fmt.Errorf("只允许拉取 %s 的资源", base.Hostname())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept-Language", c.acceptLanguage())
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("拉取资源返回 %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, "", err
	}
	return data, resp.Header.Get("Content-Type"), nil
}

// HasSession 判断 cookie jar 里是否已有登录会话。
func (c *Client) HasSession() bool {
	for _, ck := range c.Cookies() {
		if ck.Name == "session" && ck.Value != "" {
			return true
		}
	}
	return false
}

// SetSigner 注册签名器；只有 Endpoint.SigningInputParams 非 0 的接口才会调用。
func (c *Client) SetSigner(s Signer) {
	c.mu.Lock()
	c.signer = s
	c.mu.Unlock()
}

// SetDPoP 注册设备证明器；只有 Endpoint.NeedsDPoP 的接口才会调用。
func (c *Client) SetDPoP(p DPoPProver) {
	c.mu.Lock()
	c.prover = p
	c.mu.Unlock()
}

// currentBase 安全读取当前服务端地址副本。
func (c *Client) currentBase() *url.URL {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.base == nil {
		return nil
	}
	copyURL := *c.base
	return &copyURL
}

// Base 返回服务端根地址，便于日志与后续拼接；未配置时返回空串。
func (c *Client) Base() string {
	base := c.currentBase()
	if base == nil {
		return ""
	}
	return base.String()
}

// Cookies 返回当前 Cookie 集合的副本，用于持久化会话。
func (c *Client) Cookies() []*http.Cookie {
	base := c.currentBase()
	if base == nil || base.Host == "" {
		return nil
	}
	return c.http.Jar.Cookies(base)
}

// Cookie 返回当前会话里指定 Cookie 的值，不存在时返回空串。
func (c *Client) Cookie(name string) string {
	base := c.currentBase()
	if base == nil || base.Host == "" {
		return ""
	}
	return cookieValueOf(c.http.Jar.Cookies(base), name)
}

// SetCookies 注入已持久化的会话 Cookie。
func (c *Client) SetCookies(cookies []*http.Cookie) {
	base := c.currentBase()
	if base == nil || base.Host == "" {
		return
	}
	c.http.Jar.SetCookies(base, cookies)
}

// ClearCookies 清空 cookie jar（退出登录）。
func (c *Client) ClearCookies() {
	base := c.currentBase()
	if base == nil || base.Host == "" {
		return
	}
	// 标准库 jar 没有清空接口，用一组过期 Cookie 覆盖即可。
	cookies := c.Cookies()
	for _, ck := range cookies {
		ck.Value = ""
		ck.MaxAge = -1
	}
	c.http.Jar.SetCookies(base, cookies)
}

// Do 发送一次接口请求并解析统一响应外壳。
// acceptLanguage 返回 Accept-Language 头；官方客户端固定 zh-CN，
// 与 query 里的 language=zh 是两套值，不能混用。
func (c *Client) acceptLanguage() string {
	if c.lang == "" || c.lang == "zh" {
		return "zh-CN"
	}
	return c.lang
}

func (c *Client) Do(ctx context.Context, ep Endpoint, query url.Values, body any) (*Envelope, error) {
	base := c.currentBase()
	if base == nil || base.Host == "" {
		return nil, fmt.Errorf(errNoServer)
	}
	u := *base
	u.Path = strings.TrimRight(base.Path, "/") + ep.Path
	merged := c.meta.Query()
	for k, vs := range query {
		merged[k] = vs
	}
	u.RawQuery = merged.Encode()

	var payload []byte
	if body != nil {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(body); err != nil {
			return nil, fmt.Errorf("序列化请求体: %w", err)
		}
		payload = bytes.TrimRight(buf.Bytes(), "\n")
	}

	method := http.MethodGet
	if payload != nil {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("构造请求: %w", err)
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept-Language", c.acceptLanguage())
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	cookies := c.http.Jar.Cookies(&u)
	cookieHeader := cookieHeaderOf(cookies)
	csrf := cookieValueOf(cookies, "csrf-token")
	if csrf != "" {
		req.Header.Set("csrf-token", csrf)
	}

	c.mu.RLock()
	signer := c.signer
	c.mu.RUnlock()
	if ep.SigningInputParams != 0 {
		if signer == nil {
			return nil, fmt.Errorf("接口 %s 需要签名，但未配置签名器", ep.Path)
		}
		jwt := cookieValueOf(cookies, "vpn-token")
		sign, err := signer(ep, method, &u, payload, cookieHeader, csrf, jwt)
		if err != nil {
			return nil, fmt.Errorf("生成签名 %s: %w", ep.Path, err)
		}
		if sign != "" {
			req.Header.Set("sign", sign)
		}
		if jwt != "" && ep.Path == EndpointVPNConn.Path {
			req.Header.Set("jwt-token", jwt)
		}
	}

	// 设备证明独立于 v1 签名：前者证明"持有设备私钥"，后者证明"客户端身份"。
	if ep.NeedsDPoP {
		c.mu.RLock()
		prover := c.prover
		c.mu.RUnlock()
		if c.verbose {
			fmt.Printf("[dpop] path=%s prover_set=%v\n", ep.Path, prover != nil)
		}
		if prover != nil {
			proof, err := prover(ep, method, &u, payload, cookieValueOf(cookies, "session"), cookieValueOf(cookies, "vpn-token"))
			if err != nil {
				fmt.Printf("[dpop] path=%s ERROR=%v\n", ep.Path, err)
				return nil, fmt.Errorf("生成 DPoP 证明 %s: %w", ep.Path, err)
			}
			if proof != "" {
				req.Header.Set("DPoP", proof)
				if c.verbose {
					fmt.Printf("[dpop] path=%s proof_len=%d set_header=DPoP\n", ep.Path, len(proof))
				}
			} else if c.verbose {
				fmt.Printf("[dpop] path=%s proof=EMPTY\n", ep.Path)
			}
		}
	}

	if c.verbose {
		fmt.Printf("[req] %s %s\n", method, u.String())
		// 只打印与鉴权相关的头，避免把 Cookie 原文刷进日志。
		for _, name := range []string{"User-Agent", "sign", "jwt-token", "DPoP", "csrf-token"} {
			if v := req.Header.Get(name); v != "" {
				fmt.Printf("[hdr] %s=%s(len=%d)\n", name, truncate(v, 24), len(v))
			} else if name == "jwt-token" {
				fmt.Printf("[hdr] %s=<empty>\n", name)
			}
		}
		if payload != nil {
			fmt.Printf("[body] %s\n", truncate(string(payload), 300))
		}
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 %s: %w", ep.Path, err)
	}
	defer resp.Body.Close()

	// 每次响应都顺手校准时钟：Date 头是最便宜的服务端时间来源，
	// TOTP 与 DPoP 的 iat 都依赖它（官方客户端同样用 otp_time_diff 做这件事）。
	clock.SyncFromDate(resp.Header.Get("Date"))

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("读取响应 %s: %w", ep.Path, err)
	}
	if c.verbose {
		apicode := -1
		var probe map[string]interface{}
		if json.Unmarshal(raw, &probe) == nil {
			if v, ok := probe["code"].(float64); ok {
				apicode = int(v)
			}
		}
		fmt.Printf("[resp] http=%d apicode=%d %s\n", resp.StatusCode, apicode, truncate(string(raw), 400))
	}
	if resp.StatusCode != http.StatusOK {
		// 429/5xx 等由服务端/网关产生，正文可能为空，必须把状态码暴露出来。
		return nil, fmt.Errorf("接口 %s 返回 HTTP %d（正文 %d 字节）", ep.Path, resp.StatusCode, len(raw))
	}

	env := &Envelope{}
	if err := json.Unmarshal(raw, env); err != nil {
		return nil, fmt.Errorf("解析响应 %s: %w（正文 %q）", ep.Path, err, truncate(string(raw), 200))
	}
	// 业务体里带 timestamp 时优先用它（秒级整数，比 Date 头更贴近服务端逻辑时钟）。
	syncFromPayload(env.Data)
	// 只有"本来就带着会话、且不是登录链路"的请求才可能是被踢。
	// 登录链路必须整体豁免：重登时 jar 里往往还留着上一个会话的 session，
	// 服务端在登录接口上回的 action=logout / 101 会被误判成"被踢"，把登录打断。
	if !isLoginPath(ep.Path) && env.LoggedOut() && cookieValueOf(cookies, "session") != "" {
		return nil, env.KickedError()
	}
	return env, nil
}

// timestampFloor / timestampCeil 限定可信的秒级时间戳范围（2001-09 ~ 2096-10）。
// 服务端个别接口把毫秒当秒返回，直接用会把时钟偏移打到天文数字。
const (
	timestampFloor = 1_000_000_000
	timestampCeil  = 4_000_000_000
)

// syncFromPayload 在响应 data 里找 timestamp 字段做校准。
func syncFromPayload(data json.RawMessage) {
	if len(data) == 0 {
		return
	}
	var probe struct {
		Timestamp int64 `json:"timestamp"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return
	}
	if probe.Timestamp >= timestampFloor && probe.Timestamp <= timestampCeil {
		clock.SyncFromUnix(probe.Timestamp)
	}
}

// isLoginPath 判断接口是否属于登录链路（这些接口不参与"被踢"判定）。
func isLoginPath(path string) bool {
	switch {
	case strings.HasPrefix(path, "/api/tpslogin/"):
		return true
	case strings.HasPrefix(path, "/api/v1/login/"):
		return true
	case strings.HasPrefix(path, "/api/mfa/"):
		return true
	case path == EndpointLoginSetting.Path, path == EndpointOTP.Path:
		return true
	}
	return false
}

// MatchCompany 用企业代码解析服务端地址。
func MatchCompany(ctx context.Context, code string) (*CompanyInfo, error) {
	body, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return nil, fmt.Errorf("序列化企业代码: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, matchBaseURL+EndpointCompanyMatch.Path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("构造企业解析请求: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// 企业解析也是发往公司侧域名的请求，UA 必须与客户端其余请求一致。
	req.Header.Set("User-Agent", DefaultUserAgent())
	req.Header.Set("Accept-Language", "zh-CN")
	resp, err := (&http.Client{Timeout: requestTimeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("企业代码解析请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("读取企业解析响应: %w", err)
	}
	env := &Envelope{}
	if err := json.Unmarshal(raw, env); err != nil {
		return nil, fmt.Errorf("解析企业解析响应: %w（正文 %q）", err, truncate(string(raw), 200))
	}
	if !env.OK() {
		return nil, env.Error()
	}
	info := &CompanyInfo{}
	if err := json.Unmarshal(env.Data, info); err != nil {
		return nil, fmt.Errorf("解析企业信息: %w", err)
	}
	return info, nil
}

// cookieHeaderOf 把 Cookie 列表拼成 Cookie 头；签名需要原始形态。
func cookieHeaderOf(cookies []*http.Cookie) string {
	parts := make([]string, 0, len(cookies))
	for _, ck := range cookies {
		parts = append(parts, ck.Name+"="+ck.Value)
	}
	return strings.Join(parts, "; ")
}

// cookieValueOf 取指定 Cookie 的值，不存在时返回空串。
func cookieValueOf(cookies []*http.Cookie, name string) string {
	for _, ck := range cookies {
		if ck.Name == name {
			return ck.Value
		}
	}
	return ""
}

// truncate 截断日志正文，避免刷屏。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
