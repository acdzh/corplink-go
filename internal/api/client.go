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
	"time"

	"github.com/acdzh/corplink-go/internal/config"
)

// matchBaseURL 是公司代码解析服务，与具体企业的服务端地址无关。
const matchBaseURL = "https://corplink.volcengine.cn"

// requestTimeout 是单次接口调用的超时。
const requestTimeout = 20 * time.Second

// maxBodyBytes 限制读取的响应体大小，避免异常响应打爆内存。
const maxBodyBytes = 4 << 20

// Signer 为需要签名的接口生成 sign 头。返回空串表示不添加该头。
type Signer func(ep Endpoint, method string, u *url.URL, body []byte, cookie, csrf, jwt string) (string, error)

// Client 是飞连服务端的 HTTP 客户端，负责地址拼接、请求头、Cookie 与签名。
type Client struct {
	base    *url.URL
	http    *http.Client
	ua      string
	lang    string
	device  string
	signer  Signer
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
}

// New 构造客户端并初始化 Cookie 容器。
func New(opts Options) (*Client, error) {
	base, err := url.Parse(strings.TrimRight(opts.Server, "/"))
	if err != nil {
		return nil, fmt.Errorf("解析服务端地址 %q: %w", opts.Server, err)
	}
	if base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("服务端地址不完整: %q", opts.Server)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("初始化 cookie 容器: %w", err)
	}
	// device_id 以 cookie 形式参与风控，必须先于任何请求写入。
	if opts.DeviceID != "" {
		jar.SetCookies(base, []*http.Cookie{{Name: "device_id", Value: opts.DeviceID, Path: "/"}})
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if opts.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = UserAgentFrom(config.Default())
	}
	lang := opts.Language
	if lang == "" {
		lang = "zh-CN"
	}
	return &Client{
		base:    base,
		http:    &http.Client{Jar: jar, Transport: transport, Timeout: requestTimeout},
		ua:      ua,
		lang:    lang,
		device:  opts.DeviceID,
		verbose: opts.Verbose,
	}, nil
}

// UserAgentFrom 按官方客户端格式拼出 User-Agent：
// CorpLink/<version> (<brand><model>; Android <release>; <language>)
func UserAgentFrom(cfg *config.Config) string {
	brand := cfg.DeviceBrand
	model := cfg.DeviceModel
	release := cfg.OSVersion
	lang := cfg.Language
	if lang == "" {
		lang = "zh-CN"
	}
	return fmt.Sprintf("CorpLink/%s (%s%s; Android %s; %s)", AppVersion, brand, model, release, lang)
}

// SetSigner 注册签名器；只有 Endpoint.SigningInputParams 非 0 的接口才会调用。
func (c *Client) SetSigner(s Signer) { c.signer = s }

// Base 返回服务端根地址，便于日志与后续拼接。
func (c *Client) Base() string { return c.base.String() }

// Cookies 返回当前 Cookie 集合的副本，用于持久化会话。
func (c *Client) Cookies() []*http.Cookie { return c.http.Jar.Cookies(c.base) }

// SetCookies 注入已持久化的会话 Cookie。
func (c *Client) SetCookies(cookies []*http.Cookie) { c.http.Jar.SetCookies(c.base, cookies) }

// Do 发送一次接口请求并解析统一响应外壳。
func (c *Client) Do(ctx context.Context, ep Endpoint, query url.Values, body any) (*Envelope, error) {
	u := *c.base
	u.Path = strings.TrimRight(c.base.Path, "/") + ep.Path
	u.RawQuery = query.Encode()

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
	req.Header.Set("Accept-Language", c.lang)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	cookieHeader := cookieHeaderOf(c.http.Jar.Cookies(&u))
	csrf := cookieValueOf(c.http.Jar.Cookies(&u), "csrf-token")
	if csrf != "" {
		req.Header.Set("csrf-token", csrf)
	}

	if ep.SigningInputParams != 0 {
		if c.signer == nil {
			return nil, fmt.Errorf("接口 %s 需要签名，但未配置签名器", ep.Path)
		}
		jwt := cookieValueOf(c.http.Jar.Cookies(&u), "vpn-token")
		sign, err := c.signer(ep, method, &u, payload, cookieHeader, csrf, jwt)
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

	if c.verbose {
		fmt.Printf("[req] %s %s\n", method, u.String())
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 %s: %w", ep.Path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("读取响应 %s: %w", ep.Path, err)
	}
	if c.verbose {
		fmt.Printf("[resp] %d %s\n", resp.StatusCode, truncate(string(raw), 400))
	}
	if resp.StatusCode != http.StatusOK {
		// 429/5xx 等由服务端/网关产生，正文可能为空，必须把状态码暴露出来。
		return nil, fmt.Errorf("接口 %s 返回 HTTP %d（正文 %d 字节）", ep.Path, resp.StatusCode, len(raw))
	}

	env := &Envelope{}
	if err := json.Unmarshal(raw, env); err != nil {
		return nil, fmt.Errorf("解析响应 %s: %w（正文 %q）", ep.Path, err, truncate(string(raw), 200))
	}
	return env, nil
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
