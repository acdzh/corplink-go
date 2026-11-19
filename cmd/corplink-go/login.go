package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/acdzh/corplink-go/internal/api"
	"github.com/acdzh/corplink-go/internal/auth"
	"github.com/acdzh/corplink-go/internal/config"
)

// loginTimeout 覆盖一次完整授权（含人工在浏览器里确认）。
const loginTimeout = 10 * time.Minute

// runLogin 执行一次第三方授权登录并把会话落盘。
//
// 流程与官方客户端一致：PKCE -> tpslogin/link 取授权链接 -> 人工授权拿回调 ->
// device/callback 换会话 -> 拉 TOTP secret 供后续二次验证。
func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	cfgPath := fs.String("config", "./config.json", "配置文件路径")
	alias := fs.String("alias", "lark", "第三方登录方式（lark / bytedance_sso 等）")
	callback := fs.String("callback", "", "直接给回调 URL（跳过人工粘贴）")
	scene := fs.String("scene", "feilian", "MFA 的 login_scene 取值")
	mfaType := fs.String("mfa-type", "", "MFA 方式（email / mobile），默认取服务端返回的第一个")
	verbose := fs.Bool("v", false, "打印请求与响应摘要")
	if err := fs.Parse(args); err != nil {
		// -h/-help 由 flag 包返回 ErrHelp，属于正常退出。
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.DeviceID == "" {
		return fmt.Errorf("配置缺少 device_id")
	}
	ctx, cancel := context.WithTimeout(context.Background(), loginTimeout)
	defer cancel()

	if cfg.Server == "" {
		info, err := api.MatchCompany(ctx, cfg.CompanyName)
		if err != nil {
			return fmt.Errorf("解析企业代码 %q: %w", cfg.CompanyName, err)
		}
		cfg.Server = info.Domain
		if err := cfg.Save(); err != nil {
			fmt.Fprintln(os.Stderr, "警告: 保存配置失败:", err)
		}
	}

	client, err := api.New(api.Options{
		Server:   cfg.Server,
		DeviceID: cfg.DeviceID,
		Language: cfg.Language,
		Verbose:  *verbose,
	})
	if err != nil {
		return err
	}
	if err := client.LoadCookies(cfg.SessionPath()); err != nil {
		fmt.Fprintln(os.Stderr, "警告: 读取历史会话失败:", err)
	}
	svc := auth.NewService(client)

	setting, err := svc.Setting(ctx)
	if err != nil {
		return fmt.Errorf("拉取登录配置: %w", err)
	}
	fmt.Printf("登录方式: %s\n", strings.Join(setting.LoginOrders, ", "))

	pkce, err := auth.NewPKCE()
	if err != nil {
		return err
	}
	methods, err := svc.TPSLink(ctx, pkce.Challenge, true)
	if err != nil {
		return fmt.Errorf("请求授权链接: %w", err)
	}
	chosen, err := pickMethod(methods, *alias)
	if err != nil {
		return err
	}

	cb := *callback
	if cb == "" {
		fmt.Printf("\n请用飞书打开下面链接完成授权（%s）：\n\n%s\n\n", chosen.FullTitle, chosen.LoginURL)
		fmt.Println("授权完成后浏览器会跳到 corplink://login/callback?...，把整条 URL 粘贴到这里：")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return fmt.Errorf("读取回调内容: %w", err)
		}
		cb = line
	}
	parsed, err := auth.ParseCallback(cb)
	if err != nil {
		return err
	}

	data, err := svc.DeviceCallback(ctx, parsed.AliasKey, parsed.Code, parsed.State, pkce.Verifier)
	if err != nil {
		return fmt.Errorf("设备回调登录: %w", err)
	}
	fmt.Printf("device/callback 返回: %s\n", string(data))
	fmt.Printf("会话 cookie: %s\n", cookieNames(client.Cookies()))

	if action, authList, account := parseNextAction(data); action == "2FA" {
		if err := completeMfa(ctx, svc, cfg, *scene, *mfaType, authList, account); err != nil {
			return err
		}
	} else if action != "" {
		return fmt.Errorf("服务端要求暂不支持的步骤: %s", action)
	}

	otp, err := svc.OTP(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "警告: 拉取 TOTP 绑定信息失败:", err)
	} else if secret, err := auth.OtpSecret(otp.URL); err == nil {
		cfg.Code = secret
		if err := cfg.Save(); err != nil {
			fmt.Fprintln(os.Stderr, "警告: 保存 TOTP secret 失败:", err)
		}
		fmt.Println("已保存 TOTP secret，后续二次验证可自动生成验证码")
	}

	if err := client.SaveCookies(cfg.SessionPath()); err != nil {
		return fmt.Errorf("保存会话: %w", err)
	}
	fmt.Printf("会话已写入 %s\n", cfg.SessionPath())
	return nil
}

// completeMfa 完成登录 MFA。
//
// 场景与类型已从客户端源码确认：LoginV2MfaEmailFragment 调用
// sendMfaCode("feilian", "email", mCurrentAccount)。剩下不确定的是 account
// 的取值形态（完整邮箱 / 掩码邮箱 / 账号前缀 / userid），因此按候选逐个尝试。
func completeMfa(ctx context.Context, svc *auth.Service, cfg *config.Config, scene, preferredMfa string, authList []string, serverAccount string) error {
	accounts := candidateAccounts(cfg.Username, serverAccount)
	scenes := []string{scene, "feilian", "login"}
	mfaTypes := []string{preferredMfa, "email", "mobile"}

	seenScene := map[string]bool{}
	for _, s := range scenes {
		if s == "" || seenScene[s] {
			continue
		}
		seenScene[s] = true
		seenType := map[string]bool{}
		for _, t := range mfaTypes {
			if t == "" || seenType[t] {
				continue
			}
			seenType[t] = true
			for _, account := range accounts {
				if _, err := svc.MfaSend(ctx, s, t, account); err != nil {
					fmt.Printf("mfa/send scene=%s type=%s account=%s 失败: %v\n", s, t, account, err)
					continue
				}
				fmt.Printf("验证码已下发（scene=%s type=%s account=%s），请输入：", s, t, account)
				code, err := bufio.NewReader(os.Stdin).ReadString('\n')
				if err != nil {
					return fmt.Errorf("读取 MFA 验证码: %w", err)
				}
				data, err := svc.MfaVerify(ctx, s, t, account, strings.TrimSpace(code))
				if err != nil {
					return fmt.Errorf("校验 MFA 验证码: %w", err)
				}
				fmt.Printf("MFA 结果: %s\n", string(data))
				return nil
			}
		}
	}
	return fmt.Errorf("所有 mfa 组合都失败，无法下发二次认证验证码")
}

// candidateAccounts 生成 MFA 账号候选：完整账号、去掉域名的前缀、掩码邮箱。
func candidateAccounts(username, serverAccount string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	add(username)
	add(serverAccount)
	if username != "" && strings.Contains(username, "@") {
		add(strings.SplitN(username, "@", 2)[0])
	}
	return out
}

// pickCodeType 从可用类型里选一个：优先用户指定，其次邮箱，最后手机。
func pickCodeType(types []string, preferred string) string {
	has := func(v string) bool {
		for _, t := range types {
			if t == v {
				return true
			}
		}
		return false
	}
	if preferred != "" && has(preferred) {
		return preferred
	}
	if has("email") {
		return "email"
	}
	if has("mobile") {
		return "mobile"
	}
	if len(types) > 0 {
		return types[0]
	}
	return ""
}

// sendMfaProbing 依次尝试候选 login_scene（v1 接口），第一个成功的即实际场景。
func sendMfaProbing(ctx context.Context, svc *auth.Service, preferred, mfa, account string) (string, error) {
	candidates := []string{preferred, "login", "feilian", "sso", "oidc", "tpslogin"}
	seen := map[string]bool{}
	var lastErr error
	for _, scene := range candidates {
		if scene == "" || seen[scene] {
			continue
		}
		seen[scene] = true
		if _, err := svc.MfaSend(ctx, scene, mfa, account); err != nil {
			lastErr = err
			fmt.Printf("mfa/send scene=%s 失败: %v\n", scene, err)
			continue
		}
		return scene, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("没有可尝试的 login_scene")
	}
	return "", fmt.Errorf("下发 MFA 验证码: %w", lastErr)
}

// parseNextAction 解析 LoginV2Result 的 result/next，返回后续动作、可用 MFA 方式与账号。
func parseNextAction(data []byte) (string, []string, string) {
	var parsed struct {
		Result string `json:"result"`
		Next   struct {
			Action   string   `json:"action"`
			AuthList []string `json:"auth_list"`
			Email    string   `json:"email"`
			Mobile   string   `json:"mobile"`
		} `json:"next"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", nil, ""
	}
	account := parsed.Next.Email
	if account == "" {
		account = parsed.Next.Mobile
	}
	return parsed.Next.Action, parsed.Next.AuthList, account
}

// nextStepHint 从 LoginV2Result 里取出下一步 action，便于判断是否需要 2FA。
func nextStepHint(data []byte) string {
	var parsed struct {
		Result string `json:"result"`
		Next   struct {
			Action string `json:"action"`
		} `json:"next"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return ""
	}
	if parsed.Next.Action != "" {
		return parsed.Next.Action
	}
	if parsed.Result != "" && parsed.Result != "success" {
		return parsed.Result
	}
	return ""
}

// cookieNames 打印会话里出现的 cookie 名，便于判断登录态是否真的建立。
func cookieNames(cookies []*http.Cookie) string {
	names := make([]string, 0, len(cookies))
	for _, ck := range cookies {
		names = append(names, ck.Name)
	}
	return strings.Join(names, ", ")
}

// pickMethod 按 alias 选择登录方式；alias 为空时取第一个。
func pickMethod(methods []api.ThirdPartyLogin, alias string) (*api.ThirdPartyLogin, error) {
	if len(methods) == 0 {
		return nil, fmt.Errorf("服务端没有返回可用的登录方式")
	}
	if alias == "" {
		return &methods[0], nil
	}
	for i := range methods {
		if methods[i].Alias == alias || methods[i].AliasKey == alias {
			return &methods[i], nil
		}
	}
	names := make([]string, 0, len(methods))
	for _, m := range methods {
		names = append(names, m.Alias)
	}
	return nil, fmt.Errorf("没有 %q 登录方式，可选: %s", alias, strings.Join(names, ", "))
}
