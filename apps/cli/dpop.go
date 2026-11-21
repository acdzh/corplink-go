package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"github.com/acdzh/corplink-go/corplink"
)

// dpopTimeout 是设备密钥查询 / 登记的超时。
const dpopTimeout = 60 * time.Second

// runDpop 查询设备密钥状态；加 -register 时完成一次登记。
func runDpop(args []string) error {
	fs := flag.NewFlagSet("dpop", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "配置文件路径，默认用户配置目录")
	register := fs.Bool("register", false, "执行设备密钥登记（会消耗一次二次认证）")
	codeType := fs.String("type", "", "验证码类型（otp / email / mobile），默认 otp 优先")
	code := fs.String("code", "", "手动指定验证码；留空且本地有 TOTP secret 时自动生成")
	asJSON := fs.Bool("json", false, "以 JSON 输出")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), dpopTimeout)
	defer cancel()

	c, err := corplink.New(ctx, corplink.Options{ConfigPath: *cfgPath})
	if err != nil {
		return err
	}
	info, err := c.LoginDpopInfo(ctx)
	if err != nil {
		return err
	}
	if *register {
		result, err := c.LoginRegisterDpop(ctx, *codeType, *code)
		if err != nil {
			return err
		}
		for k, v := range result {
			info[k] = v
		}
		// 登记后重新查一次，展示服务端最终状态。
		if refreshed, err := c.LoginDpopInfo(ctx); err == nil {
			info["status"] = refreshed
		}
	}
	return printDpop(info, *asJSON)
}

// printDpop 输出设备密钥状态。
func printDpop(info map[string]any, asJSON bool) error {
	if asJSON {
		payload, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(payload))
		return nil
	}
	fmt.Printf("device_key_id : %v\n", info["device_key_id"])
	fmt.Printf("密钥路径       : %v\n", info["key_path"])
	fmt.Printf("已绑定         : %v\n", info["bound"])
	if v, ok := info["registered"]; ok {
		fmt.Printf("服务端已登记   : %v（status=%v）\n", v, info["device_key_status"])
	}
	if v, ok := info["server_device_key_id"]; ok {
		fmt.Printf("服务端密钥 id  : %v\n", v)
	}
	if v, ok := info["mfa_type"]; ok {
		fmt.Printf("登记认证方式   : %v（备用 %v）\n", v, info["backup_mfa_type"])
	}
	if v, ok := info["dpop_need_code"]; ok && v == true {
		fmt.Printf("需要验证码     : 是（%v），拿到后用 -code 重试\n", info["code_type"])
	}
	if v, ok := info["error"]; ok {
		fmt.Printf("查询错误       : %v\n", v)
	}
	return nil
}
