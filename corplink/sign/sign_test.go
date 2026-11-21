package sign

import (
	"net/url"
	"testing"
)

// TestHeaderStable 校验签名输出稳定：同样的输入必须得到同样的结果。
// 这里不做"与服务端一致"的断言（那需要真实设备密钥），只锁住回归。
func TestHeaderStable(t *testing.T) {
	u, err := url.Parse("https://example.com/api/vpn/list?app_version=3.3.24&timestamp=1")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"a":1}`)
	first, err := Header(510, "bytedance", "deviceid", "GET", u, body, "cookie=1", "csrf", "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Header(510, "bytedance", "deviceid", "GET", u, body, "cookie=1", "csrf", "")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("签名不稳定: %q != %q", first, second)
	}
	if len(first) < 8 || first[:3] != "v1;" {
		t.Fatalf("签名头格式不对: %q", first)
	}
}

// TestHeaderMaskZero 校验不需要签名的接口返回空串。
func TestHeaderMaskZero(t *testing.T) {
	u, _ := url.Parse("https://example.com/api/info/me")
	got, err := Header(0, "bytedance", "deviceid", "GET", u, nil, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("mask=0 时应返回空串，得到 %q", got)
	}
}

// TestHeaderRequiresDeviceID 校验缺少 device_id 时报错。
func TestHeaderRequiresDeviceID(t *testing.T) {
	u, _ := url.Parse("https://example.com/api/vpn/list")
	if _, err := Header(510, "bytedance", "", "GET", u, nil, "", "", ""); err == nil {
		t.Fatal("device_id 为空时应报错")
	}
}
