package totp

import (
	"testing"
	"time"
)

// TestCodeMatchesRFC6238 用 RFC 6238 的测试向量校验实现（SHA1/6 位）。
func TestCodeMatchesRFC6238(t *testing.T) {
	// RFC 里的 secret 是 "12345678901234567890"，base32 编码如下。
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1234567890, "005924"},
	}
	for _, c := range cases {
		got, remain, err := Code(secret, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("生成失败: %v", err)
		}
		if got != c.want {
			t.Fatalf("时间 %d 期望 %s，得到 %s", c.unix, c.want, got)
		}
		if remain <= 0 || remain > 30 {
			t.Fatalf("剩余秒数越界: %d", remain)
		}
	}
}

// TestCodeRejectsEmptySecret 校验空 secret 报错。
func TestCodeRejectsEmptySecret(t *testing.T) {
	if _, _, err := Code("", time.Now()); err == nil {
		t.Fatal("空 secret 应报错")
	}
}
