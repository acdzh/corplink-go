package dpop

import (
	"os"
	"path/filepath"
	"testing"
)

// TestKeyRejectsDeviceIDMismatch 校验 device_id 变更不会静默覆盖已登记的密钥。
//
// 回归点：同一数据目录被另一份 config（device_id 不同）打开时，Key() 过去会
// 直接生成新密钥并落盘，把服务端已登记的那把冲掉；之后当前会话的 /vpn/conn
// 因为没有有效设备证明而被服务端回 3015「Session 无效」，看起来像登录坏了。
func TestKeyRejectsDeviceIDMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device_key.json")

	store, err := Open(path, "device-a")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	first, err := store.Key()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	other, err := Open(path, "device-b")
	if err != nil {
		t.Fatalf("open other: %v", err)
	}
	if _, err := other.Key(); err == nil {
		t.Fatal("device_id 不一致时应报错，而不是生成新密钥")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("密钥文件被覆盖了")
	}
	if first.DeviceID() != "device-a" {
		t.Fatalf("DeviceID = %q", first.DeviceID())
	}
}
