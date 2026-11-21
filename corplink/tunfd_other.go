//go:build !(linux || android)

package corplink

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

// tunFromFD 只在 Linux 与 Android 上可用：其他平台的 VpnService 等价物由系统提供。
func tunFromFD(fd int) (tun.Device, error) {
	return nil, fmt.Errorf("当前平台不支持注入 TUN 文件描述符: %d", fd)
}
