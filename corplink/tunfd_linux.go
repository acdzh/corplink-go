//go:build linux || android

package corplink

import "golang.zx2c4.com/wireguard/tun"

// tunFromFD 用已就绪的 TUN 文件描述符建网卡。
//
// Android 的 VpnService.establish() 返回的 fd 必须走无监控路径：
// 该 fd 由系统持有，不能按 /dev/net/tun 的常规流程再做 ioctl 建接口。
func tunFromFD(fd int) (tun.Device, error) {
	dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	return dev, err
}
