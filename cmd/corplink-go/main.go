// corplink-go 是飞连（CorpLink）的非官方客户端与服务端化实现。
// 当前为骨架：真正的登录/签名/隧道能力在 internal/ 下逐步实现。
package main

import (
	"fmt"
	"os"
)

// version 由构建时注入，未注入时为 dev。
var version = "dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-v" || os.Args[1] == "--version") {
		fmt.Println("corplink-go", version)
		return
	}
	fmt.Fprintln(os.Stderr, "corplink-go: 尚未实现子命令，见 --help")
}
