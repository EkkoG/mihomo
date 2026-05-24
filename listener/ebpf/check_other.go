//go:build !linux

package ebpf

import (
	"fmt"
	"runtime"
)

// CheckMain is the entry point for `mihomo check-ebpf`.
func CheckMain(args []string) {
	fmt.Println("eBPF capability check")
	fmt.Println("=====================")
	fmt.Printf("  OS:   %s\n", runtime.GOOS)
	fmt.Printf("  Arch: %s\n", runtime.GOARCH)
	fmt.Println()
	fmt.Println("eBPF support: NO — only available on Linux")
}
