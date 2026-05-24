//go:build linux

package ebpf

import (
	_ "embed"
)

//go:embed kern/redirect.o
var redirectProg []byte
