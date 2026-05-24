//go:build linux && !android

package ebpf

import (
	_ "embed"
)

//go:embed kern/redirect.o
var redirectProg []byte
