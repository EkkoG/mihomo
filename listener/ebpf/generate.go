//go:build linux

package ebpf

// The eBPF C program at kern/redirect.c is compiled to kern/redirect.o
// via the Makefile ebpf target (make ebpf), then embedded via //go:embed.
//
// Build flow:
//   1. make ebpf          # compile C → .o (requires Linux + clang + kernel headers)
//   2. go build           # embed .o → Go binary
//
// For CI, add 'make ebpf' before 'go build' on Linux targets.
//
// Optional: regenerate Go bindings with bpf2go (provides type-safe struct tags):
//   go generate ./...
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type handoffKey -type handoffEntry -type ebpfParam bpf kern/redirect.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu
