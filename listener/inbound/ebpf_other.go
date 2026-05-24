//go:build !linux

package inbound

import (
	"errors"

	C "github.com/metacubex/mihomo/constant"
)

// Listen implements constant.InboundListener (non-Linux stub)
func (e *Ebpf) Listen(tunnel C.Tunnel) error {
	return errors.New("ebpf inbound is only supported on Linux")
}

// Close implements constant.InboundListener (non-Linux stub)
func (e *Ebpf) Close() error {
	return nil
}
