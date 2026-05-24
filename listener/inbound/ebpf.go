package inbound

import (
	"net/netip"

	C "github.com/metacubex/mihomo/constant"
)

// EbpfOption is the configuration for the eBPF inbound.
type EbpfOption struct {
	BaseOption
	Interfaces    []string       `inbound:"interfaces,omitempty"`
	BypassAddress []netip.Prefix `inbound:"bypass-address,omitempty"`
	UDP           bool           `inbound:"udp,omitempty"`
	TPROXYMark    uint32         `inbound:"tproxy-mark,omitempty"`
}

func (o EbpfOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

// Ebpf implements the C.InboundListener interface for eBPF-based traffic redirection.
type Ebpf struct {
	*Base
	config *EbpfOption

	// Runtime state (populated by Listen)
	loader      interface{ Close() error } // *ebpf.Loader on Linux
	tcpListener interface{ Close() error } // net.Listener on Linux
	udpConn     interface{ Close() error } // net.PacketConn on Linux
	closed      bool
}

// NewEbpf creates a new eBPF inbound.
func NewEbpf(options *EbpfOption) (*Ebpf, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &Ebpf{
		Base:   base,
		config: options,
	}, nil
}

// Config implements constant.InboundListener
func (e *Ebpf) Config() C.InboundConfig {
	return e.config
}

// Address implements constant.InboundListener
func (e *Ebpf) Address() string {
	return e.RawAddress()
}

var _ C.InboundListener = (*Ebpf)(nil)
