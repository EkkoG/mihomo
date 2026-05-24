//go:build !linux

package ebpf

import (
	"errors"
	"net/netip"
	"time"
)

var ErrNotSupported = errors.New("ebpf is only supported on Linux")

type Metadata struct {
	SrcMac  [6]uint8
	DstMac  [6]uint8
	IfIndex uint32
}

type TupleKey struct {
	SrcIP   netip.Addr
	DstIP   netip.Addr
	SrcPort uint16
	DstPort uint16
	L4Proto uint8
}

type Loader struct{}
type LoaderConfig struct {
	TProxyMark uint32
	TProxyPort uint32
}

func NewLoader(cfg *LoaderConfig) (*Loader, error) {
	return nil, ErrNotSupported
}

func (l *Loader) Load() error                                        { return ErrNotSupported }
func (l *Loader) SetParam(port uint32, mark uint32) error             { return ErrNotSupported }
func (l *Loader) PopulateBypassCIDRs(v4, v6 []netip.Prefix) error    { return ErrNotSupported }
func (l *Loader) Attach(ifaces []string) error                        { return ErrNotSupported }
func (l *Loader) Detach() error                                       { return ErrNotSupported }
func (l *Loader) LookupMetadata(key *TupleKey) (*Metadata, error)     { return nil, ErrNotSupported }
func (l *Loader) DeleteMetadata(key *TupleKey) error                  { return ErrNotSupported }
func (l *Loader) StartJanitor(interval time.Duration, ttl time.Duration) {}
func (l *Loader) Close() error                                        { return nil }
