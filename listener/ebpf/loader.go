//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

var (
	ErrNotSupported = errors.New("ebpf not supported on this platform")
)

// Metadata returned from eBPF handoff map lookup.
type Metadata struct {
	SrcMac  [6]uint8
	DstMac  [6]uint8
	IfIndex uint32
}

// TupleKey is a 5-tuple connection identifier.
type TupleKey struct {
	SrcIP   netip.Addr
	DstIP   netip.Addr
	SrcPort uint16
	DstPort uint16
	L4Proto uint8
}

// Loader manages eBPF program lifecycle.
type Loader struct {
	objs      *bpfObjects
	program   *ebpf.Program
	loIfIndex int

	attachedIfaces map[string]netlink.Qdisc // iface name -> clsact qdisc
	mu             sync.Mutex
	closed         bool
}

// LoaderConfig holds configuration for the eBPF loader.
type LoaderConfig struct {
	TProxyMark uint32
	TProxyPort uint32
}

// NewLoader creates a new eBPF loader.
func NewLoader(cfg *LoaderConfig) (*Loader, error) {
	if cfg.TProxyMark == 0 {
		cfg.TProxyMark = 0x8000000
	}

	l := &Loader{
		attachedIfaces: make(map[string]netlink.Qdisc),
	}

	// Find loopback ifindex
	loIface, err := net.InterfaceByName("lo")
	if err != nil {
		return nil, fmt.Errorf("find lo interface: %w", err)
	}
	l.loIfIndex = loIface.Index

	return l, nil
}

// Load loads eBPF objects into the kernel.
func (l *Loader) Load() error {
	// Load eBPF objects from embedded bytecode
	var objs bpfObjects
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: 1,
			LogSize:  64 * 1024,
		},
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("load ebpf objects: %w\nverifier log:\n%s", err, ve)
		}
		return fmt.Errorf("load ebpf objects: %w", err)
	}

	l.objs = &objs
	l.program = objs.EbpfIngress

	return nil
}

// SetParam writes runtime parameters to the BPF param map.
func (l *Loader) SetParam(port uint32, mark uint32) error {
	if l.objs == nil {
		return errors.New("ebpf not loaded")
	}

	param := bpfEbpfParam{
		TproxyPort: port,
		TproxyMark: mark,
	}

	key := uint32(0)
	return l.objs.ParamMap.Update(&key, &param, ebpf.UpdateAny)
}

// PopulateBypassCIDRs writes bypass CIDRs to the LPM trie maps.
func (l *Loader) PopulateBypassCIDRs(v4CIDRs, v6CIDRs []netip.Prefix) error {
	if l.objs == nil {
		return errors.New("ebpf not loaded")
	}

	// Populate IPv4 bypass map
	for _, prefix := range v4CIDRs {
		addr := prefix.Addr().As4()
		key := lpmV4Key(prefix.Bits(), addr)
		val := uint8(1)
		if err := l.objs.BypassV4Map.Update(key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("add bypass v4 %s: %w", prefix, err)
		}
	}

	// Populate IPv6 bypass map
	for _, prefix := range v6CIDRs {
		addr := prefix.Addr().As16()
		key := lpmV6Key(prefix.Bits(), addr)
		val := uint8(1)
		if err := l.objs.BypassV6Map.Update(key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("add bypass v6 %s: %w", prefix, err)
		}
	}

	return nil
}

// lpmV4Key builds an LPM trie key for an IPv4 address.
// The eBPF bypass_v4_map uses IPv6-mapped IPv4 keys: prefixlen(4) + ::ffff:x.x.x.x(16).
func lpmV4Key(bits int, addr [4]byte) any {
	type lpmKey struct {
		PrefixLen uint32
		Data      [4]uint32
	}
	key := lpmKey{
		PrefixLen: uint32(bits + 96), // IPv6-mapped prefix offset
	}
	key.Data[2] = 0x0000ffff // ::ffff:/96
	key.Data[3] = uint32(addr[0])<<24 | uint32(addr[1])<<16 | uint32(addr[2])<<8 | uint32(addr[3])
	return &key
}

// lpmV6Key builds an LPM trie key for an IPv6 address.
func lpmV6Key(bits int, addr [16]byte) any {
	type lpmKey struct {
		PrefixLen uint32
		Data      [4]uint32
	}
	key := lpmKey{PrefixLen: uint32(bits)}
	for i := 0; i < 4; i++ {
		key.Data[i] = uint32(addr[i*4])<<24 | uint32(addr[i*4+1])<<16 | uint32(addr[i*4+2])<<8 | uint32(addr[i*4+3])
	}
	return &key
}

// Attach attaches the TC eBPF program to the ingress of specified interfaces.
func (l *Loader) Attach(ifaces []string) error {
	if l.program == nil {
		return errors.New("ebpf program not loaded")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, ifaceName := range ifaces {
		if _, exists := l.attachedIfaces[ifaceName]; exists {
			continue
		}

		link, err := netlink.LinkByName(ifaceName)
		if err != nil {
			return fmt.Errorf("find interface %s: %w", ifaceName, err)
		}

		// Add clsact qdisc
		qdisc := &netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_INGRESS,
			},
		}
		if err := netlink.QdiscAdd(qdisc); err != nil {
			if !errors.Is(err, netlink.ErrQdiscExists) {
				return fmt.Errorf("add clsact to %s: %w", ifaceName, err)
			}
		}

		// Attach TC filter with eBPF program
		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_INGRESS,
				Handle:    0x1,
				Protocol:  unixHtons(3), // ETH_P_ALL
			},
			Fd:           l.program.FD(),
			Name:         "mihomo-ebpf-ingress",
			DirectAction: true,
		}

		if err := netlink.FilterAdd(filter); err != nil {
			// Clean up qdisc if filter attach fails
			_ = netlink.QdiscDel(qdisc)
			return fmt.Errorf("attach bpf filter to %s: %w", ifaceName, err)
		}

		l.attachedIfaces[ifaceName] = qdisc
	}

	return nil
}

// Detach removes all TC programs and qdiscs from attached interfaces.
func (l *Loader) Detach() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	var errs []error
	for ifaceName, qdisc := range l.attachedIfaces {
		link, err := netlink.LinkByName(ifaceName)
		if err != nil {
			errs = append(errs, fmt.Errorf("find interface %s: %w", ifaceName, err))
			continue
		}

		// Remove TC filter
		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_INGRESS,
				Handle:    0x1,
			},
		}
		if err := netlink.FilterDel(filter); err != nil {
			errs = append(errs, fmt.Errorf("remove filter from %s: %w", ifaceName, err))
		}

		// Remove clsact qdisc (ignore "no such device" errors from interface removal)
		qdiscAttrs := qdisc.Attrs()
		if qdiscAttrs != nil {
			_ = netlink.QdiscDel(qdisc)
		}
	}
	l.attachedIfaces = make(map[string]netlink.Qdisc)

	return errors.Join(errs...)
}

// LookupMetadata retrieves eBPF handoff metadata for a connection tuple.
func (l *Loader) LookupMetadata(key *TupleKey) (*Metadata, error) {
	if l.objs == nil {
		return nil, errors.New("ebpf not loaded")
	}

	hkey := bpfHandoffKey{
		L4proto: key.L4Proto,
	}
	// Copy source IP (IPv4-mapped IPv6 format)
	srcIP := key.SrcIP.As16()
	for i := 0; i < 4; i++ {
		hkey.Sip[i] = uint32(srcIP[i*4])<<24 | uint32(srcIP[i*4+1])<<16 | uint32(srcIP[i*4+2])<<8 | uint32(srcIP[i*4+3])
	}
	// Copy dest IP
	dstIP := key.DstIP.As16()
	for i := 0; i < 4; i++ {
		hkey.Dip[i] = uint32(dstIP[i*4])<<24 | uint32(dstIP[i*4+1])<<16 | uint32(dstIP[i*4+2])<<8 | uint32(dstIP[i*4+3])
	}
	hkey.Sport = key.SrcPort
	hkey.Dport = key.DstPort

	var entry bpfHandoffEntry
	if err := l.objs.HandoffMap.Lookup(&hkey, &entry); err != nil {
		return nil, fmt.Errorf("lookup handoff: %w", err)
	}

	return &Metadata{
		SrcMac:  entry.Smac,
		DstMac:  entry.Dmac,
		IfIndex: entry.Ifindex,
	}, nil
}

// DeleteMetadata removes a handoff entry after it's been consumed.
func (l *Loader) DeleteMetadata(key *TupleKey) error {
	if l.objs == nil {
		return nil
	}
	hkey := bpfHandoffKey{L4proto: key.L4Proto}
	srcIP := key.SrcIP.As16()
	for i := 0; i < 4; i++ {
		hkey.Sip[i] = uint32(srcIP[i*4])<<24 | uint32(srcIP[i*4+1])<<16 | uint32(srcIP[i*4+2])<<8 | uint32(srcIP[i*4+3])
	}
	dstIP := key.DstIP.As16()
	for i := 0; i < 4; i++ {
		hkey.Dip[i] = uint32(dstIP[i*4])<<24 | uint32(dstIP[i*4+1])<<16 | uint32(dstIP[i*4+2])<<8 | uint32(dstIP[i*4+3])
	}
	hkey.Sport = key.SrcPort
	hkey.Dport = key.DstPort
	return l.objs.HandoffMap.Delete(&hkey)
}

// StartJanitor starts a background goroutine to clean up expired handoff entries.
func (l *Loader) StartJanitor(interval time.Duration, ttl time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if closed {
				return
			}
			l.cleanExpiredEntries(ttl)
		}
	}()
}

func (l *Loader) cleanExpiredEntries(ttl time.Duration) {
	if l.objs == nil {
		return
	}

	now := uint64(time.Now().UnixNano())
	expiry := uint64(ttl.Nanoseconds())

	var key bpfHandoffKey
	var val bpfHandoffEntry
	iter := l.objs.HandoffMap.Iterate()

	for iter.Next(&key, &val) {
		if now-val.Timestamp > expiry {
			_ = l.objs.HandoffMap.Delete(&key)
		}
	}
}

// Close shuts down the eBPF loader and cleans up all resources.
func (l *Loader) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()

	err := l.Detach() // Remove all TC filters and qdiscs
	if l.objs != nil {
		l.objs.Close()
	}
	return err
}

// unixHtons converts a host byte order uint16 to network byte order.
// Avoids importing golang.org/x/sys/unix for a single function.
func unixHtons(i uint16) uint16 {
	return i<<8 | i>>8
}
