//go:build linux && !android

package ebpf

import (
	"bytes"
	"fmt"

	"github.com/cilium/ebpf"
)

// bpfHandoffKey matches the C struct handoff_key.
type bpfHandoffKey struct {
	Sip     [4]uint32
	Dip     [4]uint32
	Sport   uint16
	Dport   uint16
	L4proto uint8
	Pad     [3]uint8
}

// bpfHandoffEntry matches the C struct handoff_entry.
type bpfHandoffEntry struct {
	Smac      [6]uint8
	Dmac      [6]uint8
	Ifindex   uint32
	Timestamp uint64
}

// bpfEbpfParam matches the C struct ebpf_param.
type bpfEbpfParam struct {
	TproxyPort uint32
	TproxyMark uint32
}

// bpfObjects holds all loaded eBPF objects.
type bpfObjects struct {
	EbpfIngress *ebpf.Program `ebpf:"ebpf_ingress"`
	ParamMap    *ebpf.Map     `ebpf:"param_map"`
	BypassV4Map *ebpf.Map     `ebpf:"bypass_v4_map"`
	BypassV6Map *ebpf.Map     `ebpf:"bypass_v6_map"`
	HandoffMap  *ebpf.Map     `ebpf:"handoff_map"`
}

// Close closes all eBPF objects.
func (o *bpfObjects) Close() error {
	var errs []error
	closer := func(name string, c interface{ Close() error }) {
		if c != nil {
			if err := c.Close(); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
			}
		}
	}
	closer("ebpf_ingress", o.EbpfIngress)
	closer("param_map", o.ParamMap)
	closer("bypass_v4_map", o.BypassV4Map)
	closer("bypass_v6_map", o.BypassV6Map)
	closer("handoff_map", o.HandoffMap)
	if len(errs) > 0 {
		return fmt.Errorf("close ebpf objects: %v", errs)
	}
	return nil
}

// loadBpfObjects loads eBPF objects from the embedded BPF bytecode.
func loadBpfObjects(obj *bpfObjects, opts *ebpf.CollectionOptions) error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(redirectProg))
	if err != nil {
		return fmt.Errorf("load collection spec: %w", err)
	}

	if err := spec.LoadAndAssign(obj, opts); err != nil {
		return fmt.Errorf("load and assign: %w", err)
	}

	return nil
}
