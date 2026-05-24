//go:build linux

package ebpf

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// CheckMain is the entry point for `mihomo check-ebpf`.
func CheckMain(args []string) {
	fmt.Println("eBPF capability check")
	fmt.Println("=====================")
	fmt.Printf("  OS:      %s\n", runtime.GOOS)
	fmt.Printf("  Arch:    %s\n", runtime.GOARCH)

	// 1. Kernel version
	var uname unix.Utsname
	if err := unix.Uname(&uname); err == nil {
		release := unix.ByteSliceToString(uname.Release[:])
		fmt.Printf("  Kernel:  %s\n", release)
	}

	// 2. Program load test
	fmt.Println("\nBPF program load:")
	progOK := true
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SchedCLS,
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		License:      "GPL",
	})
	if err != nil {
		fmt.Printf("  TC (SchedCLS) program:   FAIL (%v)\n", err)
		progOK = false
	} else {
		fmt.Println("  TC (SchedCLS) program:   OK")
		prog.Close()
	}

	// 3. Map creation
	fmt.Println("\nBPF maps:")
	mapOK := true
	for _, mt := range []struct {
		name string
		typ  ebpf.MapType
	}{
		{"Hash", ebpf.Hash},
		{"LPM trie", ebpf.LPMTrie},
		{"Array", ebpf.Array},
	} {
		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: mt.typ, KeySize: 4, ValueSize: 4, MaxEntries: 1})
		if err != nil {
			fmt.Printf("  %-12s: FAIL (%v)\n", mt.name, err)
			mapOK = false
		} else {
			fmt.Printf("  %-12s: OK\n", mt.name)
			m.Close()
		}
	}

	// 4. Helpers test via small program verification
	fmt.Println("\nBPF helper availability (via program load):")
	helpers := []struct {
		name string
		prog *ebpf.ProgramSpec
	}{
		{"redirect", &ebpf.ProgramSpec{
			Type: ebpf.SchedCLS,
			Instructions: asm.Instructions{
				asm.Mov.Imm(asm.R1, 1),
				asm.Mov.Imm(asm.R2, 0),
				asm.FnRedirect.Call(),
				asm.Return(),
			},
			License: "GPL",
		}},
		{"sk_assign", &ebpf.ProgramSpec{
			Type: ebpf.SchedCLS,
			Instructions: asm.Instructions{
				asm.Mov.Imm(asm.R1, 0),
				asm.Mov.Imm(asm.R2, 0),
				asm.Mov.Imm(asm.R3, 0),
				asm.FnSkAssign.Call(),
				asm.Return(),
			},
			License: "GPL",
		}},
	}
	for _, h := range helpers {
		p, err := ebpf.NewProgram(h.prog)
		if err != nil {
			fmt.Printf("  %-15s: FAIL (%v)\n", h.name, err)
		} else {
			fmt.Printf("  %-15s: OK\n", h.name)
			p.Close()
		}
	}

	// 5. TC attach capability
	fmt.Println("\nTC attach:")
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		fmt.Printf("  clsact on lo: SKIP (cannot find lo: %v)\n", err)
	} else {
		qdisc := &netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: iface.Index,
				Parent:    netlink.HANDLE_INGRESS,
			},
		}
		if err := netlink.QdiscAdd(qdisc); err != nil {
			if os.IsExist(err) {
				fmt.Println("  clsact on lo: OK (already exists)")
			} else {
				fmt.Printf("  clsact on lo: FAIL (%v)\n", err)
			}
		} else {
			netlink.QdiscDel(qdisc)
			fmt.Println("  clsact on lo: OK")
		}
	}

	// 6. Build toolchain
	fmt.Println("\nBuild toolchain:")
	clangOK := true
	if _, err := exec.LookPath("clang"); err != nil {
		fmt.Println("  clang:   NOT FOUND (needed to compile eBPF C program)")
		clangOK = false
	} else {
		fmt.Println("  clang:   OK")
	}
	for _, h := range []string{
		"/usr/include/linux/bpf.h",
		"/usr/include/linux/if_ether.h",
		"/usr/include/linux/pkt_cls.h",
		"/usr/include/bpf/bpf_helpers.h",
	} {
		if _, err := os.Stat(h); err != nil {
			fmt.Printf("  %s: MISSING\n", h)
			clangOK = false
		}
	}
	if clangOK {
		fmt.Println("  headers: OK")
	}

	// 7. Kernel config checks (optional)
	fmt.Println("\nKernel config suggestions:")
	for _, cfg := range []string{
		"CONFIG_BPF=y",
		"CONFIG_BPF_SYSCALL=y",
		"CONFIG_BPF_JIT=y",
		"CONFIG_DEBUG_INFO_BTF=y",
	} {
		checkKernelConfig(cfg)
	}

	// 8. Summary
	fmt.Println("\n---")
	if progOK && mapOK {
		fmt.Println("eBPF support: YES (ready for ebpf inbound)")
	} else {
		fmt.Println("eBPF support: NO (required kernel features missing)")
		fmt.Println("  Requirements: Linux >= 4.19 with CONFIG_BPF_SYSCALL=y, CONFIG_DEBUG_INFO_BTF=y")
	}
}

func checkKernelConfig(name string) {
	cfg := strings.TrimPrefix(name, "CONFIG_")
	paths := []string{
		"/proc/config.gz",
		fmt.Sprintf("/boot/config-%s", unix.ByteSliceToString((&unix.Utsname{}).Release[:])),
	}
	_ = paths
	// Best-effort: check /proc/config.gz
	data, err := os.ReadFile("/proc/config.gz")
	if err != nil {
		// Try /boot/config-$(uname -r)
		var uname unix.Utsname
		unix.Uname(&uname)
		release := unix.ByteSliceToString(uname.Release[:])
		data, err = os.ReadFile(fmt.Sprintf("/boot/config-%s", release))
	}
	if err != nil {
		fmt.Printf("  %-35s cannot check\n", name)
		return
	}
	if strings.Contains(string(data), cfg) {
		fmt.Printf("  %-35s OK\n", name)
	} else {
		fmt.Printf("  %-35s NOT SET\n", name)
	}
}
