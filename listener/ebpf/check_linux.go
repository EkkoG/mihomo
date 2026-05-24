//go:build linux

package ebpf

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
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

	// 2. Required kernel features
	fmt.Println("\nBPF kernel features:")
	checkFeature("  BPF syscall", features.HaveProgramType(ebpf.SchedCLS) == nil)
	checkFeature("  BPF ringbuf", features.HaveMapType(ebpf.RingBuf) == nil)
	checkFeature("  BPF LPM trie", features.HaveMapType(ebpf.LPMTrie) == nil)
	checkFeature("  BPF hash map", features.HaveMapType(ebpf.Hash) == nil)
	checkFeature("  BPF redirect", features.HaveProgramHelper(ebpf.SchedCLS, unix.BPF_FUNC_redirect) == nil)
	checkFeature("  BPF sk_assign", features.HaveProgramHelper(ebpf.SchedCLS, unix.BPF_FUNC_sk_assign) == nil)
	checkFeature("  BPF sk_lookup_tcp", features.HaveProgramHelper(ebpf.SchedCLS, unix.BPF_FUNC_skc_lookup_tcp) == nil)
	checkFeature("  BPF sk_lookup_udp", features.HaveProgramHelper(ebpf.SchedCLS, unix.BPF_FUNC_sk_lookup_udp) == nil)
	checkFeature("  BPF ktime_get_ns", features.HaveProgramHelper(ebpf.SchedCLS, unix.BPF_FUNC_ktime_get_ns) == nil)

	// 3. Program load test
	fmt.Println("\nProgram load test:")
	loadResult := "OK"
	prog, err := loadTestProgram()
	if err != nil {
		loadResult = fmt.Sprintf("FAIL: %v", err)
	} else {
		prog.Close()
	}
	fmt.Printf("  Load simple TC program: %s\n", loadResult)

	// 4. Map creation test
	fmt.Println("\nMap creation test:")
	mapResult := "OK"
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		mapResult = fmt.Sprintf("FAIL: %v", err)
	} else {
		m.Close()
	}
	fmt.Printf("  Hash map: %s\n", mapResult)

	// 5. TC attach capability
	fmt.Println("\nTC attach test:")
	tcResult := "OK"
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		tcResult = fmt.Sprintf("SKIP: cannot find lo: %v", err)
	} else {
		qdisc := &netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: iface.Index,
				Parent:    netlink.HANDLE_INGRESS,
			},
		}
		if err := netlink.QdiscAdd(qdisc); err != nil {
			if os.IsExist(err) {
				tcResult = "OK (clsact already exists)"
			} else {
				tcResult = fmt.Sprintf("FAIL: %v", err)
			}
		} else {
			netlink.QdiscDel(qdisc)
		}
	}
	fmt.Printf("  TC clsact on lo: %s\n", tcResult)

	// 6. C compiler check
	fmt.Println("\nBuild toolchain:")
	checkCommand("  clang", "clang")
	checkHeaders("  BPF headers", []string{
		"/usr/include/linux/bpf.h",
		"/usr/include/linux/if_ether.h",
		"/usr/include/bpf/bpf_helpers.h",
	})

	// 7. Summary
	fmt.Println("\n---")
	allOK := loadResult == "OK" && mapResult == "OK" && strings.Contains(tcResult, "OK")
	if allOK {
		fmt.Println("eBPF support: YES — system is ready for ebpf inbound")
	} else {
		fmt.Println("eBPF support: NO — some capabilities are missing")
	}
}

func loadTestProgram() (*ebpf.Program, error) {
	spec := &ebpf.ProgramSpec{
		Type: ebpf.SchedCLS,
		Instructions: ebpf.Instructions{
			// Load immediate 0
			ebpf.Mov.Imm(ebpf.Reg0, 0),
			// Return
			ebpf.Return(),
		},
		License: "GPL",
	}
	return ebpf.NewProgram(spec)
}

func checkFeature(name string, ok bool) {
	status := "OK"
	if !ok {
		status = "MISSING"
	}
	fmt.Printf("%-35s %s\n", name, status)
}

func checkCommand(name, cmd string) {
	_, err := execLookPath(cmd)
	if err != nil {
		fmt.Printf("%-35s NOT FOUND\n", name)
	} else {
		fmt.Printf("%-35s OK\n", name)
	}
}

func checkHeaders(name string, paths []string) {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			fmt.Printf("%-35s MISSING (%s)\n", name, p)
			return
		}
	}
	fmt.Printf("%-35s OK\n", name)
}

func execLookPath(cmd string) (string, error) {
	return exec.LookPath(cmd)
}
