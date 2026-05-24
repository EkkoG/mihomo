//go:build linux && !android

package inbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"syscall"
	"time"

	adapterInbound "github.com/metacubex/mihomo/adapter/inbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/ebpf"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/socks5"

	"golang.org/x/sys/unix"
)

const (
	ebpfJanitorInterval = 30 * time.Second
	ebpfHandoffTTL      = 120 * time.Second
)

// Listen implements constant.InboundListener (Linux)
func (e *Ebpf) Listen(tunnel C.Tunnel) error {
	if len(e.config.Interfaces) == 0 {
		return errors.New("ebpf inbound requires at least one interface")
	}

	addr := e.RawAddress()

	// 1. Create eBPF loader
	loader, err := ebpf.NewLoader(&ebpf.LoaderConfig{
		TProxyPort: listenPort(addr),
		TProxyMark: tproxyMark(e.config.TPROXYMark),
	})
	if err != nil {
		return fmt.Errorf("create ebpf loader: %w", err)
	}
	e.loader = loader

	if err := loader.Load(); err != nil {
		return fmt.Errorf("load ebpf programs: %w", err)
	}

	// 2. Set runtime parameters
	if err := loader.SetParam(listenPort(addr), tproxyMark(e.config.TPROXYMark)); err != nil {
		return fmt.Errorf("set ebpf param: %w", err)
	}

	// 3. Populate bypass CIDRs
	v4CIDRs, v6CIDRs := splitCIDRs(e.config.BypassAddress)
	if err := loader.PopulateBypassCIDRs(v4CIDRs, v6CIDRs); err != nil {
		return fmt.Errorf("populate bypass CIDRs: %w", err)
	}

	// 4. Attach eBPF programs to interfaces
	if err := loader.Attach(e.config.Interfaces); err != nil {
		return fmt.Errorf("attach ebpf: %w", err)
	}

	// 5. Create TPROXY listener
	if err := e.createTPROXYListener(addr, tunnel); err != nil {
		_ = loader.Close()
		return fmt.Errorf("create tproxy listener: %w", err)
	}

	// 6. Setup firewall TPROXY rule on loopback (iptables or nftables)
	if err := setupFirewall(addr, e.config.TPROXYMark); err != nil {
		log.Warnln("Ebpf[%s] setup firewall TPROXY rule failed: %v", e.Name(), err)
	}

	// 7. Start handoff map janitor
	loader.StartJanitor(ebpfJanitorInterval, ebpfHandoffTTL)

	log.Infoln("Ebpf[%s] listening at: %s, interfaces: %v", e.Name(), addr, e.config.Interfaces)
	return nil
}

// Close implements constant.InboundListener (Linux)
func (e *Ebpf) Close() error {
	e.closed = true

	var errs []error

	if err := cleanupFirewall(e.RawAddress(), e.config.TPROXYMark); err != nil {
		errs = append(errs, fmt.Errorf("cleanup firewall: %w", err))
	}

	if l, ok := e.tcpListener.(net.Listener); ok && l != nil {
		if err := l.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c, ok := e.udpConn.(net.PacketConn); ok && c != nil {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if l, ok := e.loader.(interface{ Close() error }); ok && l != nil {
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close ebpf: %w", err))
		}
	}

	return errors.Join(errs...)
}

func (e *Ebpf) createTPROXYListener(addr string, tunnel C.Tunnel) error {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				_ = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
				_ = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
				if isIPv6Addr(addr) {
					_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
					_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
				}
			})
		},
	}

	l, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	e.tcpListener = l

	// Accept loop
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				if e.closed {
					return
				}
				log.Debugln("Ebpf[%s] accept error: %v", e.Name(), err)
				continue
			}
			go e.handleTCPConn(conn, tunnel)
		}
	}()

	// UDP listener
	if e.config.UDP {
		udpLc := net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
					_ = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
					_ = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
					if isIPv6Addr(addr) {
						_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
						_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
					}
				})
			},
		}
		conn, err := udpLc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			return fmt.Errorf("ebpf udp listen: %w", err)
		}
		e.udpConn = conn

		go e.handleUDPConn(conn, tunnel)
	}

	return nil
}

func (e *Ebpf) handleTCPConn(conn net.Conn, tunnel C.Tunnel) {
	target := socks5.ParseAddrToSocksAddr(conn.LocalAddr())
	additions := e.Additions()
	additions = append(additions, adapterInbound.WithInAddr(e.tcpListener.(net.Listener).Addr()))

	if meta := e.lookupMetadata(conn.RemoteAddr(), conn.LocalAddr(), 6); meta != nil {
		additions = append(additions, adapterInbound.WithSrcMac(meta.SrcMac), adapterInbound.WithInterfaceIndex(meta.IfIndex))
	}

	tunnel.HandleTCPConn(adapterInbound.NewSocket(target, conn, C.EBPF, additions...))
}

func (e *Ebpf) handleUDPConn(conn net.PacketConn, tunnel C.Tunnel) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if e.closed {
				return
			}
			continue
		}

		packet := buf[:n]
		udpAddr := addr.(*net.UDPAddr)

		metadata := &C.Metadata{
			NetWork: C.UDP,
			Type:    C.EBPF,
			SrcIP:   netip.MustParseAddr(udpAddr.IP.String()),
			SrcPort: uint16(udpAddr.Port),
		}
		_ = metadata.SetRemoteAddr(conn.LocalAddr())
		adapterInbound.ApplyAdditions(metadata, e.Additions()...)

		if meta := e.lookupMetadata(addr, conn.LocalAddr(), 17); meta != nil {
			metadata.SrcMac = meta.SrcMac
			metadata.IfIndex = meta.IfIndex
		}

		tunnel.HandleUDPPacket(&ebpfPacket{data: packet, srcAddr: addr, localAddr: conn.LocalAddr()}, metadata)
	}
}

type ebpfPacket struct {
	data      []byte
	srcAddr   net.Addr
	localAddr net.Addr
}

func (p *ebpfPacket) Data() []byte         { return p.data }
func (p *ebpfPacket) LocalAddr() net.Addr  { return p.localAddr }
func (p *ebpfPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	return len(b), nil
}
func (p *ebpfPacket) Drop() {}

func (e *Ebpf) lookupMetadata(remoteAddr, localAddr net.Addr, l4proto uint8) *ebpf.Metadata {
	loader, ok := e.loader.(*ebpf.Loader)
	if !ok || loader == nil {
		return nil
	}

	srcIP, dstIP, srcPort, dstPort := extractAddrInfo(remoteAddr, localAddr)
	if srcIP == nil {
		return nil
	}

	key := &ebpf.TupleKey{
		SrcIP:   *srcIP,
		DstIP:   *dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		L4Proto: l4proto,
	}

	meta, err := loader.LookupMetadata(key)
	if err != nil {
		return nil
	}
	_ = loader.DeleteMetadata(key)
	return meta
}

func extractAddrInfo(remoteAddr, localAddr net.Addr) (srcIP, dstIP *netip.Addr, srcPort, dstPort uint16) {
	switch a := remoteAddr.(type) {
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		srcIP = &ip
		srcPort = uint16(a.Port)
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		srcIP = &ip
		srcPort = uint16(a.Port)
	default:
		return nil, nil, 0, 0
	}

	switch a := localAddr.(type) {
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		dstIP = &ip
		dstPort = uint16(a.Port)
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		dstIP = &ip
		dstPort = uint16(a.Port)
	default:
		return nil, nil, 0, 0
	}

	return
}

func listenPort(addr string) uint32 {
	_, port, err := splitAddrPort(addr)
	if err != nil {
		return 7895
	}
	return port
}

func splitAddrPort(addr string) (string, uint32, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0, err
	}
	var p uint32
	for _, c := range portStr {
		if c < '0' || c > '9' {
			return addr, 0, fmt.Errorf("invalid port: %s", portStr)
		}
		p = p*10 + uint32(c-'0')
	}
	return host, p, nil
}

func isIPv6Addr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() == nil
}

func tproxyMark(mark uint32) uint32 {
	if mark == 0 {
		return 0x8000000
	}
	return mark
}

func splitCIDRs(prefixes []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range prefixes {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return
}

// firewallBackend detects which firewall tool to use and manages TPROXY rules.
type firewallBackend int

const (
	fwNone     firewallBackend = iota
	fwIptables
	fwNftables
)

var detectedFW firewallBackend

func detectFirewall() firewallBackend {
	if detectedFW != fwNone {
		return detectedFW
	}

	// Prefer nftables if available (modern, handles v4+v6 in one table)
	if _, err := exec.LookPath("nft"); err == nil {
		detectedFW = fwNftables
		return detectedFW
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		detectedFW = fwIptables
		return detectedFW
	}
	return fwNone
}

func setupFirewall(addr string, mark uint32) error {
	switch detectFirewall() {
	case fwNftables:
		return setupNftables(addr, mark)
	case fwIptables:
		return setupIPTables(addr, mark)
	default:
		return nil // no firewall available; routing rules may still work
	}
}

func cleanupFirewall(addr string, mark uint32) error {
	switch detectFirewall() {
	case fwNftables:
		return cleanupNftables()
	case fwIptables:
		return cleanupIPTables(addr, mark)
	default:
		return nil
	}
}

// ---- nftables ----

const nftTable = "mihomo_ebpf"

func setupNftables(addr string, mark uint32) error {
	m := tproxyMark(mark)
	port := listenPort(addr)

	// Create table (idempotent)
	exec.Command("nft", "add", "table", "inet", nftTable).Run()

	// Create prerouting chain with mangle priority
	exec.Command("nft", "add", "chain", "inet", nftTable, "prerouting",
		"{", "type", "filter", "hook", "prerouting", "priority", "mangle", ";", "}").Run()

	// Add TPROXY rule: match marked TCP packets on lo, redirect to TPROXY
	exec.Command("nft", "add", "rule", "inet", nftTable, "prerouting",
		"iif", "lo", "tcp", "meta", "mark", fmt.Sprintf("0x%x", m),
		"tproxy", "to", fmt.Sprintf(":%d", port),
		"meta", "mark", "set", fmt.Sprintf("0x%x", m),
		"accept",
	).Run() // rule is idempotent

	return nil
}

func cleanupNftables() error {
	// Flush and delete our table
	_ = exec.Command("nft", "flush", "table", "inet", nftTable).Run()
	_ = exec.Command("nft", "delete", "table", "inet", nftTable).Run()
	return nil
}

// ---- iptables (legacy) ----

func setupIPTables(addr string, mark uint32) error {
	m := tproxyMark(mark)
	port := listenPort(addr)
	markStr := fmt.Sprintf("%d/%d", m, m)
	markHex := fmt.Sprintf("0x%x", m)

	rules := [][]string{
		{"iptables", "-t", "mangle", "-I", "PREROUTING", "1",
			"-i", "lo", "-p", "tcp",
			"-m", "mark", "--mark", markStr,
			"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port),
			"--tproxy-mark", markHex},
		{"ip6tables", "-t", "mangle", "-I", "PREROUTING", "1",
			"-i", "lo", "-p", "tcp",
			"-m", "mark", "--mark", markStr,
			"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port),
			"--tproxy-mark", markHex},
	}

	for _, rule := range rules {
		cmd := exec.Command(rule[0], rule[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			// Check if rule already exists (acceptable)
			checkArgs := append([]string{"-t", "mangle", "-C", "PREROUTING"}, rule[4:]...)
			if exec.Command(rule[0], checkArgs...).Run() == nil {
				continue
			}
			return fmt.Errorf("iptables %v: %w: %s", rule, err, string(out))
		}
	}
	return nil
}

func cleanupIPTables(addr string, mark uint32) error {
	m := tproxyMark(mark)
	port := listenPort(addr)
	markStr := fmt.Sprintf("%d/%d", m, m)
	markHex := fmt.Sprintf("0x%x", m)

	rules := [][]string{
		{"iptables", "-t", "mangle", "-D", "PREROUTING",
			"-i", "lo", "-p", "tcp",
			"-m", "mark", "--mark", markStr,
			"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port),
			"--tproxy-mark", markHex},
		{"ip6tables", "-t", "mangle", "-D", "PREROUTING",
			"-i", "lo", "-p", "tcp",
			"-m", "mark", "--mark", markStr,
			"-j", "TPROXY", "--on-port", fmt.Sprintf("%d", port),
			"--tproxy-mark", markHex},
	}

	for _, rule := range rules {
		_ = exec.Command(rule[0], rule[1:]...).Run()
	}
	return nil
}
