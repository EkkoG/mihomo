//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface/anet"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/tailscale/envknob"
	"github.com/metacubex/tailscale/hostinfo"
	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/net/netmon"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/tsnet"
	D "github.com/miekg/dns"
)

type Tailscale struct {
	*Base
	server      *tsnet.Server
	dnsResolver *dns.Resolver
	option      TailscaleOption
	ctx         context.Context
	cancel      context.CancelFunc
	lifecycleMu sync.Mutex
	startOnce   sync.Once
	startErr    error

	backendInit *tailscaleBackendInit

	serverStarted bool

	unregisterDNSResolver func()

	restartInFlight atomic.Bool
	failureCount    atomic.Int32
	lastRestart     time.Time
}

type TailscaleOption struct {
	BasicOption
	Name       string `proxy:"name"`
	Hostname   string `proxy:"hostname,omitempty"`
	AuthKey    string `proxy:"auth-key,omitempty"`
	ControlURL string `proxy:"control-url,omitempty"`
	StateDir   string `proxy:"state-dir,omitempty"`
	Ephemeral  bool   `proxy:"ephemeral,omitempty"`
	UDP        bool   `proxy:"udp,omitempty"`

	AcceptRoutes           *bool  `proxy:"accept-routes,omitempty"`
	ExitNode               string `proxy:"exit-node,omitempty"`
	ExitNodeAllowLANAccess *bool  `proxy:"exit-node-allow-lan-access,omitempty"`
}

type tailscaleBackendInit struct {
	once sync.Once
	ch   chan struct{}
	err  error
}

const (
	tailscaleRecoverableFailureThreshold = 3
	tailscaleRestartMinInterval          = time.Minute
)

func init() {
	hostinfo.RegisterHostinfoNewHook(func(hi *tailcfg.Hostinfo) {
		hi.IPNVersion = C.MihomoName + " " + C.Version
	})
	envknob.SetNoLogsNoSupport()
	if runtime.GOOS == "android" { // Android SDK 30 no longer permits Go's net.Interfaces to work (Issue 2293)
		netmon.RegisterInterfaceGetter(func() (nif []netmon.Interface, err error) {
			ifaces, err := anet.Interfaces()
			if err != nil {
				return nil, err
			}
			for _, iff := range ifaces {
				addrs, err := anet.InterfaceAddrsByInterface(&iff)
				if err != nil {
					continue
				}
				nif = append(nif, netmon.Interface{
					Interface: &iff,
					AltAddrs:  addrs,
				})
			}
			return
		})
	}
}

func NewTailscale(option TailscaleOption) (*Tailscale, error) {
	if _, err := buildTailscaleMaskedPrefs(option); err != nil {
		return nil, err
	}
	if option.StateDir == "" {
		option.StateDir = "tailscale"
	}
	option.StateDir = C.Path.Resolve(option.StateDir)
	if !C.Path.IsSafePath(option.StateDir) {
		return nil, C.Path.ErrNotSafePath(option.StateDir)
	}

	addr := option.ControlURL
	if addr == "" {
		addr = "tailscale"
	}
	ctx, cancel := context.WithCancel(context.Background())
	outbound := &Tailscale{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Tailscale,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:      option,
		ctx:         ctx,
		cancel:      cancel,
		backendInit: newTailscaleBackendInit(),
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	outbound.server = outbound.newServer()
	dnsTransport := tailscaleDNSTransport{tailscale: outbound}
	outbound.dnsResolver = dns.NewResolverFromClient(dnsTransport)
	outbound.unregisterDNSResolver = dns.RegisterTailscaleDnsClient(option.Name, dnsTransport)
	return outbound, nil
}

func newTailscaleBackendInit() *tailscaleBackendInit {
	return &tailscaleBackendInit{ch: make(chan struct{})}
}

func (t *Tailscale) newServer() *tsnet.Server {
	return &tsnet.Server{
		Dir:                  t.option.StateDir,
		Hostname:             t.option.Hostname,
		AuthKey:              t.option.AuthKey,
		ControlURL:           t.option.ControlURL,
		Ephemeral:            t.option.Ephemeral,
		SystemDialer:         t.dialer.DialContext,
		SystemPacketListener: tailscalePacketListener{dialer: t.dialer}.ListenPacket,
		ExtraRootCAs:         ca.GetCertPool(),
		LookupHook:           tailscaleLookupHook,
		UserLogf: func(format string, args ...any) {
			log.Infoln("[Tailscale](%s) %s", t.option.Name, fmt.Sprintf(format, args...))
		},
		Logf: func(format string, args ...any) {
			log.Debugln("[Tailscale](%s) %s", t.option.Name, fmt.Sprintf(format, args...))
		},
	}
}

func (t *Tailscale) start() error {
	t.lifecycleMu.Lock()
	defer t.lifecycleMu.Unlock()

	t.startOnce.Do(func() {
		init := t.backendInit
		server := t.server
		if err := server.Start(); err != nil {
			t.startErr = err
			setTailscaleBackendInitialized(init, err)
			return
		}
		t.serverStarted = true
		ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
		defer cancel()
		if err := t.applyPrefs(ctx, server); err != nil {
			t.startErr = err
			setTailscaleBackendInitialized(init, err)
			return
		}
		go t.watchBackendState(server, init)
	})
	return t.startErr
}

func (t *Tailscale) ensureStarted(ctx context.Context) error {
	if err := t.start(); err != nil {
		return err
	}
	return t.waitBackendInitialized(ctx)
}

func (t *Tailscale) watchBackendState(server *tsnet.Server, init *tailscaleBackendInit) {
	lc, err := server.LocalClient()
	if err != nil {
		setTailscaleBackendInitialized(init, err)
		return
	}
	watcher, err := lc.WatchIPNBus(t.ctx, ipn.NotifyInitialState)
	if err != nil {
		setTailscaleBackendInitialized(init, err)
		return
	}
	defer watcher.Close()

	backendInitialized := false
	exitNodeNeedsStatus := tailscaleExitNodeNeedsStatus(t.option)
	for {
		n, err := watcher.Next()
		if err != nil {
			setTailscaleBackendInitialized(init, err)
			return
		}
		if n.State == nil {
			continue
		}

		if *n.State != ipn.NoState && !backendInitialized {
			setTailscaleBackendInitialized(init, nil)
			backendInitialized = true
			if !exitNodeNeedsStatus {
				return
			}
		}
		if exitNodeNeedsStatus && *n.State == ipn.Running {
			if err := t.applyExitNodePrefs(t.ctx, server); err != nil {
				log.Warnln("[Tailscale](%s) set exit node failed: %v", t.Name(), err)
			}
			return
		}
	}
}

func setTailscaleBackendInitialized(init *tailscaleBackendInit, err error) {
	init.once.Do(func() {
		init.err = err
		close(init.ch)
	})
}

func (t *Tailscale) waitBackendInitialized(ctx context.Context) error {
	t.lifecycleMu.Lock()
	init := t.backendInit
	t.lifecycleMu.Unlock()

	select {
	case <-init.ch:
		return init.err
	case <-ctx.Done():
		return ctx.Err()
	case <-t.ctx.Done():
		return t.ctx.Err()
	}
}

func (t *Tailscale) applyPrefs(ctx context.Context, server *tsnet.Server) error {
	mp, err := buildTailscaleMaskedPrefs(t.option)
	if err != nil {
		return err
	}
	if mp == nil {
		return nil
	}
	lc, err := server.LocalClient()
	if err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, mp)
	return err
}

func (t *Tailscale) applyExitNodePrefs(ctx context.Context, server *tsnet.Server) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	lc, err := server.LocalClient()
	if err != nil {
		return err
	}
	status, err := lc.Status(ctx)
	if err != nil {
		return err
	}
	mp := &ipn.MaskedPrefs{
		ExitNodeIPSet: true,
	}
	if t.option.ExitNodeAllowLANAccess != nil {
		mp.ExitNodeAllowLANAccess = *t.option.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
	}
	if err = mp.SetExitNodeIP(t.option.ExitNode, status); err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, mp)
	return err
}

func buildTailscaleMaskedPrefs(option TailscaleOption) (*ipn.MaskedPrefs, error) {
	var mp ipn.MaskedPrefs
	changed := false

	if option.AcceptRoutes != nil {
		mp.RouteAll = *option.AcceptRoutes
		mp.RouteAllSet = true
		changed = true
	}
	if option.ExitNode != "" {
		if autoExitNode, ok := ipn.ParseAutoExitNodeString(option.ExitNode); ok {
			mp.AutoExitNode = autoExitNode
			mp.AutoExitNodeSet = true
			changed = true
		}
	}
	if option.ExitNodeAllowLANAccess != nil && !tailscaleExitNodeNeedsStatus(option) {
		mp.ExitNodeAllowLANAccess = *option.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
		changed = true
	}
	if !changed {
		return nil, nil
	}
	return &mp, nil
}

func tailscaleExitNodeNeedsStatus(option TailscaleOption) bool {
	if option.ExitNode == "" {
		return false
	}
	_, ok := ipn.ParseAutoExitNodeString(option.ExitNode)
	return !ok
}

func (t *Tailscale) currentServer() *tsnet.Server {
	t.lifecycleMu.Lock()
	defer t.lifecycleMu.Unlock()
	return t.server
}

func tailscaleLookupHook(ctx context.Context, host string) ([]netip.Addr, error) {
	return resolver.LookupIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
}

func (t *Tailscale) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	if err = t.ensureStarted(ctx); err != nil {
		t.recordFailure(err)
		return nil, err
	}
	server := t.currentServer()
	if server == nil {
		err = errors.New("tailscale server is nil")
		t.recordFailure(err)
		return nil, err
	}
	netStack, err := server.Netstack(ctx)
	if err != nil {
		t.recordFailure(err)
		return nil, err
	}
	v4, v6 := server.TailscaleIPs()
	options := t.DialOptions()
	options = append(options, dialer.WithResolver(t.dnsResolver))
	options = append(options, dialer.WithNetDialer(dialer.NetDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		dst, err := netip.ParseAddrPort(address) // the dialer will resolve the domain to ip
		if err != nil {
			return nil, err
		}
		src := v4
		if dst.Addr().Is6() {
			src = v6
		}
		tcpConn, err := netStack.DialContextTCPWithBind(ctx, src, dst)
		if err != nil {
			return nil, err
		}
		return tcpConn, nil
	})))
	var conn net.Conn
	conn, err = dialer.NewDialer(options...).DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		t.recordFailure(err)
		return nil, err
	}
	if conn == nil {
		err = errors.New("conn is nil")
		t.recordFailure(err)
		return nil, err
	}
	t.recordSuccess()
	return NewConn(conn, t), nil
}

func (t *Tailscale) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = t.ensureStarted(ctx); err != nil {
		t.recordFailure(err)
		return nil, err
	}
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		t.recordFailure(err)
		return nil, err
	}
	server := t.currentServer()
	if server == nil {
		err = errors.New("tailscale server is nil")
		t.recordFailure(err)
		return nil, err
	}
	v4, v6 := server.TailscaleIPs()
	src := v4
	if metadata.DstIP.Is6() {
		src = v6
	}
	pc, err := server.ListenPacket("udp", net.JoinHostPort(src.String(), "0"))
	if err != nil {
		t.recordFailure(err)
		return nil, err
	}
	if pc == nil {
		err = errors.New("packetConn is nil")
		t.recordFailure(err)
		return nil, err
	}
	t.recordSuccess()
	return newPacketConn(pc, t), nil
}

func (t *Tailscale) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if metadata.Host != "" {
		ip, err := resolveIPWithResolver(ctx, metadata.Host, t.prefer, t.dnsResolver)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

type tailscaleDNSTransport struct {
	tailscale *Tailscale
}

func (t tailscaleDNSTransport) Address() string {
	return "tailscale://" + t.tailscale.Name()
}

func (t tailscaleDNSTransport) ResetConnection() {}

func (t tailscaleDNSTransport) ExchangeContext(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	if len(msg.Question) == 0 {
		return nil, errors.New("should have one question at least")
	}
	if err := t.tailscale.ensureStarted(ctx); err != nil {
		t.tailscale.recordFailure(err)
		return nil, err
	}
	q := msg.Question[0]
	qtypeName, ok := D.TypeToString[q.Qtype]
	if !ok {
		return nil, fmt.Errorf("unsupported query type: %d", q.Qtype)
	}
	server := t.tailscale.currentServer()
	if server == nil {
		err := errors.New("tailscale server is nil")
		t.tailscale.recordFailure(err)
		return nil, err
	}
	lc, err := server.LocalClient()
	if err != nil {
		t.tailscale.recordFailure(err)
		return nil, err
	}
	response, _, err := lc.QueryDNS(ctx, q.Name, qtypeName)
	if err != nil {
		t.tailscale.recordFailure(err)
		return nil, err
	}
	var responseMsg D.Msg
	if err = responseMsg.Unpack(response); err != nil {
		return nil, err
	}
	responseMsg.Id = msg.Id
	t.tailscale.recordSuccess()
	return &responseMsg, nil
}

func (t *Tailscale) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

func (t *Tailscale) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

func (t *Tailscale) Close() error {
	t.cancel()
	if t.unregisterDNSResolver != nil {
		t.unregisterDNSResolver()
	}
	t.lifecycleMu.Lock()
	t.startErr = errors.New("tailscale outbound closed")
	init := t.backendInit
	server := t.server
	serverStarted := t.serverStarted
	t.serverStarted = false
	t.lifecycleMu.Unlock()
	setTailscaleBackendInitialized(init, t.startErr)
	if server != nil && serverStarted { // tsnet.Server.Close() must not be called before or concurrently with Start.
		return server.Close()
	}
	return nil
}

func (t *Tailscale) recordSuccess() {
	t.failureCount.Store(0)
}

func (t *Tailscale) recordFailure(err error) {
	if !isTailscaleRecoverableError(err) {
		return
	}
	if t.failureCount.Add(1) < tailscaleRecoverableFailureThreshold {
		return
	}
	t.scheduleRestart(err.Error())
}

func isTailscaleRecoverableError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "no derp connection") ||
		strings.Contains(msg, "use of closed network connection")
}

func (t *Tailscale) scheduleRestart(reason string) {
	if !t.restartInFlight.CompareAndSwap(false, true) {
		return
	}
	go t.restart(reason)
}

func (t *Tailscale) restart(reason string) {
	defer t.restartInFlight.Store(false)

	t.lifecycleMu.Lock()
	if t.ctx.Err() != nil {
		t.lifecycleMu.Unlock()
		return
	}
	if time.Since(t.lastRestart) < tailscaleRestartMinInterval {
		t.failureCount.Store(0)
		t.lifecycleMu.Unlock()
		return
	}
	log.Warnln("[Tailscale](%s) restarting after recoverable failures: %s", t.Name(), reason)
	oldServer := t.server
	oldServerStarted := t.serverStarted
	t.server = t.newServer()
	t.serverStarted = false
	t.startOnce = sync.Once{}
	t.startErr = nil
	t.backendInit = newTailscaleBackendInit()
	t.failureCount.Store(0)
	t.lastRestart = time.Now()
	t.lifecycleMu.Unlock()

	if oldServer != nil && oldServerStarted {
		if err := oldServer.Close(); err != nil {
			log.Warnln("[Tailscale](%s) close old server failed: %v", t.Name(), err)
		}
	}

	ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
	defer cancel()
	if err := t.ensureStarted(ctx); err != nil {
		log.Warnln("[Tailscale](%s) restart failed: %v", t.Name(), err)
	}
}

type tailscalePacketListener struct {
	dialer C.Dialer
}

func (l tailscalePacketListener) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return l.dialer.ListenPacket(ctx, network, address, netip.AddrPort{})
}
