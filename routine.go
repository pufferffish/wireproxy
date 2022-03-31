package wireproxy

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"

	"github.com/armon/go-socks5"

	"golang.zx2c4.com/go118/netip"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// errorLogger is the logger to print error message
var errorLogger = log.New(os.Stderr, "ERROR: ", log.LstdFlags)

// CredentialValidator stores the authentication data of a socks5 proxy
type CredentialValidator struct {
	username string
	password string
}

// VirtualTun stores a reference to netstack network and DNS configuration
type VirtualTun struct {
	tnet      *netstack.Net
	systemDNS bool
}

// RoutineSpawner spawns a routine (e.g. socks5, tcp static routes) after the configuration is parsed
type RoutineSpawner interface {
	SpawnRoutine(vt *VirtualTun)
}

// LookupAddr lookups a hostname.
// DNS traffic may or may not be routed depending on VirtualTun's setting
func (d VirtualTun) LookupAddr(ctx context.Context, name string) ([]string, error) {
	if d.systemDNS {
		return net.DefaultResolver.LookupHost(ctx, name)
	} else {
		return d.tnet.LookupContextHost(ctx, name)
	}
}

// ResolveAddrPort resolves a hostname and returns an AddrPort.
// DNS traffic may or may not be routed depending on VirtualTun's setting
func (d VirtualTun) ResolveAddrPort(saddr string) (*netip.AddrPort, error) {
	name, sport, err := net.SplitHostPort(saddr)
	if err != nil {
		return nil, err
	}

	addr, err := d.ResolveAddrWithContext(context.Background(), name)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &net.OpError{Op: "dial", Err: errors.New("port must be numeric")}
	}

	addrPort := netip.AddrPortFrom(*addr, uint16(port))
	return &addrPort, nil
}

// ResolveAddrPort resolves a hostname and returns an AddrPort.
// DNS traffic may or may not be routed depending on VirtualTun's setting
func (d VirtualTun) ResolveAddrWithContext(ctx context.Context, name string) (*netip.Addr, error) {
	addrs, err := d.LookupAddr(ctx, name)
	if err != nil {
		return nil, err
	}

	size := len(addrs)
	if size == 0 {
		return nil, errors.New("no address found for: " + name)
	}

	rand.Shuffle(size, func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})

	var addr netip.Addr
	for _, saddr := range addrs {
		addr, err = netip.ParseAddr(saddr)
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, err
	}

	return &addr, nil
}

// ResolveAddrPort resolves a hostname and returns an IP.
// DNS traffic may or may not be routed depending on VirtualTun's setting
func (d VirtualTun) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addr, err := d.ResolveAddrWithContext(ctx, name)
	if err != nil {
		return nil, nil, err
	}

	return ctx, addr.AsSlice(), nil
}

// Spawns a socks5 server.
func (config *Socks5Config) SpawnRoutine(vt *VirtualTun) {
	conf := &socks5.Config{Dial: vt.tnet.DialContext, Resolver: vt}
	if username := config.Username; username != "" {
		validator := CredentialValidator{username: username}
		validator.password = config.Password
		conf.Credentials = validator
	}
	server, err := socks5.New(conf)
	if err != nil {
		log.Panic(err)
	}

	if err := server.ListenAndServe("tcp", config.BindAddress); err != nil {
		log.Panic(err)
	}
}

// Valid checks the authentication data in CredentialValidator and compare them
// to username and password in constant time.
func (c CredentialValidator) Valid(username, password string) bool {
	u := subtle.ConstantTimeCompare([]byte(c.username), []byte(username))
	p := subtle.ConstantTimeCompare([]byte(c.password), []byte(password))
	return u&p == 1
}

// connForward copy data from `from` to `to`, then close both stream.
func connForward(bufSize int, from io.ReadWriteCloser, to io.ReadWriteCloser) {
	buf := make([]byte, bufSize)
	_, err := io.CopyBuffer(to, from, buf)
	if err != nil {
		errorLogger.Printf("Cannot forward traffic: %s\n", err.Error())
	}
	_ = from.Close()
	_ = to.Close()
}

// tcpClientForward starts a new connection via wireguard and forward traffic from `conn`
func tcpClientForward(tnet *netstack.Net, target *net.TCPAddr, conn net.Conn) {
	sconn, err := tnet.DialTCP(target)
	if err != nil {
		errorLogger.Printf("TCP Client Tunnel to %s: %s\n", target, err.Error())
		return
	}

	go connForward(1024, sconn, conn)
	go connForward(1024, conn, sconn)
}

// Spawns a local TCP server which acts as a proxy to the specified target
func (conf *TCPClientTunnelConfig) SpawnRoutine(vt *VirtualTun) {
	raddr, err := vt.ResolveAddrPort(conf.Target)
	if err != nil {
		log.Panic(err)
	}
	tcpAddr := TCPAddrFromAddrPort(*raddr)

	server, err := net.ListenTCP("tcp", conf.BindAddress)
	if err != nil {
		log.Panic(err)
	}

	for {
		conn, err := server.Accept()
		if err != nil {
			log.Panic(err)
		}
		go tcpClientForward(vt.tnet, tcpAddr, conn)
	}
}

// tcpServerForward starts a new connection locally and forward traffic from `conn`
func tcpServerForward(target *net.TCPAddr, conn net.Conn) {
	sconn, err := net.DialTCP("tcp", nil, target)
	if err != nil {
		errorLogger.Printf("TCP Server Tunnel to %s: %s\n", target, err.Error())
		return
	}

	go connForward(1024, sconn, conn)
	go connForward(1024, conn, sconn)
}

// Spawns a TCP server on wireguard which acts as a proxy to the specified target
func (conf *TCPServerTunnelConfig) SpawnRoutine(vt *VirtualTun) {
	raddr, err := vt.ResolveAddrPort(conf.Target)
	if err != nil {
		log.Panic(err)
	}
	tcpAddr := TCPAddrFromAddrPort(*raddr)

	addr := &net.TCPAddr{Port: conf.ListenPort}
	server, err := vt.tnet.ListenTCP(addr)
	if err != nil {
		log.Panic(err)
	}

	for {
		conn, err := server.Accept()
		if err != nil {
			log.Panic(err)
		}
		go tcpServerForward(tcpAddr, conn)
	}
}
