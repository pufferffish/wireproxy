package wireproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"

	"github.com/armon/go-socks5"

	"golang.zx2c4.com/go118/netip"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type CredentialValidator struct {
	username string
	password string
}

type VirtualTun struct {
	tnet      *netstack.Net
	systemDNS bool
}

type RoutineSpawner interface {
	SpawnRoutine(vt *VirtualTun)
}

func (d VirtualTun) LookupAddr(ctx context.Context, name string) ([]string, error) {
	if d.systemDNS {
		return net.DefaultResolver.LookupHost(ctx, name)
	} else {
		return d.tnet.LookupContextHost(ctx, name)
	}
}

func (d VirtualTun) ResolveAddrPort(saddr string) (*netip.AddrPort, error) {
	name, sport, err := net.SplitHostPort(saddr)
	if err != nil {
		return nil, err
	}

	addrs, err := d.LookupAddr(context.Background(), name)
	if err != nil {
		return nil, err
	}

	size := len(addrs)
	if size == 0 {
		return nil, errors.New("no address found for: " + name)
	}

	addr, err := netip.ParseAddr(addrs[rand.Intn(size)])
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(sport)
	if err != nil || port < 0 || port > 65535 {
		return nil, &net.OpError{Op: "dial", Err: errors.New("port must be numeric")}
	}

	addrPort := netip.AddrPortFrom(addr, uint16(port))
	return &addrPort, nil
}

func (d VirtualTun) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	var addrs []string
	var err error

	addrs, err = d.LookupAddr(ctx, name)

	if err != nil {
		return ctx, nil, err
	}

	size := len(addrs)
	if size == 0 {
		return ctx, nil, errors.New("no address found for: " + name)
	}

	addr := addrs[rand.Intn(size)]
	ip := net.ParseIP(addr)
	if ip == nil {
		return ctx, nil, errors.New("invalid address: " + addr)
	}

	return ctx, ip, err
}

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

func (c CredentialValidator) Valid(username, password string) bool {
	return c.username == username && c.password == password
}

func connForward(bufSize int, from io.ReadWriteCloser, to io.ReadWriteCloser) {
	buf := make([]byte, bufSize)
	_, err := io.CopyBuffer(to, from, buf)
	if err != nil {
		to.Close()
		return
	}
}

func tcpClientForward(tnet *netstack.Net, target *net.TCPAddr, conn net.Conn) {
	sconn, err := tnet.DialTCP(target)
	if err != nil {
		fmt.Printf("[ERROR] TCP Client Tunnel to %s: %s\n", target, err.Error())
		return
	}

	go connForward(1024, sconn, conn)
	go connForward(1024, conn, sconn)
}

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

func tcpServerForward(target *net.TCPAddr, conn net.Conn) {
	sconn, err := net.DialTCP("tcp", nil, target)
	if err != nil {
		fmt.Printf("[ERROR] TCP Server Tunnel to %s: %s\n", target, err.Error())
		return
	}

	go connForward(1024, sconn, conn)
	go connForward(1024, conn, sconn)
}

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
