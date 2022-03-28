package wireproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"

	"github.com/armon/go-socks5"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

type CredentialValidator struct {
	username string
	password string
}

type RoutineSpawner interface {
	SpawnRoutine(*netstack.Net)
}

type NetstackDNSResolver struct {
	tnet *netstack.Net
}

func (d NetstackDNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addrs, err := d.tnet.LookupContextHost(ctx, name)
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

func (config *Socks5Config) SpawnRoutine(tnet *netstack.Net) {
	conf := &socks5.Config{Dial: tnet.DialContext, Resolver: NetstackDNSResolver{tnet: tnet}}
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

func connForward(bufSize int, from, to net.Conn) {
	buf := make([]byte, bufSize)
	_, err := io.CopyBuffer(to, from, buf)
	if err != nil {
		to.Close()
		return
	}
}

func tcpClientForward(tnet *netstack.Net, target string, conn net.Conn) {
	sconn, err := tnet.Dial("tcp", target)
	if err != nil {
		fmt.Printf("[ERROR] TCP Client Tunnel to %s: %s\n", target, err.Error())
		return
	}

	go connForward(1024, sconn, conn)
	go connForward(1024, conn, sconn)
}

func (conf *TCPClientTunnelConfig) SpawnRoutine(tnet *netstack.Net) {
	server, err := net.ListenTCP("tcp", conf.BindAddress)
	if err != nil {
		log.Panic(err)
	}

	for {
		conn, err := server.Accept()
		if err != nil {
			log.Panic(err)
		}
		go tcpClientForward(tnet, conf.Target, conn)
	}
}

func tcpServerForward(target string, conn net.Conn) {
	sconn, err := net.Dial("tcp", target)
	if err != nil {
		fmt.Printf("[ERROR] TCP Server Tunnel to %s: %s\n", target, err.Error())
		return
	}

	go connForward(1024, sconn, conn)
	go connForward(1024, conn, sconn)
}

func (conf *TCPServerTunnelConfig) SpawnRoutine(tnet *netstack.Net) {
	addr := &net.TCPAddr{Port: conf.ListenPort}
	server, err := tnet.ListenTCP(addr)
	if err != nil {
		log.Panic(err)
	}

	for {
		conn, err := server.Accept()
		if err != nil {
			log.Panic(err)
		}
		go tcpServerForward(conf.Target, conn)
	}
}
