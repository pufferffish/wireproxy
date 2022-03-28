package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"

	"github.com/armon/go-socks5"
	"github.com/octeep/wireproxy"

	"golang.zx2c4.com/go118/netip"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type DeviceSetting struct {
	ipcRequest string
	dns        []netip.Addr
	deviceAddr *netip.Addr
	mtu        int
}

type NetstackDNSResolver struct {
	tnet *netstack.Net
}

type CredentialValidator struct {
	username string
	password string
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

func createIPCRequest(conf *wireproxy.DeviceConfig) (*DeviceSetting, error) {
	request := fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
persistent_keepalive_interval=%d
preshared_key=%s
allowed_ip=0.0.0.0/0`, conf.SelfSecretKey, conf.PeerPublicKey, conf.PeerEndpoint, conf.KeepAlive, conf.PreSharedKey)

	setting := &DeviceSetting{ipcRequest: request, dns: conf.DNS, deviceAddr: conf.SelfEndpoint, mtu: conf.MTU}
	return setting, nil
}

func socks5Routine(config *wireproxy.Socks5Config) (func(*netstack.Net), error) {
	routine := func(tnet *netstack.Net) {
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

	return routine, nil
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

func tcpClientRoutine(conf *wireproxy.TCPClientTunnelConfig) (func(*netstack.Net), error) {
	routine := func(tnet *netstack.Net) {
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

	return routine, nil
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

func tcpServerRoutine(conf *wireproxy.TCPServerTunnelConfig) (func(*netstack.Net), error) {
	routine := func(tnet *netstack.Net) {
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

	return routine, nil
}

func startWireguard(setting *DeviceSetting) (*netstack.Net, error) {
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{*(setting.deviceAddr)}, setting.dns, setting.mtu)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	dev.IpcSet(setting.ipcRequest)
	err = dev.Up()
	if err != nil {
		return nil, err
	}

	return tnet, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: wireproxy [config file path]")
		return
	}

	conf, err := wireproxy.ParseConfig(os.Args[1])
	if err != nil {
		log.Panic(err)
	}

	setting, err := createIPCRequest(conf.Device)
	if err != nil {
		log.Panic(err)
	}

	routines := [](func(*netstack.Net)){}
	var routine func(*netstack.Net)

	for _, config := range conf.TCPClientTunnels {
		routine, err = tcpClientRoutine(&config)
		if err != nil {
			log.Panic(err)
		}

		routines = append(routines, routine)
	}

	for _, config := range conf.TCPServerTunnels {
		routine, err = tcpServerRoutine(&config)
		if err != nil {
			log.Panic(err)
		}

		routines = append(routines, routine)
	}

	for _, config := range conf.Socks5Proxies {
		routine, err = socks5Routine(&config)
		if err != nil {
			log.Panic(err)
		}

		routines = append(routines, routine)
	}

	tnet, err := startWireguard(setting)
	if err != nil {
		log.Panic(err)
	}

	for _, netRoutine := range routines {
		go netRoutine(tnet)
	}

	select {} // sleep eternally
}
