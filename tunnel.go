package wireproxy

import (
	"fmt"
	"github.com/patrickmn/go-cache"
	"github.com/txthinking/socks5"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"io"
	"log"
	"net"
	"time"
)

// VirtualTun stores a reference to netstack network and DNS configuration
type VirtualTun struct {
	tnet                 *netstack.Net
	systemDNS            bool
	mappedPortToNatEntry map[uint16]string
	natEntryToMappedPort *cache.Cache
}

type NatEntry struct {
	key        string
	srcAddr    net.Addr
	mappedPort uint16
	conn       *gonet.UDPConn
}

var unspecifiedIP = make([]byte, 16)

func (d *VirtualTun) connect(w io.Writer, r *socks5.Request) (net.Conn, error) {
	if socks5.Debug {
		log.Println("Call:", r.Address())
	}
	tmp, err := d.tnet.Dial("tcp", r.Address())
	if err != nil {
		var p *socks5.Reply
		if r.Atyp == socks5.ATYPIPv4 || r.Atyp == socks5.ATYPDomain {
			p = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(w); err != nil {
			return nil, err
		}
		return nil, err
	}

	a, addr, port, err := socks5.ParseAddress(tmp.LocalAddr().String())
	if err != nil {
		var p *socks5.Reply
		if r.Atyp == socks5.ATYPIPv4 || r.Atyp == socks5.ATYPDomain {
			p = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(w); err != nil {
			return nil, err
		}
		return nil, err
	}
	p := socks5.NewReply(socks5.RepSuccess, a, addr, port)
	if _, err := p.WriteTo(w); err != nil {
		return nil, err
	}

	return tmp, nil
}

func (d *VirtualTun) TCPHandle(s *socks5.Server, c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdConnect {
		rc, err := d.connect(c, r)
		if err != nil {
			return err
		}
		defer rc.Close()
		go func() {
			var bf [1024 * 2]byte
			for {
				if s.TCPTimeout != 0 {
					if err := rc.SetDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second)); err != nil {
						return
					}
				}
				i, err := rc.Read(bf[:])
				if err != nil {
					return
				}
				if _, err := c.Write(bf[0:i]); err != nil {
					return
				}
			}
		}()
		var bf [1024 * 2]byte
		for {
			if s.TCPTimeout != 0 {
				if err := c.SetDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second)); err != nil {
					return nil
				}
			}
			i, err := c.Read(bf[:])
			if err != nil {
				return nil
			}
			if _, err := rc.Write(bf[0:i]); err != nil {
				return nil
			}
		}
	}
	if r.Cmd == socks5.CmdUDP {
		caddr, err := r.UDP(c, s.ServerAddr)
		if err != nil {
			return err
		}
		srcAddr := caddr.String()
		mappedPort := uint16(caddr.Port)
		tries := 0
		for _, occupied := d.mappedPortToNatEntry[mappedPort]; occupied; mappedPort++ {
			tries++
			if tries > 65535 {
				return fmt.Errorf("nat table is full")
			}
		}
		laddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", mappedPort))
		if err != nil {
			return err
		}
		conn, err := d.tnet.ListenUDP(laddr)
		if err != nil {
			fmt.Println("fic")
			return err
		}
		entry := &NatEntry{
			key:        srcAddr,
			srcAddr:    caddr,
			conn:       conn,
			mappedPort: mappedPort,
		}
		d.mappedPortToNatEntry[mappedPort] = srcAddr
		d.natEntryToMappedPort.Set(srcAddr, entry, 0)
		go func() {
			buf := make([]byte, 65536)
			var b [65507]byte
			for n, from, err := conn.ReadFrom(buf); err == nil; {
				a, addr, port, err := socks5.ParseAddress(from.String())
				if err != nil {
					log.Println(err)
					break
				}
				d1 := socks5.NewDatagram(a, addr, port, b[0:n])
				if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), caddr); err != nil {
					break
				}
			}
			_ = conn.Close()
			d.natEntryToMappedPort.Delete(srcAddr)
		}()
		fmt.Printf("%s udp mapped to port %d", srcAddr, mappedPort)
		return nil
	}
	return socks5.ErrUnsupportCmd
}

func (d *VirtualTun) UDPHandle(server *socks5.Server, addr *net.UDPAddr, datagram *socks5.Datagram) error {
	srcAddr := addr.String()
	entry, ok := d.natEntryToMappedPort.Get(srcAddr)
	if !ok {
		return fmt.Errorf("this udp address %s is not associated", srcAddr)
	}
	natEntry := entry.(*NatEntry)
	raddr, err := net.ResolveUDPAddr("udp", datagram.Address())
	if err != nil {
		return err
	}
	_, err = natEntry.conn.WriteTo(datagram.Data, raddr)
	return err
}
