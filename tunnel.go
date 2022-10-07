package wireproxy

import (
	"fmt"
	"github.com/txthinking/socks5"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"
)

// VirtualTun stores a reference to netstack network and DNS configuration
type VirtualTun struct {
	tnet      *netstack.Net
	systemDNS bool
}

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
		ch := make(chan byte)
		defer close(ch)
		s.AssociatedUDP.Set(caddr.String(), ch, -1)
		defer s.AssociatedUDP.Delete(caddr.String())
		io.Copy(ioutil.Discard, c)
		if socks5.Debug {
			log.Printf("A tcp connection that udp %#v associated closed\n", caddr.String())
		}
		return nil
	}
	return socks5.ErrUnsupportCmd
}

func (d *VirtualTun) UDPHandle(server *socks5.Server, addr *net.UDPAddr, datagram *socks5.Datagram) error {
	_, err := fmt.Fprint(os.Stderr, "implement me")
	return err
}
