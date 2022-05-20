// will delete when upgrading to go 1.18

package wireproxy

import (
	"net"
	"net/netip"
)

func TCPAddrFromAddrPort(addr netip.AddrPort) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   addr.Addr().AsSlice(),
		Zone: addr.Addr().Zone(),
		Port: int(addr.Port()),
	}
}
