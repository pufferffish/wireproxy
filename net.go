// will delete when upgrading to go 1.18

package wireproxy

import (
	"golang.zx2c4.com/go118/netip"
	"net"
)

func TCPAddrFromAddrPort(addr netip.AddrPort) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   addr.Addr().AsSlice(),
		Zone: addr.Addr().Zone(),
		Port: int(addr.Port()),
	}
}

func UDPAddrFromAddrPort(addr netip.AddrPort) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   addr.Addr().AsSlice(),
		Zone: addr.Addr().Zone(),
		Port: int(addr.Port()),
	}
}
