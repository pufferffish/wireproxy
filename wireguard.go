package wireproxy

import (
	"fmt"

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

func createIPCRequest(conf *DeviceConfig) (*DeviceSetting, error) {
	request := fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
persistent_keepalive_interval=%d
preshared_key=%s
allowed_ip=0.0.0.0/0`, conf.SelfSecretKey, conf.PeerPublicKey, conf.PeerEndpoint, conf.KeepAlive, conf.PreSharedKey)

	setting := &DeviceSetting{ipcRequest: request, dns: conf.DNS, deviceAddr: conf.SelfEndpoint, mtu: conf.MTU}
	return setting, nil
}

func StartWireguard(conf *DeviceConfig) (*netstack.Net, error) {
	setting, err := createIPCRequest(conf)
	if err != nil {
		return nil, err
	}

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
