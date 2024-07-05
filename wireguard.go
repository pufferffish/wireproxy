package wireproxy

import (
	"bytes"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/MakeNowJust/heredoc/v2"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// DeviceSetting contains the parameters for setting up a tun interface
type DeviceSetting struct {
	ipcRequest string
	dns        []netip.Addr
	deviceAddr []netip.Addr
	mtu        int
}

// serialize the config into an IPC request and DeviceSetting
func createIPCRequest(conf *DeviceConfig) (*DeviceSetting, error) {
	var request bytes.Buffer

	request.WriteString(fmt.Sprintf("private_key=%s\n", conf.SecretKey))

	if conf.ListenPort != nil {
		request.WriteString(fmt.Sprintf("listen_port=%d\n", *conf.ListenPort))
	}

	for _, peer := range conf.Peers {
		request.WriteString(fmt.Sprintf(heredoc.Doc(`
				public_key=%s
				persistent_keepalive_interval=%d
				preshared_key=%s
			`),
			peer.PublicKey, peer.KeepAlive, peer.PreSharedKey,
		))
		if peer.Endpoint != nil {
			request.WriteString(fmt.Sprintf("endpoint=%s\n", *peer.Endpoint))
		}

		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				request.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip.String()))
			}
		} else {
			request.WriteString(heredoc.Doc(`
				allowed_ip=0.0.0.0/0
				allowed_ip=::0/0
			`))
		}
	}

	setting := &DeviceSetting{ipcRequest: request.String(), dns: conf.DNS, deviceAddr: conf.Endpoint, mtu: conf.MTU}
	return setting, nil
}

// StartWireguard creates a tun interface on netstack given a configuration
func StartWireguard(conf *DeviceConfig, logLevel int, configName string) (*VirtualTun, error) {
	setting, err := createIPCRequest(conf)
	if err != nil {
		return nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN(setting.deviceAddr, setting.dns, setting.mtu)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logLevel, ""))
	err = dev.IpcSet(setting.ipcRequest)
	if err != nil {
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		return nil, err
	}

	// Ensure handshake is established
	for _, peer := range conf.Peers {
		if peer.Endpoint != nil {
			// Check handshake status
			handshakeEstablished := false
			for i := 0; i < 3; i++ { // Retry for a few seconds
				peerStatus, err := dev.IpcGet()
				if err != nil {
					return nil, fmt.Errorf("failed to get device status: %w", err)
				}
				if strings.Contains(peerStatus, *peer.Endpoint) {
					handshakeEstablished = true
					break
				}
				time.Sleep(1 * time.Second)
			}
			if !handshakeEstablished {
				log.Printf("All retries are completed, VPN is not working. Config name: %s", configName)
				os.Exit(1)
			}
		}
	}

	// Perform Google connectivity check only if the handshake is successful
	err = CheckGoogleConnectivity(tnet, configName)
	if err != nil {
		return nil, err
	}

	return &VirtualTun{
		Tnet:       tnet,
		Dev:        dev,
		Conf:       conf,
		SystemDNS:  len(setting.dns) == 0,
		PingRecord: make(map[string]uint64),
	}, nil
}