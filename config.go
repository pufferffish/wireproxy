package wireproxy

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"strings"

	"github.com/go-ini/ini"

	"golang.zx2c4.com/go118/netip"
)

type DeviceConfig struct {
	SelfSecretKey string
	SelfEndpoint  []netip.Addr
	PeerPublicKey string
	PeerEndpoint  string
	DNS           []netip.Addr
	KeepAlive     int
	PreSharedKey  string
	MTU           int
}

type TCPClientTunnelConfig struct {
	BindAddress *net.TCPAddr
	Target      string
}

type TCPServerTunnelConfig struct {
	ListenPort int
	Target     string
}

type Socks5Config struct {
	BindAddress string
	Username    string
	Password    string
}

type Configuration struct {
	Device   *DeviceConfig
	Routines []RoutineSpawner
}

func parseString(section *ini.Section, keyName string) (string, error) {
	key := section.Key(strings.ToLower(keyName))
	if key == nil {
		return "", errors.New(keyName + " should not be empty")
	}
	return key.String(), nil
}

func parsePort(section *ini.Section, keyName string) (int, error) {
	key := section.Key(keyName)
	if key == nil {
		return 0, errors.New(keyName + " should not be empty")
	}

	port, err := key.Int()
	if err != nil {
		return 0, err
	}

	if !(port >= 0 && port < 65536) {
		return 0, errors.New("port should be >= 0 and < 65536")
	}

	return port, nil
}

func parseTCPAddr(section *ini.Section, keyName string) (*net.TCPAddr, error) {
	addrStr, err := parseString(section, keyName)
	if err != nil {
		return nil, err
	}
	return net.ResolveTCPAddr("tcp", addrStr)
}

func parseBase64KeyToHex(section *ini.Section, keyName string) (string, error) {
	key, err := parseString(section, keyName)
	if err != nil {
		return "", err
	}
	result, err := encodeBase64ToHex(key)
	if err != nil {
		return result, err
	}

	return result, nil
}

func encodeBase64ToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", errors.New("invalid base64 string: " + key)
	}
	if len(decoded) != 32 {
		return "", errors.New("key should be 32 bytes: " + key)
	}
	return hex.EncodeToString(decoded), nil
}

func parseNetIP(section *ini.Section, keyName string) ([]netip.Addr, error) {
	key := section.Key(keyName)
	if key == nil {
		return []netip.Addr{}, nil
	}

	ips := []netip.Addr{}
	for _, str := range key.StringsWithShadows(",") {
		str = strings.TrimSpace(str)
		ip, err := netip.ParseAddr(str)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func parseCIDRNetIP(section *ini.Section, keyName string) ([]netip.Addr, error) {
	key := section.Key(keyName)
	if key == nil {
		return []netip.Addr{}, nil
	}

	ips := []netip.Addr{}
	for _, str := range key.StringsWithShadows(",") {
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			return nil, err
		}

		addr := prefix.Addr()
		if prefix.Bits() != addr.BitLen() {
			return nil, errors.New("interface address subnet should be /32 for IPv4 and /128 for IPv6")
		}

		ips = append(ips, addr)
	}
	return ips, nil
}

func resolveIP(ip string) (*net.IPAddr, error) {
	return net.ResolveIPAddr("ip", ip)
}

func resolveIPPAndPort(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}

	ip, err := resolveIP(host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), port), nil
}

func ParseInterface(cfg *ini.File, device *DeviceConfig) error {
	sections, err := cfg.SectionsByName("Interface")
	if len(sections) != 1 || err != nil {
		return errors.New("one and only one [Interface] is expected")
	}
	section := sections[0]

	address, err := parseCIDRNetIP(section, "Address")
	if err != nil {
		return err
	}

	device.SelfEndpoint = address

	privKey, err := parseBase64KeyToHex(section, "PrivateKey")
	if err != nil {
		return err
	}
	device.SelfSecretKey = privKey

	dns, err := parseNetIP(section, "DNS")
	if err != nil {
		return err
	}
	device.DNS = dns

	if sectionKey, err := section.GetKey("MTU"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		device.MTU = value
	}

	return nil
}

func ParsePeer(cfg *ini.File, device *DeviceConfig) error {
	sections, err := cfg.SectionsByName("Peer")
	if len(sections) != 1 || err != nil {
		return errors.New("one and only one [Peer] is expected")
	}
	section := sections[0]

	decoded, err := parseBase64KeyToHex(section, "PublicKey")
	if err != nil {
		return err
	}
	device.PeerPublicKey = decoded

	if sectionKey, err := section.GetKey("PreSharedKey"); err == nil {
		value, err := encodeBase64ToHex(sectionKey.String())
		if err != nil {
			return err
		}
		device.PreSharedKey = value
	}

	decoded, err = parseString(section, "Endpoint")
	if err != nil {
		return err
	}
	decoded, err = resolveIPPAndPort(decoded)
	if err != nil {
		return err
	}
	device.PeerEndpoint = decoded

	if sectionKey, err := section.GetKey("PersistentKeepalive"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		device.KeepAlive = value
	}

	return nil
}

func parseTCPClientTunnelConfig(section *ini.Section) (*TCPClientTunnelConfig, error) {
	config := &TCPClientTunnelConfig{}
	tcpAddr, err := parseTCPAddr(section, "BindAddress")
	if err != nil {
		return nil, err
	}
	config.BindAddress = tcpAddr

	targetSection, err := parseString(section, "Target")
	if err != nil {
		return nil, err
	}
	config.Target = targetSection

	return config, nil
}

func ParseTCPClientTunnelConfig(cfg *ini.File) ([]TCPClientTunnelConfig, error) {
	sections, err := cfg.SectionsByName("TCPClientTunnel")
	if err != nil {
		return []TCPClientTunnelConfig{}, nil
	}

	configs := make([]TCPClientTunnelConfig, len(sections))
	for i, section := range sections {
		config, err := parseTCPClientTunnelConfig(section)
		if err != nil {
			return nil, err
		}
		configs[i] = *config
	}

	return configs, nil
}

func parseTCPServerTunnelConfig(section *ini.Section) (*TCPServerTunnelConfig, error) {
	config := &TCPServerTunnelConfig{}

	listenPort, err := parsePort(section, "ListenPort")
	if err != nil {
		return nil, err
	}
	config.ListenPort = listenPort

	target, err := parseString(section, "Target")
	if err != nil {
		return nil, err
	}
	config.Target = target

	return config, nil
}

func ParseTCPServerTunnelConfig(cfg *ini.File) ([]TCPServerTunnelConfig, error) {
	sections, err := cfg.SectionsByName("TCPServerTunnel")
	if err != nil {
		return []TCPServerTunnelConfig{}, nil
	}

	configs := make([]TCPServerTunnelConfig, len(sections))
	for i, section := range sections {
		config, err := parseTCPServerTunnelConfig(section)
		if err != nil {
			return nil, err
		}
		configs[i] = *config
	}

	return configs, nil
}

func parseSocks5Config(section *ini.Section) (*Socks5Config, error) {
	config := &Socks5Config{}

	bindAddress, err := parseString(section, "BindAddress")
	if err != nil {
		return nil, err
	}
	config.BindAddress = bindAddress

	username, _ := parseString(section, "Username")
	config.Username = username

	password, _ := parseString(section, "Password")
	config.Password = password

	return config, nil
}

func ParseSocks5Config(cfg *ini.File) ([]Socks5Config, error) {
	sections, err := cfg.SectionsByName("Socks5")
	if err != nil {
		return []Socks5Config{}, nil
	}

	configs := make([]Socks5Config, len(sections))
	for i, section := range sections {
		config, err := parseSocks5Config(section)
		if err != nil {
			return nil, err
		}
		configs[i] = *config
	}

	return configs, nil
}

func ParseConfig(path string) (*Configuration, error) {
	cfg, err := ini.LoadSources(ini.LoadOptions{
		Insensitive:  true,
		AllowShadows: true,
	}, path)
	if err != nil {
		return nil, err
	}

	device := &DeviceConfig{
		PreSharedKey: "0000000000000000000000000000000000000000000000000000000000000000",
		KeepAlive:    0,
		MTU:          1420,
	}

	err = ParseInterface(cfg, device)
	if err != nil {
		return nil, err
	}

	err = ParsePeer(cfg, device)
	if err != nil {
		return nil, err
	}

	routinesSpawners := []RoutineSpawner{}

	tcpClientTunnels, err := ParseTCPClientTunnelConfig(cfg)
	if err != nil {
		return nil, err
	}
	for _, i := range tcpClientTunnels {
		routinesSpawners = append(routinesSpawners, &i)
	}

	tcpServerTunnels, err := ParseTCPServerTunnelConfig(cfg)
	if err != nil {
		return nil, err
	}
	for _, i := range tcpServerTunnels {
		routinesSpawners = append(routinesSpawners, &i)
	}

	socks5Proxies, err := ParseSocks5Config(cfg)
	if err != nil {
		return nil, err
	}
	for _, i := range socks5Proxies {
		routinesSpawners = append(routinesSpawners, &i)
	}

	return &Configuration{
		Device:   device,
		Routines: routinesSpawners,
	}, nil
}
