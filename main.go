package main

import (
    "bufio"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "fmt"
    "log"
    "net"
    "os"
    "strings"
    "strconv"

    "github.com/armon/go-socks5"

    "golang.zx2c4.com/go118/netip"
    "golang.zx2c4.com/wireguard/conn"
    "golang.zx2c4.com/wireguard/device"
    "golang.zx2c4.com/wireguard/tun/netstack"
)

type ConfigSection struct {
    name    string
    entries map[string]string
}

type Configuration []ConfigSection

func configRoot(config Configuration) map[string]string {
    for _, section := range config {
        if section.name == "ROOT" {
            return section.entries
        }
    }
    return nil
}

func readConfig(path string) (Configuration, error) {
    file, err := os.Open(path)
    if err != nil {
        return nil, err
    }

    defer file.Close()
    scanner := bufio.NewScanner(file)

    section := ConfigSection{name: "ROOT", entries: map[string]string{}}
    sections := []ConfigSection{}

    lineNo := 0

    for scanner.Scan() {
        line := scanner.Text()
        lineNo += 1

        if hashIndex := strings.Index(line, "#"); hashIndex >= 0 {
            line = line[:hashIndex]
        }

        line = strings.TrimSpace(line)

        if line == "" {
            continue
        }

        if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
            sections = append(sections, section)
            section = ConfigSection{name: strings.ToLower(line), entries: map[string]string{}}
            continue
        }

        entry := strings.SplitN(line, "=", 2)
        if len(entry) != 2 {
            return nil, errors.New(fmt.Sprintf("invalid syntax at line %d: %s", lineNo, line))
        }

        key := strings.TrimSpace(entry[0])
        key = strings.ToLower(key)
        value := strings.TrimSpace(entry[1])

        if _, dup := section.entries[key]; dup {
            return nil, errors.New(fmt.Sprintf("duplicate key line %d: %s", lineNo, line))
        }

        section.entries[key] = value
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    sections = append(sections, section)
    return sections, nil
}

func parseBase64Key(key string) (string, error) {
    decoded, err := base64.StdEncoding.DecodeString(key)
    if err != nil {
        return "", errors.New("invalid base64 string")
    }
    if len(decoded) != 32 {
        return "", errors.New("key should be 32 bytes")
    }
    return hex.EncodeToString(decoded), nil
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

func parseIPs(s string) ([]netip.Addr, error) {
    ips := []netip.Addr{}
    for _, str := range strings.Split(s, ",") {
        str = strings.TrimSpace(str)
        ip, err := netip.ParseAddr(str)
        if err != nil {
            return nil, err
        }
        ips = append(ips, ip)
    }
    return ips, nil
}

func createIPCRequest(conf Configuration) (string, []netip.Addr, error) {
    root := configRoot(conf)

    peerPK, err := parseBase64Key(root["peerpublickey"])
    if err != nil {
        return "", nil, err
    }

    selfSK, err := parseBase64Key(root["selfsecretkey"])
    if err != nil {
        return "", nil, err
    }

    endpoint, err := resolveIPPAndPort(root["peerendpoint"])
    if err != nil {
        return "", nil, err
    }

    dns, err := parseIPs(root["dns"])
    if err != nil {
        return "", nil, err
    }

    keepAlive := int64(0)
    if keepAliveOpt, ok := root["keepalive"]; ok {
        keepAlive, err = strconv.ParseInt(keepAliveOpt, 10, 0)
        if err != nil {
            return "", nil, err
        }
        if keepAlive < 0 {
            keepAlive = 0
        }
    }

    preSharedKey := "0000000000000000000000000000000000000000000000000000000000000000"
    if pskOpt, ok := root["presharedkey"]; ok {
        preSharedKey, err = parseBase64Key(pskOpt)
        if err != nil {
            return "", nil, err
        }
    }

    request := fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
persistent_keepalive_interval=%d
preshared_key=%s
allowed_ip=0.0.0.0/0`, selfSK, peerPK, endpoint, keepAlive, preSharedKey)
    return request, dns, nil
}

func socks5Routine(config map[string]string) (*netip.Addr, func(*netstack.Net), error) {
    vpnAddr, err := netip.ParseAddr(config["vpnaddress"])
    if err != nil {
        return nil, nil, err
    }

    bindAddr, ok := config["bindaddress"]
    if !ok {
        return nil, nil, errors.New("missing bind address")
    }

    routine := func(tnet *netstack.Net) {
        conf := &socks5.Config{ Dial: tnet.DialContext }
        server, err := socks5.New(conf)
        if err != nil {
          log.Panic(err)
        }

        if err := server.ListenAndServe("tcp", bindAddr); err != nil {
          log.Panic(err)
        }
    }

    return &vpnAddr, routine, nil
}

func startWireguard(request string, boundAddrs, dns []netip.Addr) (*netstack.Net, error) {
    tun, tnet, err := netstack.CreateNetTUN(boundAddrs, dns, 1420)
    if err != nil {
        return nil, err
    }
    dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
    dev.IpcSet(request)
    err = dev.Up()
    if err != nil {
        return nil, err
    }

    return tnet, nil
}

func main() {
    conf, err := readConfig("/home/octeep/.config/wireproxy")
    if err != nil {
        log.Panic(err)
    }

    request, dns, err := createIPCRequest(conf)
    if err != nil {
        log.Panic(err)
    }

    routines := [](func(*netstack.Net)){}
    boundAddrs := []netip.Addr{}

    var addr *netip.Addr
    var routine func(*netstack.Net)

    confloop: for _, section := range conf {
        switch section.name {
        case "[socks5]":
            addr, routine, err = socks5Routine(section.entries)
        case "[tcpclienttunnel]":
            log.Panic(errors.New("not supported yet"))
        case "[tcpservertunnel]":
            log.Panic(errors.New("not supported yet"))
        case "ROOT":
            continue
        default:
            log.Panic(errors.New(fmt.Sprintf("unsupported proxy: %s", section.name)))
        }
        if err != nil {
            log.Panic(err)
        }
        routines = append(routines, routine)

        for _, addr2 := range boundAddrs {
            if addr2.Compare(*addr) == 0 {
                continue confloop
            }
        }
        boundAddrs = append(boundAddrs, *addr)
    }

    tnet, err := startWireguard(request, boundAddrs, dns)
    if err != nil {
        log.Panic(err)
    }

    for _, netRoutine := range routines {
        netRoutine(tnet)
    }
}
