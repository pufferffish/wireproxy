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

type DeviceSetting struct {
    ipcRequest  string
    dns         []netip.Addr
    deviceAddr  *netip.Addr
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

func createIPCRequest(conf Configuration) (*DeviceSetting, error) {
    root := configRoot(conf)

    peerPK, err := parseBase64Key(root["peerpublickey"])
    if err != nil {
        return nil, err
    }

    selfSK, err := parseBase64Key(root["selfsecretkey"])
    if err != nil {
        return nil, err
    }

    peerEndpoint, err := resolveIPPAndPort(root["peerendpoint"])
    if err != nil {
        return nil, err
    }

    selfEndpoint, err := netip.ParseAddr(root["selfendpoint"])
    if err != nil {
        return nil, err
    }

    dns, err := parseIPs(root["dns"])
    if err != nil {
        return nil, err
    }

    keepAlive := int64(0)
    if keepAliveOpt, ok := root["keepalive"]; ok {
        keepAlive, err = strconv.ParseInt(keepAliveOpt, 10, 0)
        if err != nil {
            return nil, err
        }
        if keepAlive < 0 {
            keepAlive = 0
        }
    }

    preSharedKey := "0000000000000000000000000000000000000000000000000000000000000000"
    if pskOpt, ok := root["presharedkey"]; ok {
        preSharedKey, err = parseBase64Key(pskOpt)
        if err != nil {
            return nil, err
        }
    }

    request := fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
persistent_keepalive_interval=%d
preshared_key=%s
allowed_ip=0.0.0.0/0`, selfSK, peerPK, peerEndpoint, keepAlive, preSharedKey)

    setting := &DeviceSetting{ ipcRequest: request, dns: dns, deviceAddr: &selfEndpoint }
    return setting, nil
}

func socks5Routine(config map[string]string) (func(*netstack.Net), error) {
    bindAddr, ok := config["bindaddress"]
    if !ok {
        return nil, errors.New("missing bind address")
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

    return routine, nil
}

func connForward(bufSize int, from, to net.Conn) {
    buf := make([]byte, bufSize)
    for {
        size, err := from.Read(buf)
        if err != nil {
            to.Close()
            return
        }
        _, err = to.Write(buf[:size])
        if err != nil {
            to.Close()
            return
        }
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

func tcpClientRoutine(config map[string]string) (func(*netstack.Net), error) {
    bindAddr, ok := config["bindaddress"]
    if !ok {
        return nil, errors.New("missing bind address")
    }

    bindTCPAddr, err := net.ResolveTCPAddr("tcp", bindAddr)
    if err != nil {
        return nil, err
    }

    target, ok := config["target"]
    if !ok {
        return nil, errors.New("missing target")
    }

    routine := func(tnet *netstack.Net) {
        server, err := net.ListenTCP("tcp", bindTCPAddr)
        if err != nil {
          log.Panic(err)
        }

        for {
            conn, err := server.Accept()
            if err != nil {
                log.Panic(err)
            }
            go tcpClientForward(tnet, target, conn)
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

func tcpServerRoutine(config map[string]string) (func(*netstack.Net), error) {
    listenPort, err := strconv.ParseInt(config["listenport"], 10, 0)
    if err != nil {
        return nil, err
    }

    if listenPort < 1 || listenPort > 65535 {
        return nil, errors.New("listen port out of bound")
    }

    addr := &net.TCPAddr{Port : int(listenPort)}

    target, ok := config["target"]
    if !ok {
        return nil, errors.New("missing target")
    }

    routine := func(tnet *netstack.Net) {
        server, err := tnet.ListenTCP(addr)
        if err != nil {
          log.Panic(err)
        }

        for {
            conn, err := server.Accept()
            if err != nil {
                log.Panic(err)
            }
            go tcpServerForward(target, conn)
        }
    }

    return routine, nil
}

func startWireguard(setting *DeviceSetting) (*netstack.Net, error) {
    tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{*(setting.deviceAddr)}, setting.dns, 1420)
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

    conf, err := readConfig(os.Args[1])
    if err != nil {
        log.Panic(err)
    }

    setting, err := createIPCRequest(conf)
    if err != nil {
        log.Panic(err)
    }

    routines := [](func(*netstack.Net)){}

    var routine func(*netstack.Net)

    for _, section := range conf {
        switch section.name {
        case "[socks5]":
            routine, err = socks5Routine(section.entries)
        case "[tcpclienttunnel]":
            routine, err = tcpClientRoutine(section.entries)
        case "[tcpservertunnel]":
            routine, err = tcpServerRoutine(section.entries)
        case "ROOT":
            continue
        default:
            log.Panic(errors.New(fmt.Sprintf("unsupported proxy: %s", section.name)))
        }
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

    select{} // sleep etnerally
}
