package main

import (
    "bufio"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "log"
    "net"
    "net/http"
    "os"
    "strings"

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

    request := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\n", selfSK, peerPK, endpoint)
    return request, dns, nil
}

func main() {
    fmt.Println("hi")
    conf, err := readConfig("/home/octeep/.config/wireproxy")
    if err != nil {
        log.Panic(err)
    }

    for _, section := range conf {
        fmt.Println(section.name)
    }

    request, dns, err := createIPCRequest(conf)
    if err != nil {
        log.Panic(err)
    }

    test(request, dns)
}

func test(request string, dns []netip.Addr) {
    tun, tnet, err := netstack.CreateNetTUN(
        []netip.Addr{netip.MustParseAddr("172.16.31.2")},
        dns, 1420)
    if err != nil {
        log.Panic(err)
    }
    dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
    dev.IpcSet(request)
    err = dev.Up()
    if err != nil {
        log.Panic(err)
    }

    client := http.Client{
        Transport: &http.Transport{
            DialContext: tnet.DialContext,
        },
    }
    resp, err := client.Get("https://www.zx2c4.com/ip")
    if err != nil {
        log.Panic(err)
    }
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Panic(err)
    }
    log.Println(string(body))
}
