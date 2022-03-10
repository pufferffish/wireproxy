package main

import (
    "io"
    "log"
    "net/http"
    "fmt"
    "os"
    "bufio"
    "strings"
    "errors"
    "encoding/base64"
    "encoding/hex"

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

    section := ConfigSection{ name: "ROOT", entries: map[string]string{} }
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
            section = ConfigSection{ name: strings.ToLower(line), entries: map[string]string{} }
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

func main() {
    fmt.Println("hi")
    conf, err := readConfig("/home/octeep/.config/wireproxy")
    if err != nil {
        log.Panic(err)
    }

    for _, section := range conf {
        fmt.Println(section.name)
    }

    root := configRoot(conf)

    peerPK, err := parseBase64Key(root["peerpublickey"])
    if err != nil {
        log.Panic(err)
    }

    selfSK, err := parseBase64Key(root["selfsecretkey"])
    if err != nil {
        log.Panic(err)
    }

    fmt.Println(peerPK)
    fmt.Println(selfSK)
    fmt.Println(root)
}

func test() {
    tun, tnet, err := netstack.CreateNetTUN(
        []netip.Addr{netip.MustParseAddr("192.168.4.29")},
        []netip.Addr{netip.MustParseAddr("8.8.8.8")},
        1420)
    if err != nil {
        log.Panic(err)
    }
    dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
    dev.IpcSet(`private_key=a8dac1d8a70a751f0f699fb14ba1cff7b79cf4fbd8f09f44c6e6a90d0369604f
public_key=25123c5dcd3328ff645e4f2a3fce0d754400d3887a0cb7c56f0267e20fbf3c5b
endpoint=163.172.161.0:12912
allowed_ip=0.0.0.0/0
`)
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
