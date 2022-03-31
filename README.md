# wireproxy
A wireguard client that exposes itself as a socks5 proxy or tunnels.

# What is this
`wireproxy` is a completely userspace application that connects to a wireguard peer,
and exposes a socks5 proxy or tunnels on the machine. This can be useful if you need
to connect to certain sites via a wireguard peer, but can't be bothered to setup a new network
interface for whatever reasons.

# Why you might want this
- You simply want to use wireguard as a way to proxy some traffic.
- You don't want root permission just to change wireguard settings.

Currently, I'm running wireproxy connected to a wireguard server in another country,
and configured my browser to use wireproxy for certain sites. It's pretty useful since
wireproxy is completely isolated from my network interfaces, and I don't need root to configure
anything.

# Feature
- TCP static routing for client and server
- SOCKS5 proxy (currently only CONNECT is supported) 

# Usage
```
./wireproxy -c [path to config]
```

```
usage: wireproxy [-h|--help] -c|--config "<value>" [-d|--daemon]
                 [-n|--configtest]

                 Userspace wireguard client for proxying

Arguments:

  -h  --help        Print help information
  -c  --config      Path of configuration file
  -d  --daemon      Make wireproxy run in background
  -n  --configtest  Configtest mode. Only check the configuration file for
                    validity.
```

# Build instruction
```
git clone https://github.com/octeep/wireproxy
cd wireproxy
go build ./cmd/wireproxy
```

# Sample config file
```
# The [Interface] and [Peer] configurations follow the same sematics and meaning
# of a wg-quick configuration. To understand what these fields mean, please refer to:
# https://wiki.archlinux.org/title/WireGuard#Persistent_configuration
# https://www.wireguard.com/#simple-network-interface
[Interface]
Address = 10.200.200.2/32 # The subnet should be /32 and /128 for IPv4 and v6 respectively
# MTU = 1420 (optional)
PrivateKey = uCTIK+56CPyCvwJxmU5dBfuyJvPuSXAq1FzHdnIxe1Q=
DNS = 10.200.200.1

[Peer]
PublicKey = QP+A67Z2UBrMgvNIdHv8gPel5URWNLS4B3ZQ2hQIZlg=
# PresharedKey = UItQuvLsyh50ucXHfjF0bbR4IIpVBd74lwKc8uIPXXs= (optional)
Endpoint = my.ddns.example.com:51820
# PersistentKeepalive = 25 (optional)

# TCPClientTunnel is a tunnel listening on your machine,
# and it forwards any TCP traffic received to the specified target via wireguard.
# Flow:
# <an app on your LAN> --> localhost:25565 --(wireguard)--> play.cubecraft.net:25565
[TCPClientTunnel]
BindAddress = 127.0.0.1:25565
Target = play.cubecraft.net:25565

# TCPServerTunnel is a tunnel listening on wireguard,
# and it forwards any TCP traffic received to the specified target via local network.
# Flow:
# <an app on your wireguard network> --(wireguard)--> 172.16.31.2:3422 --> localhost:25545
[TCPServerTunnel]
ListenPort = 3422
Target = localhost:25545

# Socks5 creates a socks5 proxy on your LAN, and all traffic would be routed via wireguard.
[Socks5]
BindAddress = 127.0.0.1:25344

# Socks5 authentication parameters, specifying username and password enables
# proxy authentication.
#Username = ...
# Avoid using spaces in the password field
#Password = ...
```


## Stargazers over time

[![Stargazers over time](https://starchart.cc/octeep/wireproxy.svg)](https://starchart.cc/octeep/wireproxy)
