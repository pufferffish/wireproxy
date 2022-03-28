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

# Usage
```
./wireproxy [path to config]
```

# Sample config file
```
# SelfSecretKey is the secret key of your wireguard peer.
# This should be the same as the PrivateKey in your `client.conf` wireguard setting.
SelfSecretKey = uCTIK+56CPyCvwJxmU5dBfuyJvPuSXAq1FzHdnIxe1Q=

# SelfEndpoint is the IP of your wireguard peer.
SelfEndpoint = 172.16.31.2

# PeerPublicKey is the public key of the wireguard server you want to connect to.
PeerPublicKey = QP+A67Z2UBrMgvNIdHv8gPel5URWNLS4B3ZQ2hQIZlg=

# PeerEndpoint is the endpoint of the wireguard server you want to connect to.
PeerEndpoint = 172.16.0.1:53

# DNS is the list of nameservers that will be used by wireproxy.
# For just a single nameserver:
DNS = 1.1.1.1
# For multiple nameservers:
#DNS = 1.1.1.1, 1.0.0.1

# KeepAlive is the persistent keep alive interval of the wireguard device.
# Usually not needed.
#KeepAlive = 25

# PreSharedKey is the pre shared key of your wireguard device
# If you don't know what this is, then you probably don't need it.
#PreSharedKey = UItQuvLsyh50ucXHfjF0bbR4IIpVBd74lwKc8uIPXXs=

# MTU is the maximum transmission unit size, By default this is set to 1420.
# MTU = 1234

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
