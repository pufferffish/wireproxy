# wireproxy
[![ISC licensed](https://img.shields.io/badge/license-ISC-blue)](./LICENSE)
[![Build status](https://github.com/octeep/wireproxy/actions/workflows/build.yml/badge.svg)](https://github.com/octeep/wireproxy/actions)
[![Documentation](https://img.shields.io/badge/godoc-wireproxy-blue)](https://pkg.go.dev/github.com/octeep/wireproxy)

A wireguard client that exposes itself as a socks5/http proxy or tunnels.
A straight fork of pufferffish/wireproxy

# What is this
`wireproxy` is a completely userspace application that connects to a wireguard peer,
and exposes a socks5/http proxy or tunnels on the machine. This can be useful if you need
to connect to certain sites via a wireguard peer, but can't be bothered to setup a new network
interface for whatever reasons.

# Why you might want this
- You simply want to use wireguard as a way to proxy some traffic.
- You don't want root permission just to change wireguard settings.
- You want to use firefox tabs with custom VPN services

# Feature
- TCP static routing for client and server
- SOCKS5/HTTP proxy (currently only CONNECT is supported)

# TODO
- UDP Support in SOCKS5
- UDP static routing

# Usage
```
./wireproxy -c [path to config]
```

```
usage: wireproxy [-h|--help] [-c|--config "<value>"] [-s|--silent]
                 [-d|--daemon] [-v|--version] [-n|--configtest]

                 Userspace wireguard client for proxying

Arguments:

  -h  --help        Print help information
  -c  --config      Path of configuration file
  -s  --silent      Silent mode
  -d  --daemon      Make wireproxy run in background
  -v  --version     Print version
  -n  --configtest  Configtest mode. Only check the configuration file for
                    validity.
```

# Build instruction
GO is required for build.

On a Mac with homebrew: `brew install go`

Once GO is installed:

```
git clone https://github.com/octeep/wireproxy
cd wireproxy
make
```

# Getting a Wireguard Server
You can create your own wireguard server using a host service like DigitalOcean,
or you can get a VPN service that provides WireGuard configs.

I recommend ProtonVPN, because it is highly secure and has a great WireGuard
config generator.

Simply go to https://account.protonvpn.com/downloads and scroll down to the
wireguard section to generate your configs, then paste into the apporpriate
section below.

# Simple Setup for multiple SOCKS configs for firefox

Create a folder for your configs and startup scripts. Can be the same place as
this code. That path you will use below. For reference this text uses
`/Users/jonny/vpntabs`

For each VPN you want to run, you will download your wireguard config and name
it appropriately (e.g. `ProtonUS.adblock.server.conf`) and then create two new
files from those below with similar names (e.g. `ProtonUS.adblock.conf` and
`ProtonUS.adblock.sh`)

You will also create a launch script, the reference below is only for macOS. The
naming should also be similar (e.g.
`/Users/jonny/Library/LaunchAgents/com.ProtonUS.adblock.plist`)

## Config File
Make sure you use a unique port for every separate server
I recommend you set proxy authentication, you can use the same user/pass for all
```
# Link to the Downloaded config
WGConfig = /Users/jonny/vpntabs/ProtonUS.adblock.server.conf

# Used for firefox containers
[Socks5]
BindAddress = 127.0.0.1:25344 # Update the port here for each new server

# Socks5 authentication parameters, specifying username and password enables
# proxy authentication.
#Username = ...
# Avoid using spaces in the password field
#Password = ...
```

## Startup Script File
This is a bash script to facilitate startup, not strictly essential, but adds
ease.
Note, you MUST update the first path to wherever you installed this code to.
Make sure you use the path for the config file above, not the one you downloaded
from e.g. protonvpn.
```
#!/bin/bash
/Users/jonny/wireproxy/wireproxy -c /Users/jonny/vpntabs/ProtonUS.adblock.conf
```

## MacOS LaunchAgent
To make it run every time you start your computer, you can create a launch agent
in `$HOME/Library/LaunchAgents`. Name reference above.

That file should contain the following, the label should be the same as the file
name and the paths should be set correctly:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ProtonUS.adblock</string>
    <key>Program</key>
    <string>/Users/jonny/vpntabs/ProtonUS.adblock.sh</string>
    <key>RunAtLoad</key>
	<true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

To enable it, run
`launchctl load ~/Library/LaunchAgents/com.ProtonUS.adblock.plist` and
`launchtl start ~/Library/LaunchAgents/com.PortonUS.adblock.plist`

# Firefox Setup
You will need to enable the Multi Account Container Tabs extension and a proxy extension, I
recommend Sideberry, but Container Proxy also works.

Create a container to be dedicated to this VPN, and then add the IP, port,
username, and password from above.

# Config file Reference
```
# The [Interface] and [Peer] configurations follow the same semantics and meaning
# of a wg-quick configuration. To understand what these fields mean, please refer to:
# https://wiki.archlinux.org/title/WireGuard#Persistent_configuration
# https://www.wireguard.com/#simple-network-interface
# Note: these first two sections are what you get from ProtonVPN. You can paste
# those sections below, overwriting what is already there.
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
#[TCPClientTunnel]
#BindAddress = 127.0.0.1:25565
#Target = play.cubecraft.net:25565

# TCPServerTunnel is a tunnel listening on wireguard,
# and it forwards any TCP traffic received to the specified target via local network.
# Flow:
# <an app on your wireguard network> --(wireguard)--> 172.16.31.2:3422 --> localhost:25545
#[TCPServerTunnel]
#ListenPort = 3422
#Target = localhost:25545

# Socks5 creates a socks5 proxy on your LAN, and all traffic would be routed via wireguard.
# This is what you will use for Firefox Container Tabs. Change the port below if
# you run multiple configs
[Socks5]
BindAddress = 127.0.0.1:25344

# Socks5 authentication parameters, specifying username and password enables
# proxy authentication.
#Username = ...
# Avoid using spaces in the password field
#Password = ...

# http creates a http proxy on your LAN, and all traffic would be routed via wireguard.
#[http]
#BindAddress = 127.0.0.1:25345

# HTTP authentication parameters, specifying username and password enables
# proxy authentication.
#Username = ...
# Avoid using spaces in the password field
#Password = ...
```

Alternatively, if you already have a wireguard config, you can import it in the
wireproxy config file like this:
```
WGConfig = <path to the wireguard config>

# Same semantics as above
[TCPClientTunnel]
...

[TCPServerTunnel]
...

[Socks5]
...
```

Having multiple peers is also supported. `AllowedIPs` would need to be specified
such that wireproxy would know which peer to forward to.
```
[Interface]
Address = 10.254.254.40/32
PrivateKey = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=

[Peer]
Endpoint = 192.168.0.204:51820
PublicKey = YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY=
AllowedIPs = 10.254.254.100/32
PersistentKeepalive = 25

[Peer]
PublicKey = ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ=
AllowedIPs = 10.254.254.1/32, fdee:1337:c000:d00d::1/128
Endpoint = 172.16.0.185:44044
PersistentKeepalive = 25


[TCPServerTunnel]
ListenPort = 5000
Target = service-one.servicenet:5000

[TCPServerTunnel]
ListenPort = 5001
Target = service-two.servicenet:5001

[TCPServerTunnel]
ListenPort = 5080
Target = service-three.servicenet:80
```

# Donation
This goes to the original creator, not me.
<noscript><a href="https://liberapay.com/octeep/donate"><img alt="Donate using Liberapay" src="https://liberapay.com/assets/widgets/donate.svg"></a></noscript>


# Stargazers over time

[![Stargazers over time](https://starchart.cc/octeep/wireproxy.svg)](https://starchart.cc/octeep/wireproxy)
