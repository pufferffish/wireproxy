#!/usr/bin/env bash
set -e
exec 3<>/dev/tcp/demo.wireguard.com/42912
privatekey="$(wg genkey)"
wg pubkey <<<"$privatekey" >&3
IFS=: read -r status server_pubkey server_port internal_ip <&3
[[ $status == OK ]]
cat >test.conf <<EOL
[Interface]
Address = $internal_ip/32
PrivateKey = $privatekey
DNS = 8.8.8.8

[Peer]
PublicKey = $server_pubkey
Endpoint = demo.wireguard.com:$server_port

[Socks5]
BindAddress = 127.0.0.1:64423

[http]
BindAddress = 127.0.0.1:64424

[http]
BindAddress = 127.0.0.1:64425
Username = peter
Password = hunter123
EOL
