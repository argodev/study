# VPN

In order to make testing and other work both easier and protected, we establish a simple VPN that is allowed to transit the network. While there are many approaches that could have been used, we elected to utilize wireguard. The "server" is `lap0` and it listens on port `51820`.  These are the steps taken to configure the environment

## On the _server_ (`lap01`)

Install the software

```bash
$ sudo apt install wireguard
```

Create private/public keys for the server

```bash
$ wg genkey | tee privatekey | wg pubkey > publickey
```

Create tunnel interface definition file in `/etc/wireguard/wg0.conf`

```text
[Interface]
PrivateKey=**REDACTED**
Address=192.168.88.1/24
SaveConfig=true
PostUp=iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o enp0s25 -j MASQUERADE;
PostDown=iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o enp0s25 -j MASQUERADE;  
ListenPort=51820
```

Bring the interface up

```bash
$ wg-quick up wg0
[#] ip link add wg0 type wireguard
[#] wg setconf wg0 /dev/fd/63
[#] ip -4 address add 192.168.90.1/24 dev wg0
[#] ip link set mtu 1420 up dev wg0
[#] iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o enp0s25 -j MASQUERADE;
```

Confirm it is up/running

```bash
$ sudo wg
interface: wg0
  public key: 5oAPZBxgOx3TCR/sNhzq0kFnN7gRr6Wr0GKQxZ1sxDw=
  private key: (hidden)
  listening port: 51820
```


## On the _client_

Install the software

```bash
$ sudo apt install wireguard
```

Create private/public keys for the clien

```bash
$ wg genkey | tee privatekey | wg pubkey > publickey
```

Create tunnel interface defintion file in `/etc/wireguard/wg0.conf`

```text
[Interface]
PrivateKey=**REDACTED**
Address=192.168.88.2/24
SaveConfig=true

[Peer]
PublicKey=5oAPZBxgOx3TCR/sNhzq0kFnN7gRr6Wr0GKQxZ1sxDw=
Endpoint=192.168.20.241:51820
AllowedIPs=192.168.88.0/23
PersistentKeepalive=30
```

Bring the interface up

```bash
$ wg-quick up wg0                                   
[#] ip link add wg0 type wireguard
[#] wg setconf wg0 /dev/fd/63
[#] ip -4 address add 192.168.88.2/24 dev wg0
[#] ip link set mtu 1420 up dev wg0
[#] ip -4 route add 192.168.88.0/23 dev wg0
```

Confirm it is working

```bash
sudo wg                         
interface: wg0
  public key: Tiqe/+WzNOSv6zCYFzKfuKW45guhN5e9VkoOn9zEPyc=
  private key: (hidden)
  listening port: 55015

peer: 5oAPZBxgOx3TCR/sNhzq0kFnN7gRr6Wr0GKQxZ1sxDw=
  endpoint: 192.168.20.241:51820
  allowed ips: 192.168.88.0/23
```

It is created, _but not yet connected to the server_

## Back on the Server

Configure to allow the client to make a connection

```bash
# sudo wg set wg0 peer [client_pub_key] allowed-ips [client_tunnel_ip]/32
$ sudo wg set wg0 peer Tiqe/+WzNOSv6zCYFzKfuKW45guhN5e9VkoOn9zEPyc= allowed-ips 192.168.88.2/32\

# configure to auto-restart this interface on reboot
$ sudo systemctl enable --now wg-quick@wg0.service
```

## Back on the Client

Confirm everything is working as it should be:

```bash
$ sudo wg
interface: wg0
  public key: Tiqe/+WzNOSv6zCYFzKfuKW45guhN5e9VkoOn9zEPyc=
  private key: (hidden)
  listening port: 55015

peer: 5oAPZBxgOx3TCR/sNhzq0kFnN7gRr6Wr0GKQxZ1sxDw=
  endpoint: 192.168.20.241:51820
  allowed ips: 192.168.88.0/23
  latest handshake: 1 second ago
  transfer: 1.79 KiB received, 2.96 KiB sent
  persistent keepalive: every 30 seconds
```

And I can now successfully ping boxes within the test environment
