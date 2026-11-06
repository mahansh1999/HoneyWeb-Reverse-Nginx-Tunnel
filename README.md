# HoneyWeb Reverse Nginx Tunnel

A reverse tunnel that looks like a foreign server visiting a website.

The entry server runs NGINX as an ordinary HTTPS site, with a real certificate and pages. The HoneyWeb Tunnel engine sits behind it on loopback, using the `wsmux` transport. Only a WebSocket upgrade that carries the tunnel's token reaches the engine. Every other request gets the website, and an unknown path answers 404 like any missing page.

The exit server reaches the site in one of two ways:

- **Through its own NGINX (`--via-nginx`)**: NGINX makes the TLS connection, from a chosen source address, with the site's SNI and Host, and checks the certificate. On the wire this is one NGINX talking to another.
- **Directly**: the engine makes a Chrome-shaped TLS handshake itself (`wssmux` with `tls_verify`).

The entry can also hand a WebSocket path of the site straight into the tunnel (`--route`). That is how a panel host whose address is the site reaches a WebSocket inbound on the exit.

```
user ──> NGINX (entry, :443) ──token-gated /channel, /tunnel/*──> engine (wsmux, 127.0.0.1)
                                                                     ▲ pool of multiplexed sessions
          exit: engine (wsmux) ──> NGINX (127.0.0.1) ──TLS──────────┘
```

## Install (one line, as root, on each server)

```
bash <(curl -fsSL https://raw.githubusercontent.com/mahansh1999/HoneyWeb-Reverse-Nginx-Tunnel/main/install.sh)
```

The installer fetches the scripts and the engine of the latest release, checks the engine against `SHA256SUMS`, and
opens a menu: install the entry (Iran) first, copy the token it prints, then install the exit (abroad) with it.
Afterwards `hwt-rnt` opens the menu again; `hwt-rnt status|speedtest|start|stop|remove NAME` work directly.

## The menu (hwt-rnt)

- **1) install on the Iran server:** choose a method, then give the domain (its A record points to this Iran server) and the foreign server's IP. No ports are asked: users connect on 443. The installer prints a **link**.
- **2) install on the foreign server:** paste the link, then give Xray's WebSocket inbound port and the panel host's path. This side installs NGINX, gets the Let's Encrypt certificate through the Iran server, and becomes the reverse proxy in front of Xray.
- **3) tunnel manager:** status, speed test, restart, stop, remove here, or **remove from both servers**. A small agent on the foreign server does its part; it listens on loopback only and needs the tunnel's token.
- **4) optimize:** the TCP settings (BBR, no slow start after idle, MTU probing), NGINX capacity, and a pool of 896.

| Method | How Iran hands 443/80 to the foreign server |
|---|---|
| Nginx + Reverse Nginx + Reverse Proxy | The foreign NGINX keeps a tunnel open to Iran's NGINX. Users pass through it. Anyone else who probes Iran:443 sees the foreign site and its certificate. |
| Nginx + Iptables + Reverse Proxy | DNAT of tcp/443 and tcp/80, kept by a systemd unit. |
| Nginx + Direct Nginx + Reverse Proxy | Iran's NGINX connects to the foreign NGINX itself. The direct path must be open. |

The reverse and direct methods pass the user's address with the PROXY protocol, so Xray sees it in X-Forwarded-For.

`rnt.sh` is the older multi-port variant. It is kept for tunnels that were installed with it.

## Usage without the menu (rnt.sh)

`rnt.sh` runs as root on each server. It needs these files next to it:

- the engine binary (`hwtunnel`) and its `hwtunnel.sha256`;
- a `token` file;
- `nginx/*.tmpl`;
- `site/`.

```
# entry
rnt.sh iran --name t1 --domain site.example --listen 443 --backend 19443 \
  --map 127.0.0.1:20218=62018,8443=8443 --route /ws-path=20218/ --cert fullchain.pem --key privkey.pem
rnt.sh acme t1            # switch to the site's own Let's Encrypt certificate (port 80 reaches the entry)

# exit
rnt.sh kharej --name t1 --domain site.example --port 443 --edge-ip 203.0.113.10 \
  --local-addr 198.51.100.20 --pool 512 --via-nginx 19443

rnt.sh status t1 | remove t1
```

- The script never touches the firewall or sysctl.
- NGINX is reloaded only after `nginx -t` passes.
- Every file it replaces is backed up first.

## Lab

`lab/lab_rnt.py` builds three network namespaces and compares three shapes under the same capacity and CPU budget:

1. today's WSSMUX;
2. NGINX entry with a direct client;
3. NGINX on both sides.

It also checks:

- a routed WebSocket path, end to end;
- what a stranger sees;
- an exit that trusts the wrong CA.

`docs/design_FA.md` has the design and the measurements.

## Licence

The engine is HoneyWeb Tunnel, a fork of BackPack, and is AGPL-3.0. This repository ships scripts and templates that install it.
Each release carries the engine's complete source (`hwtunnel-src-<commit>.tar.gz`) next to its binaries.
