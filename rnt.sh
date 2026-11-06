#!/usr/bin/env bash
# rnt.sh — HoneyWeb Reverse Nginx Tunnel: install, check or remove one tunnel on this server (run as root).
#
# The entry server (Iran) is an ordinary HTTPS website served by NGINX. The tunnel engine (hwtunnel, transport
# wsmux) listens on loopback behind it, and only a WebSocket upgrade that carries this tunnel's token reaches it;
# every other request — browsers, scanners, active probes — gets the website. The exit server (abroad) visits that
# site and keeps a pool of upgraded connections open; the entry carries its users' connections over them.
# A WebSocket path of the site can be handed straight into the tunnel (--route): that is how a panel host whose
# address is the site reaches a WebSocket inbound on the exit, with NGINX as its reverse proxy.
#
# The exit reaches the site one of two ways:
#   --via-nginx PORT  its own NGINX is the visitor: the engine speaks plain WebSocket (wsmux) to a loopback-only
#                     NGINX server, which carries every connection to the site over TLS — from --local-addr,
#                     naming the site in SNI and Host, refusing any certificate the CA bundle does not vouch for.
#                     On the wire: one NGINX talking to another.
#   (default)         the engine is the visitor (wssmux): a Chrome-shaped TLS handshake with tls_verify.
#
#   rnt.sh iran   --name N --domain D --listen [ADDR:]PORT --backend PORT --map [ADDR:]PORT=TARGET[,...]
#                 [--route PATH=LOCALPORT[/UPATH][,...]] [--http PORT|none] [--udp] [--mux-con 8]
#                 (--cert FILE --key FILE | --acme) [--ca-file FILE] [--check-only]
#   rnt.sh acme   N                  switch the site to its own Let's Encrypt certificate (port 80 must reach it)
#   rnt.sh kharej --name N --domain D --port PORT [--edge-ip IP] [--local-addr IP] [--pool 64] [--ca-file FILE]
#                 [--via-nginx LOCALPORT] [--stage] [--check-only]
#   rnt.sh start N | stop N | status N | remove N
#   rnt.sh menu                      (or no arguments on a terminal) an interactive menu for all of the above
#   rnt.sh speedtest N [--streams 1] [--seconds 10] [--steps 1,4,8,16] [--install-iperf]   tunnel speed, on the entry
#   rnt.sh self-install              keep this script on the server as hwt-rnt (no service is touched)
#   rnt.sh render-site ... | render-auth N | render-out ...   print what would be installed (installs nothing)
#
# Next to this script: hwtunnel + hwtunnel.sha256 (the engine; checked before it is installed), token (this
# tunnel's secret, one line, never printed), nginx/*.tmpl, and for iran site/ (the website).
#
# iran:   TARGET is what the exit dials for that user port ("8443" = its 127.0.0.1:8443). A --map entry on
#         127.0.0.1 is reachable only through NGINX, which is what a --route points at: PATH (an exact path of the
#         site, WebSocket upgrades only) goes to that local port, and to UPATH upstream if given ("/ws-path=20218/"
#         sends the inbound "/"). --http serves port 80 (default) for ACME and redirects the rest to HTTPS.
#         --cert/--key are copied under /etc/hwt-rnt/N/tls (a certificate carried from another server, say);
#         --acme gets a Let's Encrypt certificate at install, `rnt.sh acme N` does it later. --udp also carries UDP
#         on the mapped ports. --ca-file is only for the local health probe with a private CA.
# kharej: --edge-ip dials that address while still presenting the domain (SNI, Host, certificate check), so the
#         tunnel does not depend on the exit's DNS; --local-addr is the source address its connections leave
#         from. --ca-file trusts a private CA instead of the system roots. --stage installs everything but
#         starts nothing (`rnt.sh start N` later).
#
# Nothing here touches the firewall, sysctl, or any other service; NGINX is only reloaded after `nginx -t`
# passes, and every file replaced is first copied to /root/hwt-rnt-backup/<time>/.
set -euo pipefail
# Callers may run us under umask 077 (hwt-remote.sh does); the engine and NGINX run as other users and must be able
# to traverse our directories. Files holding secrets get their own explicit modes below.
umask 022
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=/opt/hwt-rnt/bin/hwtunnel
ETC=/etc/hwt-rnt
NGX_AUTH=/etc/nginx/hwt-rnt
WWW=/var/www/hwt-rnt
ACME=/var/www/hwt-rnt-acme
SYSTEM_CA=/etc/ssl/certs/ca-certificates.crt
TS=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP=/root/hwt-rnt-backup/$TS
# HoneyWeb Tunnel's Turbo profile with a 4 MiB stream window: one stream carries at most about
# window / RTT, and at the 86 ms Iran-Finland RTT the 2 MiB of Turbo held a single user near 100 Mbit/s against
# 215 on the direct path (2026-11-05). 4 MiB, not more: the entry has 4 GiB of RAM, and the window is what a slow
# reader can make the entry buffer. Capacity is separate: streams = connection_pool x mux_con.
PROFILE='nodelay = true
mux_version = 2
mux_streambuffer = 4194304
mux_recievebuffer = 16777216'
RE_NAME='^[a-z][a-z0-9_]{0,23}$'
RE_DOMAIN='^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
RE_IP='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
RE_LISTEN='^(([0-9]{1,3}\.){3}[0-9]{1,3}:)?[0-9]{1,5}$'
RE_MAP='^(([0-9]{1,3}\.){3}[0-9]{1,3}:)?[0-9]{1,5}=[0-9A-Za-z.:-]+$'
RE_ROUTE='^/[A-Za-z0-9._/-]{1,64}=[0-9]{1,5}(/[A-Za-z0-9._/-]{0,64})?$'
RE_PATH='^/[A-Za-z0-9._/-]{1,200}$'

die() { echo "rnt: ABORT: $*" >&2; exit 1; }
say() { echo "== $(date -u +%T) $*"; }
need() { [[ "$2" =~ $3 ]] || die "bad $1 '$2'"; }
backup() { local f; for f in "$@"; do [ -e "$f" ] || continue; mkdir -p "$BACKUP$(dirname "$f")"; cp -a "$f" "$BACKUP$f"; done; }
# put FILE MODE OWNER: stdin to FILE atomically, keeping a copy of what was there
put() { backup "$1"; mkdir -p "$(dirname "$1")"; cat > "$1.rnt-new"; chmod "$2" "$1.rnt-new"; chown "$3" "$1.rnt-new"; mv -f "$1.rnt-new" "$1"; }
port_free() { [ -z "$(ss -Htln "( sport = :$1 )" 2>/dev/null)" ]; }
port_owner() { ss -Htlnp "( sport = :$1 )" 2>/dev/null | grep -o 'users:(("[^"]*"' | cut -d'"' -f2 | sort -u | tr '\n' ' ' || true; }
unit() { echo "hwt-rnt-$1.service"; }
# engine_sessions PORT: established connections of the engine itself to PORT (the exit's Xray holds thousands of
# connections to port 443 elsewhere, so the process is what tells ours apart)
engine_sessions() { ss -Htnp state established "( dport = :$1 )" 2>/dev/null | grep -c '"hwtunnel"' || true; }

read_token() {
  [ -f "$HERE/token" ] || die "no token file next to rnt.sh"
  TOKEN=$(head -c 512 "$HERE/token" | tr -d '\r\n')
  # The token goes into an NGINX regex and a TOML string: keep it to characters that are literal in both.
  [[ "$TOKEN" =~ ^[A-Za-z0-9_-]{32,128}$ ]] || die "the token must be 32-128 of A-Z a-z 0-9 _ -"
}

install_engine() {
  [ -f "$HERE/hwtunnel" ] && [ -f "$HERE/hwtunnel.sha256" ] || die "hwtunnel and hwtunnel.sha256 must be next to rnt.sh"
  local want got; want=$(awk '{print $1; exit}' "$HERE/hwtunnel.sha256"); got=$(sha256sum "$HERE/hwtunnel" | awk '{print $1}')
  [ "$want" = "$got" ] || die "hwtunnel checksum mismatch (want $want, got $got)"
  if [ -f "$BIN" ] && [ "$(sha256sum "$BIN" | awk '{print $1}')" = "$got" ]; then say "engine already installed (${got:0:16})"; return; fi
  backup "$BIN"; install -D -m 0755 -o root -g root "$HERE/hwtunnel" "$BIN.rnt-new"; mv -f "$BIN.rnt-new" "$BIN"
  say "engine installed: $BIN (${got:0:16})"
}

ensure_user() {
  id hwtunnel >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin hwtunnel
  # install -d also corrects the mode of a directory an earlier run made under a tighter umask
  install -d -m 0755 /opt/hwt-rnt /opt/hwt-rnt/bin "$ETC" "$ETC/$NAME" "$WWW" "$ACME"
}

write_unit() { # write_unit NAME ROLE CAPS
  put "/etc/systemd/system/$(unit "$1")" 0644 root:root <<EOF
[Unit]
Description=HoneyWeb Reverse Nginx Tunnel $1 ($2)
After=network-online.target nginx.service
Wants=network-online.target

[Service]
User=hwtunnel
Group=hwtunnel
ExecStart=$BIN -c $ETC/$1/$2.toml
Restart=always
RestartSec=3
# The engine keeps its control socket in /run/backpack; preserved so stopping one tunnel never removes another's.
RuntimeDirectory=backpack
RuntimeDirectoryPreserve=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
LimitNOFILE=1048576
CapabilityBoundingSet=$3
AmbientCapabilities=$3

[Install]
WantedBy=multi-user.target
EOF
}

# render TEMPLATE: the template on stdout with {{KEY}} replaced from the environment variable RNT_KEY
render() {
  python3 -I - "$1" <<'PY'
import os, re, sys
t = open(sys.argv[1], encoding="utf-8").read()
def val(m):
    k = "RNT_" + m.group(1)
    if k not in os.environ:
        sys.exit("template needs " + k)
    return os.environ[k]
sys.stdout.write(re.sub(r"\{\{([A-Z_]+)\}\}", val, t))
PY
}

# nginx_install FILE TEXT: put an NGINX site in place, test, load; the previous version is restored if nginx -t
# fails. Rendered to memory by the caller, so a template error never leaves a half-written file behind.
nginx_install() {
  local site=$1 txt=$2 link prev err
  link=/etc/nginx/sites-enabled/$(basename "$site")
  prev=$(mktemp); err=$(mktemp)
  if [ -f "$site" ]; then cp -a "$site" "$prev"; else : > "$prev"; fi
  printf '%s\n' "$txt" | put "$site" 0644 root:root
  ln -sfn "$site" "$link"
  if ! nginx -t 2>"$err"; then
    sed 's/^/  /' "$err"
    if [ -s "$prev" ]; then cp -a "$prev" "$site"; else rm -f "$site" "$link"; fi
    rm -f "$prev" "$err"
    die "nginx -t failed; the previous site was restored and nothing was reloaded"
  fi
  rm -f "$prev" "$err"
  if systemctl is-active --quiet nginx; then systemctl reload nginx; else systemctl enable --now nginx >/dev/null; fi
}

# Ubuntu ships worker_connections 768, and every tunnel session and every routed user hold two.
nginx_capacity() {
  local wc; wc=$(sed -n -E 's/^\s*worker_connections\s+([0-9]+);.*/\1/p' /etc/nginx/nginx.conf | head -1)
  [ -n "$wc" ] && [ "$wc" -lt 16384 ] || return 0
  backup /etc/nginx/nginx.conf
  sed -i -E 's/^(\s*)worker_connections\s+[0-9]+;/\1worker_connections 16384;/' /etc/nginx/nginx.conf
  grep -q '^worker_rlimit_nofile' /etc/nginx/nginx.conf || sed -i -E '0,/^worker_processes/s//worker_rlimit_nofile 65536;\n&/' /etc/nginx/nginx.conf
  if ! nginx -t >/dev/null 2>&1; then cp -a "$BACKUP/etc/nginx/nginx.conf" /etc/nginx/nginx.conf; die "nginx.conf capacity change failed nginx -t; restored"; fi
  echo "  nginx: worker_connections $wc -> 16384"
}

# ---------------------------------------------------------------- iran (entry: the website)

# where one site's files live; render-site sets them explicitly (the lab renders the real site into its own tree)
site_paths() { WEBDIR=$WWW/$NAME; ACMEDIR=$ACME/$NAME; AUTHFILE=$NGX_AUTH/$NAME.auth.conf; }

# routes_text SPEC: an NGINX location per --route entry. Only WebSocket upgrades pass; anything else on the path
# answers as a missing page does. X-Forwarded-For carries the user's address to the inbound behind the tunnel.
routes_text() {
  local r path rest lport upath
  for r in ${1//,/ }; do
    path=${r%%=*}; rest=${r#*=}; lport=${rest%%/*}; upath=""
    if [[ "$rest" == */* ]]; then upath=/${rest#*/}; fi
    cat <<EOF
    location = $path {
        if (\$http_upgrade !~* ^websocket\$) { return 404; }
        proxy_pass http://127.0.0.1:$lport$upath;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_connect_timeout 5s;
        # a client's WebSocket may sit idle for long stretches; NGINX must not be the one that drops it
        proxy_send_timeout 1d;
        proxy_read_timeout 1d;
        proxy_buffering off;
        proxy_buffer_size 64k;
        proxy_buffers 4 64k;
        proxy_busy_buffers_size 128k;
        access_log off;
    }
EOF
  done
}

# http_text: the port-80 site (ACME files, everything else redirected to HTTPS), or nothing for "none".
http_text() {
  [ "$HTTP" = none ] && return 0
  cat <<EOF
server {
    listen $HTTP backlog=4096;
    server_name $DOMAIN;
    server_tokens off;
    location ^~ /.well-known/acme-challenge/ { root $ACMEDIR; default_type text/plain; try_files \$uri =404; }
    location / { return 301 https://$DOMAIN\$request_uri; }
}
EOF
}

site_text() {
  RNT_NAME=$NAME RNT_DOMAIN=$DOMAIN RNT_LISTEN=$LISTEN RNT_BACKEND=$BACKEND RNT_CERT=$CERT RNT_KEY=$KEY \
    RNT_ROOT=$WEBDIR RNT_AUTH=$AUTHFILE RNT_ROUTES="$(routes_text "$ROUTES")" RNT_HTTP_SERVER="$(http_text)" \
    render "$HERE/nginx/site.conf.tmpl"
}

site_apply() { local txt; txt=$(site_text) || die "cannot render the site"; nginx_install "/etc/nginx/sites-available/hwt-rnt-$NAME.conf" "$txt"; }

save_state() {
  put "$ETC/$NAME/site.env" 0600 root:root <<EOF
DOMAIN=$DOMAIN
LISTEN=$LISTEN
BACKEND=$BACKEND
HTTP=$HTTP
ROUTES=$ROUTES
CERT=$CERT
KEY=$KEY
EOF
}

load_state() {
  [ -f "$ETC/$NAME/site.env" ] || die "$NAME is not an entry installed by rnt.sh"
  local k v
  while IFS='=' read -r k v; do case "$k" in
    DOMAIN) DOMAIN=$v;; LISTEN) LISTEN=$v;; BACKEND) BACKEND=$v;; HTTP) HTTP=$v;; ROUTES) ROUTES=$v;;
    CERT) CERT=$v;; KEY) KEY=$v;; esac; done < "$ETC/$NAME/site.env"
}

# A Let's Encrypt certificate for DOMAIN that is good for at least another week.
le_valid() { [ -s "/etc/letsencrypt/live/$1/fullchain.pem" ] && openssl x509 -checkend 604800 -noout -in "/etc/letsencrypt/live/$1/fullchain.pem" >/dev/null 2>&1; }

# get_le: obtain the site's own certificate through its ACME webroot (dry run first), then point the site at it.
get_le() {
  local a=(certonly --webroot -w "$ACMEDIR" -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring)
  local out rc=0
  if ! le_valid "$DOMAIN"; then
    say "certificate: Let's Encrypt dry run (staging) for $DOMAIN"
    out=$(certbot "${a[@]}" --dry-run </dev/null 2>&1) || rc=$?
    printf '%s\n' "$out" | tail -3 | sed 's/^/  /'
    [ $rc = 0 ] || die "the ACME dry run failed (http://$DOMAIN/.well-known/acme-challenge/ must reach this server); the site keeps its current certificate"
    out=$(certbot "${a[@]}" </dev/null 2>&1) || rc=$?
    printf '%s\n' "$out" | grep -iE 'success|saved|error' | head -3 | sed 's/^/  /'
    le_valid "$DOMAIN" || die "no certificate after certbot"
  fi
  CERT=/etc/letsencrypt/live/$DOMAIN/fullchain.pem; KEY=/etc/letsencrypt/live/$DOMAIN/privkey.pem
  put /etc/letsencrypt/renewal-hooks/deploy/hwt-rnt-nginx-reload.sh 0755 root:root <<'EOF'
#!/bin/sh
# HoneyWeb Reverse Nginx Tunnel: pick up a renewed certificate (open connections stay on the old workers).
systemctl reload nginx
EOF
  systemctl is-active --quiet certbot.timer || systemctl enable --now certbot.timer >/dev/null 2>&1 || true
  save_state; site_apply
  say "certificate: $(openssl x509 -noout -issuer -enddate -in "$CERT" | tr '\n' ' ')"
}

site_probe() { # site_probe CA: the site as a site, and the tunnel paths as missing pages
  local port=${LISTEN##*:} laddr=127.0.0.1 copt=() r_site r_chan
  if [[ "$LISTEN" == *:* ]]; then laddr=${LISTEN%:*}; fi
  if [ -n "$1" ]; then copt=(--cacert "$1"); fi
  r_site=$(curl -sS -o /dev/null -m 5 -w '%{http_code}' "${copt[@]}" --resolve "$DOMAIN:$port:$laddr" "https://$DOMAIN:$port/" 2>&1 || true)
  r_chan=$(curl -sS -o /dev/null -m 5 -w '%{http_code}' "${copt[@]}" --resolve "$DOMAIN:$port:$laddr" -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
    -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: cm50LWhlYWx0aC1wcm9iZQ==' "https://$DOMAIN:$port/channel" 2>&1 || true)
  echo "  probe /: $r_site (want 200)   /channel without the token: $r_chan (want 404)"
  [ "$r_site" = 200 ] && [ "$r_chan" = 404 ]
}

iran() {
  local map="" muxcon=8 ca="" check=0 acme=0 udp=0 cert_in="" key_in=""
  NAME=""; DOMAIN=""; LISTEN=""; BACKEND=""; ROUTES=""; HTTP=80
  while [ $# -gt 0 ]; do case "$1" in
    --name) NAME=$2; shift 2;; --domain) DOMAIN=$2; shift 2;; --listen) LISTEN=$2; shift 2;;
    --backend) BACKEND=$2; shift 2;; --map) map=$2; shift 2;; --route) ROUTES=$2; shift 2;; --http) HTTP=$2; shift 2;;
    --cert) cert_in=$2; shift 2;; --key) key_in=$2; shift 2;; --acme) acme=1; shift;; --udp) udp=1; shift;;
    --mux-con) muxcon=$2; shift 2;; --ca-file) ca=$2; shift 2;; --check-only) check=1; shift;;
    *) die "unknown option $1";; esac; done
  need name "$NAME" "$RE_NAME"; need domain "$DOMAIN" "$RE_DOMAIN"; need listen "$LISTEN" "$RE_LISTEN"
  need backend "$BACKEND" '^[0-9]{4,5}$'; need mux-con "$muxcon" '^[0-9]{1,3}$'
  [ "$HTTP" = none ] || need http "$HTTP" "$RE_LISTEN"
  [ -n "$map" ] || die "--map is required"
  local m r u a ports="" loopback=" "
  for m in ${map//,/ }; do need map "$m" "$RE_MAP"; done
  for r in ${ROUTES//,/ }; do need route "$r" "$RE_ROUTE"; done
  if [ $acme = 0 ] && { [ -z "$cert_in" ] || [ -z "$key_in" ]; }; then die "give --cert and --key, or --acme"; fi
  # Relative paths are files that came with this script (a carried certificate, say).
  if [ -n "$cert_in" ] && [[ "$cert_in" != /* ]]; then cert_in=$HERE/$cert_in; fi
  if [ -n "$key_in" ] && [[ "$key_in" != /* ]]; then key_in=$HERE/$key_in; fi
  if [ -n "$ca" ] && [[ "$ca" != /* ]]; then ca=$HERE/$ca; fi
  local port=${LISTEN##*:}
  read_token; site_paths

  say "preflight (iran: $DOMAIN on $LISTEN, engine on 127.0.0.1:$BACKEND)"
  local bad=0
  command -v nginx >/dev/null || { echo "  nginx is not installed (apt-get install nginx)"; bad=1; }
  if [ $acme = 1 ] && ! command -v certbot >/dev/null; then echo "  certbot is not installed (apt-get install certbot)"; bad=1; fi
  if [ -n "$cert_in$key_in" ] && { [ ! -s "$cert_in" ] || [ ! -s "$key_in" ]; }; then echo "  certificate or key missing: $cert_in $key_in"; bad=1; fi
  if ! port_free "$port" && [[ "$(port_owner "$port")" != *nginx* ]]; then echo "  port $port is held by $(port_owner "$port")"; bad=1; fi
  if [ "$HTTP" != none ] && ! port_free "${HTTP##*:}" && [[ "$(port_owner "${HTTP##*:}")" != *nginx* ]]; then echo "  port ${HTTP##*:} is held by $(port_owner "${HTTP##*:}")"; bad=1; fi
  if ! port_free "$BACKEND" && [[ "$(port_owner "$BACKEND")" != *hwtunnel* ]]; then echo "  backend port $BACKEND is held by $(port_owner "$BACKEND")"; bad=1; fi
  for m in ${map//,/ }; do
    u=${m%%=*}; a=0.0.0.0
    if [[ "$u" == *:* ]]; then a=${u%:*}; u=${u##*:}; fi
    if [ "$u" = "$port" ] || { [ "$HTTP" != none ] && [ "$u" = "${HTTP##*:}" ]; }; then echo "  user port $u is one of the site's own ports"; bad=1; fi
    if ! port_free "$u" && [[ "$(port_owner "$u")" != *hwtunnel* ]]; then echo "  user port $u is held by $(port_owner "$u")"; bad=1; fi
    if [ "$a" = 127.0.0.1 ]; then loopback+="$u "; fi
    ports+="\"$a:$u=${m#*=}\", "; done
  for r in ${ROUTES//,/ }; do u=${r#*=}; u=${u%%/*}
    [[ "$loopback" == *" $u "* ]] || { echo "  route $r points at $u, which is not a --map entry on 127.0.0.1"; bad=1; }; done
  if [ ! -f "$HERE/nginx/site.conf.tmpl" ] || [ ! -f "$HERE/nginx/auth.conf.tmpl" ] || [ ! -d "$HERE/site" ]; then
    echo "  nginx templates or site/ missing next to rnt.sh"; bad=1; fi
  if [ -n "$ca" ] && [ ! -s "$ca" ]; then echo "  --ca-file $ca missing"; bad=1; fi
  echo "  nginx: $(nginx -v 2>&1 | sed 's/.*: //')  active=$(systemctl is-active nginx 2>/dev/null || true)"
  [ $bad = 0 ] || die "preflight failed; nothing was changed"
  if [ $check = 1 ]; then say "check only: ready; nothing was changed"; return; fi

  install_engine; ensure_user; nginx_capacity
  local udpline=""; if [ $udp = 1 ]; then udpline="accept_udp = true"; fi
  put "$ETC/$NAME/server.toml" 0640 root:hwtunnel <<EOF
# HoneyWeb Reverse Nginx Tunnel $NAME: entry. Only NGINX reaches this listener.
[server]
bind_addr = "127.0.0.1:$BACKEND"
transport = "wsmux"
token = "$TOKEN"
skip_optz = true
log_level = "info"
$PROFILE
mux_con = $muxcon
$udpline
ports = [${ports%, }]
EOF
  "$BIN" check -c "$ETC/$NAME/server.toml" >/dev/null || die "the engine refused the server config"

  # The website (kept if it already exists, so a customised site survives a reinstall) and its ACME webroot.
  if [ ! -d "$WEBDIR" ]; then mkdir -p "$WEBDIR"; cp -a "$HERE/site/." "$WEBDIR/"; touch "$WEBDIR/.hwt-rnt"; fi
  mkdir -p "$ACMEDIR"; chmod -R a+rX "$WEBDIR" "$ACMEDIR"

  # The access map: who may reach the tunnel (root only; the token is in it).
  local atxt; atxt=$(RNT_NAME=$NAME RNT_TOKEN=$TOKEN render "$HERE/nginx/auth.conf.tmpl") || die "cannot render the access map"
  printf '%s\n' "$atxt" | put "$AUTHFILE" 0600 root:root

  # Certificate: a given one is kept under our own directory (the payload is temporary); --acme starts on a
  # placeholder only when nothing better exists, and switches as soon as Let's Encrypt has issued.
  if [ -n "$cert_in" ]; then
    install -D -m 0644 -o root -g root "$cert_in" "$ETC/$NAME/tls/fullchain.pem"
    install -D -m 0600 -o root -g root "$key_in" "$ETC/$NAME/tls/privkey.pem"
    CERT=$ETC/$NAME/tls/fullchain.pem; KEY=$ETC/$NAME/tls/privkey.pem
  elif le_valid "$DOMAIN"; then
    CERT=/etc/letsencrypt/live/$DOMAIN/fullchain.pem; KEY=/etc/letsencrypt/live/$DOMAIN/privkey.pem
  else
    CERT=$ETC/$NAME/tls/placeholder.pem; KEY=$ETC/$NAME/tls/placeholder.key; mkdir -p "$ETC/$NAME/tls"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3 -subj "/CN=$DOMAIN" \
      -addext "subjectAltName=DNS:$DOMAIN" -keyout "$KEY" -out "$CERT" >/dev/null 2>&1 || die "cannot make the placeholder certificate"
    chmod 600 "$KEY"
  fi
  save_state; site_apply
  say "nginx: site $DOMAIN on $LISTEN$( [ "$HTTP" = none ] || echo " and $HTTP")"
  if [ $acme = 1 ]; then get_le; fi

  local caps=""
  for m in ${map//,/ }; do u=${m%%=*}; u=${u##*:}; if [ "$u" -lt 1024 ]; then caps=CAP_NET_BIND_SERVICE; fi; done
  write_unit "$NAME" server "$caps"
  systemctl daemon-reload; systemctl enable "$(unit "$NAME")" >/dev/null 2>&1; systemctl restart "$(unit "$NAME")"

  # Health: the engine answers on loopback, the site answers as a site, and the tunnel paths are invisible
  # without the token. User ports open only once the exit's control channel is up (engine behaviour).
  local i ok=0
  for i in $(seq 1 30); do if [ -n "$(ss -Htln "( sport = :$BACKEND )")" ]; then ok=1; break; fi; sleep 0.5; done
  [ $ok = 1 ] || { journalctl -u "$(unit "$NAME")" -n 20 --no-pager | sed 's/^/  /'; die "the engine is not listening on 127.0.0.1:$BACKEND"; }
  site_probe "$ca" || die "health probe failed (rollback: rnt.sh remove $NAME)"
  self_install
  say "IRAN_OK $NAME: waiting for the exit; mapped ports open when it connects"
}

acme() {
  NAME=${1:-}; need name "$NAME" "$RE_NAME"; load_state; site_paths
  command -v certbot >/dev/null || die "certbot is not installed (apt-get install certbot)"
  [ "$HTTP" != none ] || die "$NAME serves no port 80, so the HTTP challenge cannot reach it"
  get_le
  site_probe "" || die "the site does not answer properly on its new certificate"
  say "ACME_OK $NAME"
}

# ---------------------------------------------------------------- kharej (exit: the site's visitor)

# out_text: the exit's loopback NGINX server that carries the engine's connections to the entry's site.
out_text() {
  local bind=""; if [ -n "$OUT_BIND" ]; then bind="        proxy_bind $OUT_BIND;"; fi
  RNT_NAME=$NAME RNT_DOMAIN=$DOMAIN RNT_LISTEN_PORT=$OUT_PORT RNT_UPSTREAM=$OUT_UPSTREAM RNT_CA=$OUT_CA RNT_BIND="$bind" \
    render "$HERE/nginx/out.conf.tmpl"
}

kharej() {
  local port="" edge="" laddr="" pool=64 ca="" check=0 stage=0 via=""
  NAME=""; DOMAIN=""
  while [ $# -gt 0 ]; do case "$1" in
    --name) NAME=$2; shift 2;; --domain) DOMAIN=$2; shift 2;; --port) port=$2; shift 2;;
    --edge-ip) edge=$2; shift 2;; --local-addr) laddr=$2; shift 2;; --pool) pool=$2; shift 2;;
    --ca-file) ca=$2; shift 2;; --via-nginx) via=$2; shift 2;; --stage) stage=1; shift;; --check-only) check=1; shift;;
    *) die "unknown option $1";; esac; done
  need name "$NAME" "$RE_NAME"; need domain "$DOMAIN" "$RE_DOMAIN"
  need port "$port" '^[0-9]{1,5}$'; need pool "$pool" '^[0-9]{1,4}$'
  [ -z "$edge" ] || need edge-ip "$edge" "$RE_IP"
  [ -z "$laddr" ] || need local-addr "$laddr" "$RE_IP"
  [ -z "$via" ] || need via-nginx "$via" '^[0-9]{4,5}$'
  if [ -n "$ca" ] && [[ "$ca" != /* ]]; then ca=$HERE/$ca; fi
  read_token

  say "preflight (kharej: https://$DOMAIN:$port${edge:+ via $edge}${laddr:+ from $laddr}${via:+ through nginx 127.0.0.1:$via}, pool $pool)"
  local bad=0
  if [ -n "$laddr" ] && ! ip -4 -o addr show | grep -q " $laddr/"; then echo "  $laddr is not an address of this host"; bad=1; fi
  if [ -n "$ca" ] && [ ! -s "$ca" ]; then echo "  --ca-file $ca missing"; bad=1; fi
  if [ -n "$via" ]; then
    command -v nginx >/dev/null || { echo "  --via-nginx needs nginx (apt-get install nginx)"; bad=1; }
    [ -f "$HERE/nginx/out.conf.tmpl" ] || { echo "  nginx/out.conf.tmpl missing next to rnt.sh"; bad=1; }
    if ! port_free "$via" && [[ "$(port_owner "$via")" != *nginx* ]]; then echo "  port $via is held by $(port_owner "$via")"; bad=1; fi
    if [ -z "$ca" ] && [ ! -s "$SYSTEM_CA" ]; then echo "  no system CA bundle at $SYSTEM_CA"; bad=1; fi
  fi
  local copt=() r
  if [ -n "$ca" ]; then copt+=(--cacert "$ca"); fi
  if [ -n "$edge" ]; then copt+=(--resolve "$DOMAIN:$port:$edge"); fi
  if [ -n "$laddr" ]; then copt+=(--interface "$laddr"); fi
  r=$(curl -sS -o /dev/null -m 8 -w '%{http_code} %{ssl_verify_result}' "${copt[@]}" "https://$DOMAIN:$port/" 2>&1 || true)
  echo "  the site from here: $r (want 200 0: page served, certificate valid)"
  [[ "$r" == "200 0" ]] || { echo "  the site is not reachable with a valid certificate"; bad=1; }
  [ $bad = 0 ] || die "preflight failed; nothing was changed"
  if [ $check = 1 ]; then say "check only: ready; nothing was changed"; return; fi

  install_engine; ensure_user
  local conf
  if [ -n "$via" ]; then
    # The exit's own NGINX visits the site; the engine only speaks plain WebSocket to it over loopback.
    nginx_capacity
    if [ -n "$ca" ]; then install -D -m 0644 "$ca" "$ETC/$NAME/ca.pem"; OUT_CA=$ETC/$NAME/ca.pem; else OUT_CA=$SYSTEM_CA; fi
    OUT_PORT=$via; OUT_UPSTREAM=${edge:-$DOMAIN}:$port; OUT_BIND=$laddr
    local otxt; otxt=$(out_text) || die "cannot render the exit's nginx server"
    nginx_install "/etc/nginx/sites-available/hwt-rnt-$NAME-out.conf" "$otxt"
    say "nginx: 127.0.0.1:$via -> https://$DOMAIN:$port (${edge:-DNS})${laddr:+ from $laddr}"
    conf="remote_addr = \"127.0.0.1:$via\"
transport = \"wsmux\""
  else
    local cafile="" edgeline="" laddrline=""
    if [ -n "$ca" ]; then install -D -m 0644 "$ca" "$ETC/$NAME/ca.pem"; cafile="tls_ca_file = \"$ETC/$NAME/ca.pem\""; fi
    if [ -n "$edge" ]; then edgeline="edge_ip = \"$edge\""; fi
    if [ -n "$laddr" ]; then laddrline="local_addr = \"$laddr\""; fi
    conf="remote_addr = \"$DOMAIN:$port\"
$edgeline
$laddrline
transport = \"wssmux\"
simple_auth = true
tls_verify = true
$cafile"
  fi
  put "$ETC/$NAME/client.toml" 0640 root:hwtunnel <<EOF
# HoneyWeb Reverse Nginx Tunnel $NAME: exit. Visits the entry's website and keeps a pool of connections to it.
[client]
$conf
token = "$TOKEN"
connection_pool = $pool
skip_optz = true
log_level = "info"
$PROFILE
EOF
  "$BIN" check -c "$ETC/$NAME/client.toml" >/dev/null || die "the engine refused the client config"
  write_unit "$NAME" client ""
  systemctl daemon-reload; systemctl enable "$(unit "$NAME")" >/dev/null 2>&1
  self_install
  if [ $stage = 1 ]; then say "STAGED $NAME: installed and enabled, not started (rnt.sh start $NAME)"; return; fi
  start "$NAME"
}

start() {
  local name=${1:-}; need name "$name" "$RE_NAME"
  systemctl restart "$(unit "$name")"
  [ -f "$ETC/$name/client.toml" ] || { say "STARTED $name"; return; }
  # Health: the pool fills (control channel + pool sessions) within a minute.
  local p pool i n=0
  p=$(sed -n -E 's/^remote_addr = ".*:([0-9]+)"/\1/p' "$ETC/$name/client.toml")
  pool=$(sed -n -E 's/^connection_pool = ([0-9]+)/\1/p' "$ETC/$name/client.toml")
  for i in $(seq 1 60); do n=$(engine_sessions "$p"); [ "$n" -ge $((pool + 1)) ] && break; sleep 1; done
  echo "  engine sessions: $n (want $((pool + 1)): control + pool)"
  if [ -f "/etc/nginx/sites-available/hwt-rnt-$name-out.conf" ]; then
    local up; up=$(sed -n -E 's/^\s*proxy_pass https:\/\/[^:]+:([0-9]+);/\1/p' "/etc/nginx/sites-available/hwt-rnt-$name-out.conf")
    echo "  nginx connections to the entry: $(ss -Htnp state established "( dport = :$up )" 2>/dev/null | grep -c '"nginx"' || true)"
  fi
  if [ "$n" -lt 1 ]; then journalctl -u "$(unit "$name")" -n 25 --no-pager | sed 's/^/  /'; die "no session reached the entry (rollback: rnt.sh remove $name)"; fi
  say "KHAREJ_OK $name: $n sessions"
}

# ---------------------------------------------------------------- speedtest / self-install

# iperf_run PORT SECONDS STREAMS [-R]: Mbps received by iperf3 through 127.0.0.1:PORT, or "error".
iperf_run() {
  timeout $(( $2 + 20 )) iperf3 -c 127.0.0.1 -p "$1" -t "$2" -P "$3" ${4:-} -J 2>/dev/null | python3 -c '
import json, sys
try:
    print(round(json.load(sys.stdin)["end"]["sum_received"]["bits_per_second"] / 1e6, 1))
except Exception:
    print("error")' || true
  sleep 2
}

# speedtest NAME: how much the tunnel itself carries, measured on the entry. iperf3 runs to the mapped test port (a
# --map entry whose target is the exit's iperf3 on 5201, e.g. 7070=5201), so the traffic crosses only the tunnel.
# It shows iperf3's own second-by-second output for the download (the exit sends, -R) and then the upload, and a
# summary at the end. --streams N runs N parallel connections (default 1); --steps 1,4,8,16 instead runs one short
# download+upload per value and prints a table, to find where the tunnel stops scaling. Each run is real load on
# the link; the exit's iperf3 serves one client at a time.
speedtest() {
  local name=${1:-}; shift || true; need name "$name" "$RE_NAME"
  local secs=10 streams=1 steps="" inst=0
  while [ $# -gt 0 ]; do case "$1" in
    --seconds) secs=$2; shift 2;; --streams) streams=$2; shift 2;; --steps) steps=$2; shift 2;;
    --install-iperf) inst=1; shift;; *) die "unknown option $1";; esac; done
  need seconds "$secs" '^[0-9]{1,2}$'; need streams "$streams" '^[0-9]{1,3}$'
  [ -z "$steps" ] || need steps "$steps" '^[0-9]{1,3}(,[0-9]{1,3})*$'
  [ -f "$ETC/$name/server.toml" ] || die "speedtest runs on the entry server ($ETC/$name/server.toml not found)"
  local port; port=$({ grep -oE '"[0-9.]+:[0-9]+=(127\.0\.0\.1:)?5201"' "$ETC/$name/server.toml" || true; } | head -1 | sed -E 's/^"[0-9.]+:([0-9]+)=.*/\1/')
  [ -n "$port" ] || die "no test port: add a --map entry to the exit's iperf3 (for example 7070=5201) and run iperf3 -s on the exit"
  if ! command -v iperf3 >/dev/null; then
    [ $inst = 1 ] || die "iperf3 is not installed here (add --install-iperf, or apt-get install iperf3)"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q iperf3 >/dev/null 2>&1 || die "apt-get install iperf3 failed"
  fi
  if [ -n "$steps" ]; then
    say "speedtest $name: 127.0.0.1:$port -> tunnel -> exit iperf3, ${secs}s per run (real load on the link)"
    printf '  %-8s %15s %15s\n' streams "download Mbps" "upload Mbps"
    local n d u bd=0 bu=0
    for n in ${steps//,/ }; do
      d=$(iperf_run "$port" "$secs" "$n" -R); u=$(iperf_run "$port" "$secs" "$n")
      printf '  %-8s %15s %15s\n' "$n" "$d" "$u"
      bd=$(awk -v a="$bd" -v b="$d" 'BEGIN { print (b + 0 > a + 0) ? b : a }')
      bu=$(awk -v a="$bu" -v b="$u" 'BEGIN { print (b + 0 > a + 0) ? b : a }')
    done
    say "SPEEDTEST $name: best download $bd Mbps, best upload $bu Mbps (if the last row is still the best, more streams may go higher)"
    return
  fi
  local d u
  say "download through the tunnel (exit -> entry), $streams stream(s), ${secs}s"
  d=$(timeout $(( secs + 20 )) iperf3 -c 127.0.0.1 -p "$port" -t "$secs" -P "$streams" -R --forceflush 2>&1 | tee /dev/stderr | awk '/receiver/ {v=$(NF-2) " " $(NF-1)} END {print v}') || true
  sleep 2
  say "upload through the tunnel (entry -> exit), $streams stream(s), ${secs}s"
  u=$(timeout $(( secs + 20 )) iperf3 -c 127.0.0.1 -p "$port" -t "$secs" -P "$streams" --forceflush 2>&1 | tee /dev/stderr | awk '/receiver/ {v=$(NF-2) " " $(NF-1)} END {print v}') || true
  say "SPEEDTEST $name ($streams stream(s)): download ${d:-error}, upload ${u:-error}"
}

# self-install: keep this script and its templates on the server (/opt/hwt-rnt, command hwt-rnt) for status,
# speedtest, acme and remove later. No service is started, stopped or reloaded.
self_install() {
  local d=/opt/hwt-rnt
  install -d -m 0755 "$d" "$d/nginx"
  if [ "$HERE" != "$d" ]; then
    install -m 0755 "$HERE/rnt.sh" "$d/rnt.sh"
    cp -f "$HERE"/nginx/*.tmpl "$d/nginx/"
    if [ -d "$HERE/site" ]; then rm -rf "$d/site"; cp -a "$HERE/site" "$d/site"; fi
  fi
  ln -sfn "$d/rnt.sh" /usr/local/bin/hwt-rnt
  say "installed: hwt-rnt (status | speedtest | acme | remove)"
}

# ---------------------------------------------------------------- render (print only, no root needed)

# render-site: the site rnt.sh iran would install, with its paths given explicitly.
#   --name --domain --listen --backend --cert --key --root --acme-root --auth [--route] [--http]
render_site() {
  NAME=""; DOMAIN=""; LISTEN=""; BACKEND=""; CERT=""; KEY=""; ROUTES=""; HTTP=none; WEBDIR=""; ACMEDIR=""; AUTHFILE=""
  while [ $# -gt 1 ]; do case "$1" in
    --name) NAME=$2;; --domain) DOMAIN=$2;; --listen) LISTEN=$2;; --backend) BACKEND=$2;; --cert) CERT=$2;; --key) KEY=$2;;
    --route) ROUTES=$2;; --http) HTTP=$2;; --root) WEBDIR=$2;; --acme-root) ACMEDIR=$2;; --auth) AUTHFILE=$2;;
    *) die "unknown option $1";; esac; shift 2; done
  need name "$NAME" "$RE_NAME"; need domain "$DOMAIN" "$RE_DOMAIN"; need listen "$LISTEN" "$RE_LISTEN"
  need backend "$BACKEND" '^[0-9]{4,5}$'; [ "$HTTP" = none ] || need http "$HTTP" "$RE_LISTEN"
  local r; for r in ${ROUTES//,/ }; do need route "$r" "$RE_ROUTE"; done
  for r in "$CERT" "$KEY" "$WEBDIR" "$ACMEDIR" "$AUTHFILE"; do need path "$r" "$RE_PATH"; done
  site_text
}

# render-auth NAME: the access map for the token next to rnt.sh.
render_auth() { NAME=${1:-}; need name "$NAME" "$RE_NAME"; read_token; RNT_NAME=$NAME RNT_TOKEN=$TOKEN render "$HERE/nginx/auth.conf.tmpl"; }

# render-out: the exit's NGINX server. --name --domain --listen-port --upstream HOST:PORT --ca FILE [--bind IP]
render_out() {
  NAME=""; DOMAIN=""; OUT_PORT=""; OUT_UPSTREAM=""; OUT_CA=""; OUT_BIND=""
  while [ $# -gt 1 ]; do case "$1" in
    --name) NAME=$2;; --domain) DOMAIN=$2;; --listen-port) OUT_PORT=$2;; --upstream) OUT_UPSTREAM=$2;; --ca) OUT_CA=$2;; --bind) OUT_BIND=$2;;
    *) die "unknown option $1";; esac; shift 2; done
  need name "$NAME" "$RE_NAME"; need domain "$DOMAIN" "$RE_DOMAIN"; need listen-port "$OUT_PORT" '^[0-9]{4,5}$'
  need upstream "$OUT_UPSTREAM" '^[A-Za-z0-9.-]+:[0-9]{1,5}$'; need ca "$OUT_CA" "$RE_PATH"
  [ -z "$OUT_BIND" ] || need bind "$OUT_BIND" "$RE_IP"
  out_text
}

# ---------------------------------------------------------------- stop / menu

stop() { local name=${1:-}; need name "$name" "$RE_NAME"; systemctl disable --now "$(unit "$name")" >/dev/null 2>&1 || true; say "STOPPED $name (start it again with: hwt-rnt start $name)"; }

ask() { # ask VAR "question" [default]
  local _a; read -r -p "  $2${3:+ [$3]}: " _a </dev/tty || true; printf -v "$1" '%s' "${_a:-${3:-}}"; }
yes_no() { local _a; read -r -p "  $1 [${2:-y}/n]: " _a </dev/tty || true; [[ "${_a:-${2:-y}}" =~ ^[Yy] ]]; }
tunnels() { ls "$ETC" 2>/dev/null | tr '\n' ' '; }
pick() { local d; d=$(ls "$ETC" 2>/dev/null | head -1); ask "$1" "tunnel name" "$d"; }

menu_iran() {
  local name domain listen backend maps route rpath rport tport cert key args
  echo "== entry server (Iran): an HTTPS website with the tunnel behind it"
  ask name "tunnel name (a-z, 0-9, _)" t1; ask domain "the site's domain (its A record points here)"
  ask listen "HTTPS port of the site" 443; ask backend "engine's loopback port" 19443
  ask maps "user ports to carry, PORT=PORT_ON_EXIT, comma separated (e.g. 8443=8443,22281=22281)"
  ask rpath "a WebSocket path of the site to hand into the tunnel (panel host path), blank for none"
  if [ -n "$rpath" ]; then
    ask rport "the exit's port for that path (its WS inbound, e.g. 62018)"
    maps="127.0.0.1:20218=$rport${maps:+,$maps}"; route="$rpath=20218"; if yes_no "send the inbound path \"/\" instead of $rpath?"; then route+="/"; fi
  fi
  if yes_no "add test port 7070 for speedtest (needs iperf3 -s on the exit)?"; then maps="${maps:+$maps,}7070=5201"; fi
  if [ ! -s "$HERE/token" ]; then (umask 077; openssl rand -hex 32 > "$HERE/token"); fi
  args=(--name "$name" --domain "$domain" --listen "$listen" --backend "$backend" --map "$maps")
  [ -z "${route:-}" ] || args+=(--route "$route")
  if yes_no "get a Let's Encrypt certificate now (port 80 of this server must be reachable)?"; then args+=(--acme)
  else ask cert "certificate chain file (fullchain.pem)"; ask key "private key file"; args+=(--cert "$cert" --key "$key"); fi
  iran "${args[@]}"
  echo; echo "  On the exit server, run the installer, choose 2, and paste this token (keep it secret):"
  echo "  $(cat "$HERE/token")"
}

menu_kharej() {
  local name domain port edge laddr pool via tok args
  echo "== exit server (abroad): visits the entry's site and carries its users"
  ask name "tunnel name (the same as on the entry)" t1; ask domain "the entry site's domain"
  ask port "the site's HTTPS port" 443; ask edge "the entry server's IP (blank: use DNS)"
  ask laddr "source IP for the tunnel's connections (blank: default)"; ask pool "connections in the pool" 512
  ask tok "the token printed by the entry"
  [[ "$tok" =~ ^[A-Za-z0-9_-]{32,128}$ ]] || die "that is not a token"
  (umask 077; printf '%s\n' "$tok" > "$HERE/token")
  args=(--name "$name" --domain "$domain" --port "$port" --pool "$pool")
  [ -z "$edge" ] || args+=(--edge-ip "$edge"); [ -z "$laddr" ] || args+=(--local-addr "$laddr")
  if yes_no "visit the site through this server's own NGINX (recommended; installs nginx if missing)?"; then
    command -v nginx >/dev/null || { DEBIAN_FRONTEND=noninteractive apt-get install -y -q nginx >/dev/null; }
    args+=(--via-nginx 19443); fi
  kharej "${args[@]}"
}

menu() {
  local c n
  while true; do
    echo; echo "== HoneyWeb Reverse Nginx Tunnel    installed: $(tunnels)"
    echo "  1) install entry (Iran: website + tunnel)     2) install exit (abroad: visits the site)"
    echo "  3) status      4) speed test (entry)      5) Let's Encrypt certificate (entry)"
    echo "  6) restart     7) stop                    8) remove                0) quit"
    read -r -p "  choose: " c </dev/tty || return 0
    case "$c" in
      1) ( menu_iran ) || true;; 2) ( menu_kharej ) || true;;
      3) pick n; ( status "$n" ) || true;;
      4) pick n; local st; ask st "parallel streams" 8; ( speedtest "$n" --streams "$st" --install-iperf ) || true;;
      5) pick n; ( acme "$n" ) || true;;
      6) pick n; ( start "$n" ) || true;; 7) pick n; ( stop "$n" ) || true;;
      8) pick n; if yes_no "remove $n completely (a backup is kept)?" n; then ( remove "$n" ) || true; fi;;
      0|q) return 0;; *) echo "  ?";;
    esac
  done
}

# ---------------------------------------------------------------- status / remove

status() {
  local name=${1:-}; need name "$name" "$RE_NAME"
  local u; u=$(unit "$name")
  echo "== $name: $(systemctl is-active "$u" 2>/dev/null || true) since $(systemctl show -p ActiveEnterTimestamp --value "$u" 2>/dev/null || true)"
  if [ -f "$ETC/$name/server.toml" ]; then
    local b; b=$(sed -n 's/^bind_addr = "127.0.0.1:\([0-9]*\)"/\1/p' "$ETC/$name/server.toml")
    echo "  role entry; engine 127.0.0.1:$b; sessions from nginx: $(ss -Htn state established "( sport = :$b )" | wc -l)"
    { grep -oE '"[0-9.]+:[0-9]+=[^"]*"' "$ETC/$name/server.toml" || true; } | tr -d '"' | while IFS='=' read -r l t; do
      echo "  port ${l} -> exit $t: $( [ -n "$(ss -Htln "( sport = :${l##*:} )")" ] && echo listening || echo closed), $(ss -Htn state established "( sport = :${l##*:} )" | wc -l) connections"; done
    if [ -f "$ETC/$name/site.env" ]; then
      local c; c=$(sed -n 's/^CERT=//p' "$ETC/$name/site.env")
      echo "  certificate: $c $(openssl x509 -noout -enddate -in "$c" 2>/dev/null || true)"
    fi
  elif [ -f "$ETC/$name/client.toml" ]; then
    local p; p=$(sed -n -E 's/^remote_addr = ".*:([0-9]+)"/\1/p' "$ETC/$name/client.toml")
    echo "  role exit; engine sessions: $(engine_sessions "$p")"
  else echo "  not installed"; fi
  echo "  errors in the last 10 min: $(journalctl -u "$u" --since -10min --no-pager 2>/dev/null | grep -ciE 'error|fail' || true)"
}

remove() {
  local name=${1:-}; need name "$name" "$RE_NAME"
  local u f reload=0; u=$(unit "$name")
  say "remove $name"
  backup "/etc/systemd/system/$u" "$ETC/$name" "/etc/nginx/sites-available/hwt-rnt-$name.conf" \
    "/etc/nginx/sites-available/hwt-rnt-$name-out.conf" "$NGX_AUTH/$name.auth.conf"
  systemctl disable --now "$u" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$u"; systemctl daemon-reload
  rm -rf "${ETC:?}/$name"
  for f in "hwt-rnt-$name.conf" "hwt-rnt-$name-out.conf"; do
    if [ -f "/etc/nginx/sites-available/$f" ]; then rm -f "/etc/nginx/sites-enabled/$f" "/etc/nginx/sites-available/$f"; reload=1; fi
  done
  rm -f "$NGX_AUTH/$name.auth.conf"
  if [ -f "$WWW/$name/.hwt-rnt" ]; then rm -rf "${WWW:?}/$name"; fi
  rm -rf "${ACME:?}/$name"
  if [ $reload = 1 ] && nginx -t >/dev/null 2>&1; then systemctl reload nginx; echo "  nginx sites removed and reloaded"; fi
  ls "$ETC" 2>/dev/null | grep -q . || { rm -f "$BIN"; echo "  last tunnel: engine removed"; }
  say "REMOVED $name (backup $BACKUP)"
}

cmd=${1:-}; shift || true
case "$cmd" in
  render-site) render_site "$@"; exit;; render-auth) render_auth "$@"; exit;; render-out) render_out "$@"; exit;;
esac
[ "$(id -u)" = 0 ] || die "run as root"
case "$cmd" in
  iran) iran "$@";; acme) acme "$@";; kharej) kharej "$@";; start) start "$@";; status) status "$@";; remove) remove "$@";;
  speedtest) speedtest "$@";; self-install) self_install;; stop) stop "$@";; menu) menu;;
  "") if [ -t 0 ] || [ -e /dev/tty ]; then menu; else sed -n '2,45p' "$0"; exit 64; fi;;
  *) sed -n '2,42p' "$0"; exit 64;;
esac
