#!/usr/bin/env bash
# hwt-rnt.sh — HoneyWeb Reverse Nginx Tunnel: a VLESS-WS-TLS host on 443 carried from an Iran server to a foreign
# server. Run as root. Without arguments it opens a menu.
#
# Three methods. In all of them the FOREIGN server holds the certificate (Let's Encrypt) and is the reverse proxy
# in front of Xray's WebSocket inbound; the Iran server only hands ports 443 and 80 over to it.
#   reverse   Nginx + Reverse Nginx + Reverse Proxy. The foreign server's NGINX visits the Iran server's NGINX
#             (TLS, from the foreign IP) and keeps a pool of tunnel connections open (HoneyWeb Tunnel engine, wsmux).
#             Iran's NGINX passes users' 443/80 through that tunnel to the foreign NGINX. Connections from the
#             foreign IP land on Iran's own tunnel site (a private certificate the foreign side pins); anyone else
#             reaching Iran:443 — users, scanners — gets the foreign server's real site and certificate.
#   iptables  Nginx + Iptables + Reverse Proxy. Iran DNATs tcp/443 and tcp/80 to the foreign server (kept by a
#             systemd unit, not rc.local).
#   direct    Nginx + Direct Nginx + Reverse Proxy. Iran's NGINX (stream) connects to the foreign NGINX itself.
#             The Iran server must be able to reach the foreign IP directly.
# reverse and direct carry the user's address with the PROXY protocol, so Xray sees it in X-Forwarded-For.
#
# Setup: install on Iran first; it prints a link (it holds the tunnel's secret: give it only to the foreign
# server). Then install on the foreign server with that link. Both sides keep a manager: status, speed test,
# restart, stop, remove (on Iran also "remove both": an agent on the foreign server, reachable only by the entry
# with the tunnel's token, removes that side too), and an optimize button (TCP and NGINX tuning, the pool).
#
#   hwt-rnt.sh                                   menu
#   hwt-rnt.sh iran --method M --domain D --foreign-ip IP [--name N]
#   hwt-rnt.sh foreign --link LINK --inbound-port P [--host-path /p] [--inbound-path /] [--pool 896] [--self-signed]
#   hwt-rnt.sh list | status N | speedtest N [--streams 8] | restart N | stop N | optimize [N] [--undo]
#   hwt-rnt.sh remove N [--both]
#
# Next to this script (install.sh puts them there): hwtunnel + hwtunnel.sha256 (the engine, for reverse) and site/.
set -euo pipefail
umask 022
HERE=$(cd "$(dirname "$0")" && pwd)
ETC=/etc/hwt-rnt
BIN=/opt/hwt-rnt/bin/hwtunnel
NGX=/etc/nginx/hwt-rnt
WWW=/var/www/hwt-rnt
ACME=/var/www/hwt-rnt-acme
SYSTEM_CA=/etc/ssl/certs/ca-certificates.crt
TS=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP=/root/hwt-rnt-backup/$TS
# Internal ports (loopback unless said otherwise).
P_TUNSITE=18443   # Iran: its own tunnel site (TLS, PROXY protocol), for connections from the foreign IP
P_ENGINE=19443    # Iran: the engine (wsmux) behind the tunnel site; foreign: its loopback NGINX out to Iran
P_T443=20443      # Iran: tunnel port that reaches the foreign NGINX's 10443
P_T80=20080       # Iran: tunnel port that reaches the foreign NGINX's P_PP80
P_TAGENT=20900    # Iran: tunnel port that reaches the foreign agent
P_TIPERF=27070    # Iran: tunnel port that reaches the foreign iperf3 (speed test)
# The foreign listeners use odd ports: Linux gives outgoing connections even ports first, so on a busy exit (Xray's
# own outbound connections, ephemeral range from 1024) an even port such as 10080 was found held by one.
P_PP443=10443     # foreign: TLS with the PROXY protocol (reverse: on loopback; direct: on the foreign IP, Iran only)
P_PP80=10081      # foreign: plain HTTP with the PROXY protocol, for ACME
P_AGENT=19900     # foreign: the agent (loopback)
# Turbo with a 4 MiB stream window (see rnt.sh); capacity = pool x mux_con.
PROFILE='nodelay = true
mux_version = 2
mux_streambuffer = 4194304
mux_recievebuffer = 16777216'
RE_NAME='^[a-z][a-z0-9_]{0,23}$'
RE_DOMAIN='^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
RE_IP='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
RE_PATH='^/[A-Za-z0-9._~/-]{0,128}$'

die() { echo "hwt-rnt: ABORT: $*" >&2; exit 1; }
say() { echo "== $(date -u +%T) $*"; }
need() { [[ "$2" =~ $3 ]] || die "bad $1 '$2'"; }
backup() { local f; for f in "$@"; do [ -e "$f" ] || continue; mkdir -p "$BACKUP$(dirname "$f")"; cp -a "$f" "$BACKUP$f"; done; }
put() { backup "$1"; mkdir -p "$(dirname "$1")"; cat > "$1.new"; chmod "$2" "$1.new"; chown "$3" "$1.new"; mv -f "$1.new" "$1"; }
port_owner() { ss -Htlnp "( sport = :$1 )" 2>/dev/null | grep -o 'users:(("[^"]*"' | cut -d'"' -f2 | sort -u | tr '\n' ' ' || true; }
# port_busy ADDR PORT: ADDR:PORT (or the wildcard address) is held by a socket other than NGINX's own listener. An
# outgoing connection can hold any port of the ephemeral range, and NGINX then cannot bind it. TIME-WAIT never blocks
# NGINX (SO_REUSEADDR), and below the ephemeral range only another listener can.
port_busy() { local lo; lo=$(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null | awk '{print $1}')
  ss -Htanp "( sport = :$2 )" 2>/dev/null | awk -v a="$1:$2" -v w="0.0.0.0:$2" -v s="*:$2" -v v="[::]:$2" -v p="$2" -v lo="${lo:-1024}" \
  '($4 == a || $4 == w || $4 == s || $4 == v) && $1 != "TIME-WAIT" && !($1 == "LISTEN" && /"nginx"/) && ($1 == "LISTEN" || p + 0 >= lo + 0)' | grep -c . >/dev/null; }
engine_unit() { echo "hwt-rnt-$1.service"; }
agent_unit() { echo "hwt-rnt-$1-agent.service"; }
iperf_unit() { echo "hwt-rnt-$1-iperf.service"; }
nat_unit() { echo "hwt-rnt-$1-nat.service"; }
my_ip() { ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="src") {print $(i+1); exit}}'; }
apt_install() { local p missing=(); for p in "$@"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
  [ ${#missing[@]} = 0 ] && return 0
  say "installing ${missing[*]}"; DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${missing[@]}" >/dev/null 2>&1 \
    || { apt-get update -q >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${missing[@]}" >/dev/null 2>&1; } \
    || die "apt-get install ${missing[*]} failed"; }

save_state() { local f=$ETC/$NAME/state.env k; mkdir -p "$ETC/$NAME"; : > "$f.new"; chmod 600 "$f.new"
  for k in ROLE METHOD DOMAIN IR EX TOKEN XPORT HPATH XPATH POOL; do printf '%s=%s\n' "$k" "${!k:-}" >> "$f.new"; done; mv -f "$f.new" "$f"; }
load_state() { NAME=$1; need name "$NAME" "$RE_NAME"; [ -f "$ETC/$NAME/state.env" ] || die "no tunnel named $NAME here"
  local k v; while IFS='=' read -r k v; do case "$k" in ROLE|METHOD|DOMAIN|IR|EX|TOKEN|XPORT|HPATH|XPATH|POOL) printf -v "$k" '%s' "$v";; esac; done < "$ETC/$NAME/state.env"; }

# nginx_test_reload FILE...: nginx -t, and on failure restore every FILE from this run's backup (or remove it if it
# is new); reload (or start) on success. If NGINX cannot start with the new files, the previous ones are restored and
# NGINX is started again, so a failed install never leaves it down.
nginx_restore() { local f; for f in "$@"; do if [ -e "$BACKUP$f" ]; then cp -a "$BACKUP$f" "$f"; else rm -f "$f" "/etc/nginx/sites-enabled/$(basename "$f")"; fi; done; }
nginx_test_reload() { local err; err=$(mktemp)
  if ! nginx -t 2>"$err"; then sed 's/^/  /' "$err"; rm -f "$err"; nginx_restore "$@"
    die "nginx -t failed; the previous configuration was restored"; fi
  rm -f "$err"
  if ! systemctl is-active --quiet nginx; then
    systemctl enable --now nginx >/dev/null 2>&1 && return
    nginx_restore "$@"; systemctl start nginx >/dev/null 2>&1 || true
    die "nginx did not start with the new configuration (see /var/log/nginx/error.log); the previous one was restored"; fi
  # A reload that cannot bind a new address (e.g. a fresh install's 0.0.0.0:80 still held while this site wants
  # IP:80) keeps the old configuration and still reports success: check the log, and restart once if it failed.
  local log=/var/log/nginx/error.log before=0; [ -f "$log" ] && before=$(stat -c %s "$log")
  systemctl reload nginx; sleep 1
  if [ -f "$log" ] && tail -c +"$((before + 1))" "$log" | grep -c '\[emerg\]' >/dev/null; then
    echo "  nginx: the reload did not take (bind), restarting it"
    systemctl restart nginx && return
    nginx_restore "$@"; systemctl restart nginx >/dev/null 2>&1 || true
    die "nginx did not restart with the new configuration (see /var/log/nginx/error.log); the previous one was restored and NGINX started again ($(systemctl is-active nginx))"; fi; }
site_put() { printf '%s\n' "$2" | put "/etc/nginx/sites-available/$1" 0644 root:root; ln -sfn "/etc/nginx/sites-available/$1" "/etc/nginx/sites-enabled/$1"; }
# One stream{} block for all tunnels, included once from nginx.conf's main context.
stream_hook() {
  grep -qE '^\s*stream\s*\{' /etc/nginx/nginx.conf && ! grep -q 'hwt-rnt/stream.conf' /etc/nginx/nginx.conf \
    && die "nginx.conf already has its own stream {} block; add 'include $NGX/stream.d/*.conf;' inside it by hand"
  mkdir -p "$NGX/stream.d"
  [ -f "$NGX/stream.conf" ] || printf '%s\n' "# HoneyWeb Reverse Nginx Tunnel: TCP pass-through of every tunnel" "stream {" "    include $NGX/stream.d/*.conf;" "}" > "$NGX/stream.conf"
  if ! grep -q 'hwt-rnt/stream.conf' /etc/nginx/nginx.conf; then backup /etc/nginx/nginx.conf; printf '\ninclude %s/stream.conf;\n' "$NGX" >> /etc/nginx/nginx.conf; fi
}
nginx_capacity() { local wc; wc=$(sed -n -E 's/^\s*worker_connections\s+([0-9]+);.*/\1/p' /etc/nginx/nginx.conf | head -1)
  [ -n "$wc" ] && [ "$wc" -lt 16384 ] || return 0
  backup /etc/nginx/nginx.conf
  sed -i -E 's/^(\s*)worker_connections\s+[0-9]+;/\1worker_connections 16384;/' /etc/nginx/nginx.conf
  grep -q '^worker_rlimit_nofile' /etc/nginx/nginx.conf || sed -i -E '0,/^worker_processes/s//worker_rlimit_nofile 65536;\n&/' /etc/nginx/nginx.conf
  echo "  nginx: worker_connections $wc -> 16384"; }
no_default_site() { if [ -L /etc/nginx/sites-enabled/default ]; then backup /etc/nginx/sites-enabled/default; rm -f /etc/nginx/sites-enabled/default; echo "  nginx: default site disabled (ports 80/443 belong to the tunnel)"; fi; }

install_engine() {
  [ -f "$HERE/hwtunnel" ] && [ -f "$HERE/hwtunnel.sha256" ] || die "the engine (hwtunnel, hwtunnel.sha256) must be next to this script (install.sh puts it there)"
  local want got; want=$(awk '{print $1; exit}' "$HERE/hwtunnel.sha256"); got=$(sha256sum "$HERE/hwtunnel" | awk '{print $1}')
  [ "$want" = "$got" ] || die "engine checksum mismatch"
  install -d -m 0755 /opt/hwt-rnt /opt/hwt-rnt/bin; install -m 0755 "$HERE/hwtunnel" "$BIN.new"; mv -f "$BIN.new" "$BIN"
  id hwtunnel >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin hwtunnel
  install -d -m 0755 "$ETC" "$ETC/$NAME"; }
engine_unit_write() { # NAME ROLE
  put "/etc/systemd/system/$(engine_unit "$1")" 0644 root:root <<EOF
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
RuntimeDirectory=backpack
RuntimeDirectoryPreserve=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
LimitNOFILE=1048576
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
EOF
}
self_install() { local d=/opt/hwt-rnt; install -d -m 0755 "$d"
  if [ "$HERE" != "$d" ]; then install -m 0755 "$HERE/hwt-rnt.sh" "$d/hwt-rnt.sh"; [ -d "$HERE/site" ] && { rm -rf "$d/site"; cp -a "$HERE/site" "$d/site"; }; fi
  ln -sfn "$d/hwt-rnt.sh" /usr/local/bin/hwt-rnt; }

# ---------------------------------------------------------------- link

make_link() { python3 -c '
import base64, json, sys
keys = ["mode", "name", "domain", "ir", "ex", "token", "ca"]
d = dict(zip(keys, sys.argv[1:])); d["v"] = 1
print("hwt-rnt://" + base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode().rstrip("="))
' "$METHOD" "$NAME" "$DOMAIN" "$IR" "$EX" "$TOKEN" "${1:-}"; }
read_link() { local out; out=$(python3 -c '
import base64, json, sys
s = sys.argv[1].strip()
if not s.startswith("hwt-rnt://"): sys.exit("not a hwt-rnt link")
b = s[len("hwt-rnt://"):]; d = json.loads(base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)))
if d.get("v") != 1: sys.exit("unknown link version")
for k in ("mode", "name", "domain", "ir", "ex", "token"): print(k.upper() + "=" + str(d.get(k, "")))
print("CA_B64=" + base64.b64encode(d.get("ca", "").encode()).decode())
' "$1") || die "that link is not valid"
  local k v; while IFS='=' read -r k v; do case "$k" in MODE) METHOD=$v;; NAME) NAME=$v;; DOMAIN) DOMAIN=$v;; IR) IR=$v;; EX) EX=$v;; TOKEN) TOKEN=$v;; CA_B64) CA_B64=$v;; esac; done <<<"$out"
  need method "$METHOD" '^(reverse|iptables|direct)$'; need name "$NAME" "$RE_NAME"; need domain "$DOMAIN" "$RE_DOMAIN"
  need iran-ip "$IR" "$RE_IP"; need foreign-ip "$EX" "$RE_IP"; [[ "$TOKEN" =~ ^[a-f0-9]{64}$ ]] || die "the link's token is malformed"; }

# ---------------------------------------------------------------- Iran (entry)

iran() {
  NAME=""; METHOD=""; DOMAIN=""; EX=""
  while [ $# -gt 0 ]; do case "$1" in
    --method) METHOD=$2; shift 2;; --domain) DOMAIN=$2; shift 2;; --foreign-ip) EX=$2; shift 2;; --name) NAME=$2; shift 2;;
    *) die "unknown option $1";; esac; done
  need method "$METHOD" '^(reverse|iptables|direct)$'; need domain "$DOMAIN" "$RE_DOMAIN"; need foreign-ip "$EX" "$RE_IP"
  [ -n "$NAME" ] || NAME=$(echo "${DOMAIN%%.*}" | tr -c 'a-z0-9_\n' '_' | sed 's/^[^a-z]*/t/' | cut -c1-24)
  need name "$NAME" "$RE_NAME"
  IR=$(my_ip); need "this server's IP" "$IR" "$RE_IP"; ROLE=iran
  [ ! -f "$ETC/$NAME/state.env" ] || die "a tunnel named $NAME already exists here (remove it first, or choose another name)"
  say "Iran side: method $METHOD, $DOMAIN -> foreign $EX (this server $IR)"
  TOKEN=$(openssl rand -hex 32)
  local ca=""
  case "$METHOD" in
    reverse|direct)
      local p o; for p in 443 80; do o=$(port_owner $p); [ -z "$o" ] || [[ "$o" == nginx* ]] || die "port $p is held by $o"; done
      apt_install nginx libnginx-mod-stream openssl curl
      # NGINX's stream part takes 443 and 80 itself, so no web site may listen there
      local busy; busy=$(grep -lE '^\s*listen\s+([0-9.]+:)?(443|80)[ ;]' /etc/nginx/sites-enabled/* 2>/dev/null | grep -v '/default$' | tr '\n' ' ' || true)
      [ -z "$busy" ] || die "these NGINX sites listen on 443/80 and would collide with the tunnel: $busy (remove them first; an old rnt.sh tunnel: /opt/hwt-rnt/rnt.sh remove NAME)"
      stream_hook; nginx_capacity; no_default_site;;
    iptables)
      local o; for p in 443 80; do o=$(port_owner $p); [ -z "$o" ] || echo "  note: $o listens on $p here; the DNAT takes the traffic before it";  done
      apt_install iptables curl;;
  esac
  install -d -m 0755 "$ETC" "$ETC/$NAME"

  case "$METHOD" in
  reverse)
    install_engine
    # The tunnel's own site: a private CA the foreign side pins (it is in the link), so no public certificate is needed
    # here and only the foreign NGINX can complete the handshake it checks.
    local t=$ETC/$NAME/tls; install -d -m 0700 "$t"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj "/CN=hwt-rnt $NAME CA" \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -keyout "$t/ca.key" -out "$t/ca.pem" >/dev/null 2>&1
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$DOMAIN" -keyout "$t/site.key" -out "$t/site.csr" >/dev/null 2>&1
    printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' "$DOMAIN" > "$t/site.ext"
    openssl x509 -req -in "$t/site.csr" -CA "$t/ca.pem" -CAkey "$t/ca.key" -CAcreateserial -days 3650 -extfile "$t/site.ext" -out "$t/site.pem" >/dev/null 2>&1
    chmod 600 "$t"/*.key; ca=$(cat "$t/ca.pem")
    printf 'map "$http_upgrade:$http_authorization" $rnt_%s_ok {\n    default 0;\n    "~^websocket:Bearer %s$" 1;\n}\n' "$NAME" "$TOKEN" | put "$NGX/$NAME.auth.conf" 0600 root:root
    local loc; loc=$(cat <<EOF
        if (\$rnt_${NAME}_ok = 0) { return 404; }
        proxy_pass http://127.0.0.1:$P_ENGINE;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_connect_timeout 5s;
        proxy_send_timeout 1d;
        proxy_read_timeout 1d;
        proxy_buffering off;
        proxy_buffer_size 64k;
        proxy_buffers 4 64k;
        proxy_busy_buffers_size 128k;
        proxy_socket_keepalive on;
        access_log off;
EOF
)
    site_put "hwt-rnt-$NAME-tunnel.conf" "# HoneyWeb Reverse Nginx Tunnel $NAME: the tunnel's way in (reached only through the stream map below)
include $NGX/$NAME.auth.conf;
server {
    listen 127.0.0.1:$P_TUNSITE ssl proxy_protocol;
    server_name $DOMAIN;
    server_tokens off;
    ssl_certificate     $t/site.pem;
    ssl_certificate_key $t/site.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:rnt_$NAME:10m;
    ssl_session_tickets off;
    root $WWW/$NAME;
    location = /channel {
$loc
    }
    location ^~ /tunnel/ {
$loc
    }
    location / { try_files \$uri \$uri/ =404; }
}"
    mkdir -p "$WWW/$NAME"; [ -d "$HERE/site" ] && cp -a "$HERE/site/." "$WWW/$NAME/"; chmod -R a+rX "$WWW/$NAME"
    printf '%s\n' "# HoneyWeb Reverse Nginx Tunnel $NAME (reverse): the foreign IP reaches the tunnel site, everyone else the foreign NGINX through the tunnel" \
      "map \$remote_addr \$rnt_${NAME}_443 { $EX 127.0.0.1:$P_TUNSITE; default 127.0.0.1:$P_T443; }" \
      "server { listen 443 backlog=4096; proxy_pass \$rnt_${NAME}_443; proxy_protocol on; proxy_connect_timeout 5s; proxy_timeout 1d; }" \
      "server { listen 80 backlog=4096; proxy_pass 127.0.0.1:$P_T80; proxy_protocol on; proxy_connect_timeout 5s; proxy_timeout 10m; }" \
      | put "$NGX/stream.d/$NAME.conf" 0644 root:root
    put "$ETC/$NAME/server.toml" 0640 root:hwtunnel <<EOF
# HoneyWeb Reverse Nginx Tunnel $NAME (reverse): entry. Only NGINX reaches this listener.
[server]
bind_addr = "127.0.0.1:$P_ENGINE"
transport = "wsmux"
token = "$TOKEN"
skip_optz = true
log_level = "info"
$PROFILE
mux_con = 8
ports = ["127.0.0.1:$P_T443=$P_PP443", "127.0.0.1:$P_T80=$P_PP80", "127.0.0.1:$P_TAGENT=$P_AGENT", "127.0.0.1:$P_TIPERF=5201"]
EOF
    "$BIN" check -c "$ETC/$NAME/server.toml" >/dev/null || die "the engine refused its configuration"
    nginx_test_reload "/etc/nginx/sites-available/hwt-rnt-$NAME-tunnel.conf" "$NGX/stream.d/$NAME.conf"
    engine_unit_write "$NAME" server; systemctl daemon-reload; systemctl enable --now "$(engine_unit "$NAME")" >/dev/null 2>&1
    systemctl restart "$(engine_unit "$NAME")";;
  direct)
    printf '%s\n' "# HoneyWeb Reverse Nginx Tunnel $NAME (direct): 443/80 straight to the foreign NGINX, the user's address in the PROXY protocol" \
      "server { listen 443 backlog=4096; proxy_pass $EX:$P_PP443; proxy_protocol on; proxy_connect_timeout 5s; proxy_timeout 1d; }" \
      "server { listen 80 backlog=4096; proxy_pass $EX:$P_PP80; proxy_protocol on; proxy_connect_timeout 5s; proxy_timeout 10m; }" \
      | put "$NGX/stream.d/$NAME.conf" 0644 root:root
    nginx_test_reload "$NGX/stream.d/$NAME.conf"
    # the port this method uses; "refused" means the path is open and the foreign side is not installed yet
    local r; r=$(timeout 6 bash -c "exec 3<>/dev/tcp/$EX/$P_PP443" 2>&1) && r=open || case "$r" in
      *refused*) r="open (nothing listens there yet: install the foreign side)";;
      *) r="BLOCKED (direct needs an open path to the foreign IP; reverse does not)";; esac
    echo "  this server -> $EX:$P_PP443 directly: $r";;
  iptables)
    put "$ETC/$NAME/nat.sh" 0755 root:root <<EOF
#!/bin/sh
# HoneyWeb Reverse Nginx Tunnel $NAME (iptables): tcp/443 and tcp/80 to the foreign server. "add" or "del".
op=\${1:-add}; A=-A; [ "\$op" = del ] && A=-D
sysctl -q -w net.ipv4.ip_forward=1
for p in 443 80; do
  r="PREROUTING -p tcp -m tcp --dport \$p -m comment --comment hwt-rnt-$NAME -j DNAT --to-destination $EX:\$p"
  if [ "\$op" = add ]; then iptables -t nat -C \$r 2>/dev/null || iptables -t nat -A \$r; else iptables -t nat -D \$r 2>/dev/null || true; fi
done
r="POSTROUTING -d $EX/32 -p tcp -m comment --comment hwt-rnt-$NAME -j MASQUERADE"
if [ "\$op" = add ]; then iptables -t nat -C \$r 2>/dev/null || iptables -t nat -A \$r; else iptables -t nat -D \$r 2>/dev/null || true; fi
EOF
    printf 'net.ipv4.ip_forward = 1\n' | put /etc/sysctl.d/91-hw-rnt-forward.conf 0644 root:root
    put "/etc/systemd/system/$(nat_unit "$NAME")" 0644 root:root <<EOF
[Unit]
Description=HoneyWeb Reverse Nginx Tunnel $NAME (iptables forward to $EX)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$ETC/$NAME/nat.sh add
ExecStop=$ETC/$NAME/nat.sh del

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload; systemctl enable --now "$(nat_unit "$NAME")" >/dev/null 2>&1
    echo "  nat: $(iptables-save -t nat | grep -c "hwt-rnt-$NAME") rules";;
  esac
  save_state; self_install
  say "IRAN_OK $NAME ($METHOD). Install the foreign server with this link (it holds the tunnel's secret):"
  echo; make_link "$ca"; echo
}

# ---------------------------------------------------------------- foreign (exit)

foreign_site() { # the foreign NGINX: the site, the reverse proxy to Xray, ACME, the agent
  local cert=$1 key=$2 trust ppl pp80 pub443 pub80
  case "$METHOD" in
    reverse)  trust=127.0.0.1; ppl="127.0.0.1:$P_PP443"; pp80="127.0.0.1:$P_PP80";;
    direct)   trust=$IR;       ppl="$EX:$P_PP443";       pp80="$EX:$P_PP80";;
    iptables) trust="";        ppl="";                   pp80="";;
  esac
  local body; body=$(cat <<EOF
    server_name $DOMAIN;
    server_tokens off;
    ssl_certificate     $cert;
    ssl_certificate_key $key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:rnt_$NAME:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    root $WWW/$NAME;
    index index.html;
    client_max_body_size 1m;
    keepalive_timeout 65s;

    # VLESS over WebSocket: only upgrades reach Xray; anything else on the path is a missing page
    location = $HPATH {
        if (\$http_upgrade !~* ^websocket\$) { return 404; }
        proxy_pass http://127.0.0.1:$XPORT$XPATH;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_connect_timeout 5s;
        proxy_send_timeout 1d;
        proxy_read_timeout 1d;
        proxy_buffering off;
        proxy_buffer_size 64k;
        proxy_buffers 4 64k;
        proxy_busy_buffers_size 128k;
        access_log off;
    }
    # the entry's manager (remove/status of this side), token only
    location ^~ /.hwt-rnt-agent/ {
        if (\$rnt_${NAME}_agent = 0) { return 404; }
        proxy_pass http://127.0.0.1:$P_AGENT/;
        access_log off;
    }
    location / { try_files \$uri \$uri/ =404; }
EOF
)
  local pp=""; if [ -n "$ppl" ]; then pp=$(cat <<EOF
# the Iran side's connections: the user's address arrives in the PROXY protocol
server {
    listen $ppl ssl proxy_protocol backlog=4096;
    set_real_ip_from $trust;
    real_ip_header proxy_protocol;
$( [ "$METHOD" = direct ] && printf '    if ($realip_remote_addr != "%s") { return 444; }\n' "$IR" )
$body
}
server {
    listen $pp80 proxy_protocol backlog=4096;
    server_name $DOMAIN;
    server_tokens off;
$( [ "$METHOD" = direct ] && printf '    if ($realip_remote_addr != "%s") { return 444; }\n' "$IR" )
    location ^~ /.well-known/acme-challenge/ { root $ACME/$NAME; default_type text/plain; try_files \$uri =404; }
    location / { return 301 https://$DOMAIN\$request_uri; }
}
EOF
); fi
  site_put "hwt-rnt-$NAME.conf" "# HoneyWeb Reverse Nginx Tunnel $NAME ($METHOD): the site and the reverse proxy in front of Xray. Generated by hwt-rnt.
map \"\$http_authorization\" \$rnt_${NAME}_agent { default 0; \"~^Bearer $TOKEN\$\" 1; }
server {
    listen $EX:443 ssl backlog=4096;
$body
}
server {
    listen $EX:80 backlog=4096;
    server_name $DOMAIN;
    server_tokens off;
    location ^~ /.well-known/acme-challenge/ { root $ACME/$NAME; default_type text/plain; try_files \$uri =404; }
    location / { return 301 https://$DOMAIN\$request_uri; }
}
$pp"
  chmod 0600 "/etc/nginx/sites-available/hwt-rnt-$NAME.conf"
}

foreign() {
  local link="" self=0; XPORT=""; HPATH=""; XPATH=/; POOL=896
  while [ $# -gt 0 ]; do case "$1" in
    --link) link=$2; shift 2;; --inbound-port) XPORT=$2; shift 2;; --host-path) HPATH=$2; shift 2;;
    --inbound-path) XPATH=$2; shift 2;; --pool) POOL=$2; shift 2;; --self-signed) self=1; shift;;
    *) die "unknown option $1";; esac; done
  [ -n "$link" ] || die "--link is required"; read_link "$link"; ROLE=foreign
  need inbound-port "$XPORT" '^[0-9]{1,5}$'; [ -n "$HPATH" ] || HPATH=/; need host-path "$HPATH" "$RE_PATH"; need inbound-path "$XPATH" "$RE_PATH"
  need pool "$POOL" '^[0-9]{1,4}$'
  [ ! -f "$ETC/$NAME/state.env" ] || die "a tunnel named $NAME already exists here"
  [[ "$(ip -4 -o addr show)" == *" $EX/"* ]] || die "$EX (the foreign IP in the link) is not an address of this server"
  local other; other=$(grep -lE "server_name[^;]*[[:space:]]$DOMAIN[ ;]" /etc/nginx/sites-enabled/* 2>/dev/null | grep -v "/hwt-rnt-$NAME" | tr '\n' ' ' || true)
  [ -z "$other" ] || die "another NGINX site already serves $DOMAIN here ($other); remove or disable it first"
  say "foreign side: $NAME ($METHOD), $DOMAIN, Iran $IR, Xray WS inbound 127.0.0.1:$XPORT$XPATH, host path $HPATH"
  [ -n "$(ss -Htln "( sport = :$XPORT )")" ] || echo "  note: nothing listens on $XPORT yet (Xray's WebSocket inbound must be there)"
  local a busy=""; for a in "$EX:443" "$EX:80" $(case "$METHOD" in direct) echo "$EX:$P_PP443 $EX:$P_PP80";;
      reverse) echo "127.0.0.1:$P_PP443 127.0.0.1:$P_PP80 127.0.0.1:$P_ENGINE";; esac); do
    port_busy "${a%:*}" "${a##*:}" && busy+="$a "; done
  [ -z "$busy" ] || die "in use here by another socket: $busy(an outgoing connection can hold any port of the ephemeral range $(sysctl -n net.ipv4.ip_local_port_range | tr '\t' '-')); wait until it closes, or reserve the port with net.ipv4.ip_local_reserved_ports, then run this again"
  apt_install nginx certbot openssl curl python3
  nginx_capacity; no_default_site
  install -d -m 0755 "$ETC" "$ETC/$NAME" "$WWW/$NAME" "$ACME/$NAME"
  [ -d "$HERE/site" ] && cp -a "$HERE/site/." "$WWW/$NAME/"; chmod -R a+rX "$WWW/$NAME" "$ACME/$NAME"
  local t=$ETC/$NAME/tls; install -d -m 0700 "$t"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=$DOMAIN" \
    -addext "subjectAltName=DNS:$DOMAIN" -keyout "$t/placeholder.key" -out "$t/placeholder.pem" >/dev/null 2>&1; chmod 600 "$t/placeholder.key"
  foreign_site "$t/placeholder.pem" "$t/placeholder.key"
  nginx_test_reload "/etc/nginx/sites-available/hwt-rnt-$NAME.conf"

  # the agent: lets the entry remove this side (and read its status) with the tunnel's token; loopback only
  printf '%s\n' "$TOKEN" | put "$ETC/$NAME/agent.token" 0600 root:root
  install -d -m 0755 /opt/hwt-rnt; agent_write
  put "/etc/systemd/system/$(agent_unit "$NAME")" 0644 root:root <<EOF
[Unit]
Description=HoneyWeb Reverse Nginx Tunnel $NAME (agent for the entry's manager)
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 -I /opt/hwt-rnt/agent.py $NAME $P_AGENT $ETC/$NAME/agent.token
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  if [ "$METHOD" = reverse ]; then
    install_engine
    printf '%s' "$CA_B64" | base64 -d | put "$ETC/$NAME/entry-ca.pem" 0644 root:root
    grep -q 'BEGIN CERTIFICATE' "$ETC/$NAME/entry-ca.pem" || die "the link has no entry certificate (was it made for the reverse method?)"
    site_put "hwt-rnt-$NAME-out.conf" "# HoneyWeb Reverse Nginx Tunnel $NAME: the foreign NGINX visits the Iran site; the engine speaks wsmux to it here.
server {
    listen 127.0.0.1:$P_ENGINE;
    server_tokens off;
    access_log off;
    location / {
        proxy_pass https://$IR:443;
        proxy_http_version 1.1;
        proxy_set_header Host $DOMAIN;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_ssl_server_name on;
        proxy_ssl_name $DOMAIN;
        proxy_ssl_protocols TLSv1.2 TLSv1.3;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate $ETC/$NAME/entry-ca.pem;
        proxy_ssl_session_reuse on;
        # the Iran side recognises the tunnel by this address
        proxy_bind $EX;
        proxy_connect_timeout 10s;
        proxy_send_timeout 1d;
        proxy_read_timeout 1d;
        proxy_buffering off;
        proxy_buffer_size 64k;
        proxy_buffers 4 64k;
        proxy_busy_buffers_size 128k;
        proxy_socket_keepalive on;
    }
}"
    nginx_test_reload "/etc/nginx/sites-available/hwt-rnt-$NAME-out.conf"
    put "$ETC/$NAME/client.toml" 0640 root:hwtunnel <<EOF
# HoneyWeb Reverse Nginx Tunnel $NAME (reverse): exit, through the loopback NGINX above.
[client]
remote_addr = "127.0.0.1:$P_ENGINE"
transport = "wsmux"
token = "$TOKEN"
connection_pool = $POOL
skip_optz = true
log_level = "info"
$PROFILE
EOF
    "$BIN" check -c "$ETC/$NAME/client.toml" >/dev/null || die "the engine refused its configuration"
    engine_unit_write "$NAME" client
    # the speed test's far end, on loopback (the entry reaches it through the tunnel)
    if ! ss -Htln '( sport = :5201 )' | grep -c . >/dev/null; then apt_install iperf3
      put "/etc/systemd/system/$(iperf_unit "$NAME")" 0644 root:root <<EOF
[Unit]
Description=HoneyWeb Reverse Nginx Tunnel $NAME (speed test server, loopback)
[Service]
ExecStart=/usr/bin/iperf3 -s -B 127.0.0.1 -p 5201
Restart=always
[Install]
WantedBy=multi-user.target
EOF
    fi
  fi
  systemctl daemon-reload
  systemctl enable --now "$(agent_unit "$NAME")" >/dev/null 2>&1
  [ -f "/etc/systemd/system/$(iperf_unit "$NAME")" ] && systemctl enable --now "$(iperf_unit "$NAME")" >/dev/null 2>&1
  save_state; self_install
  if [ "$METHOD" = reverse ]; then
    systemctl enable --now "$(engine_unit "$NAME")" >/dev/null 2>&1; systemctl restart "$(engine_unit "$NAME")"
    local i n=0; for i in $(seq 1 60); do n=$(sessions); [ "$n" -ge $((POOL + 1)) ] && break; sleep 1; done
    echo "  tunnel sessions to Iran: $n (want $((POOL + 1)))"; [ "$n" -gt 0 ] || die "the tunnel did not come up (check the Iran side and hwt-rnt status $NAME)"
  fi

  # the certificate: Let's Encrypt over HTTP-01; the challenge reaches this NGINX through the Iran server
  if [ $self = 1 ]; then say "certificate: self-signed placeholder kept (--self-signed)"
  else
    local a=(certonly --webroot -w "$ACME/$NAME" -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --keep-until-expiring)
    say "certificate: Let's Encrypt for $DOMAIN (dry run first)"
    certbot "${a[@]}" --dry-run </dev/null >/dev/null 2>&1 || die "the ACME dry run failed: http://$DOMAIN/ must reach this server through $IR (A record of $DOMAIN = $IR?)"
    certbot "${a[@]}" </dev/null >/dev/null 2>&1 || die "certbot failed"
    printf '#!/bin/sh\nsystemctl reload nginx\n' | put /etc/letsencrypt/renewal-hooks/deploy/hwt-rnt-nginx-reload.sh 0755 root:root
    systemctl enable --now certbot.timer >/dev/null 2>&1 || true
    foreign_site "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    nginx_test_reload "/etc/nginx/sites-available/hwt-rnt-$NAME.conf"
    say "certificate: $(openssl x509 -noout -enddate -in "/etc/letsencrypt/live/$DOMAIN/fullchain.pem")"
  fi
  local r; r=$(curl -sS -o /dev/null -m 6 -w '%{http_code}' -k --resolve "$DOMAIN:443:$EX" -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
      -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: aHd0LXJudC1jaGVjay0xMg==' "https://$DOMAIN$HPATH" 2>/dev/null || true)
  echo "  host path $HPATH through this NGINX: $r (101 = Xray answered)"
  say "FOREIGN_OK $NAME ($METHOD). Users: host address $DOMAIN, port 443, TLS, SNI and Host $DOMAIN, path $HPATH."
}

agent_write() { put /opt/hwt-rnt/agent.py 0755 root:root <<'PY'
#!/usr/bin/env python3
"""HoneyWeb Reverse Nginx Tunnel agent: lets the entry server's manager read the status of this foreign side and
remove it. Listens on 127.0.0.1 only; every request must carry the tunnel's token (compared in constant time)."""
import hmac, http.server, json, subprocess, sys

NAME, PORT, TOKEN = sys.argv[1], int(sys.argv[2]), open(sys.argv[3]).read().strip()

class Handler(http.server.BaseHTTPRequestHandler):
    def reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def authorised(self):
        return hmac.compare_digest(self.headers.get("Authorization", "").encode(), ("Bearer " + TOKEN).encode())

    def do_GET(self):
        if not self.authorised() or self.path != "/status":
            return self.reply(404, {})
        out = subprocess.run(["/usr/local/bin/hwt-rnt", "status", NAME], capture_output=True, text=True, timeout=30)
        self.reply(200, {"name": NAME, "status": out.stdout[-4000:]})

    def do_POST(self):
        if not self.authorised() or self.path != "/remove":
            return self.reply(404, {})
        self.reply(202, {"removing": NAME})
        # after this answer has gone out, and outside this unit (removing stops the agent itself)
        subprocess.Popen(["systemd-run", "--quiet", "--on-active=3s", "/usr/local/bin/hwt-rnt", "remove", NAME])

    def log_message(self, *args):
        pass

http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
PY
}

# ---------------------------------------------------------------- manager

sessions() { local p; p=$([ "$ROLE" = iran ] && echo "sport = :$P_ENGINE" || echo "dport = :$P_ENGINE")
  ss -Htnp state established "( $p )" 2>/dev/null | grep -c '"hwtunnel"' || true; }
list() { local d; for d in "$ETC"/*/state.env; do [ -f "$d" ] || continue; ( load_state "$(basename "$(dirname "$d")")"; echo "  $NAME: $ROLE, $METHOD, $DOMAIN (Iran $IR, foreign $EX)" ); done; }
status() {
  load_state "${1:-}"
  echo "== $NAME: $ROLE side, method $METHOD, $DOMAIN (Iran $IR <-> foreign $EX)"
  if [ "$METHOD" = reverse ]; then echo "  engine: $(systemctl is-active "$(engine_unit "$NAME")" 2>/dev/null || true), tunnel sessions: $(sessions)"; fi
  if [ "$ROLE" = iran ] && [ "$METHOD" != iptables ]; then echo "  users on 443: $(ss -Htn state established '( sport = :443 )' | wc -l)"; fi
  if [ "$ROLE" = iran ] && [ "$METHOD" = iptables ]; then echo "  nat rules: $(iptables-save -t nat | grep -c "hwt-rnt-$NAME"), unit $(systemctl is-active "$(nat_unit "$NAME")" 2>/dev/null || true)"; fi
  if [ "$ROLE" = foreign ]; then
    echo "  agent: $(systemctl is-active "$(agent_unit "$NAME")" 2>/dev/null || true), Xray inbound 127.0.0.1:$XPORT: $( [ -n "$(ss -Htln "( sport = :$XPORT )")" ] && echo listening || echo NOT listening)"
    local c=/etc/letsencrypt/live/$DOMAIN/fullchain.pem; [ -f "$c" ] && echo "  certificate: $(openssl x509 -noout -enddate -in "$c")"
  fi
}
speedtest() {
  load_state "${1:-}"; shift || true; local n=8; [ "${1:-}" = --streams ] && n=${2:-8}; need streams "$n" '^[0-9]{1,3}$'
  [ "$ROLE" = iran ] || die "run the speed test on the Iran server"
  command -v iperf3 >/dev/null || apt_install iperf3
  local host=127.0.0.1 port=$P_TIPERF
  [ "$METHOD" = reverse ] || { host=$EX; port=5201; echo "  ($METHOD: measured straight to $EX:5201, the path this method uses; needs iperf3 -s there)"; }
  say "download (foreign -> Iran), $n stream(s)"; timeout 40 iperf3 -c "$host" -p "$port" -t 10 -P "$n" -R 2>&1 | grep -E 'SUM.*receiver|receiver|error' | tail -1
  sleep 2
  say "upload (Iran -> foreign), $n stream(s)"; timeout 40 iperf3 -c "$host" -p "$port" -t 10 -P "$n" 2>&1 | grep -E 'SUM.*receiver|receiver|error' | tail -1
}
restart() { load_state "${1:-}"
  case "$ROLE:$METHOD" in *:reverse) systemctl restart "$(engine_unit "$NAME")";; iran:iptables) systemctl restart "$(nat_unit "$NAME")";; esac
  systemctl reload nginx 2>/dev/null || true; say "restarted $NAME"; }
stop() { load_state "${1:-}"
  case "$ROLE:$METHOD" in *:reverse) systemctl disable --now "$(engine_unit "$NAME")" >/dev/null 2>&1 || true;; iran:iptables) systemctl disable --now "$(nat_unit "$NAME")" >/dev/null 2>&1 || true;; esac
  say "stopped $NAME (hwt-rnt restart $NAME brings it back)"; }

agent_call() { # agent_call METHOD PATH: talk to the foreign agent from the entry
  if [ "$METHOD" = reverse ]; then curl -sS -m 15 -X "$1" -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$P_TAGENT$2"
  else curl -sS -m 15 -k -X "$1" -H "Authorization: Bearer $TOKEN" --resolve "$DOMAIN:443:$EX" "https://$DOMAIN/.hwt-rnt-agent$2"; fi; }

remove() {
  load_state "${1:-}"; local both=0; [ "${2:-}" = --both ] && both=1
  if [ $both = 1 ]; then
    [ "$ROLE" = iran ] || die "--both is for the Iran side"
    say "asking the foreign side ($EX) to remove $NAME"
    local r; r=$(agent_call POST /remove 2>&1 || true); echo "  foreign: ${r:-no answer}"
    [[ "$r" == *removing* ]] || echo "  the foreign side did not confirm; remove it there with: hwt-rnt remove $NAME"
    sleep 4
  fi
  say "removing $NAME here ($ROLE, $METHOD)"
  local f u
  for u in "$(engine_unit "$NAME")" "$(agent_unit "$NAME")" "$(iperf_unit "$NAME")" "$(nat_unit "$NAME")"; do
    [ -f "/etc/systemd/system/$u" ] || continue; backup "/etc/systemd/system/$u"; systemctl disable --now "$u" >/dev/null 2>&1 || true; rm -f "/etc/systemd/system/$u"; done
  systemctl daemon-reload
  backup "$ETC/$NAME"
  for f in "hwt-rnt-$NAME.conf" "hwt-rnt-$NAME-out.conf" "hwt-rnt-$NAME-tunnel.conf"; do
    [ -f "/etc/nginx/sites-available/$f" ] && { backup "/etc/nginx/sites-available/$f"; rm -f "/etc/nginx/sites-available/$f" "/etc/nginx/sites-enabled/$f"; }; done
  for f in "$NGX/stream.d/$NAME.conf" "$NGX/$NAME.auth.conf"; do [ -f "$f" ] && { backup "$f"; rm -f "$f"; }; done
  rm -rf "${ETC:?}/$NAME" "${WWW:?}/$NAME" "${ACME:?}/$NAME"
  if command -v nginx >/dev/null && nginx -t >/dev/null 2>&1; then systemctl reload nginx 2>/dev/null || true; fi
  say "REMOVED $NAME here (backup $BACKUP)"
}

optimize() { # optimize [NAME] [--undo]: the tuning measured on 2026-11-05 (one stream 90 -> 189 Mbit/s)
  local undo=0 name=""; for a in "$@"; do case "$a" in --undo) undo=1;; *) name=$a;; esac; done
  local f=/etc/sysctl.d/91-hw-rnt.conf prev=/root/hwt-rnt-sysctl.prev
  if [ $undo = 1 ]; then rm -f "$f"; [ -f "$prev" ] && sysctl -q -p "$prev"; say "optimize undone (sysctl back to $(tr '\n' ' ' < "$prev" 2>/dev/null))"; return; fi
  [ -f "$prev" ] || for k in net.ipv4.tcp_slow_start_after_idle net.ipv4.tcp_mtu_probing net.ipv4.tcp_congestion_control net.core.default_qdisc net.core.somaxconn; do
    echo "$k=$(sysctl -n $k)"; done > "$prev"
  { echo "# HoneyWeb Reverse Nginx Tunnel: optimize (hwt-rnt optimize --undo removes it)"
    echo "net.ipv4.tcp_slow_start_after_idle = 0"; echo "net.ipv4.tcp_mtu_probing = 1"
    grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || modprobe tcp_bbr 2>/dev/null || true
    if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then echo "net.core.default_qdisc = fq"; echo "net.ipv4.tcp_congestion_control = bbr"; fi
    [ "$(sysctl -n net.core.somaxconn)" -ge 4096 ] || echo "net.core.somaxconn = 4096"; } > "$f"
  sysctl -q -p "$f"; say "TCP: $(sed -n 's/^net\.//p' "$f" | tr '\n' ';')"
  if command -v nginx >/dev/null; then nginx_capacity; nginx -t >/dev/null 2>&1 && systemctl reload nginx; fi
  if [ -n "$name" ]; then load_state "$name"
    if [ "$ROLE:$METHOD" = foreign:reverse ] && [ "${POOL:-0}" -lt 896 ]; then
      sed -i -E 's/^connection_pool = .*/connection_pool = 896/' "$ETC/$NAME/client.toml"; POOL=896; save_state
      systemctl restart "$(engine_unit "$NAME")"; say "tunnel pool -> 896 (engine restarted)"; fi
  fi
  say "optimized (previous values in $prev; undo: hwt-rnt optimize --undo)"
}

# ---------------------------------------------------------------- menu

ask() { local _a; read -r -p "  $2${3:+ [$3]}: " _a </dev/tty || true; printf -v "$1" '%s' "${_a:-${3:-}}"; }
pick() { local d; d=$(ls "$ETC" 2>/dev/null | head -1); ask "$1" "tunnel name" "$d"; }
menu() {
  local c n m d e l x h p
  while true; do
    echo; echo "== HoneyWeb Reverse Nginx Tunnel"; list
    echo "  1) install on the Iran server       2) install on the foreign server (with the link)"
    echo "  3) tunnel manager                    4) optimize this server              0) quit"
    read -r -p "  choose: " c </dev/tty || return 0
    case "$c" in
      1) echo "  methods: 1) Nginx + Reverse Nginx + Reverse Proxy   2) Nginx + Iptables + Reverse Proxy   3) Nginx + Direct Nginx + Reverse Proxy"
         ask m "method" 1; case "$m" in 1) m=reverse;; 2) m=iptables;; 3) m=direct;; *) echo "  ?"; continue;; esac
         ask d "domain (its A record points to this Iran server)"; ask e "the foreign server's IP"
         ( iran --method "$m" --domain "$d" --foreign-ip "$e" ) || true;;
      2) ask l "the link from the Iran server"; ask x "Xray WebSocket inbound port on this server (e.g. 62018)"
         ask h "the path users connect to (the panel host's path)" /; ask p "the inbound's own path" /
         ( foreign --link "$l" --inbound-port "$x" --host-path "$h" --inbound-path "$p" ) || true;;
      3) pick n; echo "  a) status  b) speed test  c) restart  d) stop  e) remove here  f) remove from BOTH servers"
         ask c "action"; case "$c" in a) ( status "$n" ) || true;; b) ( speedtest "$n" ) || true;; c) ( restart "$n" ) || true;;
           d) ( stop "$n" ) || true;; e) ( remove "$n" ) || true;; f) ( remove "$n" --both ) || true;; *) echo "  ?";; esac;;
      4) pick n; ( optimize "$n" ) || true;;
      0|q) return 0;; *) echo "  ?";;
    esac
  done
}

[ "$(id -u)" = 0 ] || die "run as root"
cmd=${1:-}; shift || true
case "$cmd" in
  iran) iran "$@";; foreign) foreign "$@";; list) list;; status) status "$@";; speedtest) speedtest "$@";;
  restart) restart "$@";; stop) stop "$@";; remove) remove "$@";; optimize) optimize "$@";; menu|"") menu;;
  *) sed -n '2,30p' "$0"; exit 64;;
esac
