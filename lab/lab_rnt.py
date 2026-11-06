"""HoneyWeb Reverse Nginx Tunnel lab. Runs on the lab host as root (dev.sh lab lab_rnt.py ...), never on a
production server.

Topology (three network namespaces of their own; nothing else on the host changes):

    rntU (users) --veth--> rntI (entry, "Iran") --veth, netem 40 ms each way, 1 Gbit/s--> rntG (exit, abroad)

Three ways to carry the same tunnel, same engine binary, same Turbo profile, same capacity (pool x mux_con), the
same CPU budget per side (entry CPU0, exit CPU1, users CPU2, backends CPU3):
  wssmux    today's production shape: the engine terminates TLS itself on rntI 10.78.2.1:19090.
  direct    the entry is a real NGINX website (rnt.sh render-site) with the engine (wsmux) behind it on loopback;
            the exit engine visits it with a Chrome-shaped handshake (wssmux, simple_auth, tls_verify, local_addr).
  vianginx  the same entry; the exit's own NGINX (rnt.sh render-out) visits it — proxy_bind, SNI, certificate check —
            and the exit engine speaks plain wsmux to that NGINX over loopback. NGINX to NGINX on the wire.
For the two NGINX shapes also: a routed WebSocket path (the panel-host case) from a user through the entry's NGINX
and the tunnel to a WebSocket server on the exit (it must see path "/" and the user's address in X-Forwarded-For);
what a stranger sees; and an exit that trusts a different CA (it must never get a session).

Files it expects (dev.sh put ... lab NAME): lab_rnt.py, rnt.sh, rnt-site.conf.tmpl, rnt-auth.conf.tmpl,
rnt-out.conf.tmpl, rnt-index.html; the engine at ENGINE (dev.sh build rnt); hwtload in bin/. NGINX is unpacked from
the distribution's .deb into the lab directory, never installed on the host.

Usage:  python3 -I lab_rnt.py run [quick]  |  teardown
        python3 -I lab_rnt.py wsecho PORT LOG  |  wsprobe HOST PORT SNI CA PATH N   (helpers, run inside a namespace)
"""
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import statistics
import subprocess
import sys
import time

LAB = "/opt/hwtunnel-lab"
ENGINE = "/opt/hwtunnel-build/src/rnt/hwtunnel"
LOAD = f"{LAB}/bin/hwtload"
RUN = f"{LAB}/run-rnt"
PKG = f"{RUN}/pkg"
NGX_ROOT = f"{LAB}/nginx-root"
NGINX = f"{NGX_ROOT}/usr/sbin/nginx"
OUT_DIR = f"{LAB}/results/rnt"
SELF = os.path.abspath(__file__)
NS_U, NS_I, NS_G = "rntU", "rntI", "rntG"
USER_IP, ENTRY_IP, EXIT_IP, USER_SRC = "10.78.1.1", "10.78.2.1", "10.78.2.2", "10.78.1.2"
DOMAIN, SITE_PORT, HTTP_PORT, DIRECT_PORT, BACKEND, OUT_PORT, OUT_OTHER = "rnt.lab", 8443, 8080, 19090, 19091, 19800, 19801
PORTS = {"source": (15411, 17011), "sink": (15412, 17012), "echo": (15413, 17013), "tls": (15414, 17014)}
ROUTE_PATH, ROUTE_LOCAL, ROUTE_BACKEND = "/wsroute", 20900, 17020
NETEM = "delay 40ms rate 1000mbit limit 100000"
MiB = 1024 * 1024
POOL, MUX_CON = 64, 8
PROFILE = {"nodelay": True, "mux_version": 2, "mux_streambuffer": 2 * MiB, "mux_recievebuffer": 16 * MiB}
TOKEN = secrets.token_hex(32)
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def sh(cmd, check=True, timeout=120):
    r = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd[:140]}: {(r.stderr or r.stdout).strip()[:600]}")
    return r.stdout


def nsx(ns, cmd, **kw):
    return sh(f"ip netns exec {ns} {cmd}", **kw)


def log(msg):
    print(time.strftime("%H:%M:%S ") + msg, flush=True)


def write(path, text, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def toml(section, kv):
    out = [f"[{section}]"]
    for k, v in kv.items():
        v = ("true" if v else "false") if isinstance(v, bool) else json.dumps(v) if isinstance(v, (str, list)) else v
        out.append(f"{k} = {v}")
    return "\n".join(out) + "\n"


def pct(values, q):
    if not values:
        return None
    v = sorted(values)
    return round(v[min(len(v) - 1, int(q * len(v)))], 2)


# ---------------------------------------------------------------- helpers run inside a namespace

def wsecho(port, logpath):
    """A minimal WebSocket server: answers the upgrade, records what reached it, then echoes raw bytes."""
    import asyncio

    async def handle(r, w):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = await r.read(4096)
            if not chunk or len(data) > 16384:
                w.close()
                return
            data += chunk
        head, rest = data.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        hdr = {k.strip().lower(): v.strip() for k, v in (x.split(":", 1) for x in lines[1:] if ":" in x)}
        acc = base64.b64encode(hashlib.sha1((hdr.get("sec-websocket-key", "") + GUID).encode()).digest()).decode()
        with open(logpath, "a") as f:
            f.write(json.dumps({"path": lines[0].split(" ")[1], "xff": hdr.get("x-forwarded-for"), "host": hdr.get("host")}) + "\n")
        w.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                 f"Sec-WebSocket-Accept: {acc}\r\n\r\n").encode())
        if rest:
            w.write(rest)
        await w.drain()
        while True:
            chunk = await r.read(65536)
            if not chunk:
                break
            w.write(chunk)
            await w.drain()
        w.close()

    async def main():
        srv = await asyncio.start_server(handle, "127.0.0.1", int(port))
        async with srv:
            await srv.serve_forever()

    asyncio.run(main())


def wsprobe(host, port, sni, ca, path, n):
    """N WebSocket upgrades through the site, each followed by a 64-byte echo; timings in ms."""
    ctx = ssl.create_default_context(cafile=ca)
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)  # lab CA; the chain itself is still checked
    shake, echo, fails = [], [], {}
    for _ in range(int(n)):
        try:
            t0 = time.perf_counter()
            s = ctx.wrap_socket(socket.create_connection((host, int(port)), timeout=5), server_hostname=sni)
            key = base64.b64encode(os.urandom(16)).decode()
            s.sendall((f"GET {path} HTTP/1.1\r\nHost: {sni}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                       f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                c = s.recv(4096)
                if not c:
                    break
                resp += c
            if not resp.startswith(b"HTTP/1.1 101"):
                raise RuntimeError("status " + resp[:12].decode("latin-1", "replace"))
            t1 = time.perf_counter()
            payload, got = os.urandom(64), b""
            s.sendall(payload)
            while len(got) < 64:
                c = s.recv(64 - len(got))
                if not c:
                    break
                got += c
            if got != payload:
                raise RuntimeError("echo mismatch")
            echo.append((time.perf_counter() - t1) * 1000)
            shake.append((t1 - t0) * 1000)
            s.close()
        except Exception as e:  # noqa: BLE001 - counted, the probe goes on
            k = type(e).__name__ + ": " + str(e)[:60]
            fails[k] = fails.get(k, 0) + 1
        time.sleep(0.05)
    print(json.dumps({"n": int(n), "ok": len(shake), "upgrade_p50_ms": pct(shake, 0.5), "upgrade_p90_ms": pct(shake, 0.9),
                      "echo_p50_ms": pct(echo, 0.5), "fails": fails}))


# ---------------------------------------------------------------- setup

def nginx_binary():
    if os.path.exists(NGINX):
        return
    deb = f"{LAB}/nginx-deb"
    shutil.rmtree(deb, ignore_errors=True)
    os.makedirs(deb)
    sh(f"cd {deb} && apt-get download nginx", timeout=180)
    pkg = [f for f in os.listdir(deb) if f.endswith(".deb")][0]
    sh(f"dpkg-deb -x {deb}/{pkg} {NGX_ROOT}")
    log("nginx unpacked: " + sh(f"{NGINX} -v 2>&1").strip())


def package():
    """The real generator: rnt.sh and its templates, laid out as on a server."""
    shutil.rmtree(PKG, ignore_errors=True)
    os.makedirs(f"{PKG}/nginx")
    for src, dst in (("rnt.sh", "rnt.sh"), ("rnt-site.conf.tmpl", "nginx/site.conf.tmpl"),
                     ("rnt-auth.conf.tmpl", "nginx/auth.conf.tmpl"), ("rnt-out.conf.tmpl", "nginx/out.conf.tmpl")):
        shutil.copy(f"{LAB}/lab/{src}", f"{PKG}/{dst}")
    write(f"{PKG}/token", TOKEN + "\n")


def rnt(*args):
    return sh(f"bash {PKG}/rnt.sh " + " ".join(args))


def setup():
    teardown(quiet=True)
    for f in (ENGINE, LOAD, f"{LAB}/lab/rnt.sh", f"{LAB}/lab/rnt-site.conf.tmpl", f"{LAB}/lab/rnt-auth.conf.tmpl",
              f"{LAB}/lab/rnt-out.conf.tmpl", f"{LAB}/lab/rnt-index.html"):
        if not os.path.exists(f):
            sys.exit(f"missing {f}")
    nginx_binary()
    sh("modprobe tcp_bbr")
    for ns in (NS_U, NS_I, NS_G):
        sh(f"ip netns add {ns}")
        sh(f"ip -n {ns} link set lo up")
    sh(f"ip link add rU netns {NS_U} type veth peer name rIU netns {NS_I}")
    sh(f"ip link add rIG netns {NS_I} type veth peer name rG netns {NS_G}")
    for ns, dev, a in ((NS_U, "rU", USER_SRC + "/24"), (NS_I, "rIU", USER_IP + "/24"),
                       (NS_I, "rIG", ENTRY_IP + "/24"), (NS_G, "rG", EXIT_IP + "/24")):
        sh(f"ip -n {ns} addr add {a} dev {dev}")
        sh(f"ip -n {ns} link set {dev} mtu 1500 up")
    sh(f"tc -n {NS_I} qdisc replace dev rIG root netem {NETEM}")
    sh(f"tc -n {NS_G} qdisc replace dev rG root netem {NETEM}")
    for ns in (NS_I, NS_G):
        nsx(ns, "sysctl -qw net.ipv4.tcp_congestion_control=bbr")
    shutil.rmtree(RUN, ignore_errors=True)
    os.makedirs(RUN, mode=0o700)
    for d in ("www", "tmpI", "tmpG", "tmpH", "acme/.well-known/acme-challenge"):
        os.makedirs(f"{RUN}/{d}", exist_ok=True)
    shutil.copy(f"{LAB}/lab/rnt-index.html", f"{RUN}/www/index.html")
    write(f"{RUN}/acme/.well-known/acme-challenge/labtoken", "acme-ok\n", 0o644)
    package()
    # A lab CA, the site's certificate from it, and a second CA nobody uses (an impostor's trust).
    for ca in ("ca", "otherca"):
        sh(f"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=rnt-lab-{ca} "
           f"-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign "
           f"-addext subjectKeyIdentifier=hash -keyout {RUN}/{ca}.key -out {RUN}/{ca}.pem")
    sh(f"openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN={DOMAIN} -keyout {RUN}/site.key -out {RUN}/site.csr")
    write(f"{RUN}/site.ext", f"subjectAltName=DNS:{DOMAIN}\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n"
                             "keyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    sh(f"openssl x509 -req -in {RUN}/site.csr -CA {RUN}/ca.pem -CAkey {RUN}/ca.key -CAcreateserial -days 2 "
       f"-extfile {RUN}/site.ext -out {RUN}/site.pem")
    log("lab ready: " + nsx(NS_I, f"ping -c 3 -q {EXIT_IP}").splitlines()[-1])


def teardown(quiet=False):
    sh(f"pkill -f '^{ENGINE} ' || true; pkill -f '^{LOAD} ' || true; pkill -f '{NGX_ROOT}/usr/sbin/nginx' || true; "
       f"pkill -f '{SELF} wsecho' || true", check=False)
    time.sleep(1)
    for ns in (NS_U, NS_I, NS_G):
        sh(f"ip netns del {ns}", check=False)
    if not quiet:
        log("lab removed")


# ---------------------------------------------------------------- processes

def popen(ns, cpu, cmd, logname):
    return subprocess.Popen(f"exec ip netns exec {ns} taskset -c {cpu} {cmd}", shell=True,
                            stdout=open(f"{RUN}/{logname}.log", "w"), stderr=subprocess.STDOUT)


def established(ns, filt, proc=None):
    out = nsx(ns, f"ss -tnpH state established '{filt}'", check=False).splitlines()
    return len([x for x in out if proc is None or f'"{proc}"' in x])


def listening(ns, port):
    return bool(nsx(ns, f"ss -ltnH '( sport = :{port} )'", check=False).strip())


def nginx_main(side, include):
    return f"""user root;
worker_processes 2;
worker_rlimit_nofile 65536;
pid {RUN}/nginx-{side}.pid;
error_log {RUN}/nginx-{side}-error.log warn;
events {{ worker_connections 16384; }}
http {{
    access_log off;
    default_type text/html;
    sendfile on;
    tcp_nodelay on;
    client_body_temp_path {RUN}/tmp{side}/body;
    proxy_temp_path {RUN}/tmp{side}/proxy;
    fastcgi_temp_path {RUN}/tmp{side}/fastcgi;
    uwsgi_temp_path {RUN}/tmp{side}/uwsgi;
    scgi_temp_path {RUN}/tmp{side}/scgi;
{include}
}}
"""


def start_nginx(ns, side, cpu, port):
    conf = f"{RUN}/nginx-{side}.conf"
    base = f"{NGINX} -p {RUN} -c {conf} -e {RUN}/nginx-{side}-error.log"
    r = subprocess.run(f"ip netns exec {ns} {base} -t", shell=True, text=True, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"nginx -t ({side}): " + r.stderr.strip()[:800])
    p = popen(ns, cpu, f"{base} -g 'daemon off;'", f"nginx-{side}")
    for _ in range(50):
        if listening(ns, port):
            return p
        time.sleep(0.1)
    raise RuntimeError(f"nginx ({side}) did not listen on {port}")


def entry_nginx():
    """The entry's site exactly as rnt.sh iran renders it (plus the lab's own main nginx.conf)."""
    write(f"{RUN}/auth.conf", rnt("render-auth", "lab"))
    site = rnt("render-site", "--name lab", f"--domain {DOMAIN}", f"--listen {SITE_PORT}", f"--backend {BACKEND}",
               f"--cert {RUN}/site.pem", f"--key {RUN}/site.key", f"--root {RUN}/www", f"--acme-root {RUN}/acme",
               f"--auth {RUN}/auth.conf", f"--route {ROUTE_PATH}={ROUTE_LOCAL}/", f"--http {HTTP_PORT}")
    write(f"{RUN}/site.conf", site, 0o644)
    write(f"{RUN}/nginx-I.conf", nginx_main("I", f"    include {RUN}/site.conf;"))
    return start_nginx(NS_I, "I", 0, SITE_PORT)


def exit_nginx():
    """The exit's way out exactly as rnt.sh kharej --via-nginx renders it, plus one trusting the wrong CA."""
    out = rnt("render-out", "--name lab", f"--domain {DOMAIN}", f"--listen-port {OUT_PORT}",
              f"--upstream {ENTRY_IP}:{SITE_PORT}", f"--ca {RUN}/ca.pem", f"--bind {EXIT_IP}")
    other = rnt("render-out", "--name labother", f"--domain {DOMAIN}", f"--listen-port {OUT_OTHER}",
                f"--upstream {ENTRY_IP}:{SITE_PORT}", f"--ca {RUN}/otherca.pem", f"--bind {EXIT_IP}")
    write(f"{RUN}/out.conf", out, 0o644)
    write(f"{RUN}/out-other.conf", other, 0o644)
    write(f"{RUN}/nginx-G.conf", nginx_main("G", f"    include {RUN}/out.conf;"))
    # The impostor's NGINX is a separate process: one NGINX shares an implicit upstream (and its resumable TLS
    # sessions) between servers that proxy to the same address, which would let it skip the certificate check.
    write(f"{RUN}/nginx-H.conf", nginx_main("H", f"    include {RUN}/out-other.conf;"))
    return start_nginx(NS_G, "G", 1, OUT_PORT)


def server_toml(mode):
    ports = [f"0.0.0.0:{u}={b}" for u, b in PORTS.values()] + [f"127.0.0.1:{ROUTE_LOCAL}={ROUTE_BACKEND}"]
    kv = {"transport": "wsmux", "bind_addr": f"127.0.0.1:{BACKEND}"}
    if mode == "wssmux":
        kv = {"transport": "wssmux", "bind_addr": f"0.0.0.0:{DIRECT_PORT}", "tls_cert": f"{RUN}/site.pem", "tls_key": f"{RUN}/site.key"}
    return toml("server", {**kv, "token": TOKEN, "skip_optz": True, "log_level": "info", **PROFILE, "mux_con": MUX_CON, "ports": ports})


def client_toml(mode, ca="ca.pem", pool=POOL, out_port=OUT_PORT):
    common = {"token": TOKEN, "connection_pool": pool, "skip_optz": True, "log_level": "info", **PROFILE}
    if mode == "wssmux":
        kv = {"remote_addr": f"{ENTRY_IP}:{DIRECT_PORT}", "transport": "wssmux"}
    elif mode == "direct":
        kv = {"remote_addr": f"{DOMAIN}:{SITE_PORT}", "edge_ip": ENTRY_IP, "local_addr": EXIT_IP, "transport": "wssmux",
              "simple_auth": True, "tls_verify": True, "tls_ca_file": f"{RUN}/{ca}"}
    else:
        kv = {"remote_addr": f"127.0.0.1:{out_port}", "transport": "wsmux"}
    return toml("client", {**kv, **common})


class Tunnel:
    def __init__(self, mode):
        self.mode = mode
        self.wire = {"wssmux": DIRECT_PORT, "direct": SITE_PORT, "vianginx": OUT_PORT}[mode]
        write(f"{RUN}/server-{mode}.toml", server_toml(mode))
        write(f"{RUN}/client-{mode}.toml", client_toml(mode))

    def start(self):
        self.srv = popen(NS_I, 0, f"{ENGINE} -c {RUN}/server-{self.mode}.toml", f"server-{self.mode}")
        port = DIRECT_PORT if self.mode == "wssmux" else BACKEND
        for _ in range(50):
            if listening(NS_I, port):
                break
            time.sleep(0.2)
        t0 = time.monotonic()
        self.cli = popen(NS_G, 1, f"{ENGINE} -c {RUN}/client-{self.mode}.toml", f"client-{self.mode}")
        while time.monotonic() - t0 < 90:
            if established(NS_G, f"( dport = :{self.wire} )", "hwtunnel") >= POOL + 1:
                break
            time.sleep(0.25)
        self.ready_s = round(time.monotonic() - t0, 2)
        time.sleep(3)
        return established(NS_G, f"( dport = :{self.wire} )", "hwtunnel")

    def stop(self):
        for p in (self.cli, self.srv):
            p.terminate()
        for p in (self.cli, self.srv):
            try:
                p.wait(8)
            except subprocess.TimeoutExpired:
                p.kill()
        time.sleep(2)


def backends():
    procs = [popen(NS_G, 3, f"{LOAD} -serve {k} -listen 127.0.0.1:{b}", f"backend-{k}") for k, (_, b) in PORTS.items()]
    procs.append(popen(NS_G, 3, f"python3 -I {SELF} wsecho {ROUTE_BACKEND} {RUN}/wsecho.jsonl", "wsecho"))
    time.sleep(1.5)
    return procs


def load(args, timeout=120):
    r = subprocess.run(f"ip netns exec {NS_U} taskset -c 2 {LOAD} {args}", shell=True, text=True,
                       capture_output=True, timeout=timeout)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001 - a failed client is recorded, the run goes on
        return {"error": (r.stderr or r.stdout).strip()[:300]}


def tree(pid):
    pids = [pid]
    for child in sh(f"pgrep -P {pid}", check=False).split():
        pids += tree(int(child))
    return pids


def cpu_seconds(pids):
    total = 0.0
    for pid in pids:
        try:
            f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
            total += (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")
        except OSError:
            pass
    return total


def addr(kind):
    return f"{USER_IP}:{PORTS[kind][0]}"


# ---------------------------------------------------------------- probes

def curl(args):
    return nsx(NS_G, f"curl -sS -m 5 --cacert {RUN}/ca.pem --resolve {DOMAIN}:{SITE_PORT}:{ENTRY_IP} {args}", check=False).strip()


def stranger():
    up = "-H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: cm50LWxhYi1wcm9iZQ=='"
    base = f"https://{DOMAIN}:{SITE_PORT}"
    code = lambda a: curl(f"-o /dev/null -w '%{{http_code}}' {a}")  # noqa: E731
    res = {
        "site": code(f"{base}/"),
        "site_is_the_site": "<html" in curl(f"{base}/"),
        "channel_plain": code(f"{base}/channel"),
        "channel_upgrade_no_token": code(f"{up} {base}/channel"),
        "tunnel_wrong_token": code(f"{up} -H 'Authorization: Bearer {'0' * 64}' {base}/tunnel/123"),
        "tunnel_dotdot": code(f"{up} --path-as-is {base}/static/../tunnel/1"),
        "route_plain": code(f"{base}{ROUTE_PATH}"),
        "missing_page": code(f"{base}/no-such-page"),
        "http_root": nsx(NS_G, f"curl -sS -m 5 -o /dev/null -w '%{{http_code}} %{{redirect_url}}' http://{ENTRY_IP}:{HTTP_PORT}/", check=False).strip(),
        "http_acme": nsx(NS_G, f"curl -sS -m 5 http://{ENTRY_IP}:{HTTP_PORT}/.well-known/acme-challenge/labtoken", check=False).strip(),
    }
    res["tunnel_404_same_as_missing"] = curl(f"{up} {base}/channel") == curl(f"{base}/no-such-page")
    alpn = nsx(NS_G, f"sh -c 'echo | openssl s_client -connect {ENTRY_IP}:{SITE_PORT} -servername {DOMAIN} -alpn h2,http/1.1 2>/dev/null'", check=False)
    m = re.search(r"ALPN protocol: (\S+)", alpn)
    res["alpn_for_h2_offer"] = m.group(1) if m else "none"
    return res


def route_probe(n):
    r = subprocess.run(f"ip netns exec {NS_U} python3 -I {SELF} wsprobe {USER_IP} {SITE_PORT} {DOMAIN} {RUN}/ca.pem {ROUTE_PATH} {n}",
                       shell=True, text=True, capture_output=True, timeout=120)
    try:
        res = json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        return {"error": (r.stderr or r.stdout).strip()[:300]}
    seen = [json.loads(x) for x in open(f"{RUN}/wsecho.jsonl").read().splitlines()[-int(n):]] if os.path.exists(f"{RUN}/wsecho.jsonl") else []
    res["upstream_paths"] = sorted({s["path"] for s in seen})
    res["xff_has_user"] = bool(seen) and all(USER_SRC in (s.get("xff") or "") for s in seen)
    return res


def impostor(mode):
    """An exit that trusts another CA: it must never hold a session to the entry."""
    if mode == "direct":
        write(f"{RUN}/client-imp.toml", client_toml("direct", ca="otherca.pem", pool=2))
        wire = SITE_PORT
    else:
        write(f"{RUN}/client-imp.toml", client_toml("vianginx", pool=2, out_port=OUT_OTHER))
        wire = OUT_OTHER
        ngx_h = start_nginx(NS_G, "H", 1, OUT_OTHER)
    main_log = f"{RUN}/client-{mode}.log"
    restarts0 = open(main_log).read().count("restarting client")
    p = popen(NS_G, 1, f"{ENGINE} -c {RUN}/client-imp.toml", f"client-imp-{mode}")
    time.sleep(12)
    own = nsx(NS_G, f"ss -tnpH state established '( dport = :{wire} )'", check=False)
    sessions = sum(1 for line in own.splitlines() if f"pid={p.pid}," in line)
    # through NGINX the engine reaches the loopback server; what matters is whether the entry let anything in
    entry_seen = nsx(NS_I, f"ss -tnH state established '( sport = :{BACKEND} )'", check=False).count("\n")
    p.terminate()
    p.wait(8)
    text = open(f"{RUN}/client-imp-{mode}.log").read()
    if mode != "direct":
        ngx_h.terminate()
        ngx_h.wait(8)
        text += open(f"{RUN}/nginx-H-error.log").read()
    # The engine hands the control seat to any client with the token, so an impostor that got through shows up
    # as the real exit being thrown out.
    displaced = open(main_log).read().count("restarting client") > restarts0
    return {"own_sessions_to_wire": sessions, "certificate_refused": bool(re.search(r"certificate|x509|unknown authority|verify", text, re.I)),
            "main_exit_displaced": displaced, "entry_engine_sessions_during": entry_seen}


# ---------------------------------------------------------------- run

def measure(t, entry_pids, exit_pids, quick):
    warm, dur = (2, 5) if quick else (3, 8)
    rec = {"ready_s": t.ready_s}
    rec["latency_tls"] = load(f"-mode tls -addr {addr('tls')} -n {15 if quick else 40} -c 1 -gap 100ms -timeout 5s")
    rec["latency_open"] = load(f"-mode open -addr {addr('echo')} -n {20 if quick else 60} -c 1 -gap 80ms -timeout 5s")
    rec["rtt"] = load(f"-mode rtt -addr {addr('echo')} -n {20 if quick else 60} -gap 50ms -timeout 5s")
    for name, mode, k, target in (("down1", "down", 1, "source"), ("down8", "down", 8, "source"),
                                  ("up1", "up", 1, "sink"), ("up8", "up", 8, "sink")):
        ep, xp = entry_pids(), exit_pids()
        e0, x0, w0 = cpu_seconds(ep), cpu_seconds(xp), time.monotonic()
        rec[name] = load(f"-mode {mode} -addr {addr(target)} -k {k} -rate 0 -ramp 1s -warm {warm}s -for {dur}s -label {name}")
        el = time.monotonic() - w0
        rec[name]["entry_cpu"] = round((cpu_seconds(ep) - e0) / el, 3)
        rec[name]["exit_cpu"] = round((cpu_seconds(xp) - x0) / el, 3)
        time.sleep(2)
    return rec


def summary(results):
    lines = []
    for mode in ("wssmux", "direct", "vianginx"):
        r = results.get(mode)
        if not isinstance(r, dict) or "down1" not in r:
            lines.append(f"{mode:9s} {r.get('error') if isinstance(r, dict) else 'not run'}")
            continue
        g = lambda d, k: (d.get(k) or {}).get("p50") if isinstance(d, dict) else None  # noqa: E731
        lines.append(f"{mode:9s} ready={r['ready_s']}s sessions={r['sessions']} tls_p50={g(r['latency_tls'], 'total_ms')}ms "
                     f"open_p50={g(r['latency_open'], 'total_ms')}ms rtt_p50={g(r['rtt'], 'rtt_ms')}ms | "
                     + " ".join(f"{n}={round(r[n].get('mbps') or 0, 1)}Mbps(cpu entry {r[n].get('entry_cpu')} exit {r[n].get('exit_cpu')})"
                                for n in ("down1", "down8", "up1", "up8")))
        if "route" in r:
            lines.append(f"{'':9s} route: {json.dumps(r['route'], ensure_ascii=False)}")
        if "impostor" in r:
            lines.append(f"{'':9s} impostor: {json.dumps(r['impostor'])}")
    return "\n".join(lines)


def run(quick):
    setup()
    os.makedirs(OUT_DIR, exist_ok=True)
    out = f"{OUT_DIR}/{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-v2.json"
    results = {"env": {"kernel": os.uname().release, "netem": NETEM, "pool": POOL, "mux_con": MUX_CON, "profile": PROFILE,
                       "engine_sha": sh(f"sha256sum {ENGINE}").split()[0][:16], "nginx": sh(f"{NGINX} -v 2>&1").strip(),
                       "rnt_sha": sh(f"sha256sum {PKG}/rnt.sh").split()[0][:16], "quick": quick}}
    bk = backends()
    try:
        for mode in ("wssmux", "direct", "vianginx"):
            ngx_i = ngx_g = None
            try:
                if mode != "wssmux":
                    ngx_i = entry_nginx()
                if mode == "vianginx":
                    ngx_g = exit_nginx()
                t = Tunnel(mode)
                sessions = t.start()
                log(f"{mode}: {sessions} engine sessions in {t.ready_s}s")
                entry_pids = lambda: tree(t.srv.pid) + (tree(ngx_i.pid) if ngx_i else [])  # noqa: E731
                exit_pids = lambda: tree(t.cli.pid) + (tree(ngx_g.pid) if ngx_g else [])  # noqa: E731
                rec = {"sessions": sessions}
                if ngx_g:
                    rec["exit_nginx_to_entry"] = established(NS_G, f"( dport = :{SITE_PORT} )", "nginx")
                rec.update(measure(t, entry_pids, exit_pids, quick))
                if ngx_i:
                    rec["route"] = route_probe(10 if quick else 30)
                    rec["impostor"] = impostor(mode)
                if mode == "vianginx":
                    rec["stranger"] = stranger()
                    rec["nginx_errors"] = {s: open(f"{RUN}/nginx-{s}-error.log").read()[-1200:] for s in ("I", "G")}
                rec["client_log_tail"] = open(f"{RUN}/client-{mode}.log").read()[-1000:]
                results[mode] = rec
                t.stop()
            except Exception as e:  # noqa: BLE001 - one shape failing must not hide the others
                results[mode] = {"error": f"{type(e).__name__}: {str(e)[:800]}"}
                log(f"{mode}: FAILED {results[mode]['error']}")
                sh(f"pkill -f '^{ENGINE} ' || true", check=False)
            finally:
                for p in (ngx_g, ngx_i):
                    if p:
                        p.terminate()
                        p.wait(8)
                time.sleep(1)
    finally:
        for b in bk:
            b.terminate()
        write(out, json.dumps(results, ensure_ascii=False, indent=1), 0o644)
        teardown()
    log("results: " + out)
    print(summary(results))
    if "vianginx" in results and isinstance(results["vianginx"], dict):
        print("stranger:", json.dumps(results["vianginx"].get("stranger"), ensure_ascii=False))


if __name__ == "__main__":
    act = sys.argv[1] if len(sys.argv) > 1 else ""
    if act == "run":
        run(quick=len(sys.argv) > 2 and sys.argv[2] == "quick")
    elif act == "teardown":
        teardown()
    elif act == "wsecho":
        wsecho(sys.argv[2], sys.argv[3])
    elif act == "wsprobe":
        wsprobe(*sys.argv[2:8])
    else:
        sys.exit(__doc__)
