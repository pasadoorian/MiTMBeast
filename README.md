# MiTM Beast - Firmware & Network Device Security Testing Toolkit

MiTM Beast turns a Linux machine into a wireless MITM router purpose-built for security testing of firmware-based devices: IoT, edge gateways, enterprise routers/switches/firewalls, server BMCs (iDRAC, iLO, Supermicro), storage controllers, and network appliances. It intercepts device-to-cloud communication — with a focus on OTA firmware update channels — to identify vulnerabilities in how devices establish and validate TLS, authenticate update servers, and handle protocol downgrades.

The full interception stack: wireless access point, DHCP, DNS spoofing, five TLS proxy modes (mitmproxy, sslsplit, certmitm, sslstrip, intercept), NTP time manipulation, and a fake firmware server that impersonates vendor update infrastructure.

**v2.0 status (alpha):** the toolkit is being rewritten in Python with a Textual TUI front-end. Today the new `mitmbeast` CLI is a drop-in replacement for the v1.1 bash entry points — the entire feature surface is exposed and the proxy/router lifecycle runs natively in Python under `--python`. The TUI (`./mitmbeast`) wraps it all into a single interactive interface.

## Architecture

```
                                Internet
                                    |
+-----------------------------------------------------------------------+
|  MITM Router                      |                                   |
|                           +-------+-------+                           |
|  +-------------+          |  WAN (eth0)   |                           |
|  |   WiFi AP   |          |  <WAN-IP>     |                           |
|  |   (wlan0)   |          +---------------+                           |
|  +------+------+                                                      |
|         |                                                             |
|  +------+------+    +-------------+                                   |
|  |   Bridge    |----+  LAN (eth1) |                                   |
|  |    (br0)    |    +-------------+                                   |
|  |192.168.200.1|                                                      |
|  +------+------+                                                      |
|         |                                                             |
|  +------+----------------------------------------------------+        |
|  |  dnsmasq (DHCP + DNS spoofing)                            |        |
|  |  hostapd (WiFi AP)                                        |        |
|  |  iptables (NAT + traffic redirect)                        |        |
|  |  Proxy: mitmproxy / sslsplit / certmitm / sslstrip        |        |
|  +-----------------------------------------------------------+        |
+-----------------------------------------------------------------------+
                                    |
                          +---------+---------+
                          |   Target Device   |
                          +-------------------+
```

---

## Installation

### Required packages (Arch Linux)

```bash
sudo pacman -S hostapd dnsmasq bridge-utils net-tools iptables mitmproxy sslsplit tcpdump libfaketime
```

### Required packages (Kali / Debian)

```bash
sudo apt install hostapd dnsmasq bridge-utils net-tools iptables mitmproxy sslsplit tcpdump faketime
```

### certmitm (optional)

```bash
git clone https://github.com/aapooksman/certmitm /opt/certmitm
cd /opt/certmitm && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
```

### Delorean NTP spoofer (optional)

```bash
git clone https://github.com/jselvi/Delorean delorean
```

### Python venv (v2.0+)

The `mitmbeast` CLI runs in a `uv`-managed Python venv. First-time setup is automatic — `./mitmbeast` will run `uv sync` if the venv is missing.

If you don't have `uv`:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Setup

```bash
cp mitm.conf.example mitm.conf
# Edit mitm.conf — set interface names, Wi-Fi credentials, and mode settings
./mitmbeast --version    # auto-creates the venv on first run
```

> **Warning:** bringing the router up stops NetworkManager, systemd-networkd, and systemd-resolved. Use a dedicated machine or VM. Run `mitmbeast restore` (or `mitm.sh restore` in v1.1) to repurpose the host afterward.

---

## Configuration

### mitm.conf — key variables

| Variable | Purpose |
|----------|---------|
| `WAN_IFACE`, `LAN_IFACE`, `WIFI_IFACE` | Network interfaces |
| `WIFI_SSID`, `WIFI_PASSWORD` | Access point credentials |
| `LAN_IP`, `LAN_SUBNET`, `LAN_DHCP_*` | Bridge network (default: 192.168.200.0/24) |
| `WAN_STATIC_IP` | Static WAN IP — leave empty for DHCP |
| `PROXY_MODE` | Default mode (overridden by `-m` flag) |
| `MITMPROXY_PORT`, `MITMPROXY_WEB_PORT` | mitmproxy listen and web UI ports |
| `SSLSPLIT_PORT`, `SSLSPLIT_PCAP_DIR` | sslsplit settings |
| `CERTMITM_PATH`, `CERTMITM_PORT`, `CERTMITM_WORKDIR` | certmitm settings |
| `SSLSTRIP_PORT`, `SSLSTRIP_FAKE_SERVER_PORT` | sslstrip + HTTP server ports |
| `INTERCEPT_PORT`, `INTERCEPT_FAKE_SERVER_PORT`, `INTERCEPT_DOMAINS` | intercept mode settings |

### dns-spoof.conf

Maps domains to the router IP for interception. Domains not listed resolve normally (passthrough).

```bash
# Redirect update.example.com to the MITM router
address=/update.example.com/192.168.200.1

# api.example.com is NOT listed — resolves to real IP (passthrough)
```

Manage entries with `dns-spoof.sh`:

```bash
./dns-spoof.sh add update.example.com 192.168.200.1
./dns-spoof.sh add device.example.com ::1            # IPv6 also accepted
./dns-spoof.sh add api.example.com 192.168.200.1 --force   # Skip passthrough warning
./dns-spoof.sh rm update.example.com
./dns-spoof.sh list
./dns-spoof.sh reload          # Reload dnsmasq
./dns-spoof.sh dump example.com  # Test resolution
```

The `add` subcommand validates the domain (DNS-safe characters only) and the IP (IPv4 or IPv6) before writing to `dns-spoof.conf`, blocking injection attempts. If the domain matches a `*_PASSTHROUGH_DOMAINS` entry in `mitm.conf`, a warning is printed (DNS-spoofing it would break the passthrough mode that depends on it). Pass `--force` to suppress the warning.

---

## Router Commands

### TUI (recommended for interactive use)

```bash
sudo ./mitmbeast                    # opens the Textual TUI
```

The TUI exposes five tabs (Dashboard / Clients / DNS Spoofs / Sessions / Logs) with hotkeys (D, C, N, S, L). The Dashboard has a mode dropdown + Up/Down/Refresh buttons; the Up button uses the new Python core for `mode=none` and falls through to the legacy bash for proxy modes pending P2.10.

### CLI (scripting / automation)

```bash
sudo mitmbeast up -m <mode>          # legacy bash (default — fully tested)
sudo mitmbeast up --python -m none   # Python core (P2.9b+)
sudo mitmbeast up --python -m sslsplit/sslstrip/certmitm/intercept
sudo mitmbeast up -k -m mitmproxy    # -k keeps WAN, preserving SSH
sudo mitmbeast down [--python] [-k]
sudo mitmbeast reload [-m mode]
sudo mitmbeast restore [--python] [--manager NetworkManager|systemd-networkd|none]
```

**Modes:** `mitmproxy` | `sslsplit` | `certmitm` | `sslstrip` | `intercept` | `none`

The bash entry points still work too — `./mitm.sh up …`, `./dns-spoof.sh add …`, `./delorean.sh start …` — for backwards compatibility with v1.1 documentation and any external scripts. They will be retired in v3.0.

`restore` puts the host back into a normal Linux configuration after MITM Beast use. It re-enables the network manager you choose (interactive prompt, or `--manager <NetworkManager|systemd-networkd|none>`), restores `/etc/resolv.conf`, and removes any leftover `MITM_*` iptables chains. See `RESTORE.md` for the manual procedure if the tool is unavailable.

### `--python` flag

`mitmbeast up --python` (and `down`, `restore`) opt into the new pure-Python core that's replacing the v1.1 bash implementation. Without `--python`, the CLI shells out to the v1.1 bash scripts (which still work). Use this to A/B-test old vs new behavior. v3.0 will drop the bash shims and make `--python` the (only) implementation.

---

## Proxy Modes

### mitmproxy (`-m mitmproxy`)

Transparent HTTPS proxy with interactive web UI. Intercepts all port 443 traffic.

```bash
sudo ./mitm.sh up -m mitmproxy
# Web UI: http://<WAN_IP>:8080
```

iptables rule set:
```
-i br0 --dport 443 -> REDIRECT :8081
```

### sslsplit (`-m sslsplit`)

Generic TLS interception. Generates a session CA, terminates TLS, and captures connections to PCAP files under `sslsplit_logs/session_*/`.

```bash
sudo ./mitm.sh up -m sslsplit
# Session logs: sslsplit_logs/session_YYYYMMDD_HHMMSS/
```

### certmitm (`-m certmitm`)

Tests TLS certificate validation by presenting various invalid certificates (self-signed, wrong CN, expired, untrusted CA). Reports VULNERABLE or SECURE per connection.

```bash
sudo ./mitm.sh up -m certmitm
# Logs: certmitm_logs/session_YYYYMMDD_HHMMSS/
```

**Passthrough domains** — devices often make sequential connections where the first must succeed before the second is attempted. DNS-spoof only the domains to test; leave passthrough domains out of `dns-spoof.conf` so they resolve to real servers.

```bash
# mitm.conf
CERTMITM_TEST_DOMAINS="update.example.com"
CERTMITM_PASSTHROUGH_DOMAINS="api.example.com"

# dns-spoof.conf
address=/update.example.com/192.168.200.1
# api.example.com NOT listed — connects to real server
```

iptables rule set:
```
-i br0 -d 192.168.200.1 --dport 443 -> REDIRECT :8081
```

### sslstrip (`-m sslstrip`)

Tests TLS downgrade vulnerability. Intercepts HTTPS connections from DNS-spoofed domains and responds with HTTP. Starts `fake-firmware-server.py` on port 80 to serve content over HTTP.

```bash
sudo ./mitm.sh up -m sslstrip
# Logs: sslstrip_logs/session_YYYYMMDD_HHMMSS/
```

iptables rules set:
```
-i br0 -d 192.168.200.1 --dport 443 -> REDIRECT :10000  (sslstrip)
-i br0 -d 192.168.200.1 --dport 80  -> REDIRECT :80     (fake server)
```

Result: if the device accepts HTTP content it expected over HTTPS → **vulnerable to TLS downgrade**.

### intercept (`-m intercept`)

Exploits missing certificate pinning to serve fake responses. mitmproxy terminates TLS (device accepts the MITM certificate), then forwards requests as plaintext HTTP to `fake-firmware-server.py`.

```bash
sudo ./mitm.sh up -m intercept
# Web UI: http://<WAN_IP>:8080
# Logs: intercept_logs/session_YYYYMMDD_HHMMSS/
```

**Configuration:**

```bash
# mitm.conf
INTERCEPT_PORT="8081"
INTERCEPT_FAKE_SERVER_PORT="8443"
INTERCEPT_FAKE_SERVER_SCRIPT="./fake-firmware-server.py"
INTERCEPT_DOMAINS="update.example.com"
INTERCEPT_PASSTHROUGH_DOMAINS="api.example.com"

# dns-spoof.conf
address=/update.example.com/192.168.200.1
# api.example.com NOT listed
```

The `mitmproxy-intercept.py` addon reads `FAKE_SERVER_HOST`, `FAKE_SERVER_PORT`, and `INTERCEPT_DOMAINS` from the environment (set automatically by `mitm.sh`). It redirects matching domains to the fake server and logs unexpected traffic.

iptables rule set:
```
-i br0 -d 192.168.200.1 --dport 443 -> REDIRECT :8081
```

### none (`-m none`)

Router only — NAT and DHCP, no traffic interception. Useful for baseline testing or manual proxy setup.

```bash
sudo ./mitm.sh up -m none
```

---

## Packet Capture

Add `-c` to any `up` or `reload` command to capture traffic on the bridge interface:

```bash
sudo ./mitm.sh up -m mitmproxy -c
# Saves to: captures/br0_YYYYMMDD_HHMMSS_<id>.pcap
```

---

## NTP Spoofing (Delorean)

`delorean.sh` wraps the Delorean NTP spoofer and sets iptables DNAT rules to intercept NTP traffic — including devices that use hardcoded NTP IPs (Cloudflare `162.159.200.1/123`, Google `216.239.35.0/4/8/12`).

```bash
sudo ./delorean.sh start +1500     # Offset in days from current date
sudo ./delorean.sh start -3650
sudo ./delorean.sh start "2030-06-15"  # Absolute date
./delorean.sh status
sudo ./delorean.sh stop            # Stops and removes iptables rules
```

### NTP + Certificate Time Attack

Combine NTP spoofing with a time-matched self-signed certificate to MITM connections. The device's manipulated clock makes the certificate appear valid.

**1. Generate a time-matched certificate:**

```bash
mkdir -p certs

# Certificate valid 2029–2032 (for +1500 day offset ~2030)
faketime '2029-01-01' openssl req -x509 -newkey rsa:4096 \
  -keyout certs/future-2030.key \
  -out certs/future-2030.crt \
  -sha256 -days 1095 -nodes \
  -subj "/CN=api.example.com" \
  -addext "subjectAltName=DNS:api.example.com,DNS:update.example.com"

# Verify
openssl x509 -in certs/future-2030.crt -noout -dates
```

Include all DNS-spoofed hostnames in the SAN.

**2. Configure DNS spoofing** — spoof all domains the device will contact:

```bash
address=/api.example.com/192.168.200.1
address=/update.example.com/192.168.200.1
```

**3. Run the attack:**

```bash
sudo ./mitm.sh up -m none
sudo ./delorean.sh start +1500

# Serve content with the time-matched cert
sudo python3 ./fake-firmware-server.py \
  --cert certs/future-2030.crt \
  --key certs/future-2030.key \
  --firmware-dir ./firmware

# Reboot device (triggers NTP sync), then trigger an update check
```

**Time offset reference:**

| Offset | Approx year | Use cert |
|--------|-------------|----------|
| +1500 | ~2030 | future-2030 |
| -3650 | ~2015 | past-2016 |

**4. Cleanup:**

```bash
sudo ./delorean.sh stop
sudo ./mitm.sh down
```

---

## Fake Firmware Server

`fake-firmware-server.py` impersonates a vendor update API. It responds to `/releases` with a high version number (triggering an update), then serves firmware files from a local directory. SHA256 hashes are calculated automatically.

### IoT update flow

```
Device  ->  GET /releases?deviceId=XXX
        <-  {"appVersion":"99.0.0", "appUrl":"https://update.example.com/app/99.0.0/firmware_app"}
Device  ->  GET /app/99.0.0/firmware_app
        <-  [custom firmware binary]
```

### Usage

```bash
# HTTP only (for sslstrip or intercept mode)
sudo python3 ./fake-firmware-server.py --http --http-port 80 --firmware-dir ./firmware

# HTTPS with certificate (for direct or NTP-time attack)
sudo python3 ./fake-firmware-server.py \
  --cert server.crt --key server.key \
  --firmware-dir ./firmware \
  --update-host update.example.com \
  --app-filename firmware_app \
  --firmware-version 99.0.0
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--http` | off | Enable HTTP server |
| `--http-port PORT` | 80 | HTTP port |
| `--cert CERT` | — | SSL certificate (enables HTTPS) |
| `--key KEY` | — | SSL private key |
| `--https-port PORT` | 443 | HTTPS port |
| `--firmware-dir DIR` | `./firmware` | Directory with firmware files |
| `--firmware-version VER` | `99.0.0` | Version advertised in `/releases` |
| `--update-host HOST` | `update.example.com` | Hostname in download URLs |
| `--app-filename NAME` | `firmware_app` | Application firmware filename |
| `--firmware-files F...` | `<app-filename> system.tar` | Allowed filenames (whitelist) |

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `/releases?deviceId=XXX` | Returns firmware version + download URLs |
| `/app/<ver>/<app-filename>` | Serves application firmware |
| `/system/<ver>/system.tar` | Serves system update tarball |

### SSL certificate options

**Self-signed** (works if device doesn't validate certs):
```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
  -days 1 -nodes -subj "/CN=api.example.com"
```

**Time-matched self-signed** (for NTP time attack — see above).

**Custom CA** (if you can install the CA on the device):
```bash
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365 -nodes -subj "/CN=MITM CA"
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=api.example.com"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 1
# Then install ca.crt on the target device
```

---

## Certificate Hostname Substring Test

Tests whether a device accepts a certificate for `update.example.com.attacker.com` when connecting to `update.example.com` (substring hostname matching vulnerability).

**Requires:** a domain you control (e.g., `attacker.com`) and certbot.

**1. Add DNS A record:**
```
update.example.com.attacker.com  A  <your-public-IP>
```

**2. Get a Let's Encrypt certificate:**
```bash
# HTTP challenge
sudo certbot certonly --standalone -d update.example.com.attacker.com

# DNS challenge (no open port required)
sudo certbot certonly --manual --preferred-challenges dns -d update.example.com.attacker.com
```

Cert saves to: `/etc/letsencrypt/live/update.example.com.attacker.com/`

**3. Configure DNS spoofing and start:**
```bash
# dns-spoof.conf
address=/update.example.com/192.168.200.1

sudo ./mitm.sh up -m none

sudo python3 ./fake-firmware-server.py \
  --cert /etc/letsencrypt/live/update.example.com.attacker.com/fullchain.pem \
  --key /etc/letsencrypt/live/update.example.com.attacker.com/privkey.pem
```

**4. Trigger a connection** from the device to `update.example.com`.

- **Vulnerable:** device accepts the certificate → substring hostname matching
- **Secure:** device rejects with hostname mismatch error

**Cleanup:**
```bash
sudo ./mitm.sh down
sudo certbot delete --cert-name update.example.com.attacker.com  # optional
```

---

## Troubleshooting

**Router won't start:**
```bash
ss -tuln | grep -E ':(53|80|443|8080|8081)'   # Check port conflicts
ip link show                                    # Check interface names
```

**DNS spoofing not working:**
```bash
./dns-spoof.sh list
dig update.example.com @192.168.200.1          # Should return 192.168.200.1
./dns-spoof.sh reload
```

**No traffic intercepted:**
```bash
sudo iptables -t nat -L PREROUTING -n -v       # Verify redirect rules
ip neigh show dev br0                          # Verify device is connected
pgrep -a mitmweb; pgrep -a sslsplit           # Verify proxy is running
```

**certmitm fails to start:**
```bash
cat tmp_certmitm.log
# Common: missing venv deps — run pip install -r requirements.txt in venv
```

**NTP spoofing not working:**
```bash
./delorean.sh status
sudo iptables -t nat -L PREROUTING -n -v | grep 123
sudo tcpdump -i br0 -n udp port 123
```

**Certificate errors:**
```bash
openssl x509 -in cert.crt -noout -dates
openssl x509 -in cert.crt -noout -text | grep -A1 "Subject Alternative Name"
```

---

## Legal Notice

For use on devices you own, in authorized penetration testing engagements, and in controlled lab environments. Unauthorized access to computer systems is illegal.

---

## Works That Inspired This Project

MiTM Beast was directly inspired by Matt Brown's ([nmatt0](https://github.com/nmatt0)) open source MITM tooling for IoT security research:

- **[mitmrouter](https://github.com/nmatt0/mitmrouter)** — Bash script to automate setup of a Linux router for IoT device traffic analysis and SSL MITM. The foundation for the router setup approach used in MiTM Beast.
- **[mitmtools](https://github.com/nmatt0/mitmtools)** — System setup and scripts for various MITM activities. Informed the broader tooling philosophy here.

## References

- [Delorean](https://github.com/jselvi/Delorean) — NTP spoofing
- [certmitm](https://github.com/aapooksman/certmitm) — Certificate validation testing
- [mitmproxy](https://mitmproxy.org/)
- [sslsplit](https://www.roe.ch/SSLsplit)
