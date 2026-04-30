# MiTM Beast - Firmware & Network Device Security Testing Toolkit

MiTM Beast turns a Linux machine into a wireless MITM router purpose-built for security testing of firmware-based devices: IoT, edge gateways, enterprise routers/switches/firewalls, server BMCs (iDRAC, iLO, Supermicro), storage controllers, and network appliances. It intercepts device-to-cloud communication — with a focus on OTA firmware update channels — to identify vulnerabilities in how devices establish and validate TLS, authenticate update servers, and handle protocol downgrades.

The full interception stack: wireless access point, DHCP, DNS spoofing, five TLS proxy modes (mitmproxy, sslsplit, certmitm, sslstrip, intercept), NTP time manipulation, and a fake firmware server that impersonates vendor update infrastructure.

**v2.0.0-alpha1** is the current release. The toolkit is now a Python package (`mitmbeast`) with a Textual TUI front-end (`./mitmbeast`). All five proxy modes plus `none` run natively in Python under `mitmbeast up --python`; the v1.x bash entry points (`mitm.sh`, `dns-spoof.sh`, `delorean.sh`) remain as compatibility shims and will be retired in v3.0.

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

Manage entries from the TUI (DNS Spoofs tab — press `n`) or via the CLI:

```bash
mitmbeast spoof add update.example.com 192.168.200.1
mitmbeast spoof add device.example.com ::1            # IPv6 also accepted
mitmbeast spoof add api.example.com 192.168.200.1 --force   # Skip passthrough warning
mitmbeast spoof rm update.example.com
mitmbeast spoof list
```

The `add` subcommand validates the domain (DNS-safe characters only) and the IP (IPv4 or IPv6) before writing to `dns-spoof.conf`, blocking injection attempts. If the domain matches a `*_PASSTHROUGH_DOMAINS` entry in `mitm.conf`, a warning is printed (DNS-spoofing it would break the passthrough mode that depends on it). Pass `--force` to suppress the warning. The legacy `./dns-spoof.sh …` form still works.

---

## Router Commands

### TUI (recommended for interactive use)

```bash
sudo ./mitmbeast                    # opens the Textual TUI
```

Seven tabs with single-letter hotkeys:

| Key | Tab | What it shows |
|---|---|---|
| `d` | Dashboard | Status line + mode dropdown + Up/Down/Refresh + scrollable event log (5000-line buffer) |
| `c` | Clients | DHCP leases joined with Wi-Fi station info (signal, RX/TX, lease TTL) |
| `n` | DNS Spoofs | Add / remove `dns-spoof.conf` entries — domain validated, IPv4 + IPv6 accepted |
| `s` | Sessions | Past pcap and proxy-session directories on disk |
| `p` | Proxy | Live HTTP flow table (method / status / host / URL / size) — populated when `mitmproxy` mode is up |
| `l` | Logs | journalctl tail of dnsmasq / hostapd / mitmweb / sslsplit / sslstrip / mitmbeast |
| `t` | Settings | Read-only `mitm.conf` viewer with secret redaction (in-TUI editing is a v2.x follow-up) |

The Dashboard mode dropdown selects from `none / mitmproxy / sslsplit / certmitm / sslstrip / intercept`. Up/Down spawn `mitmbeast up`/`down` with the chosen mode; output streams into the event log. Up will use the Python core (`--python`) when available; the bash dispatch is the fallback for any modes not yet ported (currently: none — all five are ported).

### CLI (scripting / automation)

```bash
sudo mitmbeast up --python -m <mode>     # Python core — preferred
sudo mitmbeast up --python -m none       # router only (no TLS interception)
sudo mitmbeast up -m <mode>              # legacy bash dispatch
sudo mitmbeast up --python -k -m mitmproxy  # -k keeps WAN config, preserving SSH
sudo mitmbeast down --python [-k]
sudo mitmbeast reload [-m mode]
sudo mitmbeast restore [--python] [--manager NetworkManager|systemd-networkd|none]

# DNS / NTP helpers
sudo mitmbeast spoof add update.example.com 192.168.200.1
sudo mitmbeast spoof rm update.example.com
sudo mitmbeast spoof list
sudo mitmbeast delorean start +1500
sudo mitmbeast delorean stop
```

**Modes:** `mitmproxy` | `sslsplit` | `certmitm` | `sslstrip` | `intercept` | `none`

`restore` puts the host back into a normal Linux configuration after a MITM Beast session. It re-enables the network manager you choose (interactive prompt, or `--manager <NetworkManager|systemd-networkd|none>`), restores `/etc/resolv.conf`, and removes any leftover `MITM_*` iptables chains. See `RESTORE.md` for the manual procedure if the tool is unavailable.

### `--python` flag

`mitmbeast up --python` (and `down`, `restore`) drives the pure-Python core (router, dnsmasq, hostapd, firewall, all five proxy modes, fakefw, delorean). Without `--python`, the CLI shells out to the v1.x bash scripts — useful for A/B comparison or as a fallback if you hit a Python regression. v3.0 will drop the bash shims and make `--python` the only implementation.

### Migrating from v1.x bash

| v1.x bash | v2.x Python equivalent |
|---|---|
| `sudo ./mitm.sh up -m mitmproxy` | `sudo mitmbeast up --python -m mitmproxy` |
| `sudo ./mitm.sh down` | `sudo mitmbeast down --python` |
| `sudo ./mitm.sh reload` | `sudo mitmbeast reload` |
| `sudo ./mitm.sh restore` | `sudo mitmbeast restore --python` |
| `./dns-spoof.sh add d ip` | `mitmbeast spoof add d ip` |
| `./dns-spoof.sh rm d` | `mitmbeast spoof rm d` |
| `./dns-spoof.sh list` | `mitmbeast spoof list` |
| `sudo ./delorean.sh start +1500` | `sudo mitmbeast delorean start +1500` |

The v1.x bash scripts remain at the top level and continue to work — they are now thin shims that you can keep using if your existing automation references them by name.

---

## Proxy Modes

### mitmproxy (`-m mitmproxy`)

Transparent HTTPS proxy with an interactive web UI. Intercepts all port 443 traffic; live flows also stream into the TUI Proxy tab.

```bash
sudo mitmbeast up --python -m mitmproxy
# Web UI: http://<WAN_IP>:8080
# Live flows: TUI -> Proxy tab (press 'p')
```

iptables rule set:
```
-i br0 --dport 443 -> REDIRECT :8081
```

### sslsplit (`-m sslsplit`)

Generic TLS interception. Generates a session CA, terminates TLS, and captures connections to PCAP files under `sslsplit_logs/session_*/`.

```bash
sudo mitmbeast up --python -m sslsplit
# Session logs: sslsplit_logs/session_YYYYMMDD_HHMMSS/
```

### certmitm (`-m certmitm`)

Tests TLS certificate validation by presenting various invalid certificates (self-signed, wrong CN, expired, untrusted CA). Reports VULNERABLE or SECURE per connection.

```bash
sudo mitmbeast up --python -m certmitm
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

Tests TLS downgrade vulnerability. Intercepts HTTPS connections from DNS-spoofed domains and responds with HTTP. Starts the fake firmware server on port 80 to serve content over HTTP.

```bash
sudo mitmbeast up --python -m sslstrip
# Logs: sslstrip_logs/session_YYYYMMDD_HHMMSS/
```

iptables rules set:
```
-i br0 -d 192.168.200.1 --dport 443 -> REDIRECT :10000  (sslstrip)
-i br0 -d 192.168.200.1 --dport 80  -> REDIRECT :80     (fake server)
```

Result: if the device accepts HTTP content it expected over HTTPS → **vulnerable to TLS downgrade**.

### intercept (`-m intercept`)

Exploits missing certificate pinning to serve fake responses. mitmproxy terminates TLS (device accepts the MITM certificate), then the bundled `mitmproxy-intercept.py` addon forwards requests as plaintext HTTP to the fake firmware server.

```bash
sudo mitmbeast up --python -m intercept
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

The `mitmproxy-intercept.py` addon reads `FAKE_SERVER_HOST`, `FAKE_SERVER_PORT`, and `INTERCEPT_DOMAINS` from the environment — set automatically by both `mitmbeast up --python -m intercept` and the legacy `./mitm.sh -m intercept`. It redirects matching domains to the fake server and logs unexpected traffic.

iptables rule set:
```
-i br0 -d 192.168.200.1 --dport 443 -> REDIRECT :8081
```

### none (`-m none`)

Router only — bridge + NAT + DHCP + DNS, no traffic interception. Useful for baseline testing, manual proxy setup, or just providing a controlled Wi-Fi for traffic capture.

```bash
sudo mitmbeast up --python -m none
```

---

## Packet Capture

Add `-c` to any `up` or `reload` command to capture traffic on the bridge interface:

```bash
sudo mitmbeast up --python -m mitmproxy -c
# Saves to: captures/br0_YYYYMMDD_HHMMSS_<id>.pcap
```

Captures appear in the TUI Sessions tab once written.

---

## NTP Spoofing (Delorean)

`mitmbeast delorean` wraps the Delorean NTP spoofer and sets iptables DNAT rules to intercept NTP traffic — including devices that use hardcoded NTP IPs (Cloudflare `162.159.200.1/123`, Google `216.239.35.0/4/8/12`).

```bash
sudo mitmbeast delorean start +1500            # Offset in days from current date
sudo mitmbeast delorean start -3650
sudo mitmbeast delorean start "2030-06-15"     # Absolute date
mitmbeast delorean status
sudo mitmbeast delorean stop                   # Stops and removes iptables rules
```

The legacy `./delorean.sh start +1500` form still works.

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
sudo mitmbeast up --python -m none
sudo mitmbeast delorean start +1500

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
sudo mitmbeast delorean stop
sudo mitmbeast down --python
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

sudo mitmbeast up --python -m none

sudo python3 ./fake-firmware-server.py \
  --cert /etc/letsencrypt/live/update.example.com.attacker.com/fullchain.pem \
  --key /etc/letsencrypt/live/update.example.com.attacker.com/privkey.pem
```

**4. Trigger a connection** from the device to `update.example.com`.

- **Vulnerable:** device accepts the certificate → substring hostname matching
- **Secure:** device rejects with hostname mismatch error

**Cleanup:**
```bash
sudo mitmbeast down --python
sudo certbot delete --cert-name update.example.com.attacker.com  # optional
```

---

## Troubleshooting

**Router won't start:**
```bash
ss -tuln | grep -E ':(53|80|443|8080|8081)'   # Check port conflicts
ip link show                                    # Check interface names
```

**Phone / device won't associate to the Wi-Fi AP:**

The AP runs WPA2-PSK on 2.4 GHz channel 11 with country code US. If a client (especially Android 13+ or iOS 16+) refuses to connect, work down this list — most failures are on the radio side, not in mitmbeast itself.

```bash
# 1. Verify hostapd is up and the radio is in AP mode
pgrep -fa hostapd
iw dev <WIFI_IFACE> info        # type should be 'AP', not 'managed'

# 2. Tail hostapd's journal for association attempts and reason codes
sudo journalctl -t hostapd -f
# Look for STA-CONNECTED / STA-DISCONNECTED with reason= codes:
#   reason=1   unspecified
#   reason=2   previous auth no longer valid
#   reason=3   STA leaving
#   reason=15  4-way handshake timeout (passphrase mismatch)
#   reason=23  IEEE 802.1X auth failed

# 3. Confirm the rendered hostapd config is what you expect
sudo cat /run/mitmbeast/hostapd.conf       # or `tmp_hostapd.conf` on v1.1

# 4. Check the host regulatory domain matches country_code
iw reg get
# If 'global' is set to '00' or doesn't include US, set it:
sudo iw reg set US

# 5. Confirm the channel is actually allowed for your regdomain + adapter
iw phy   # look for 'Frequencies:' under your phy; channel 11 = 2462 MHz
```

Common Android-specific gotchas:
- **MAC randomisation** — phone presents a different MAC each connect attempt; some saved-network state on the phone can fail. Forget the network on the phone and re-add.
- **PMF (Protected Management Frames)** — mitmbeast does not advertise PMF support. If the phone is configured to *require* PMF (rare; usually only on enterprise networks), it will refuse our AP.
- **Stale Wi-Fi state on the host** — if hostapd was killed uncleanly, the radio may stay in a half-configured state. `mitmbeast down --python` followed by `mitmbeast up --python` (or rebooting the host) clears it.
- **AR9271 / ath9k_htc adapter** — needs the `linux-firmware` package (Arch) or `firmware-atheros` (Debian/Kali). Check `dmesg | grep -i ath9k` for firmware-load messages.

**DNS spoofing not working:**
```bash
mitmbeast spoof list
dig update.example.com @192.168.200.1          # Should return 192.168.200.1
sudo systemctl reload dnsmasq                  # or `mitmbeast reload`
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
mitmbeast delorean status
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
