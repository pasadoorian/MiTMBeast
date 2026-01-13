# mitm-beast - IoT Security Testing Toolkit

A comprehensive toolkit for network man-in-the-middle (MITM) traffic interception and analysis, primarily designed for IoT device security testing. This toolkit transforms a Linux machine into a wireless access point router capable of intercepting, analyzing, and manipulating network traffic.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Proxy Modes](#proxy-modes)
- [Scripts Reference](#scripts-reference)
- [Attack Vectors](#attack-vectors)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

---

## Overview

This toolkit provides:

- **Wireless Access Point**: Creates a WPA2-protected WiFi network for target devices
- **DNS Spoofing**: Redirects specific domains to the router for interception
- **Multiple Proxy Modes**: Different interception strategies for various testing scenarios
- **NTP Spoofing**: Time manipulation attacks using Delorean
- **Packet Capture**: Full traffic capture for offline analysis

### Use Cases

- IoT device firmware update security testing
- TLS certificate validation vulnerability assessment
- Protocol downgrade attack testing
- Network-level security research

---

## Architecture

```
                                    Internet
                                        |
                                        |
+---------------------------------------+---------------------------------------+
|  MITM Router                          |                                       |
|                                       |                                       |
|  +-------------+              +-------+-------+                               |
|  |   WiFi AP   |              |  WAN (eth0)   |                               |
|  |   (wlan0)   |              | 192.168.1.30  |                               |
|  +------+------+              +---------------+                               |
|         |                                                                     |
|  +------+------+    +-------------+                                           |
|  |   Bridge    |----+  LAN (eth1) |                                           |
|  |    (br0)    |    +-------------+                                           |
|  |192.168.200.1|                                                              |
|  +------+------+                                                              |
|         |                                                                     |
|  +------+------------------------------------------------------------+       |
|  |                         Services                                   |       |
|  |  +----------+  +----------+  +----------+  +--------------------+  |       |
|  |  | dnsmasq  |  | hostapd  |  | iptables |  |   Proxy (varies)   |  |       |
|  |  | DHCP/DNS |  |  WiFi AP |  |   NAT    |  | mitmproxy/sslsplit/|  |       |
|  |  | spoofing |  |          |  |          |  | certmitm/sslstrip  |  |       |
|  |  +----------+  +----------+  +----------+  +--------------------+  |       |
|  +--------------------------------------------------------------------+       |
+-------------------------------------------------------------------------------+
                                        |
                                        |
                              +---------+---------+
                              |   Target Device   |
                              |   (IoT Device)    |
                              +-------------------+
```

---

## Installation

### Prerequisites (Arch Linux)

```bash
# Core networking tools
sudo pacman -S hostapd dnsmasq bridge-utils net-tools iptables

# Proxy tools
sudo pacman -S mitmproxy sslsplit

# NTP spoofing
sudo pacman -S libfaketime

# Optional: packet capture
sudo pacman -S tcpdump wireshark-cli
```

### Prerequisites (Kali Linux)

```bash
# Core networking tools
sudo apt update
sudo apt install hostapd dnsmasq bridge-utils net-tools iptables

# Proxy tools (mitmproxy is pre-installed on Kali)
sudo apt install mitmproxy sslsplit

# NTP spoofing
sudo apt install faketime

# Optional: packet capture (usually pre-installed)
sudo apt install tcpdump wireshark
```

**Note:** Kali Linux comes with many security tools pre-installed. You may already have mitmproxy, tcpdump, and wireshark available. Check with `which mitmproxy` or `apt list --installed | grep mitmproxy`.

### Setup

> **WARNING:** This toolkit takes full control of networking on your device. Running `mitm.sh up` will:
> - Stop and disable NetworkManager, systemd-networkd, and systemd-resolved
> - Remove existing IP configurations from the configured interfaces
> - Reconfigure all network interfaces according to `mitm.conf`
>
> **Use a dedicated machine or VM for MITM testing.** Do not run this on your primary workstation or a system where you need NetworkManager for connectivity. Running `mitm.sh down` will restore services but may require manual network reconfiguration.

```bash
# Clone repository
git clone <repository-url> mitm-beast
cd mitm-beast

# Copy and edit configuration
cp mitm.conf.example mitm.conf
# Edit mitm.conf with your network interface names, WiFi credentials, etc.

# Install Delorean for NTP spoofing
git clone https://github.com/jselvi/Delorean delorean

# Install certmitm for certificate validation testing
git clone https://github.com/aapooksman/certmitm /opt/certmitm
cd /opt/certmitm
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Quick Start

### Basic Router (No Interception)

```bash
sudo ./mitm.sh up -m none
```

### HTTPS Interception with mitmproxy

```bash
sudo ./mitm.sh up -m mitmproxy
# Web UI: http://<WAN_IP>:8080
```

### Stop Router

```bash
sudo ./mitm.sh down
```

---

## Proxy Modes

### 1. mitmproxy (`-m mitmproxy`)

Interactive HTTP/HTTPS proxy with web interface. Best for inspecting and modifying HTTP traffic.

```bash
sudo ./mitm.sh up -m mitmproxy
```

- Web UI at `http://<WAN_IP>:8080`
- Intercepts all HTTPS traffic on port 443
- Requires target to trust mitmproxy CA (or lack certificate validation)

### 2. sslsplit (`-m sslsplit`)

Generic TLS interception for any protocol. Captures all TLS streams to PCAP files.

```bash
sudo ./mitm.sh up -m sslsplit
```

- Generates session CA certificates automatically
- Logs connections to `sslsplit_logs/session_*/`
- Uses SNI for upstream routing

### 3. certmitm (`-m certmitm`)

Tests TLS certificate validation vulnerabilities. Attempts various invalid certificates.

```bash
sudo ./mitm.sh up -m certmitm
```

- Tests self-signed, expired, wrong CN certificates
- Reports VULNERABLE or SECURE for each test
- See `certmitm-setup.md` for detailed configuration

### 4. sslstrip (`-m sslstrip`)

Tests TLS downgrade vulnerabilities. Attempts to serve HTTP when device expects HTTPS.

```bash
sudo ./mitm.sh up -m sslstrip
```

- Redirects HTTPS to sslstrip, HTTP to local server
- Tests if device falls back to HTTP
- See `sslstrip-mode.md` for details

### 5. none (`-m none`)

Router only, no traffic interception. Useful for baseline testing or manual interception setup.

```bash
sudo ./mitm.sh up -m none
```

---

## Scripts Reference

### Core Scripts

| Script | Purpose |
|--------|---------|
| `mitm.sh` | Main router setup script. Manages interfaces, services, and proxy modes |
| `mitm.conf` | Configuration file for all settings |
| `dns-spoof.conf` | DNS spoofing entries (domain -> IP mappings) |
| `dns-spoof.sh` | Helper for managing DNS spoof entries |

### Attack Tools

| Script | Purpose |
|--------|---------|
| `delorean.sh` | Wrapper for Delorean NTP spoofing tool |
| `mitmproxy-intercept.py` | mitmproxy addon for routing intercepted traffic |

### Documentation

| File | Description |
|------|-------------|
| `attack-vectors.md` | Network-level attack techniques overview |
| `certmitm-setup.md` | Certificate validation testing guide |
| `intercept-mode.md` | Exploiting missing certificate pinning |
| `sslstrip-mode.md` | TLS downgrade testing guide |
| `ntp-cert-attack-test.md` | NTP + certificate time manipulation attack |
| `cert-hostname-substring-test.md` | Certificate hostname substring matching test |

---

## Attack Vectors

### 1. TLS Downgrade (sslstrip)

Tests if device accepts HTTP when expecting HTTPS.

```bash
sudo ./mitm.sh up -m sslstrip
```

### 2. Certificate Validation (certmitm)

Tests if device properly validates TLS certificates.

```bash
sudo ./mitm.sh up -m certmitm
```

### 3. NTP Time Manipulation

Manipulates device clock to make expired/future certificates appear valid.

```bash
# Start router
sudo ./mitm.sh up -m none

# Start NTP spoofing (+1500 days)
sudo ./delorean.sh start +1500

# Generate time-matched certificate
faketime '2029-01-01' openssl req -x509 -newkey rsa:4096 \
  -keyout certs/future-2030.key \
  -out certs/future-2030.crt \
  -sha256 -days 1095 -nodes \
  -subj "/CN=update.example.com" \
  -addext "subjectAltName=DNS:api.example.com,DNS:update.example.com"
```

### 4. Certificate Hostname Substring Matching

Tests if device accepts certificate for `update.example.com.attacker.com` when connecting to `update.example.com`.

See `cert-hostname-substring-test.md` for full procedure with Let's Encrypt.

---

## Configuration

### mitm.conf

```bash
# Network Interfaces
BR_IFACE="br0"          # Bridge interface
WAN_IFACE="eth0"        # Internet uplink
LAN_IFACE="eth1"        # Wired clients
WIFI_IFACE="wlan0"      # WiFi AP

# WiFi Access Point
WIFI_SSID="mitm_network"
WIFI_PASSWORD="your_password"

# LAN Network
LAN_IP="192.168.200.1"
LAN_SUBNET="255.255.255.0"
LAN_DHCP_START="192.168.200.10"
LAN_DHCP_END="192.168.200.100"

# WAN Network (static or DHCP)
WAN_STATIC_IP="192.168.1.30"
WAN_STATIC_NETMASK="255.255.255.0"
WAN_STATIC_GATEWAY="192.168.1.1"
WAN_STATIC_DNS="192.168.1.1"

# Proxy Mode (default)
PROXY_MODE="mitmproxy"
```

### dns-spoof.conf

```bash
# Redirect domains to router for interception
address=/update.example.com/192.168.200.1
address=/api.example.com/192.168.200.1

# Passthrough domains should NOT be listed
# (they resolve normally and bypass interception)
```

---

## Troubleshooting

### Router won't start

```bash
# Check for port conflicts
ss -tuln | grep -E ':(53|80|443|8080|8081)'

# Check interface names
ip link show

# Verify configuration
cat mitm.conf
```

### DNS spoofing not working

```bash
# Verify entry exists
./dns-spoof.sh list

# Test resolution via router
dig update.example.com @192.168.200.1

# Reload dnsmasq after config changes
./dns-spoof.sh reload
```

### No traffic intercepted

```bash
# Check iptables rules
sudo iptables -t nat -L PREROUTING -n -v

# Verify device is connected to MITM network
ip neigh show dev br0

# Check proxy is running
pgrep -a mitmweb
pgrep -a sslsplit
```

### Certificate errors

```bash
# Verify certificate dates
openssl x509 -in cert.crt -noout -dates

# Check certificate hostnames
openssl x509 -in cert.crt -noout -text | grep -A1 "Subject Alternative Name"
```

### NTP spoofing issues

```bash
# Check delorean status
./delorean.sh status

# Verify iptables DNAT rules
sudo iptables -t nat -L PREROUTING -n -v | grep 123

# Monitor NTP traffic
sudo tcpdump -i br0 -n udp port 123
```

---

## Legal Notice

This toolkit is intended for:
- Security research on devices you own
- Authorized penetration testing engagements
- Educational purposes in controlled environments

**Unauthorized access to computer systems is illegal.** Always obtain proper authorization before testing.

---

## References

- [Delorean NTP Tool](https://github.com/jselvi/Delorean)
- [certmitm](https://github.com/aapooksman/certmitm)
- [mitmproxy](https://mitmproxy.org/)
- [sslsplit](https://www.roe.ch/SSLsplit)
- [OWASP Certificate Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)
