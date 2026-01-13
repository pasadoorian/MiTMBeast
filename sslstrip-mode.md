# SSLstrip Mode - TLS Downgrade Vulnerability Testing

SSLstrip mode tests whether IoT devices accept HTTP responses when they expect HTTPS. This vulnerability occurs when a device either:
1. Falls back to HTTP if HTTPS fails
2. Doesn't properly validate that the response uses TLS

## Attack Flow

```
Device                  MITM Router                 Real Server
   |                        |                           |
   |-- DNS: api.example.com ---------------------->     |
   |<-- Real IP (passthrough) ----------------------|   |
   |                        |                           |
   |-- HTTPS: api.example.com ---------------------->   |
   |<-- Response: "download from https://update.example.com/..." --|
   |                        |                           |
   |-- DNS: update.example.com -->                      |
   |<-- 192.168.200.1 (spoofed) --|                     |
   |                        |                           |
   |-- HTTPS:443 ---------->|                           |
   |   (expects TLS)        |                           |
   |                    [iptables redirect]             |
   |                        |                           |
   |                   [sslstrip :10000]                |
   |                   [strips TLS]                     |
   |                        |                           |
   |                   [HTTP to fake server :8080]      |
   |                        |                           |
   |<-- HTTP response ------|                           |
   |   (no TLS!)            |                           |
   |                        |                           |
   If device accepts this HTTP response = VULNERABLE
```

## Configuration

### 1. Edit mitm.conf

The following variables control sslstrip mode:

```bash
# sslstrip Settings
SSLSTRIP_PORT="10000"                    # sslstrip listen port
SSLSTRIP_FAKE_SERVER_PORT="8080"         # HTTP server for fake content
SSLSTRIP_FAKE_SERVER_SCRIPT="./fake-server.py"

# Domains to strip (DNS spoofed to router)
SSLSTRIP_TEST_DOMAINS="update.example.com"

# Passthrough domains (NOT spoofed - real connection)
SSLSTRIP_PASSTHROUGH_DOMAINS="api.example.com"
```

### 2. Configure DNS spoofing

In `dns-spoof.conf`, only add domains you want to intercept:

```bash
# Intercept domain - traffic redirected to sslstrip
address=/update.example.com/192.168.200.1

# Do NOT add passthrough domains like api.example.com
# They must resolve to real IPs for the attack to work
```

### 3. Prepare fake content

```bash
mkdir -p content/
cp /path/to/custom/file content/
```

## Usage

```bash
# Start sslstrip mode
sudo ./mitm.sh up -m sslstrip

# Monitor sslstrip logs
tail -f sslstrip_logs/session_*/sslstrip.log

# Monitor fake server logs
tail -f sslstrip_logs/session_*/fake_server.log

# Stop
sudo ./mitm.sh down
```

## iptables Rules

sslstrip mode sets up the following traffic redirection:

```bash
# Redirect HTTPS to sslstrip (only DNS-spoofed traffic)
iptables -t nat -A PREROUTING -i br0 -p tcp -d 192.168.200.1 --dport 443 -j REDIRECT --to-ports 10000

# Redirect HTTP to fake server (for retry attempts)
iptables -t nat -A PREROUTING -i br0 -p tcp -d 192.168.200.1 --dport 80 -j REDIRECT --to-ports 8080
```

The `-d 192.168.200.1` ensures only DNS-spoofed traffic is intercepted. Passthrough domains resolve to real IPs and bypass these rules.

## Expected Results

### Vulnerable Device

If the device is vulnerable to TLS downgrade:
- sslstrip logs show successful connection handling
- Fake server logs show download requests
- Device accepts and processes the fake content

```
[sslstrip] Connection from 192.168.200.x
[fake-server] GET /path/to/file - 200 OK
```

### Secure Device

If the device properly validates TLS:
- Device rejects the connection (TLS handshake fails)
- No download requests in fake server logs
- Device reports an error

The device should either:
1. Reject the non-TLS response entirely
2. Refuse to download content over HTTP
3. Validate that URL matches expected HTTPS scheme

## Comparison with Other Modes

| Mode | What it tests |
|------|---------------|
| mitmproxy | Basic HTTPS interception (requires installed CA) |
| sslsplit | Full TLS interception for any protocol |
| certmitm | Certificate validation (self-signed, expired, wrong CN) |
| **sslstrip** | TLS downgrade (device accepts HTTP instead of HTTPS) |
| intercept | Exploit known vulnerabilities to serve fake content |

## Prerequisites

### Install sslstrip

```bash
# Via pip
pip install sslstrip

# Or from source
git clone https://github.com/moxie0/sslstrip
cd sslstrip
python setup.py install
```

## Troubleshooting

### No traffic intercepted

1. Check DNS spoofing is working:
   ```bash
   dig update.example.com @192.168.200.1
   # Should return 192.168.200.1
   ```

2. Check iptables rules:
   ```bash
   iptables -t nat -L -n | grep 10000
   ```

3. Verify device is connected to MITM network

### sslstrip fails to start

1. Check if port is available:
   ```bash
   ss -tuln | grep 10000
   ```

2. Check sslstrip is installed:
   ```bash
   which sslstrip
   ```

### Device immediately rejects connection

This is expected behavior for secure devices. The device properly requires TLS and rejects non-TLS responses. This indicates the device is NOT vulnerable to this attack.

### Connection hangs

Check that fake server is running:
```bash
curl http://127.0.0.1:8080/
```

## Security Considerations

This mode tests a specific vulnerability class:
- Devices that don't enforce HTTPS for sensitive operations
- Devices that fall back to HTTP if HTTPS fails
- Devices that don't validate the connection security

A properly implemented device should:
1. Refuse to download sensitive content over HTTP
2. Validate TLS certificate chain
3. Use certificate pinning for update servers
4. Implement HSTS (though embedded devices rarely do)

## Related Documentation

- `intercept-mode.md` - For devices without certificate pinning (uses mitmproxy)
- `certmitm-setup.md` - For testing certificate validation vulnerabilities
- `attack-vectors.md` - Overview of all attack techniques
