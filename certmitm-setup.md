# certmitm Setup Guide

certmitm is a tool for testing TLS certificate validation vulnerabilities in client applications and devices. It attempts various certificate-based attacks to identify improper validation implementations.

## Overview

Unlike mitmproxy or sslsplit which focus on intercepting traffic, certmitm specifically tests whether clients properly validate TLS certificates. It attempts multiple attack types:

- Self-signed certificates
- Certificates with wrong CN/SAN
- Expired certificates
- Certificates signed by untrusted CAs
- And other certificate validation bypass techniques

## Installation

### 1. Clone certmitm

```bash
git clone https://github.com/aapooksman/certmitm /opt/certmitm
cd /opt/certmitm
```

### 2. Create Python Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. (Optional) Add Real Certificates

For some tests, certmitm can use valid SSL certificates (e.g., Let's Encrypt) placed in the `real_certs` directory. This helps test scenarios where a valid cert for a different domain is presented.

```bash
mkdir -p /opt/certmitm/real_certs
# Copy your valid certificate files here
```

### 4. Configure mitm.conf

Edit your `mitm.conf` file to set the certmitm path:

```bash
# certmitm Settings
CERTMITM_PATH="/opt/certmitm/certmitm.py"
CERTMITM_PORT="8081"
CERTMITM_WORKDIR="./certmitm_logs"
CERTMITM_VERBOSE=true
CERTMITM_SHOW_DATA=true

# Domains to test with certmitm (must be in dns-spoof.conf)
CERTMITM_TEST_DOMAINS="update.example.com"

# Domains to passthrough (must NOT be in dns-spoof.conf)
CERTMITM_PASSTHROUGH_DOMAINS="api.example.com"
```

## Passthrough Domains

Many devices make sequential connections to multiple servers. If the first connection fails (due to certmitm's certificate tests), the device may not proceed to make subsequent connections. The passthrough feature allows you to:

1. Let certain domains connect directly to real servers (passthrough)
2. Only test specific domains with certmitm

### How It Works

```
Device
  |
  +--- api.example.com (passthrough)
  |    -> DNS returns real IP (NOT in dns-spoof.conf)
  |    -> Direct connection to real server
  |    -> Device gets valid response, proceeds to next step
  |
  +--- update.example.com (test)
       -> DNS returns router IP (in dns-spoof.conf)
       -> iptables redirects to certmitm
       -> certmitm tests certificate validation
```

### Configuration Steps

1. **Edit mitm.conf** - Set passthrough and test domains:
   ```bash
   CERTMITM_TEST_DOMAINS="update.example.com"
   CERTMITM_PASSTHROUGH_DOMAINS="api.example.com"
   ```

2. **Edit dns-spoof.conf** - Only include TEST domains:
   ```bash
   # Only test domains - passthrough domains must NOT be listed
   address=/update.example.com/192.168.200.1

   # Do NOT add passthrough domains here:
   # api.example.com - connects directly to real server
   ```

3. **Start certmitm**:
   ```bash
   sudo ./mitm.sh up -m certmitm
   ```

### Example: IoT Device Testing

For an IoT device that:
1. First connects to `api.example.com` to check for updates
2. Then connects to `update.example.com` to download firmware

To test only the firmware download:
```bash
# mitm.conf
CERTMITM_PASSTHROUGH_DOMAINS="api.example.com"
CERTMITM_TEST_DOMAINS="update.example.com"
```

```bash
# dns-spoof.conf
address=/update.example.com/192.168.200.1
# api.example.com is NOT listed - resolves to real IP
```

## Usage

### Start the MITM Router with certmitm

```bash
sudo ./mitm.sh up -m certmitm
```

### What Happens

1. The router starts with iptables redirecting port 443 traffic to certmitm
2. certmitm listens for incoming TLS connections
3. For each connection, it attempts various certificate attacks
4. Results are logged to the session directory

### View Results

Session output is stored in `./certmitm_logs/session_YYYYMMDD_HHMMSS/`

Check the log file for details:
```bash
cat tmp_certmitm.log
```

### Stop the Router

```bash
sudo ./mitm.sh down
```

## Interpreting Results

certmitm will report which certificate validation checks passed or failed for each client connection:

- **VULNERABLE**: Client accepted an invalid certificate (security issue)
- **SECURE**: Client properly rejected the invalid certificate

Common vulnerabilities found:
- Accepting self-signed certificates without user prompt
- Not checking certificate expiration
- Not validating the certificate chain
- Ignoring CN/SAN mismatch

## Use Cases

1. **IoT Device Testing**: Test if embedded devices properly validate TLS certificates
2. **Mobile App Testing**: Verify mobile applications implement certificate pinning correctly
3. **API Client Testing**: Ensure API clients don't disable certificate validation
4. **Security Audits**: Part of comprehensive TLS security assessments

## Comparison with Other Tools

| Tool | Purpose | Best For |
|------|---------|----------|
| mitmproxy | HTTP/HTTPS proxy with web UI | Inspecting HTTP traffic, modifying requests |
| sslsplit | Generic TLS interception | Capturing all TLS traffic to PCAP files |
| certmitm | Certificate validation testing | Finding certificate validation vulnerabilities |

## Troubleshooting

### certmitm fails to start

Check the log file:
```bash
cat tmp_certmitm.log
```

Common issues:
- Missing Python dependencies (re-run `pip install -r requirements.txt` in venv)
- Port 8081 already in use
- Invalid CERTMITM_PATH in mitm.conf

### No connections detected

- Verify DNS spoofing is configured in `dns-spoof.conf`
- Check iptables rules are set: `iptables -t nat -L -n`
- Ensure client traffic is routed through the MITM router

## References

- [certmitm GitHub](https://github.com/aapooksman/certmitm)
- [OWASP Certificate Pinning](https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning)
