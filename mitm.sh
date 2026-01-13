#!/bin/bash

#
# mitm-beast - MITM Router Script
# Configuration is loaded from mitm.conf
#

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root (use sudo)"
  exit 1
fi

#
# Determine script directory and load configuration
#
SCRIPT_RELATIVE_DIR=$(dirname "${BASH_SOURCE[0]}")

#-----------------------------------------------------------------------------------------------------------------------
# Load configuration options
#-----------------------------------------------------------------------------------------------------------------------

load_config() {
  local config_file="${SCRIPT_RELATIVE_DIR}/mitm.conf"
  if [ ! -f "$config_file" ]; then
    echo "Error: Configuration file not found: $config_file"
    echo ""
    echo "Create configuration file from example:"
    echo "  cp ${SCRIPT_RELATIVE_DIR}/mitm.conf.example ${SCRIPT_RELATIVE_DIR}/mitm.conf"
    echo ""
    echo "Then edit mitm.conf with your settings."
    exit 1
  fi
  # shellcheck source=mitm.conf
  source "$config_file"

  # Set derived variables
  LAN_DNS_SERVER="${LAN_IP}"
}

load_config

#-----------------------------------------------------------------------------------------------------------------------
# Parse command line arguments
#-----------------------------------------------------------------------------------------------------------------------

ACTION=""
KEEP_WAN=false

show_usage() {
  echo "Usage: $0 <up|down|reload> [-k|--keep-wan] [-m|--mode <mode>] [-c|--capture]"
  echo "  Actions:"
  echo "    up                Start the MITM router"
  echo "    down              Stop the MITM router"
  echo "    reload            Stop then start (down + up)"
  echo "  Options:"
  echo "    -k, --keep-wan      Preserve WAN interface if already configured (keeps SSH alive)"
  echo "    -m, --mode <mode>   Proxy mode: mitmproxy, sslsplit, certmitm, sslstrip, or none"
  echo "    -c, --capture       Enable packet capture (tcpdump on bridge interface)"
}

while [ $# -gt 0 ]; do
  case "$1" in
    up|down|reload)
      ACTION="$1"
      ;;
    -k|--keep-wan)
      KEEP_WAN=true
      ;;
    -m|--mode)
      shift
      if [ -z "$1" ] || [[ "$1" == -* ]]; then
        echo "Error: --mode requires an argument (mitmproxy, sslsplit, certmitm, sslstrip, or none)"
        show_usage
        exit 1
      fi
      PROXY_MODE="$1"
      ;;
    -c|--capture)
      TCPDUMP_ENABLED=true
      ;;
    *)
      echo "Unknown argument: $1"
      show_usage
      exit 1
      ;;
  esac
  shift
done

if [ -z "$ACTION" ]; then
  show_usage
  exit 1
fi

# Validate proxy mode
case "$PROXY_MODE" in
  mitmproxy|sslsplit|certmitm|sslstrip|none)
    ;;
  *)
    echo "Error: Invalid proxy mode '$PROXY_MODE'"
    echo "Valid modes: mitmproxy, sslsplit, certmitm, sslstrip, none"
    exit 1
    ;;
esac

# Change to script directory for relative paths
cd "$SCRIPT_RELATIVE_DIR" || { echo "Error: Cannot change to script directory"; exit 1; }

#-----------------------------------------------------------------------------------------------------------------------
# Functions
#-----------------------------------------------------------------------------------------------------------------------

#
# Function to check if WAN interface is already configured with static IP
#
wan_is_configured() {
  current_ip=$(ip -4 addr show $WAN_IFACE 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
  [ "$current_ip" = "$WAN_STATIC_IP" ]
}

#
# Function to check required dependencies are installed
#
check_dependencies() {
  local missing=()
  local deps="hostapd dnsmasq brctl ip iptables"
  # Add proxy-specific dependencies based on mode
  case "$PROXY_MODE" in
    mitmproxy)
      deps="mitmweb $deps"
      ;;
    sslsplit)
      deps="sslsplit openssl $deps"
      ;;
    certmitm)
      # certmitm uses its own venv, validated separately
      ;;
    sslstrip)
      deps="sslstrip $deps"
      ;;
  esac
  # Add tcpdump if capture is enabled
  if [ "$TCPDUMP_ENABLED" = true ]; then
    deps="tcpdump $deps"
  fi
  for cmd in $deps; do
    if ! command -v $cmd &>/dev/null; then
      missing+=($cmd)
    fi
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo "Error: Missing required commands: ${missing[*]}"
    echo "Install with: pacman -S mitmproxy sslsplit hostapd dnsmasq bridge-utils"
    exit 1
  fi
}

# Check dependencies
check_dependencies

#
# Function to check if a port is available
#
check_port_available() {
  local port=$1
  local name=$2
  if ss -tuln | grep -q ":$port "; then
    echo "Error: Port $port ($name) is already in use"
    ss -tuln | grep ":$port "
    return 1
  fi
  return 0
}

#
# Function to wait for a service to start and verify it's running
#
wait_for_service() {
  local name="$1"
  local process="$2"
  local timeout=5
  local count=0

  while [ $count -lt $timeout ]; do
    if pgrep -x "$process" >/dev/null; then
      echo "   ✓ $name started successfully"
      return 0
    fi
    sleep 1
    ((count++))
  done
  echo "   ✗ $name FAILED to start"
  return 1
}

#
# Function to generate session certificates for sslsplit
#
generate_session_certs() {
  SESSION_CERT_DIR=$(mktemp -d /tmp/mitm_certs.XXXXXX)
  echo "   Generating session CA certificate..."
  openssl req -x509 -newkey rsa:4096 \
    -keyout "$SESSION_CERT_DIR/ca.key" \
    -out "$SESSION_CERT_DIR/ca.crt" \
    -sha256 -days 1 -nodes \
    -subj "/CN=MITM Session CA/O=MITM Router" \
    2>/dev/null
  if [ $? -eq 0 ]; then
    chmod 600 "$SESSION_CERT_DIR/ca.key"
    # Save cert dir location for cleanup
    echo "$SESSION_CERT_DIR" > /tmp/mitm_session_cert_dir
    echo "   ✓ Session certificates generated in $SESSION_CERT_DIR"
    # Display fingerprint for verification
    local fingerprint=$(openssl x509 -fingerprint -sha256 -noout -in "$SESSION_CERT_DIR/ca.crt" 2>/dev/null | cut -d= -f2)
    echo "   CA fingerprint: $fingerprint"
  else
    echo "   ✗ Failed to generate session certificates"
    return 1
  fi
}

#
# Function to cleanup session certificates
#
cleanup_session_certs() {
  local cert_dir=""
  # Try to get cert dir from temp file or use SESSION_CERT_DIR variable
  if [ -f /tmp/mitm_session_cert_dir ]; then
    cert_dir=$(cat /tmp/mitm_session_cert_dir)
    rm -f /tmp/mitm_session_cert_dir
  elif [ -n "$SESSION_CERT_DIR" ]; then
    cert_dir="$SESSION_CERT_DIR"
  fi

  if [ -n "$cert_dir" ] && [ -d "$cert_dir" ]; then
    echo "   Cleaning up session certificates..."
    # Securely delete private key if shred is available
    if command -v shred &>/dev/null; then
      shred -u "$cert_dir/ca.key" 2>/dev/null
    else
      rm -f "$cert_dir/ca.key"
    fi
    rm -f "$cert_dir/ca.crt"
    rmdir "$cert_dir" 2>/dev/null
    echo "   ✓ Session certificates removed"
  fi
}

#
# Function to validate certmitm installation
#
check_certmitm_installation() {
  if [ "$PROXY_MODE" != "certmitm" ]; then
    return 0
  fi

  # Check if certmitm.py exists
  if [ ! -f "$CERTMITM_PATH" ]; then
    echo "Error: certmitm.py not found at: $CERTMITM_PATH"
    echo ""
    echo "Install from: https://github.com/aapooksman/certmitm"
    echo "Then update CERTMITM_PATH in mitm.conf"
    exit 1
  fi

  # Derive venv path from script location
  CERTMITM_DIR=$(dirname "$CERTMITM_PATH")
  CERTMITM_VENV="$CERTMITM_DIR/venv"
  CERTMITM_ACTIVATE="$CERTMITM_VENV/bin/activate"

  # Check if venv exists
  if [ ! -d "$CERTMITM_VENV" ]; then
    echo "Error: Python virtual environment not found at: $CERTMITM_VENV"
    echo ""
    echo "Create it with:"
    echo "  cd $CERTMITM_DIR"
    echo "  python3 -m venv venv"
    echo "  source venv/bin/activate"
    echo "  pip install -r requirements.txt"
    exit 1
  fi

  # Check if venv activate script exists
  if [ ! -f "$CERTMITM_ACTIVATE" ]; then
    echo "Error: venv activate script not found: $CERTMITM_ACTIVATE"
    exit 1
  fi

  echo "   ✓ certmitm found: $CERTMITM_PATH"
  echo "   ✓ venv found: $CERTMITM_VENV"
}

#
# Function to start tcpdump packet capture
#
start_tcpdump() {
  mkdir -p "$TCPDUMP_DIR"
  # Generate unique filename: interface_date_time_sessionid.pcap
  local session_id=$(head -c 2 /dev/urandom | xxd -p)
  local timestamp=$(date +%Y%m%d_%H%M%S)
  TCPDUMP_PCAP="$TCPDUMP_DIR/${TCPDUMP_IFACE}_${timestamp}_${session_id}.pcap"
  TCPDUMP_PIDFILE="/tmp/mitm_tcpdump.pid"

  echo "   Starting tcpdump on $TCPDUMP_IFACE..."
  tcpdump -i "$TCPDUMP_IFACE" $TCPDUMP_OPTIONS -w "$TCPDUMP_PCAP" > /dev/null 2>&1 &
  local pid=$!
  echo "$pid" > "$TCPDUMP_PIDFILE"
  # Save pcap path for status display
  echo "$TCPDUMP_PCAP" > /tmp/mitm_tcpdump_pcap
  sleep 1
  if kill -0 "$pid" 2>/dev/null; then
    echo "   ✓ tcpdump started (PID: $pid)"
    echo "   Capturing to: $TCPDUMP_PCAP"
  else
    echo "   ✗ tcpdump failed to start"
    rm -f "$TCPDUMP_PIDFILE" /tmp/mitm_tcpdump_pcap
    return 1
  fi
}

#
# Function to stop tcpdump packet capture
#
stop_tcpdump() {
  if [ -f /tmp/mitm_tcpdump.pid ]; then
    local pid=$(cat /tmp/mitm_tcpdump.pid)
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null
      sleep 1
      echo "   ✓ tcpdump stopped (PID: $pid)"
      if [ -f /tmp/mitm_tcpdump_pcap ]; then
        local pcap=$(cat /tmp/mitm_tcpdump_pcap)
        echo "   Capture saved: $pcap"
      fi
    fi
    rm -f /tmp/mitm_tcpdump.pid /tmp/mitm_tcpdump_pcap
  fi
}

# Check certmitm installation (only if mode is certmitm)
check_certmitm_installation

echo "== stop router services"
killall wpa_supplicant 2>/dev/null || true
killall dnsmasq 2>/dev/null || true
killall hostapd 2>/dev/null || true
killall mitmweb 2>/dev/null || true
killall mitmproxy 2>/dev/null || true
killall sslsplit 2>/dev/null || true

echo "== Disabling system network managers (NetworkManager, networkd, resolved)"

#
# Stop and disable NetworkManager, systemd-networkd, and systemd-resolved
#
# Stop socket units first to prevent service reactivation
for sock in systemd-networkd.socket systemd-networkd-varlink.socket systemd-networkd-resolve-hook.socket; do
  systemctl stop $sock 2>/dev/null || true
done

for svc in NetworkManager systemd-networkd systemd-resolved; do
  if systemctl is-active --quiet $svc; then
    echo "Stopping $svc..."
    systemctl stop $svc
  fi
  if systemctl is-enabled --quiet $svc; then
    echo "Disabling $svc..."
    systemctl disable $svc 2>/dev/null
  fi
done

#-----------------------------------------------------------------------------------------------------------------------
# Setup resolv.conf
#-----------------------------------------------------------------------------------------------------------------------

#
# Ensure /etc/resolv.conf is a regular file, not a symlink
#
if [ -L /etc/resolv.conf ]; then
  echo "Removing symlinked /etc/resolv.conf..."
  rm -f /etc/resolv.conf
fi

#
# Create a clean resolv.conf file (replace DNS servers as needed)
#
echo "Creating clean /etc/resolv.conf with default nameservers..."
bash -c 'cat > /etc/resolv.conf' << EOF
# Static resolv.conf managed by mitmrouter.sh
nameserver ${WAN_STATIC_DNS}
EOF

echo "== Network services disabled, system now uses /etc/resolv.conf directly"

#-----------------------------------------------------------------------------------------------------------------------
# Reset network interfaces, but not the WAN
#-----------------------------------------------------------------------------------------------------------------------

echo "== reset all network interfaces"
ifconfig $LAN_IFACE 0.0.0.0 2>/dev/null || true
ifconfig $LAN_IFACE down 2>/dev/null || true
ifconfig $BR_IFACE 0.0.0.0 2>/dev/null || true
ifconfig $BR_IFACE down 2>/dev/null || true
ifconfig $WIFI_IFACE 0.0.0.0 2>/dev/null || true
ifconfig $WIFI_IFACE down 2>/dev/null || true
# remove bridge if exists
brctl delbr $BR_IFACE 2>/dev/null || true

#-----------------------------------------------------------------------------------------------------------------------
# Setup reload actions and create new configuration files
#-----------------------------------------------------------------------------------------------------------------------

# For reload: cleanup temp files and session certs before starting fresh
if [ "$ACTION" = "reload" ]; then
  echo "== reload: cleaning up before restart"
  rm -f tmp_mitmproxy_creds.txt tmp_mitmproxy.log
  rm -f tmp_sslsplit_info.txt tmp_sslsplit.log
  cleanup_session_certs
  # Stop certmitm if running
  if [ -f /tmp/mitm_certmitm.pid ]; then
    CERTMITM_PID=$(cat /tmp/mitm_certmitm.pid)
    if kill -0 "$CERTMITM_PID" 2>/dev/null; then
      kill "$CERTMITM_PID" 2>/dev/null
    fi
    rm -f /tmp/mitm_certmitm.pid
  fi
  rm -f tmp_certmitm_info.txt tmp_certmitm.log
  stop_tcpdump
fi

if [ "$ACTION" = "up" ] || [ "$ACTION" = "reload" ]; then
  echo "== create dnsmasq config file"
  echo "interface=${BR_IFACE}" > $DNSMASQ_CONF
  echo "dhcp-range=${LAN_DHCP_START},${LAN_DHCP_END},${LAN_SUBNET},12h" >> $DNSMASQ_CONF
  echo "dhcp-option=6,${LAN_DNS_SERVER}" >> $DNSMASQ_CONF
  echo "conf-file=${SCRIPT_RELATIVE_DIR}/dns-spoof.conf" >> $DNSMASQ_CONF
  echo "log-queries" >> $DNSMASQ_CONF
  echo "log-dhcp" >> $DNSMASQ_CONF

  echo "== create hostapd config file"
  echo "interface=${WIFI_IFACE}" > $HOSTAPD_CONF
  echo "bridge=${BR_IFACE}" >> $HOSTAPD_CONF
  echo "ssid=${WIFI_SSID}" >> $HOSTAPD_CONF
  echo "country_code=US" >> $HOSTAPD_CONF
  echo "hw_mode=g" >> $HOSTAPD_CONF
  echo "channel=11" >> $HOSTAPD_CONF
  echo "wpa=2" >> $HOSTAPD_CONF
  echo "wpa_passphrase=${WIFI_PASSWORD}" >> $HOSTAPD_CONF
  echo "wpa_key_mgmt=WPA-PSK" >> $HOSTAPD_CONF
  echo "wpa_pairwise=CCMP" >> $HOSTAPD_CONF
  echo "ieee80211n=1" >> $HOSTAPD_CONF
  #echo "ieee80211w=1" >> $HOSTAPD_CONF # PMF

#-----------------------------------------------------------------------------------------------------------------------
# Setup network interfaces, including WAN based on user options
#-----------------------------------------------------------------------------------------------------------------------

  echo "== bring up interfaces and bridge"
  ifconfig $WIFI_IFACE up

  # Check if we should preserve WAN interface
  WAN_PRESERVED=false
  if [ "$KEEP_WAN" = true ] && wan_is_configured; then
    echo "== WAN interface $WAN_IFACE already configured with $WAN_STATIC_IP (preserving)"
    WAN_PRESERVED=true
  else
    # Configure WAN: static if configured, otherwise attempt DHCP
    if [ -n "$WAN_STATIC_IP" ] && [ -n "$WAN_STATIC_NETMASK" ]; then
      echo "== configuring WAN interface $WAN_IFACE with static IP $WAN_STATIC_IP"
      # remove any old addresses, then assign static address
      ip addr flush dev $WAN_IFACE
      ifconfig $WAN_IFACE $WAN_STATIC_IP netmask $WAN_STATIC_NETMASK up

      # add default route via gateway if provided
      if [ -n "$WAN_STATIC_GATEWAY" ]; then
        echo "== adding default route via $WAN_STATIC_GATEWAY"
        ip route replace default via $WAN_STATIC_GATEWAY dev $WAN_IFACE
      fi

      if [ -n "$WAN_STATIC_DNS" ]; then
        echo "== setting DNS to $WAN_STATIC_DNS (overwriting /etc/resolv.conf)"
        # Back up existing resolv.conf if possible
        cp /etc/resolv.conf /etc/resolv.conf.backup 2>/dev/null || true
        echo "nameserver $WAN_STATIC_DNS" | tee /etc/resolv.conf > /dev/null
      fi
    else
      echo "== bringing $WAN_IFACE up (DHCP)"
      ifconfig $WAN_IFACE up
      # try to get DHCP address (dhclient may be needed on some distros)
      dhclient -v $WAN_IFACE 2>/dev/null || true
    fi
  fi

  ifconfig $LAN_IFACE up
  brctl addbr $BR_IFACE
  brctl addif $BR_IFACE $LAN_IFACE
  ifconfig $BR_IFACE up

#-----------------------------------------------------------------------------------------------------------------------
# Setup IP forwarding and iptables rules
#-----------------------------------------------------------------------------------------------------------------------

  echo "== enable IP forwarding"
  sysctl -w net.ipv4.ip_forward=1

  echo "== setup iptables"
  iptables --flush
  iptables -t nat --flush
  iptables -t nat -A POSTROUTING -o $WAN_IFACE -j MASQUERADE
  iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -A FORWARD -i $BR_IFACE -o $WAN_IFACE -j ACCEPT

  # Traffic redirect rules based on proxy mode
  case "$PROXY_MODE" in
    mitmproxy)
      iptables -t nat -A PREROUTING -i $BR_IFACE -p tcp --dport 443 -j REDIRECT --to-ports $MITMPROXY_PORT
      ;;
    sslsplit)
      iptables -t nat -A PREROUTING -i $BR_IFACE -p tcp --dport 443 -j REDIRECT --to-ports $SSLSPLIT_PORT
      ;;
    certmitm)
      # Only intercept traffic destined for router IP (DNS-spoofed domains)
      # Passthrough domains resolve to real IPs and bypass this rule
      iptables -t nat -A PREROUTING -i $BR_IFACE -p tcp -d $LAN_IP --dport 443 -j REDIRECT --to-ports $CERTMITM_PORT
      ;;
    sslstrip)
      # Redirect HTTPS to sslstrip (only DNS-spoofed traffic destined for router)
      iptables -t nat -A PREROUTING -i $BR_IFACE -p tcp -d $LAN_IP --dport 443 -j REDIRECT --to-ports $SSLSTRIP_PORT
      # Redirect HTTP to fake server (for devices that retry on HTTP)
      iptables -t nat -A PREROUTING -i $BR_IFACE -p tcp -d $LAN_IP --dport 80 -j REDIRECT --to-ports $SSLSTRIP_FAKE_SERVER_PORT
      ;;
  esac

  echo "== setting static IP on bridge interface"
  ifconfig $BR_IFACE $LAN_IP netmask $LAN_SUBNET

#-----------------------------------------------------------------------------------------------------------------------
# Start services: dnsmasq, hostapd, mitmproxy or sslsplit, and tcpdump capture
#-----------------------------------------------------------------------------------------------------------------------
  echo "== starting services"

  # Start dnsmasq
  echo "   Starting dnsmasq..."
  if dnsmasq -C $DNSMASQ_CONF; then
    wait_for_service "dnsmasq" "dnsmasq"
  else
    echo "   ✗ dnsmasq failed to start (config error?)"
  fi

  # Start hostapd
  echo "   Starting hostapd..."
  if hostapd -B $HOSTAPD_CONF; then
    wait_for_service "hostapd" "hostapd"
  else
    echo "   ✗ hostapd failed to start (config error?)"
  fi

  # Start proxy based on mode
  case "$PROXY_MODE" in
    mitmproxy)
      echo "   Starting mitmproxy web interface..."
      MITMPROXY_LOG="tmp_mitmproxy.log"
      if check_port_available $MITMPROXY_PORT "mitmproxy" && check_port_available $MITMPROXY_WEB_PORT "mitmweb"; then
        mitmweb --mode transparent --showhost \
          -p $MITMPROXY_PORT \
          --web-host $MITMPROXY_WEB_HOST \
          --web-port $MITMPROXY_WEB_PORT \
          --set web_password=$MITMPROXY_WEB_PASSWORD \
          -k > $MITMPROXY_LOG 2>&1 &
        sleep 2
        wait_for_service "mitmweb" "mitmweb"
      else
        echo "   ✗ mitmweb not started due to port conflict"
      fi

      # Save credentials to temp file for easy retrieval
      cat > tmp_mitmproxy_creds.txt << EOF
mitmproxy web interface:
  URL: http://$WAN_STATIC_IP:$MITMPROXY_WEB_PORT
  URL (with token): http://$WAN_STATIC_IP:$MITMPROXY_WEB_PORT?token=$MITMPROXY_WEB_PASSWORD
  Password: $MITMPROXY_WEB_PASSWORD
  Log: $MITMPROXY_LOG
EOF
      ;;
    sslsplit)
      # Generate session certificates
      generate_session_certs
      if [ $? -ne 0 ]; then
        echo "   ✗ sslsplit not started due to certificate generation failure"
      else
        echo "   Starting sslsplit..."
        # Create session directory for this run
        SSLSPLIT_SESSION_DIR="$SSLSPLIT_PCAP_DIR/session_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$SSLSPLIT_SESSION_DIR"
        SSLSPLIT_LOG="tmp_sslsplit.log"
        SSLSPLIT_CONN_LOG="$SSLSPLIT_SESSION_DIR/connections.log"

        if check_port_available $SSLSPLIT_PORT "sslsplit"; then
          # Run sslsplit with SNI-based upstream detection (sni 443)
          # This allows sslsplit to work even when DNS is spoofed,
          # by reading the real destination from the TLS ClientHello SNI
          # -Y pcapdir: packets to separate files in dir (excludes -X/-y)
          # -l logfile: write connection log to file
          sslsplit -D \
            -Y "$SSLSPLIT_SESSION_DIR" \
            -l "$SSLSPLIT_CONN_LOG" \
            -k "$SESSION_CERT_DIR/ca.key" \
            -c "$SESSION_CERT_DIR/ca.crt" \
            ssl 127.0.0.1 $SSLSPLIT_PORT \
            sni 443 \
            > $SSLSPLIT_LOG 2>&1 &
          sleep 2
          wait_for_service "sslsplit" "sslsplit"

          # Save session info to temp file
          cat > tmp_sslsplit_info.txt << EOF
sslsplit session:
  Session dir: $SSLSPLIT_SESSION_DIR
  Connection log: $SSLSPLIT_CONN_LOG
  Debug log: $SSLSPLIT_LOG
  Cert dir: $SESSION_CERT_DIR
  CA fingerprint: $(openssl x509 -fingerprint -sha256 -noout -in "$SESSION_CERT_DIR/ca.crt" 2>/dev/null | cut -d= -f2)
EOF
        else
          echo "   ✗ sslsplit not started due to port conflict"
          cleanup_session_certs
        fi
      fi
      ;;
    certmitm)
      echo "   Starting certmitm..."
      # Create session directory for this run
      CERTMITM_SESSION_DIR="$CERTMITM_WORKDIR/session_$(date +%Y%m%d_%H%M%S)"
      mkdir -p "$CERTMITM_SESSION_DIR"
      CERTMITM_LOG="tmp_certmitm.log"

      # Derive paths from CERTMITM_PATH
      CERTMITM_DIR=$(dirname "$CERTMITM_PATH")
      CERTMITM_SCRIPT=$(basename "$CERTMITM_PATH")

      if check_port_available $CERTMITM_PORT "certmitm"; then
        # Build certmitm options
        CERTMITM_OPTS="--listen $CERTMITM_PORT --workdir $CERTMITM_SESSION_DIR"

        if [ "$CERTMITM_VERBOSE" = true ]; then
          CERTMITM_OPTS="$CERTMITM_OPTS --verbose"
        fi

        if [ "$CERTMITM_SHOW_DATA" = true ]; then
          CERTMITM_OPTS="$CERTMITM_OPTS --show-data"
        fi

        # Run certmitm from its directory with activated venv
        (cd "$CERTMITM_DIR" && source venv/bin/activate && python3 "$CERTMITM_SCRIPT" $CERTMITM_OPTS) > "$CERTMITM_LOG" 2>&1 &
        CERTMITM_PID=$!
        echo "$CERTMITM_PID" > /tmp/mitm_certmitm.pid

        sleep 2

        if kill -0 "$CERTMITM_PID" 2>/dev/null; then
          echo "   ✓ certmitm started (PID: $CERTMITM_PID)"
        else
          echo "   ✗ certmitm FAILED to start (check $CERTMITM_LOG)"
        fi

        # Save session info to temp file
        cat > tmp_certmitm_info.txt << EOF
certmitm session:
  Session dir: $CERTMITM_SESSION_DIR
  Debug log: $CERTMITM_LOG
  Port: $CERTMITM_PORT
  Script: $CERTMITM_PATH
  Venv: $CERTMITM_DIR/venv
  PID: $CERTMITM_PID

Domain configuration:
  Test domains (DNS spoofed -> certmitm): ${CERTMITM_TEST_DOMAINS:-"(all spoofed domains)"}
  Passthrough domains (NOT spoofed -> real server): ${CERTMITM_PASSTHROUGH_DOMAINS:-"(none)"}

Note: Only domains in dns-spoof.conf are tested. Passthrough domains must NOT be in dns-spoof.conf.
EOF
      else
        echo "   ✗ certmitm not started due to port conflict"
      fi
      ;;
    sslstrip)
      echo "   Starting sslstrip mode..."
      SSLSTRIP_SESSION_DIR="./sslstrip_logs/session_$(date +%Y%m%d_%H%M%S)"
      mkdir -p "$SSLSTRIP_SESSION_DIR"

      # Start fake HTTP server first
      echo "   Starting fake HTTP server on port $SSLSTRIP_FAKE_SERVER_PORT..."
      if check_port_available $SSLSTRIP_FAKE_SERVER_PORT "fake-http-server"; then
        python3 "$SSLSTRIP_FAKE_SERVER_SCRIPT" \
          --http \
          --http-port $SSLSTRIP_FAKE_SERVER_PORT \
          --firmware-dir ./firmware \
          > "$SSLSTRIP_SESSION_DIR/fake_server.log" 2>&1 &
        FAKE_SERVER_PID=$!
        echo "$FAKE_SERVER_PID" > /tmp/mitm_sslstrip_fake_server.pid
        sleep 1
        if kill -0 "$FAKE_SERVER_PID" 2>/dev/null; then
          echo "   ✓ Fake HTTP server started (PID: $FAKE_SERVER_PID)"
        else
          echo "   ✗ Fake HTTP server failed to start"
        fi
      else
        echo "   ✗ Fake HTTP server port $SSLSTRIP_FAKE_SERVER_PORT in use"
      fi

      # Start sslstrip
      echo "   Starting sslstrip on port $SSLSTRIP_PORT..."
      if check_port_available $SSLSTRIP_PORT "sslstrip"; then
        sslstrip -l $SSLSTRIP_PORT \
          -w "$SSLSTRIP_SESSION_DIR/sslstrip.log" \
          > "$SSLSTRIP_SESSION_DIR/sslstrip_debug.log" 2>&1 &
        sleep 2
        wait_for_service "sslstrip" "sslstrip"
      else
        echo "   ✗ sslstrip port $SSLSTRIP_PORT in use"
      fi

      # Save session info
      cat > tmp_sslstrip_info.txt << EOF
sslstrip session:
  Session dir: $SSLSTRIP_SESSION_DIR
  sslstrip port: $SSLSTRIP_PORT
  Fake HTTP server: port $SSLSTRIP_FAKE_SERVER_PORT

Test domains: $SSLSTRIP_TEST_DOMAINS
Passthrough: $SSLSTRIP_PASSTHROUGH_DOMAINS
EOF
      ;;
    none)
      echo "   (proxy skipped - router-only mode)"
      ;;
  esac

  # Start packet capture if enabled
  if [ "$TCPDUMP_ENABLED" = true ]; then
    start_tcpdump
  fi

  echo ""
  echo "== Service Status Summary"
  pgrep -x dnsmasq >/dev/null && echo "   ✓ dnsmasq running" || echo "   ✗ dnsmasq NOT running"
  pgrep -x hostapd >/dev/null && echo "   ✓ hostapd running" || echo "   ✗ hostapd NOT running"
  case "$PROXY_MODE" in
    mitmproxy)
      if pgrep -x mitmweb >/dev/null; then
        echo "   ✓ mitmweb running"
      else
        echo "   ✗ mitmweb NOT running (check $MITMPROXY_LOG)"
      fi
      ;;
    sslsplit)
      if pgrep -x sslsplit >/dev/null; then
        echo "   ✓ sslsplit running"
      else
        echo "   ✗ sslsplit NOT running (check tmp_sslsplit.log)"
      fi
      ;;
    certmitm)
      if [ -f /tmp/mitm_certmitm.pid ] && kill -0 $(cat /tmp/mitm_certmitm.pid) 2>/dev/null; then
        echo "   ✓ certmitm running (PID: $(cat /tmp/mitm_certmitm.pid))"
      else
        echo "   ✗ certmitm NOT running (check tmp_certmitm.log)"
      fi
      ;;
    sslstrip)
      if pgrep -f "sslstrip" >/dev/null; then
        echo "   ✓ sslstrip running"
      else
        echo "   ✗ sslstrip NOT running"
      fi
      if [ -f /tmp/mitm_sslstrip_fake_server.pid ] && kill -0 $(cat /tmp/mitm_sslstrip_fake_server.pid) 2>/dev/null; then
        echo "   ✓ fake HTTP server running"
      else
        echo "   ✗ fake HTTP server NOT running"
      fi
      ;;
    none)
      echo "   - proxy disabled (router-only mode)"
      ;;
  esac
  if [ "$TCPDUMP_ENABLED" = true ]; then
    if [ -f /tmp/mitm_tcpdump.pid ] && kill -0 $(cat /tmp/mitm_tcpdump.pid) 2>/dev/null; then
      echo "   ✓ tcpdump running"
    else
      echo "   ✗ tcpdump NOT running"
    fi
  fi

  echo ""
  case "$PROXY_MODE" in
    mitmproxy|sslsplit|certmitm|sslstrip)
      echo "== MITM router is up (mode: $PROXY_MODE)"
      ;;
    none)
      echo "== Router is up (no traffic interception)"
      ;;
  esac
  if [ "$WAN_PRESERVED" = true ]; then
    echo "   WAN: $WAN_IFACE ($WAN_STATIC_IP) [preserved]"
  else
    echo "   WAN: $WAN_IFACE ($WAN_STATIC_IP) [configured]"
  fi
  echo "   LAN: $BR_IFACE ($LAN_IP)"
  echo "   WiFi SSID: $WIFI_SSID"
  case "$PROXY_MODE" in
    mitmproxy)
      echo "   mitmproxy web: http://$WAN_STATIC_IP:$MITMPROXY_WEB_PORT"
      ;;
    sslsplit)
      echo "   sslsplit session: $SSLSPLIT_SESSION_DIR"
      echo "   sslsplit connections: $SSLSPLIT_CONN_LOG"
      ;;
    certmitm)
      echo "   certmitm session: $CERTMITM_SESSION_DIR"
      echo "   certmitm log: $CERTMITM_LOG"
      ;;
    sslstrip)
      echo "   sslstrip port: $SSLSTRIP_PORT"
      echo "   fake server: port $SSLSTRIP_FAKE_SERVER_PORT"
      echo "   session: $SSLSTRIP_SESSION_DIR"
      ;;
  esac
  if [ "$TCPDUMP_ENABLED" = true ] && [ -f /tmp/mitm_tcpdump_pcap ]; then
    echo "   tcpdump capture: $(cat /tmp/mitm_tcpdump_pcap)"
  fi
fi

#-----------------------------------------------------------------------------------------------------------------------
# Handle the down option, stop services, cleanup
#-----------------------------------------------------------------------------------------------------------------------

if [ "$ACTION" = "down" ]; then
  echo "== stopping services and bringing interfaces down"
  killall hostapd 2>/dev/null || true
  killall dnsmasq 2>/dev/null || true
  killall mitmweb 2>/dev/null || true
  killall mitmproxy 2>/dev/null || true
  killall sslsplit 2>/dev/null || true
  # Cleanup mitmproxy temp files
  rm -f tmp_mitmproxy_creds.txt tmp_mitmproxy.log
  # Cleanup sslsplit temp files and session certificates
  rm -f tmp_sslsplit_info.txt tmp_sslsplit.log
  cleanup_session_certs
  # Stop certmitm using PID file and cleanup temp files
  if [ -f /tmp/mitm_certmitm.pid ]; then
    CERTMITM_PID=$(cat /tmp/mitm_certmitm.pid)
    if kill -0 "$CERTMITM_PID" 2>/dev/null; then
      kill "$CERTMITM_PID" 2>/dev/null
      echo "   Stopped certmitm (PID: $CERTMITM_PID)"
    fi
    rm -f /tmp/mitm_certmitm.pid
  fi
  rm -f tmp_certmitm_info.txt tmp_certmitm.log
  # Stop sslstrip processes and cleanup
  killall sslstrip 2>/dev/null || true
  if [ -f /tmp/mitm_sslstrip_fake_server.pid ]; then
    FAKE_SERVER_PID=$(cat /tmp/mitm_sslstrip_fake_server.pid)
    if kill -0 "$FAKE_SERVER_PID" 2>/dev/null; then
      kill "$FAKE_SERVER_PID" 2>/dev/null
      echo "   Stopped fake HTTP server (PID: $FAKE_SERVER_PID)"
    fi
    rm -f /tmp/mitm_sslstrip_fake_server.pid
  fi
  rm -f tmp_sslstrip_info.txt
  # Stop tcpdump if running (keeps pcap files)
  stop_tcpdump
  # restore resolv.conf backup if it exists
  if [ -f /etc/resolv.conf.backup ]; then
    mv /etc/resolv.conf.backup /etc/resolv.conf 2>/dev/null || true
  fi
  # flush routes and bring interfaces down
  if [ "$KEEP_WAN" = true ]; then
    echo "== preserving WAN interface $WAN_IFACE"
  else
    ip route flush dev $WAN_IFACE 2>/dev/null || true
    ifconfig $WAN_IFACE 0.0.0.0 down || true
  fi
  ifconfig $BR_IFACE 0.0.0.0 down || true
  brctl delbr $BR_IFACE 2>/dev/null || true
fi
