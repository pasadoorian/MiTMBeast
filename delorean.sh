#!/bin/bash
#
# delorean.sh - Delorean NTP Spoofing Wrapper Script
#
# Manages the Delorean NTP spoofing tool for time manipulation attacks.
# Delorean must be installed at ./delorean/delorean.py
#
# Usage:
#   ./delorean.sh start              # Start with default +1000 days
#   ./delorean.sh start +365         # Start with +365 days in future
#   ./delorean.sh start -365         # Start with -365 days in past
#   ./delorean.sh start "2030-06-15" # Start with specific date
#   ./delorean.sh stop               # Stop Delorean
#   ./delorean.sh reload             # Restart with current settings
#   ./delorean.sh status             # Show running status
#   ./delorean.sh set +1000          # Change time offset (restarts)
#   ./delorean.sh set "2030-06-15"   # Change to specific date (restarts)
#

# Configuration
SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
DELOREAN_DIR="$SCRIPT_DIR/delorean"
DELOREAN_SCRIPT="$DELOREAN_DIR/delorean.py"
DELOREAN_PID_FILE="/tmp/mitm_delorean.pid"
DELOREAN_TIME_FILE="/tmp/mitm_delorean_time.conf"
DELOREAN_LOG="$SCRIPT_DIR/tmp_delorean.log"

# Default time offset (days in future)
DEFAULT_OFFSET="+1000"

# Network interface for iptables rules
BR_IFACE="br0"
ROUTER_IP="192.168.200.1"

# Known NTP server IPs (some IoT devices use hardcoded IPs, not DNS)
# Cloudflare: 162.159.200.1, 162.159.200.123
# Google: 216.239.35.0, 216.239.35.4, 216.239.35.8, 216.239.35.12
NTP_SERVERS=(
    "162.159.200.1"
    "162.159.200.123"
    "216.239.35.0"
    "216.239.35.4"
    "216.239.35.8"
    "216.239.35.12"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

#
# Check if running as root
#
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
        exit 1
    fi
}

#
# Check if Delorean is installed
#
check_delorean() {
    if [ ! -f "$DELOREAN_SCRIPT" ]; then
        echo -e "${RED}Error: Delorean not found at $DELOREAN_SCRIPT${NC}"
        echo ""
        echo "Install Delorean with:"
        echo "  git clone https://github.com/jselvi/Delorean.git $DELOREAN_DIR"
        echo ""
        exit 1
    fi
}

#
# Check if Delorean is running
#
is_running() {
    if [ -f "$DELOREAN_PID_FILE" ]; then
        local pid=$(cat "$DELOREAN_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

#
# Get current PID
#
get_pid() {
    if [ -f "$DELOREAN_PID_FILE" ]; then
        cat "$DELOREAN_PID_FILE"
    fi
}

#
# Calculate target date from offset
#
calculate_date() {
    local offset="$1"

    if [[ "$offset" =~ ^[+-][0-9]+$ ]]; then
        # Offset in days (e.g., +1000, -365)
        local days="${offset:1}"
        local sign="${offset:0:1}"

        if [ "$sign" = "+" ]; then
            date -d "+$days days" "+%Y-%m-%d %H:%M:%S"
        else
            date -d "-$days days" "+%Y-%m-%d %H:%M:%S"
        fi
    else
        # Specific date/time provided
        echo "$offset"
    fi
}

#
# Save current time setting
#
save_time_setting() {
    local setting="$1"
    echo "$setting" > "$DELOREAN_TIME_FILE"
}

#
# Load saved time setting
#
load_time_setting() {
    if [ -f "$DELOREAN_TIME_FILE" ]; then
        cat "$DELOREAN_TIME_FILE"
    else
        echo "$DEFAULT_OFFSET"
    fi
}

#
# Add iptables rules to redirect NTP traffic
#
add_iptables_rules() {
    echo "Adding iptables rules to redirect NTP traffic..."

    # Method 1: Redirect ALL NTP traffic (catches any NTP server)
    iptables -t nat -A PREROUTING -i "$BR_IFACE" -p udp --dport 123 -j DNAT --to-destination "$ROUTER_IP:123"

    # Method 2: Also add rules for specific known NTP server IPs (belt and suspenders)
    # This ensures traffic to hardcoded IPs is caught even if Method 1 has issues
    for ip in "${NTP_SERVERS[@]}"; do
        iptables -t nat -A PREROUTING -i "$BR_IFACE" -p udp -d "$ip" --dport 123 -j DNAT --to-destination "$ROUTER_IP:123" 2>/dev/null
    done

    echo -e "${GREEN}✓ iptables NTP redirect rules added${NC}"
}

#
# Remove iptables rules
#
remove_iptables_rules() {
    echo "Removing iptables NTP redirect rules..."

    # Remove the general rule
    iptables -t nat -D PREROUTING -i "$BR_IFACE" -p udp --dport 123 -j DNAT --to-destination "$ROUTER_IP:123" 2>/dev/null

    # Remove specific IP rules
    for ip in "${NTP_SERVERS[@]}"; do
        iptables -t nat -D PREROUTING -i "$BR_IFACE" -p udp -d "$ip" --dport 123 -j DNAT --to-destination "$ROUTER_IP:123" 2>/dev/null
    done

    echo -e "${GREEN}✓ iptables NTP redirect rules removed${NC}"
}

#
# Check if iptables rules are active
#
check_iptables_rules() {
    if iptables -t nat -C PREROUTING -i "$BR_IFACE" -p udp --dport 123 -j DNAT --to-destination "$ROUTER_IP:123" 2>/dev/null; then
        return 0
    fi
    return 1
}

#
# Start Delorean
#
do_start() {
    local time_arg="${1:-$(load_time_setting)}"

    if is_running; then
        echo -e "${YELLOW}Delorean is already running (PID: $(get_pid))${NC}"
        echo "Use './delorean.sh stop' first or './delorean.sh reload'"
        return 1
    fi

    check_delorean

    # Calculate target date
    local target_date=$(calculate_date "$time_arg")

    echo "Starting Delorean NTP spoofer..."
    echo "  Time setting: $time_arg"
    echo "  Target date: $target_date"
    echo "  Log file: $DELOREAN_LOG"

    # Save time setting
    save_time_setting "$time_arg"

    # Start Delorean
    # Delorean's -d flag expects format like "2030-01-01 12:00:00"
    python3 "$DELOREAN_SCRIPT" -d "$target_date" > "$DELOREAN_LOG" 2>&1 &
    local pid=$!
    echo "$pid" > "$DELOREAN_PID_FILE"

    sleep 1

    if kill -0 "$pid" 2>/dev/null; then
        echo -e "${GREEN}✓ Delorean started (PID: $pid)${NC}"
        echo ""

        # Add iptables rules to redirect NTP traffic
        add_iptables_rules

        echo ""
        echo "NTP clients connecting will receive time: $target_date"
        echo ""
        echo "Intercepting NTP traffic from:"
        echo "  - All UDP port 123 traffic on $BR_IFACE"
        echo "  - Cloudflare NTP: 162.159.200.1, 162.159.200.123"
        echo "  - Google NTP: 216.239.35.0, 216.239.35.4, 216.239.35.8, 216.239.35.12"
    else
        echo -e "${RED}✗ Delorean failed to start${NC}"
        echo "Check log: $DELOREAN_LOG"
        rm -f "$DELOREAN_PID_FILE"
        return 1
    fi
}

#
# Stop Delorean
#
do_stop() {
    # Always try to remove iptables rules (even if Delorean not running)
    remove_iptables_rules

    if ! is_running; then
        echo "Delorean is not running"
        rm -f "$DELOREAN_PID_FILE"
        return 0
    fi

    local pid=$(get_pid)
    echo "Stopping Delorean (PID: $pid)..."

    kill "$pid" 2>/dev/null
    sleep 1

    if kill -0 "$pid" 2>/dev/null; then
        echo "Sending SIGKILL..."
        kill -9 "$pid" 2>/dev/null
        sleep 1
    fi

    rm -f "$DELOREAN_PID_FILE"
    echo -e "${GREEN}✓ Delorean stopped${NC}"
}

#
# Reload Delorean (stop + start)
#
do_reload() {
    local time_arg="${1:-$(load_time_setting)}"

    echo "Reloading Delorean..."
    do_stop
    sleep 1
    do_start "$time_arg"
}

#
# Show status
#
do_status() {
    echo "Delorean NTP Spoofer Status"
    echo "==========================="

    if is_running; then
        local pid=$(get_pid)
        local time_setting=$(load_time_setting)
        local target_date=$(calculate_date "$time_setting")

        echo -e "Status: ${GREEN}Running${NC} (PID: $pid)"
        echo "Time setting: $time_setting"
        echo "Target date: $target_date"
        echo "Log file: $DELOREAN_LOG"

        echo ""
        echo "iptables NTP redirect:"
        if check_iptables_rules; then
            echo -e "  ${GREEN}Active${NC} - All UDP:123 traffic on $BR_IFACE redirected"
        else
            echo -e "  ${RED}Not active${NC}"
        fi

        echo ""
        echo "Known NTP server IPs being intercepted:"
        for ip in "${NTP_SERVERS[@]}"; do
            echo "  - $ip"
        done

        echo ""
        echo "Recent log entries:"
        tail -5 "$DELOREAN_LOG" 2>/dev/null || echo "  (no log entries)"
    else
        echo -e "Status: ${RED}Stopped${NC}"

        if [ -f "$DELOREAN_TIME_FILE" ]; then
            echo "Last time setting: $(load_time_setting)"
        fi

        echo ""
        echo "iptables NTP redirect:"
        if check_iptables_rules; then
            echo -e "  ${YELLOW}Rules still active${NC} (run 'stop' to clean up)"
        else
            echo "  Not active"
        fi
    fi
}

#
# Set new time (restart with new setting)
#
do_set() {
    local time_arg="$1"

    if [ -z "$time_arg" ]; then
        echo -e "${RED}Error: Time argument required${NC}"
        echo "Usage: ./delorean.sh set +1000"
        echo "       ./delorean.sh set -365"
        echo "       ./delorean.sh set \"2030-06-15 12:00:00\""
        return 1
    fi

    echo "Setting new time: $time_arg"
    save_time_setting "$time_arg"

    if is_running; then
        do_reload "$time_arg"
    else
        echo "Delorean is not running. Start with: ./delorean.sh start"
    fi
}

#
# Show usage
#
show_usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  start [time]    Start Delorean NTP spoofer (auto-adds iptables rules)"
    echo "  stop            Stop Delorean (auto-removes iptables rules)"
    echo "  reload [time]   Restart Delorean"
    echo "  status          Show current status and iptables rules"
    echo "  set <time>      Set new time (restarts if running)"
    echo ""
    echo "Time formats:"
    echo "  +DAYS           Days in future (e.g., +1000, +365)"
    echo "  -DAYS           Days in past (e.g., -365, -3650)"
    echo "  \"YYYY-MM-DD\"    Specific date"
    echo "  \"YYYY-MM-DD HH:MM:SS\"  Specific date and time"
    echo ""
    echo "Examples:"
    echo "  $0 start                    # Start with +1000 days (default)"
    echo "  $0 start +1500              # Start with +1500 days"
    echo "  $0 start -3650              # Start with -10 years"
    echo "  $0 start \"2030-06-15\"       # Start with specific date"
    echo "  $0 set +2000                # Change to +2000 days"
    echo "  $0 status                   # Check if running"
    echo "  $0 stop                     # Stop Delorean"
    echo ""
    echo "NTP Interception (automatic):"
    echo "  - Redirects all UDP port 123 traffic on $BR_IFACE"
    echo "  - Intercepts hardcoded NTP server IPs (Cloudflare, Google)"
    echo "  - iptables rules added on start, removed on stop"
}

#
# Main
#
ACTION="$1"
shift

case "$ACTION" in
    start)
        check_root
        do_start "$1"
        ;;
    stop)
        check_root
        do_stop
        ;;
    reload)
        check_root
        do_reload "$1"
        ;;
    status)
        do_status
        ;;
    set)
        check_root
        do_set "$1"
        ;;
    -h|--help|help)
        show_usage
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
