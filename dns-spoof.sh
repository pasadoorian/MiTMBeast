#!/bin/bash
#
# DNS Spoof Helper - Manage DNS spoofing entries without restarting dnsmasq
#
# Usage:
#   ./dns-spoof.sh add <domain> <ip>    # Add a spoof entry
#   ./dns-spoof.sh rm <domain>          # Remove a spoof entry
#   ./dns-spoof.sh list                 # List active spoofs
#   ./dns-spoof.sh reload               # Restart dnsmasq to apply config changes
#   ./dns-spoof.sh flush                # Clear dnsmasq cache (SIGHUP)
#   ./dns-spoof.sh dump                 # Dump cache stats and test resolution
#   ./dns-spoof.sh logs [N]             # Show last N DNS queries (default 50)

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
SPOOF_CONF="${SCRIPT_DIR}/dns-spoof.conf"
DNSMASQ_CONF="${SCRIPT_DIR}/tmp_dnsmasq.conf"

usage() {
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  add <domain> <ip>   Add DNS spoof (domain -> ip)"
    echo "  rm <domain>         Remove DNS spoof for domain"
    echo "  list                List all active spoof entries"
    echo "  reload              Restart dnsmasq to apply config changes"
    echo "  flush               Clear dnsmasq cache only (SIGHUP)"
    echo "  dump [domain]       Dump cache stats; optionally test a domain"
    echo "  logs [N]            Show last N DNS queries (default 50)"
    echo ""
    echo "Examples:"
    echo "  $0 add api.example.com 192.168.200.1"
    echo "  $0 rm api.example.com"
    echo "  $0 list"
    echo "  $0 dump api.example.com"
    exit 1
}

add_spoof() {
    local domain="$1"
    local ip="$2"

    if [ -z "$domain" ] || [ -z "$ip" ]; then
        echo "Error: add requires <domain> and <ip>"
        usage
    fi

    # Check if entry already exists
    if grep -q "^address=/${domain}/" "$SPOOF_CONF" 2>/dev/null; then
        echo "Entry for ${domain} already exists. Removing old entry..."
        rm_spoof "$domain" quiet
    fi

    echo "address=/${domain}/${ip}" >> "$SPOOF_CONF"
    echo "Added: ${domain} -> ${ip}"
    reload_dnsmasq
}

rm_spoof() {
    local domain="$1"
    local quiet="$2"

    if [ -z "$domain" ]; then
        echo "Error: rm requires <domain>"
        usage
    fi

    if grep -q "^address=/${domain}/" "$SPOOF_CONF" 2>/dev/null; then
        # Use sed to remove the line
        sed -i "/^address=\/${domain}\//d" "$SPOOF_CONF"
        [ -z "$quiet" ] && echo "Removed: ${domain}"
        [ -z "$quiet" ] && reload_dnsmasq
    else
        [ -z "$quiet" ] && echo "No entry found for: ${domain}"
    fi
}

list_spoofs() {
    echo "Active DNS spoofs (from dns-spoof.conf):"
    echo "========================================="
    if grep "^address=" "$SPOOF_CONF" 2>/dev/null | grep -v "^#"; then
        grep "^address=" "$SPOOF_CONF" | while read -r line; do
            domain=$(echo "$line" | sed 's/address=\/\([^/]*\)\/.*/\1/')
            ip=$(echo "$line" | sed 's/address=\/[^/]*\/\(.*\)/\1/')
            printf "  %-40s -> %s\n" "$domain" "$ip"
        done
    else
        echo "  (none)"
    fi
}

reload_dnsmasq() {
    # Full restart required to reload conf-file includes
    # SIGHUP only clears cache and re-reads /etc/hosts, NOT config files
    if pgrep -x dnsmasq > /dev/null; then
        echo "Restarting dnsmasq to apply config changes..."
        sudo killall dnsmasq
        sleep 0.5
        if [ -f "$DNSMASQ_CONF" ]; then
            sudo dnsmasq -C "$DNSMASQ_CONF"
            echo "dnsmasq restarted with config: $DNSMASQ_CONF"
        else
            echo "Warning: Config file not found: $DNSMASQ_CONF"
            echo "Run 'sudo ./mitm.sh up' to regenerate config"
        fi
    else
        echo "Warning: dnsmasq is not running"
    fi
}

flush_cache() {
    # SIGHUP clears cache but does NOT reload config files
    if pgrep -x dnsmasq > /dev/null; then
        sudo killall -HUP dnsmasq
        echo "dnsmasq cache flushed (SIGHUP)"
        echo "Note: This does NOT reload dns-spoof.conf. Use 'reload' for config changes."
    else
        echo "Warning: dnsmasq is not running"
    fi
}

dump_cache() {
    local test_domain="$1"

    echo "dnsmasq Cache Info"
    echo "=================="

    # Check if dnsmasq is running
    if ! pgrep -x dnsmasq > /dev/null; then
        echo "Error: dnsmasq is not running"
        return 1
    fi

    # Get dnsmasq PID
    local pid=$(pgrep -x dnsmasq)
    echo "dnsmasq PID: $pid"
    echo ""

    # Show current config file
    echo "Config file: $DNSMASQ_CONF"
    if [ -f "$DNSMASQ_CONF" ]; then
        echo "Includes: $(grep 'conf-file=' "$DNSMASQ_CONF" 2>/dev/null || echo '(none)')"
    fi
    echo ""

    # Dump cache stats via SIGUSR1 (writes to syslog)
    echo "Sending SIGUSR1 to dump cache stats to syslog..."
    sudo kill -USR1 $pid
    sleep 0.5

    # Try to show recent cache stats from journal
    echo ""
    echo "Recent dnsmasq cache stats:"
    echo "---------------------------"
    journalctl -u dnsmasq --no-pager -n 20 2>/dev/null | grep -i "cache" || \
        echo "(Could not retrieve cache stats from journal)"

    # Test domain resolution if provided
    if [ -n "$test_domain" ]; then
        echo ""
        echo "Testing resolution for: $test_domain"
        echo "-----------------------------------"

        # Get LAN IP from config
        local lan_ip=$(grep "^LAN_IP=" "${SCRIPT_DIR}/mitm.conf" 2>/dev/null | cut -d'"' -f2)
        lan_ip="${lan_ip:-192.168.200.1}"

        echo "Query via local dnsmasq ($lan_ip):"
        host "$test_domain" "$lan_ip" 2>&1 | head -5

        echo ""
        echo "Query via external DNS (8.8.8.8):"
        host "$test_domain" 8.8.8.8 2>&1 | head -5

        # Check if it's in spoof config
        echo ""
        if grep -q "^address=/${test_domain}/" "$SPOOF_CONF" 2>/dev/null; then
            echo "Status: SPOOFED in dns-spoof.conf"
            grep "^address=/${test_domain}/" "$SPOOF_CONF"
        else
            echo "Status: NOT in dns-spoof.conf (should resolve normally)"
        fi
    fi
}

show_logs() {
    local count="${1:-50}"
    echo "Last ${count} DNS queries (from syslog):"
    echo "========================================="
    journalctl -u dnsmasq --no-pager -n "$count" 2>/dev/null || \
        grep -i dnsmasq /var/log/syslog 2>/dev/null | tail -n "$count" || \
        grep -i dnsmasq /var/log/messages 2>/dev/null | tail -n "$count" || \
        echo "Could not find dnsmasq logs. Try: journalctl | grep dnsmasq"
}

# Main
case "${1:-}" in
    add)
        add_spoof "$2" "$3"
        ;;
    rm|remove)
        rm_spoof "$2"
        ;;
    list|ls)
        list_spoofs
        ;;
    reload)
        reload_dnsmasq
        ;;
    flush)
        flush_cache
        ;;
    dump)
        dump_cache "$2"
        ;;
    logs|log)
        show_logs "$2"
        ;;
    *)
        usage
        ;;
esac
