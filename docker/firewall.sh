#!/bin/bash
# firewall.sh — enforce network isolation for the apt_test topology.
#
# Docker's internal:true only blocks containers from reaching the internet.
# The host machine can still reach every internal bridge directly, so nmap
# from Kali bypasses isolation. This script adds iptables OUTPUT rules to
# block the host from initiating connections to isolated subnets, making
# pivoting genuinely necessary.
#
# Allowed:     host → 172.20.0.0/24  (DMZ — attacker's entry point)
# Blocked:     host → 172.21.0.0/24  (internal)
# Blocked:     host → 172.22.0.0/24  (deep)
# Blocked:     host → 172.23.0.0/24  (db)
#
# MSF route add is application-level (Rex::Socket intercepts calls inside
# the MSF process and tunnels through the Meterpreter session), so it is
# NOT affected by these kernel-level iptables rules.
#
# Meterpreter callbacks from internal containers reach the host via INPUT,
# not OUTPUT — also not affected.
#
# Usage:
#   sudo ./firewall.sh up    — apply isolation rules
#   sudo ./firewall.sh down  — remove isolation rules

ISOLATED_SUBNETS=(172.21.0.0/24 172.22.0.0/24 172.23.0.0/24)

cmd="${1:-up}"

apply() {
    local action="$1"   # -I = insert, -D = delete
    for subnet in "${ISOLATED_SUBNETS[@]}"; do
        iptables $action OUTPUT -d "$subnet" -m state --state NEW -j DROP && \
            echo "[$cmd] OUTPUT -d $subnet NEW: $([ "$action" = "-I" ] && echo "BLOCKED" || echo "removed")"
    done
}

case "$cmd" in
    up)
        echo "[firewall] Blocking host direct access to isolated subnets..."
        apply -I
        echo "[firewall] Done. Kali can only reach 172.20.0.0/24 (DMZ) directly."
        ;;
    down)
        echo "[firewall] Removing isolation rules..."
        apply -D
        echo "[firewall] Done. Host can reach all subnets directly again."
        ;;
    status)
        echo "[firewall] Current OUTPUT rules for isolated subnets:"
        iptables -L OUTPUT -n --line-numbers | grep -E "172\.2[1-3]\."
        ;;
    *)
        echo "Usage: $0 {up|down|status}"
        exit 1
        ;;
esac
