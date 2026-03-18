#!/usr/bin/env bash
# =============================================================================
# health-check.sh — Post-deployment verification and compliance check
#
# Verifies that all services are running correctly and that the system meets
# CIS Benchmark and PCI-DSS requirements.
#
# Usage:
#   sudo bash scripts/health-check.sh
#
# Exit code: 0 = all checks passed, 1 = one or more checks failed
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass() { echo -e "  ${GREEN}[PASS]${NC} $*"; (( PASS++ )) || true; }
fail() { echo -e "  ${RED}[FAIL]${NC} $*"; (( FAIL++ )) || true; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $*"; (( WARN++ )) || true; }
header() { echo -e "\n${CYAN}▶ $*${NC}"; }

require_root() {
    [[ "$(id -u)" -eq 0 ]] || { echo "Run as root: sudo bash scripts/health-check.sh"; exit 1; }
}

# --------------------------------------------------------------------------- #
# Check 1 — Unbound service
# --------------------------------------------------------------------------- #

check_unbound_service() {
    header "Unbound service"

    if systemctl is-active --quiet unbound; then
        pass "Unbound is running."
    else
        fail "Unbound is NOT running. Check: journalctl -u unbound -n 50"
        return
    fi

    if systemctl is-enabled --quiet unbound; then
        pass "Unbound is enabled at boot."
    else
        fail "Unbound is NOT enabled at boot."
    fi

    if unbound-checkconf /etc/unbound/unbound.conf &>/dev/null; then
        pass "Unbound configuration syntax is valid."
    else
        fail "Unbound configuration has syntax errors: unbound-checkconf /etc/unbound/unbound.conf"
    fi
}

# --------------------------------------------------------------------------- #
# Check 2 — DNS resolution
# --------------------------------------------------------------------------- #

check_dns_resolution() {
    header "DNS resolution"

    if ! command -v dig &>/dev/null; then
        warn "dig not found (install dnsutils). Skipping DNS resolution tests."
        return
    fi

    # Plain UDP resolution
    if dig +short +timeout=5 @127.0.0.1 www.google.com A &>/dev/null; then
        pass "Plain UDP DNS resolution to www.google.com: OK"
    else
        fail "Plain UDP DNS resolution failed. Check Unbound logs."
    fi

    # DNSSEC validation — sigfail.verteiltesysteme.net must return SERVFAIL
    local result
    result="$(dig +short +timeout=5 @127.0.0.1 sigfail.verteiltesysteme.net A 2>/dev/null || true)"
    local rcode
    rcode="$(dig +timeout=5 @127.0.0.1 sigfail.verteiltesysteme.net A 2>/dev/null \
             | grep -oP 'NOERROR|SERVFAIL|NXDOMAIN|REFUSED' | head -1 || true)"

    if [[ "${rcode}" == "SERVFAIL" ]]; then
        pass "DNSSEC validation: SERVFAIL correctly returned for invalid signature."
    else
        fail "DNSSEC validation: expected SERVFAIL, got '${rcode}'. DNSSEC may be misconfigured."
    fi

    # DNSSEC positive test — google.com should resolve with AD flag
    local ad_flag
    ad_flag="$(dig +timeout=5 @127.0.0.1 google.com A 2>/dev/null \
               | grep -c 'flags:.*ad' || true)"
    if [[ "${ad_flag}" -gt 0 ]]; then
        pass "DNSSEC AD flag present for google.com (validated response)."
    else
        warn "DNSSEC AD flag not present for google.com. May indicate DNSSEC not fully active."
    fi
}

# --------------------------------------------------------------------------- #
# Check 3 — Version hiding (CIS DNS 2.1 / PCI-DSS Req. 2)
# --------------------------------------------------------------------------- #

check_version_hiding() {
    header "Version & identity hiding (CIS DNS 2.1)"

    if ! command -v dig &>/dev/null; then
        warn "dig not found. Skipping version hiding tests."
        return
    fi

    local version_answer
    version_answer="$(dig +short @127.0.0.1 version.bind chaos txt 2>/dev/null || true)"
    if [[ -z "${version_answer}" ]]; then
        pass "version.bind query returns empty (version hidden)."
    else
        fail "version.bind returned: '${version_answer}' — set hide-version: yes in unbound.conf"
    fi

    local id_answer
    id_answer="$(dig +short @127.0.0.1 id.server chaos txt 2>/dev/null || true)"
    if [[ -z "${id_answer}" ]]; then
        pass "id.server query returns empty (identity hidden)."
    else
        fail "id.server returned: '${id_answer}' — set hide-identity: yes in unbound.conf"
    fi
}

# --------------------------------------------------------------------------- #
# Check 4 — Access control (anti-amplification)
# --------------------------------------------------------------------------- #

check_access_control() {
    header "Access control (anti-amplification)"

    if ! command -v dig &>/dev/null; then
        warn "dig not found. Skipping access control tests."
        return
    fi

    # Loopback must be allowed
    if dig +short +timeout=3 @127.0.0.1 www.google.com A &>/dev/null; then
        pass "Loopback (127.0.0.1) queries are allowed."
    else
        fail "Loopback queries are refused — check access-control in unbound.conf"
    fi

    # Check that the default is 'refuse' in the config
    if grep -q "access-control: 0\.0\.0\.0/0 refuse" /etc/unbound/unbound.conf; then
        pass "Default access-control is 'refuse' (anti-amplification)."
    else
        warn "Default access-control may not be 'refuse' — review unbound.conf"
    fi
}

# --------------------------------------------------------------------------- #
# Check 5 — UFW firewall (CIS 3.5 / PCI-DSS Req. 1)
# --------------------------------------------------------------------------- #

check_ufw() {
    header "UFW firewall (CIS 3.5 / PCI-DSS Req. 1)"

    if ufw status | grep -q "^Status: active"; then
        pass "UFW is active."
    else
        fail "UFW is NOT active."
        return
    fi

    local ufw_rules
    ufw_rules="$(ufw status numbered)"

    for port_proto in "22/tcp" "53/tcp" "53/udp" "853/tcp" "443/tcp"; do
        # Match both the port number and the protocol to avoid false positives
        # (e.g. 22/udp open must not satisfy the 22/tcp check)
        if echo "${ufw_rules}" | grep -qE "\b${port_proto}\b"; then
            pass "UFW allows port ${port_proto}."
        else
            fail "UFW missing rule for port ${port_proto}."
        fi
    done

    if ufw status | grep -q "deny (incoming)"; then
        pass "UFW default incoming policy is DENY."
    else
        fail "UFW default incoming policy is not DENY."
    fi
}

# --------------------------------------------------------------------------- #
# Check 6 — fail2ban (PCI-DSS Req. 8)
# --------------------------------------------------------------------------- #

check_fail2ban() {
    header "fail2ban (PCI-DSS Req. 8)"

    if systemctl is-active --quiet fail2ban; then
        pass "fail2ban is running."
    else
        fail "fail2ban is NOT running."
        return
    fi

    if fail2ban-client status sshd &>/dev/null; then
        pass "fail2ban sshd jail is active."
    else
        fail "fail2ban sshd jail is not active. Check /etc/fail2ban/jail.local"
    fi
}

# --------------------------------------------------------------------------- #
# Check 7 — auditd (PCI-DSS Req. 10)
# --------------------------------------------------------------------------- #

check_auditd() {
    header "auditd (PCI-DSS Req. 10)"

    if systemctl is-active --quiet auditd; then
        pass "auditd is running."
    else
        fail "auditd is NOT running."
        return
    fi

    if auditctl -l 2>/dev/null | grep -q "dns_config_changes"; then
        pass "DNS config change audit rules are loaded."
    else
        warn "DNS config audit rules not found in kernel. Run: augenrules --load"
    fi

    if auditctl -l 2>/dev/null | grep -q "root_commands"; then
        pass "Root command execution audit rules are loaded."
    else
        warn "Root command audit rules not found. Run: augenrules --load"
    fi
}

# --------------------------------------------------------------------------- #
# Check 8 — SSH hardening (CIS 5.2 / PCI-DSS Req. 8)
# --------------------------------------------------------------------------- #

check_ssh() {
    header "SSH hardening (CIS 5.2 / PCI-DSS Req. 8)"

    if systemctl is-active --quiet sshd; then
        pass "sshd is running."
    else
        fail "sshd is NOT running."
    fi

    # Read the effective sshd configuration
    local sshd_effective
    sshd_effective="$(sshd -T 2>/dev/null || true)"

    declare -A expected=(
        [permitrootlogin]="no"
        [passwordauthentication]="no"
        [x11forwarding]="no"
        [maxauthtries]="3"
    )

    for key in "${!expected[@]}"; do
        local actual
        actual="$(echo "${sshd_effective}" | grep -i "^${key} " | awk '{print $2}' || true)"
        if [[ "${actual,,}" == "${expected[$key],,}" ]]; then
            pass "sshd ${key}=${actual} (expected: ${expected[$key]})."
        else
            fail "sshd ${key}='${actual}' — expected '${expected[$key]}'. Review sshd_config."
        fi
    done
}

# --------------------------------------------------------------------------- #
# Check 9 — Kernel / network optimisation (BBR, sysctl)
# --------------------------------------------------------------------------- #

check_sysctl() {
    header "Kernel optimisation (BBR, sysctl)"

    local cc
    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'unknown')"
    if [[ "${cc}" == "bbr" ]]; then
        pass "BBR congestion control is active."
    else
        fail "BBR is NOT active (current: ${cc}). Check /etc/sysctl.d/99-dns-optimize.conf"
    fi

    local qdisc
    qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo 'unknown')"
    if [[ "${qdisc}" == "fq" ]]; then
        pass "Default qdisc is fq (required for BBR)."
    else
        fail "Default qdisc is '${qdisc}' — should be 'fq' for BBR."
    fi

    if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" == "0" ]]; then
        pass "IP forwarding is disabled (CIS / PCI-DSS Req. 1)."
    else
        fail "IP forwarding is ENABLED — disable it: sysctl net.ipv4.ip_forward=0"
    fi

    if [[ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" == "1" ]]; then
        pass "SYN cookies are enabled (CIS 3.3.2)."
    else
        fail "SYN cookies are NOT enabled — set net.ipv4.tcp_syncookies=1"
    fi
}

# --------------------------------------------------------------------------- #
# Check 10 — Memory budget
# --------------------------------------------------------------------------- #

check_memory() {
    header "Memory budget (1 GB RAM OOM prevention)"

    local total_mb
    total_mb="$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)"
    local avail_mb
    avail_mb="$(awk '/MemAvailable/ {printf "%.0f", $2/1024}' /proc/meminfo)"
    local used_mb=$(( total_mb - avail_mb ))

    echo "    Total RAM : ${total_mb} MB"
    echo "    Used      : ${used_mb} MB"
    echo "    Available : ${avail_mb} MB"

    if [[ "${avail_mb}" -gt 200 ]]; then
        pass "Available memory (${avail_mb} MB) is above the 200 MB safety threshold."
    else
        fail "Available memory (${avail_mb} MB) is LOW. Risk of OOM. Reduce cache sizes."
    fi

    # Check Unbound cache configuration
    local msg_cache rrset_cache
    msg_cache="$(grep -oP '(?<=msg-cache-size:\s)\S+' /etc/unbound/unbound.conf 2>/dev/null || echo 'N/A')"
    rrset_cache="$(grep -oP '(?<=rrset-cache-size:\s)\S+' /etc/unbound/unbound.conf 2>/dev/null || echo 'N/A')"
    echo "    Unbound msg-cache-size  : ${msg_cache}"
    echo "    Unbound rrset-cache-size: ${rrset_cache}"
    pass "Unbound cache sizes read from config (verify they are ≤192m total)."
}

# --------------------------------------------------------------------------- #
# Check 11 — DoT status
# --------------------------------------------------------------------------- #

check_dot() {
    header "DNS over TLS (DoT) status"

    if ss -tlnp 2>/dev/null | grep -q ":853 "; then
        pass "Unbound is listening on port 853 (DoT active)."
        # Verify TLS cert paths exist
        local key_path pem_path
        key_path="$(grep -oP '(?<=tls-service-key:\s")[^"]+' /etc/unbound/unbound.conf 2>/dev/null || true)"
        pem_path="$(grep -oP '(?<=tls-service-pem:\s")[^"]+' /etc/unbound/unbound.conf 2>/dev/null || true)"
        if [[ -f "${key_path:-/nonexistent}" ]]; then
            pass "TLS private key exists: ${key_path}"
        else
            fail "TLS private key NOT found: ${key_path}"
        fi
        if [[ -f "${pem_path:-/nonexistent}" ]]; then
            pass "TLS certificate exists: ${pem_path}"
        else
            fail "TLS certificate NOT found: ${pem_path}"
        fi
    else
        warn "Unbound is NOT listening on port 853. DoT not yet enabled."
        warn "To enable DoT, run: sudo bash scripts/setup-tls.sh <domain> <email>"
    fi
}

# --------------------------------------------------------------------------- #
# Check 12 — DNSSEC root trust anchor
# --------------------------------------------------------------------------- #

check_trust_anchor() {
    header "DNSSEC root trust anchor"

    if [[ -f /var/lib/unbound/root.key ]]; then
        local key_age_days
        key_age_days=$(( ( $(date +%s) - $(stat -c %Y /var/lib/unbound/root.key) ) / 86400 ))
        if [[ "${key_age_days}" -lt 30 ]]; then
            pass "root.key exists and is ${key_age_days} day(s) old."
        else
            warn "root.key is ${key_age_days} days old. Consider refreshing: unbound-anchor -a /var/lib/unbound/root.key"
        fi
    else
        fail "root.key not found. Run: unbound-anchor -a /var/lib/unbound/root.key"
    fi

    if [[ -f /var/lib/unbound/root.hints ]]; then
        local hints_age_days
        hints_age_days=$(( ( $(date +%s) - $(stat -c %Y /var/lib/unbound/root.hints) ) / 86400 ))
        if [[ "${hints_age_days}" -lt 90 ]]; then
            pass "root.hints exists and is ${hints_age_days} day(s) old."
        else
            warn "root.hints is ${hints_age_days} days old. Refresh: curl -sSo /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache"
        fi
    else
        fail "root.hints not found at /var/lib/unbound/root.hints"
    fi
}

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

print_summary() {
    local total=$(( PASS + FAIL + WARN ))
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "  Results: ${GREEN}${PASS} passed${NC}  ${RED}${FAIL} failed${NC}  ${YELLOW}${WARN} warnings${NC}  (${total} total)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [[ "${FAIL}" -gt 0 ]]; then
        echo -e "  ${RED}Action required: review the FAIL items above before production use.${NC}"
        return 1
    elif [[ "${WARN}" -gt 0 ]]; then
        echo -e "  ${YELLOW}Review warnings above. Deployment is functional but not fully optimised.${NC}"
        return 0
    else
        echo -e "  ${GREEN}All checks passed. Server is ready for production use.${NC}"
        return 0
    fi
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

main() {
    require_root

    echo -e "${CYAN}================================================================"
    echo "  DNS Server Health Check — $(hostname) — $(date -u)"
    echo -e "================================================================${NC}"

    check_unbound_service
    check_dns_resolution
    check_version_hiding
    check_access_control
    check_ufw
    check_fail2ban
    check_auditd
    check_ssh
    check_sysctl
    check_memory
    check_dot
    check_trust_anchor

    print_summary
}

main "$@"
