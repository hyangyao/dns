#!/usr/bin/env bash
# =============================================================================
# deploy.sh — Public DNS Server (Unbound + DoT/DoH) Deployment Script
#
# Target:     Azure B2ast (2 vCPU / 1 GB RAM), Ubuntu 22.04/24.04 LTS
# Location:   Japan East (optimized for Qingdao, China clients)
# Compliance: CIS Benchmarks (Ubuntu) · PCI-DSS v4.0
#
# Usage:
#   sudo bash scripts/deploy.sh
#
# After completion, replace the TLS certificate placeholder paths in
# /etc/unbound/unbound.conf with your actual Let's Encrypt certificate paths,
# then run: sudo systemctl reload unbound
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

require_root() {
    [[ "$(id -u)" -eq 0 ]] || die "This script must be run as root (sudo bash $0)"
}

# Create a timestamped backup of a file
backup_file() {
    local file="$1"
    [[ -f "${file}" ]] && cp "${file}" "${file}.bak.$(date +%Y%m%d%H%M%S)"
}

# Detect the script's repository root (one level above scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# --------------------------------------------------------------------------- #
# Phase 1 — System update & package installation
# --------------------------------------------------------------------------- #

phase1_packages() {
    log "Phase 1: Updating system and installing packages..."

    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        unbound \
        ufw \
        fail2ban \
        auditd \
        apparmor-profiles \
        curl \
        jq

    log "Phase 1 complete."
}

# --------------------------------------------------------------------------- #
# Phase 2 — Kernel / network optimization (BBR, buffer tuning)
# --------------------------------------------------------------------------- #

phase2_sysctl() {
    log "Phase 2: Applying sysctl network optimizations..."

    local src="${REPO_ROOT}/config/99-dns-optimize.conf"
    local dst="/etc/sysctl.d/99-dns-optimize.conf"

    if [[ -f "${src}" ]]; then
        cp "${src}" "${dst}"
        log "Copied ${src} -> ${dst}"
    else
        warn "config/99-dns-optimize.conf not found; writing defaults inline."
        cat > "${dst}" <<'SYSCTL'
# BBR congestion control — reduces latency on lossy cross-border links
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# UDP receive/send buffers — prevents DNS query drops under burst load
net.core.rmem_max = 4194304
net.core.wmem_max = 4194304
net.core.rmem_default = 262144
net.core.wmem_default = 262144

# SYN flood protection (CIS 3.3.2)
net.ipv4.tcp_syncookies = 1

# Disable packet forwarding — VM is a DNS resolver, not a router (PCI-DSS Req.1)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable IPv6 if unused (reduces attack surface)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Ignore ICMP redirects (CIS 3.3.1)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Log martian packets
net.ipv4.conf.all.log_martians = 1
SYSCTL
    fi

    sysctl -p "${dst}" || warn "Some sysctl settings may require a reboot."
    log "Phase 2 complete."
}

# --------------------------------------------------------------------------- #
# Phase 3 — UFW firewall rules (CIS 3.5 / PCI-DSS Req. 1)
# --------------------------------------------------------------------------- #

phase3_ufw() {
    log "Phase 3: Configuring UFW firewall..."

    ufw --force reset

    ufw default deny incoming
    ufw default allow outgoing

    ufw allow 22/tcp    comment 'SSH'
    ufw allow 53/tcp    comment 'DNS TCP'
    ufw allow 53/udp    comment 'DNS UDP'
    ufw allow 853/tcp   comment 'DNS over TLS (DoT)'
    ufw allow 443/tcp   comment 'DNS over HTTPS (DoH)'

    ufw --force enable

    ufw status verbose
    log "Phase 3 complete."
}

# --------------------------------------------------------------------------- #
# Phase 4 — SSH hardening (CIS Section 5.2 / PCI-DSS Req. 8)
# --------------------------------------------------------------------------- #

phase4_ssh() {
    log "Phase 4: Hardening SSH configuration..."

    local sshd_config="/etc/ssh/sshd_config"

    # Back up original
    backup_file "${sshd_config}"

    # Apply hardened settings via sshd_config.d drop-in (Ubuntu 22.04+)
    local drop_in="/etc/ssh/sshd_config.d/99-hardened.conf"
    cat > "${drop_in}" <<'SSHD'
# CIS Ubuntu 22.04 SSH hardening (PCI-DSS Req. 8)
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 0
AllowTcpForwarding no
PrintMotd no
SSHD

    # Validate the full sshd configuration (including drop-ins on Ubuntu 22.04+)
    # before restarting to prevent lockouts
    if sshd -t; then
        systemctl restart sshd
        log "SSH hardened and restarted."
    else
        warn "sshd config test failed — reverting drop-in."
        rm -f "${drop_in}"
    fi

    log "Phase 4 complete."
}

# --------------------------------------------------------------------------- #
# Phase 5 — auditd rules (PCI-DSS Req. 10)
# --------------------------------------------------------------------------- #

phase5_auditd() {
    log "Phase 5: Configuring auditd rules..."

    cat > /etc/audit/rules.d/dns-server.rules <<'AUDIT'
# PCI-DSS Req. 10 — Audit log all privileged access and configuration changes

# Monitor Unbound configuration
-w /etc/unbound/ -p wa -k dns_config_changes

# Monitor identity files
-w /etc/passwd  -p wa -k identity_changes
-w /etc/shadow  -p wa -k identity_changes
-w /etc/group   -p wa -k identity_changes

# Monitor SSH configuration
-w /etc/ssh/sshd_config   -p wa -k sshd_config_changes
-w /etc/ssh/sshd_config.d -p wa -k sshd_config_changes

# Monitor sudoers
-w /etc/sudoers    -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Monitor sysctl configuration
-w /etc/sysctl.conf  -p wa -k sysctl_changes
-w /etc/sysctl.d/    -p wa -k sysctl_changes

# Log all root command executions
-a always,exit -F arch=b64 -S execve -F uid=0 -k root_commands
AUDIT

    systemctl enable --now auditd
    augenrules --load || warn "augenrules --load failed; rules will apply on next reboot."
    log "Phase 5 complete."
}

# --------------------------------------------------------------------------- #
# Phase 6 — Unbound configuration
# --------------------------------------------------------------------------- #

phase6_unbound() {
    log "Phase 6: Installing Unbound configuration..."

    local src="${REPO_ROOT}/config/unbound.conf"
    local dst="/etc/unbound/unbound.conf"

    if [[ -f "${src}" ]]; then
        # Back up existing config
        backup_file "${dst}"
        cp "${src}" "${dst}"
        log "Copied ${src} -> ${dst}"
    else
        warn "config/unbound.conf not found in repo; using OS default."
    fi

    # Ensure the unbound user owns its data directory
    chown -R unbound:unbound /var/lib/unbound/ 2>/dev/null || true

    # Download latest root hints
    log "Downloading root hints..."
    curl -sSo /var/lib/unbound/root.hints \
        https://www.internic.net/domain/named.cache \
        || warn "Failed to download root hints; cached copy will be used."

    # Validate configuration
    if unbound-checkconf "${dst}"; then
        systemctl enable --now unbound
        log "Unbound started successfully."
    else
        die "Unbound configuration check failed. Please review ${dst}"
    fi

    log "Phase 6 complete."
}

# --------------------------------------------------------------------------- #
# Phase 7 — fail2ban
# --------------------------------------------------------------------------- #

phase7_fail2ban() {
    log "Phase 7: Configuring fail2ban..."

    cat > /etc/fail2ban/jail.local <<'F2B'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1/8

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
backend  = %(syslog_backend)s
F2B

    systemctl enable --now fail2ban
    log "Phase 7 complete."
}

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

print_summary() {
    cat <<SUMMARY

${GREEN}=============================================================
  Deployment complete!
=============================================================${NC}

Next steps:
  1. Obtain a TLS certificate for DoT:
       sudo certbot certonly --standalone -d <your-domain>

  2. Update TLS paths in /etc/unbound/unbound.conf:
       tls-service-key: "/etc/letsencrypt/live/<domain>/privkey.pem"
       tls-service-pem: "/etc/letsencrypt/live/<domain>/fullchain.pem"

  3. Reload Unbound:
       sudo systemctl reload unbound

  4. Restrict DNS access to your Qingdao IP in /etc/unbound/unbound.conf:
       access-control: <your-ip>/32 allow

  5. Verify DNS resolution:
       dig @127.0.0.1 www.google.com A

  6. Verify DNSSEC validation:
       dig @127.0.0.1 sigfail.verteiltesysteme.net A
       (Expect: SERVFAIL)

  7. Check Unbound statistics:
       sudo unbound-control stats_noreset

SUMMARY
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

main() {
    require_root

    log "Starting DNS server deployment on $(hostname) at $(date -u)"
    log "Repository root: ${REPO_ROOT}"

    phase1_packages
    phase2_sysctl
    phase3_ufw
    phase4_ssh
    phase5_auditd
    phase6_unbound
    phase7_fail2ban

    print_summary
}

main "$@"
