#!/usr/bin/env bash
# =============================================================================
# deploy.sh — Public DNS Server (Unbound + DoT/DoH) Deployment Script
#
# Target:     Azure B2ast (2 vCPU / 1 GB RAM), Ubuntu 22.04/24.04 LTS
# Location:   Japan East (optimised for Qingdao, China clients)
# Compliance: CIS Benchmarks (Ubuntu) · PCI-DSS v4.0
#
# Usage:
#   sudo bash scripts/deploy.sh
#
# After completion:
#   - Add your client IP to /etc/unbound/unbound.conf (access-control section)
#   - Run scripts/setup-tls.sh <domain> <email> to enable DNS over TLS
#   - Run scripts/health-check.sh to verify the deployment
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

# Create a timestamped backup of an existing file
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
        certbot \
        dnsutils \
        curl \
        jq

    log "Phase 1 complete."
}

# --------------------------------------------------------------------------- #
# Phase 2 — UFW firewall rules (CIS 3.5 / PCI-DSS Req. 1)
# Must run BEFORE phase3_sysctl so that UFW loads the nf_conntrack module;
# the sysctl config contains net.netfilter.nf_conntrack_* keys that require
# that module to be present in the kernel.
# --------------------------------------------------------------------------- #

phase2_ufw() {
    log "Phase 2: Configuring UFW firewall..."

    ufw --force reset

    ufw default deny incoming
    ufw default allow outgoing

    ufw allow 22/tcp    comment 'SSH'
    ufw allow 53/tcp    comment 'DNS TCP'
    ufw allow 53/udp    comment 'DNS UDP'
    ufw allow 853/tcp   comment 'DNS over TLS (DoT)'
    ufw allow 443/tcp   comment 'DNS over HTTPS / Nginx (DoH)'

    # Enable UFW — this loads the nf_conntrack netfilter module into the kernel
    ufw --force enable

    ufw status verbose
    log "Phase 2 complete."
}

# --------------------------------------------------------------------------- #
# Phase 3 — Kernel / network optimisation (BBR, buffer tuning)
# Runs AFTER UFW (phase2) to ensure nf_conntrack module is already loaded.
# --------------------------------------------------------------------------- #

phase3_sysctl() {
    log "Phase 3: Applying sysctl network optimisations..."

    local src="${REPO_ROOT}/config/99-dns-optimize.conf"
    local dst="/etc/sysctl.d/99-dns-optimize.conf"

    if [[ -f "${src}" ]]; then
        cp "${src}" "${dst}"
        log "Copied ${src} -> ${dst}"
    else
        warn "config/99-dns-optimize.conf not found; writing minimum inline settings."
        cat > "${dst}" <<'SYSCTL'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 4194304
net.core.wmem_max = 4194304
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.netfilter.nf_conntrack_max = 131072
vm.swappiness = 10
vm.overcommit_memory = 0
SYSCTL
    fi

    # Apply all sysctl drop-in files. Suppress nf_conntrack key errors that
    # occur when the module hasn't fully initialised yet; all other errors are
    # shown to aid troubleshooting.
    sysctl --system 2>&1 | grep -vE '^net\.netfilter\.nf_conntrack' || true
    # Reload the conntrack keys explicitly now that the module is definitely loaded
    sysctl -q -p "${dst}" || warn "Some sysctl settings may require a reboot."

    log "Phase 3 complete."
}

# --------------------------------------------------------------------------- #
# Phase 4 — SSH hardening (CIS Section 5.2 / PCI-DSS Req. 8)
# --------------------------------------------------------------------------- #

phase4_ssh() {
    log "Phase 4: Hardening SSH configuration..."

    local sshd_config="/etc/ssh/sshd_config"

    # Back up original before any modification
    backup_file "${sshd_config}"

    # Write a drop-in file (Ubuntu 22.04+ reads /etc/ssh/sshd_config.d/*.conf)
    local drop_in="/etc/ssh/sshd_config.d/99-hardened.conf"
    cat > "${drop_in}" <<'SSHD'
# CIS Ubuntu 22.04 SSH hardening — PCI-DSS Req. 8
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

    # Validate the complete sshd configuration (main file + all drop-ins)
    # before restarting to prevent accidental lockout
    if sshd -t; then
        systemctl restart sshd
        log "SSH hardened and restarted."
    else
        warn "sshd config test failed — reverting drop-in to avoid lockout."
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
# PCI-DSS Req. 10 — audit all privileged access and configuration changes

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

    systemctl enable auditd
    # Restart (not just start) so that the new rule file is picked up cleanly
    systemctl restart auditd
    # Load rules into the running kernel
    augenrules --load || warn "augenrules --load failed; rules apply on next reboot."

    log "Phase 5 complete."
}

# --------------------------------------------------------------------------- #
# Phase 6 — Unbound DNS configuration
# --------------------------------------------------------------------------- #

phase6_unbound() {
    log "Phase 6: Installing Unbound configuration..."

    local src="${REPO_ROOT}/config/unbound.conf"
    local dst="/etc/unbound/unbound.conf"

    if [[ -f "${src}" ]]; then
        backup_file "${dst}"
        cp "${src}" "${dst}"
        log "Copied ${src} -> ${dst}"
    else
        warn "config/unbound.conf not found in repo; using OS default."
    fi

    # Ensure the unbound user owns its data directory
    chown -R unbound:unbound /var/lib/unbound/ 2>/dev/null || true

    # Initialise / refresh the DNSSEC root trust anchor
    log "Initialising DNSSEC root trust anchor..."
    if [[ -f /etc/unbound/icannbundle.pem ]]; then
        unbound-anchor -a /var/lib/unbound/root.key \
                       -c /etc/unbound/icannbundle.pem || true
    else
        unbound-anchor -a /var/lib/unbound/root.key || true
    fi

    # Download the latest root hints
    log "Downloading root hints..."
    curl -sSf -o /var/lib/unbound/root.hints \
        https://www.internic.net/domain/named.cache \
        || warn "Root hints download failed; cached copy will be used."

    chown unbound:unbound /var/lib/unbound/root.hints 2>/dev/null || true

    # Validate configuration before starting
    if unbound-checkconf "${dst}"; then
        systemctl enable --now unbound
        log "Unbound started successfully."
    else
        die "Unbound configuration check failed. Review ${dst} and re-run."
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

Required next steps:
  1. Add your client IP to /etc/unbound/unbound.conf:
       access-control: <YOUR_IP>/32 allow
     Then reload Unbound:
       sudo systemctl reload unbound

  2. Enable DNS over TLS (DoT) once you have a domain:
       sudo bash scripts/setup-tls.sh dns.example.com admin@example.com

  3. Run the health check to verify everything works:
       sudo bash scripts/health-check.sh

Verification commands:
  # Test plain DNS resolution
  dig @127.0.0.1 www.google.com A

  # Test DNSSEC (expect SERVFAIL — validation working)
  dig @127.0.0.1 sigfail.verteiltesysteme.net A

  # Check Unbound statistics
  sudo unbound-control stats_noreset

  # Confirm firewall rules
  sudo ufw status verbose

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
    phase2_ufw        # UFW before sysctl — loads nf_conntrack module
    phase3_sysctl     # sysctl after UFW — nf_conntrack keys now safe to apply
    phase4_ssh
    phase5_auditd
    phase6_unbound
    phase7_fail2ban

    print_summary
}

main "$@"
