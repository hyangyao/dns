#!/usr/bin/env bash
# =============================================================================
# setup-tls.sh — Provision a Let's Encrypt certificate and enable Unbound DoT
#
# This script:
#   1. Temporarily opens port 80 in UFW for the ACME HTTP-01 challenge
#   2. Obtains a TLS certificate via certbot --standalone
#   3. Closes port 80 in UFW
#   4. Patches /etc/unbound/unbound.conf to activate DoT on port 853
#   5. Validates and reloads Unbound
#   6. Installs a cron job for automatic certificate renewal
#
# Usage:
#   sudo bash scripts/setup-tls.sh <domain> <email>
#
# Example:
#   sudo bash scripts/setup-tls.sh dns.example.com admin@example.com
#
# Prerequisites:
#   - deploy.sh has already been run
#   - The domain's A record points to this server's public IP
#   - Port 80 must be reachable from the internet (Azure NSG must allow it)
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

# --------------------------------------------------------------------------- #
# Argument validation
# --------------------------------------------------------------------------- #

usage() {
    echo "Usage: sudo bash scripts/setup-tls.sh <domain> <email>"
    echo "  domain  — fully-qualified domain name pointing to this server"
    echo "  email   — contact address for Let's Encrypt expiry notices"
    exit 1
}

[[ $# -eq 2 ]] || usage
DOMAIN="$1"
EMAIL="$2"

# Basic validation
[[ "${DOMAIN}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]] \
    || die "Invalid domain name: ${DOMAIN}"
[[ "${EMAIL}" =~ ^[^@]+@[^@]+\.[^@]+$ ]] \
    || die "Invalid email address: ${EMAIL}"

CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
UNBOUND_CONF="/etc/unbound/unbound.conf"

# --------------------------------------------------------------------------- #
# Pre-flight checks
# --------------------------------------------------------------------------- #

preflight() {
    log "Pre-flight checks..."

    command -v certbot   &>/dev/null || die "certbot not found. Run deploy.sh first."
    command -v ufw       &>/dev/null || die "ufw not found. Run deploy.sh first."
    command -v unbound   &>/dev/null || die "unbound not found. Run deploy.sh first."
    [[ -f "${UNBOUND_CONF}" ]]       || die "Unbound config not found: ${UNBOUND_CONF}"

    # Confirm the domain resolves to this host's public IP
    local server_ip
    server_ip="$(curl -sf --max-time 5 https://api.ipify.org || echo 'unknown')"
    local domain_ip
    domain_ip="$(dig +short "${DOMAIN}" A | tail -1 || echo 'unknown')"

    if [[ "${server_ip}" == "unknown" || "${domain_ip}" == "unknown" ]]; then
        warn "Could not verify DNS: server IP=${server_ip}, ${DOMAIN}=${domain_ip}"
        warn "Proceeding anyway — certbot will report if the domain is unreachable."
    elif [[ "${server_ip}" != "${domain_ip}" ]]; then
        warn "${DOMAIN} resolves to ${domain_ip}, but this server's IP is ${server_ip}."
        warn "The ACME challenge will fail if the domain does not point here."
        read -rp "Continue anyway? [y/N] " confirm
        [[ "${confirm}" =~ ^[Yy]$ ]] || die "Aborted."
    else
        log "Domain ${DOMAIN} correctly resolves to ${server_ip}."
    fi

    log "Pre-flight checks passed."
}

# --------------------------------------------------------------------------- #
# Step 1 — Obtain TLS certificate
# --------------------------------------------------------------------------- #

obtain_certificate() {
    log "Obtaining TLS certificate for ${DOMAIN}..."

    # Open port 80 temporarily for the ACME HTTP-01 challenge
    log "Opening port 80 temporarily for ACME challenge..."
    ufw allow 80/tcp comment 'ACME HTTP-01 challenge (temporary)'

    # Run certbot; port 80 is closed in a trap even if certbot fails
    trap 'log "Closing port 80..."; ufw delete allow 80/tcp 2>/dev/null || true' EXIT

    certbot certonly \
        --standalone \
        --preferred-challenges http \
        --non-interactive \
        --agree-tos \
        --email "${EMAIL}" \
        -d "${DOMAIN}"

    # Close port 80 now (trap also fires, but being explicit is cleaner)
    log "Closing port 80..."
    ufw delete allow 80/tcp 2>/dev/null || true
    trap - EXIT

    [[ -f "${CERT_DIR}/fullchain.pem" ]] \
        || die "Certificate not found after certbot run: ${CERT_DIR}/fullchain.pem"

    log "Certificate obtained: ${CERT_DIR}"
}

# --------------------------------------------------------------------------- #
# Step 2 — Enable DoT in Unbound configuration
# --------------------------------------------------------------------------- #

enable_dot() {
    log "Enabling DNS over TLS in Unbound configuration..."

    # Create a timestamped backup before modifying; store exact filename for
    # safe restore if validation fails
    local backup_ts
    backup_ts="${UNBOUND_CONF}.bak.$(date +%Y%m%d%H%M%S)"
    cp "${UNBOUND_CONF}" "${backup_ts}"

    # Uncomment the DoT interface directive
    sed -i "s|^    # interface: 0\.0\.0\.0@853$|    interface: 0.0.0.0@853|" \
        "${UNBOUND_CONF}"

    # Uncomment and populate the TLS certificate directives
    sed -i "s|^    # tls-service-key: .*$|    tls-service-key: \"${CERT_DIR}/privkey.pem\"|" \
        "${UNBOUND_CONF}"
    sed -i "s|^    # tls-service-pem: .*$|    tls-service-pem: \"${CERT_DIR}/fullchain.pem\"|" \
        "${UNBOUND_CONF}"
    sed -i "s|^    # tls-min-version: .*$|    tls-min-version: \"TLSv1.2\"|" \
        "${UNBOUND_CONF}"

    # Verify the patched configuration is syntactically valid
    if unbound-checkconf "${UNBOUND_CONF}"; then
        log "Unbound configuration validated."
    else
        warn "Unbound config validation failed — restoring backup."
        cp "${backup_ts}" "${UNBOUND_CONF}" 2>/dev/null || true
        die "DoT activation aborted. Fix the configuration manually."
    fi

    # Reload Unbound to apply the changes
    systemctl reload unbound
    log "Unbound reloaded with DoT on port 853."
}

# --------------------------------------------------------------------------- #
# Step 3 — Install automatic certificate renewal cron job
# --------------------------------------------------------------------------- #

install_renewal_cron() {
    log "Installing certificate auto-renewal cron job..."

    cat > /etc/cron.d/certbot-renew-unbound <<CRON
# Renew Let's Encrypt certificates daily; reload Unbound on success
# Added by scripts/setup-tls.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
0 3 * * * root certbot renew --quiet --deploy-hook "systemctl reload unbound"
CRON

    chmod 644 /etc/cron.d/certbot-renew-unbound
    log "Cron job installed at /etc/cron.d/certbot-renew-unbound"
}

# --------------------------------------------------------------------------- #
# Step 4 — Verify DoT is working
# --------------------------------------------------------------------------- #

verify_dot() {
    log "Verifying DoT on port 853..."

    # Give Unbound a moment to bind the new socket
    sleep 2

    if command -v kdig &>/dev/null; then
        if kdig -d @127.0.0.1 +tls-ca +tls-host="${DOMAIN}" \
                www.google.com A &>/dev/null; then
            log "DoT verified successfully via kdig."
        else
            warn "kdig DoT test failed — check Unbound logs: journalctl -u unbound -n 50"
        fi
    else
        # Fall back to openssl s_client
        if echo | openssl s_client -connect "127.0.0.1:853" \
                -servername "${DOMAIN}" &>/dev/null 2>&1; then
            log "TLS handshake on port 853 successful."
        else
            warn "TLS handshake test failed — check Unbound logs: journalctl -u unbound -n 50"
        fi
    fi
}

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

print_summary() {
    cat <<SUMMARY

${GREEN}=============================================================
  DoT setup complete!
=============================================================${NC}

  Domain  : ${DOMAIN}
  Cert dir: ${CERT_DIR}
  DoT port: 853 (active)

Test from your Qingdao client:
  # Using kdig (knot-dnsutils)
  kdig -d @<SERVER_IP> +tls-ca +tls-host=${DOMAIN} www.google.com

  # Using systemd-resolved
  resolvectl query --protocol=dot --server=<SERVER_IP> www.google.com

Configure your DNS client:
  - Android 9+:  Private DNS → ${DOMAIN}
  - iOS 14+:     Settings → General → VPN & Device Management → DNS
  - Windows:     PowerShell: Add-DnsClientDohServerAddress ...
  - Linux (systemd-resolved):  DNS=${DOMAIN}  DNSOverTLS=yes

Certificate renewal:
  Automatic renewal runs daily at 03:00 UTC via cron.
  Manual renewal: certbot renew --deploy-hook "systemctl reload unbound"

SUMMARY
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

main() {
    require_root

    log "Starting DoT setup for ${DOMAIN} on $(hostname) at $(date -u)"

    preflight
    obtain_certificate
    enable_dot
    install_renewal_cron
    verify_dot

    print_summary
}

main "$@"
