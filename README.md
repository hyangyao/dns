# Public DNS Server Deployment Guide

> **Target:** Azure B2ast (2 vCPU / 1 GB RAM) — Japan East region  
> **Client Location:** Qingdao, China  
> **Stack:** Unbound + DoT/DoH + UFW + fail2ban + auditd  
> **Compliance:** CIS Benchmarks (Ubuntu 22.04) · PCI-DSS v4.0

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [Phase 1 — System Security Hardening (CIS / PCI-DSS)](#3-phase-1--system-security-hardening)
4. [Phase 2 — Network & Kernel Optimization](#4-phase-2--network--kernel-optimization)
5. [Phase 3 — Unbound DNS Configuration](#5-phase-3--unbound-dns-configuration)
6. [Phase 4 — DoT / DoH Setup](#6-phase-4--dot--doh-setup)
7. [Phase 5 — Automated Deployment](#7-phase-5--automated-deployment)
8. [Phase 6 — Verification & Compliance Checklist](#8-phase-6--verification--compliance-checklist)
9. [Memory & Resource Reference](#9-memory--resource-reference)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Architecture Overview

```
Qingdao Client
     │
     │  Encrypted tunnel (DoT :853 / DoH :443)
     ▼
Azure Japan East — B2ast VM (2 vCPU / 1 GB RAM)
┌─────────────────────────────────────────────────┐
│  UFW Firewall  (22/tcp · 53/tcp+udp · 853/tcp · 443/tcp)
│  ┌───────────────────────────────────────────┐  │
│  │  Unbound (recursive resolver)             │  │
│  │  · 2 threads (one per vCPU)               │  │
│  │  · msg-cache 64 MB + rrset-cache 128 MB   │  │
│  │  · QNAME minimisation (privacy)           │  │
│  │  · DNSSEC validation                      │  │
│  │  · Rate-limit 1000 QPS (anti-amplification│  │
│  └───────────────────────────────────────────┘  │
│  fail2ban · auditd · AppArmor                   │
└─────────────────────────────────────────────────┘
     │
     ▼  Plain UDP/TCP (inside Azure datacenter)
  Root servers / TLD servers / Authoritative servers
```

### Why this stack?

| Concern | Solution |
|---|---|
| Cross-border DNS poisoning | DoT (port 853) encrypts the query end-to-end |
| 1 GB RAM OOM risk | Unbound cache strictly capped at ~192 MB total |
| High latency (China–Japan) | BBR congestion control + UDP buffer tuning |
| CIS Benchmark compliance | SSH hardening, UFW, auditd, AppArmor |
| PCI-DSS logging requirement | auditd rules, syslog forwarding, log-queries |
| DNS amplification attacks | Rate-limiting + access-control ACLs |

---

## 2. Prerequisites

- **OS:** Ubuntu 22.04 LTS (recommended) or Ubuntu 24.04 LTS
- **Inbound ports** opened in the **Azure Network Security Group**:
  - TCP 22 (SSH)
  - TCP/UDP 53 (DNS)
  - TCP 853 (DNS over TLS)
  - TCP 443 (DNS over HTTPS)
- A **domain name** pointing to the VM's public IP (required for TLS certificate)
- Root / sudo access

---

## 3. Phase 1 — System Security Hardening

### 3.1 System update & package installation

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y \
    unbound \
    ufw \
    fail2ban \
    auditd \
    apparmor-profiles \
    certbot \
    curl \
    jq
```

### 3.2 SSH hardening (CIS Section 5.2)

Edit `/etc/ssh/sshd_config`:

```text
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 0
AllowTcpForwarding no
Banner /etc/issue.net
```

```bash
sudo systemctl restart sshd
```

### 3.3 UFW Firewall rules (CIS 3.5 / PCI-DSS Req. 1)

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp        # SSH
sudo ufw allow 53/tcp        # DNS (TCP)
sudo ufw allow 53/udp        # DNS (UDP)
sudo ufw allow 853/tcp       # DoT
sudo ufw allow 443/tcp       # DoH
sudo ufw enable
```

> **PCI-DSS Req 1.3:** Only allow ports explicitly required for business purposes. Remove any other rules.

### 3.4 fail2ban configuration

```bash
# /etc/fail2ban/jail.local
sudo tee /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
backend = %(syslog_backend)s
EOF

sudo systemctl enable --now fail2ban
```

### 3.5 auditd rules (PCI-DSS Req. 10)

```bash
sudo tee /etc/audit/rules.d/dns-server.rules <<'EOF'
# Monitor Unbound configuration changes
-w /etc/unbound/ -p wa -k dns_config_changes

# Monitor identity files
-w /etc/passwd -p wa -k identity_changes
-w /etc/shadow -p wa -k identity_changes
-w /etc/group  -p wa -k identity_changes

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor sudo usage
-w /etc/sudoers -p wa -k sudoers_changes
-a always,exit -F arch=b64 -S execve -F uid=0 -k root_commands

# Monitor network configuration
-w /etc/sysctl.conf -p wa -k sysctl_changes
-w /etc/sysctl.d/   -p wa -k sysctl_changes
EOF

sudo systemctl enable --now auditd
sudo augenrules --load
```

---

## 4. Phase 2 — Network & Kernel Optimization

Apply the sysctl settings from `config/99-dns-optimize.conf`:

```bash
sudo cp config/99-dns-optimize.conf /etc/sysctl.d/99-dns-optimize.conf
sudo sysctl -p /etc/sysctl.d/99-dns-optimize.conf
```

Key parameters explained:

| Parameter | Value | Reason |
|---|---|---|
| `tcp_congestion_control` | `bbr` | Reduces latency & improves throughput on lossy China–Japan cross-border links |
| `default_qdisc` | `fq` | Required companion queue for BBR |
| `rmem_max` / `wmem_max` | `4194304` (4 MB) | Larger UDP receive buffer prevents DNS query drops under burst load |
| `tcp_syncookies` | `1` | Mitigates SYN flood attacks (CIS 3.3.2) |
| `disable_ipv6` | `1` | Reduces attack surface (only if IPv6 is unused) |
| `ip_forward` | `0` | Prevents the VM from acting as a router (PCI-DSS Req. 1) |

---

## 5. Phase 3 — Unbound DNS Configuration

Apply the configuration from `config/unbound.conf`:

```bash
# Backup original
sudo cp /etc/unbound/unbound.conf /etc/unbound/unbound.conf.bak

# Install the optimized configuration
sudo cp config/unbound.conf /etc/unbound/unbound.conf

# Download root hints
sudo curl -sSo /var/lib/unbound/root.hints \
    https://www.internic.net/domain/named.cache

# Verify configuration
sudo unbound-checkconf /etc/unbound/unbound.conf

# Enable and start
sudo systemctl enable --now unbound
```

### Memory budget breakdown (1 GB RAM)

| Component | Allocation |
|---|---|
| OS kernel + system processes | ~300 MB |
| Unbound msg-cache | 64 MB |
| Unbound rrset-cache | 128 MB |
| Unbound key-cache + infra-cache | ~16 MB |
| Unbound threads + overhead | ~32 MB |
| fail2ban + auditd + sshd | ~50 MB |
| **Total** | **~590 MB** |
| **Safety headroom** | **~410 MB** |

This allocation ensures no OOM kills under normal recursive resolver workload.

### Thread & slab tuning (2 vCPUs)

```
num-threads: 2          # One thread per vCPU
msg-cache-slabs: 2      # Must be a power of 2, >= num-threads
rrset-cache-slabs: 2
infra-cache-slabs: 2
key-cache-slabs: 2
```

Slabs partition cache structures to reduce lock contention between threads.

### Security settings

| Setting | Value | Standard |
|---|---|---|
| `hide-identity` | `yes` | CIS DNS 2.1 |
| `hide-version` | `yes` | CIS DNS 2.1 |
| `qname-minimisation` | `yes` | RFC 7816, privacy |
| `harden-glue` | `yes` | Prevents cache poisoning |
| `harden-dnssec-stripped` | `yes` | DNSSEC integrity |
| `use-caps-for-id` | `yes` | 0x20 encoding anti-spoofing |
| `ratelimit` | `1000` | Anti-amplification (PCI-DSS Req. 6) |

---

## 6. Phase 4 — DoT / DoH Setup

### 6.1 Obtain a TLS certificate (Let's Encrypt)

```bash
# Replace dns.example.com with your actual domain
sudo certbot certonly --standalone \
    --preferred-challenges http \
    -d dns.example.com \
    --agree-tos \
    --email admin@example.com
```

### 6.2 Configure Unbound for DoT (port 853)

Edit `config/unbound.conf` and replace the placeholder paths:

```text
# Interface already listens on port 853 via: interface: 0.0.0.0@853
tls-service-key: "/etc/letsencrypt/live/dns.example.com/privkey.pem"
tls-service-pem: "/etc/letsencrypt/live/dns.example.com/fullchain.pem"
```

Then reload Unbound:

```bash
sudo systemctl reload unbound
```

### 6.3 DoH via nginx reverse proxy (optional)

```bash
sudo apt install -y nginx
sudo tee /etc/nginx/sites-available/doh <<'EOF'
server {
    listen 443 ssl http2;
    server_name dns.example.com;

    ssl_certificate     /etc/letsencrypt/live/dns.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dns.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location /dns-query {
        proxy_pass       http://127.0.0.1:8053;
        proxy_set_header Host $host;
        add_header       Strict-Transport-Security "max-age=31536000" always;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/doh /etc/nginx/sites-enabled/doh
sudo nginx -t && sudo systemctl reload nginx
```

### 6.4 Certificate auto-renewal

```bash
sudo tee /etc/cron.d/certbot-renew <<'EOF'
0 3 * * * root certbot renew --quiet --deploy-hook "systemctl reload unbound nginx"
EOF
```

---

## 7. Phase 5 — Automated Deployment

The `scripts/deploy.sh` script automates all phases above.

```bash
# Clone the repository on the target VM
git clone --depth 1 https://github.com/hyangyao/dns.git
cd dns

# Make the script executable
chmod +x scripts/deploy.sh

# Run as root (or with sudo)
sudo bash scripts/deploy.sh
```

The script will:
1. Update the system and install all required packages
2. Apply sysctl network optimizations (BBR, buffer tuning)
3. Configure UFW firewall rules
4. Harden SSH configuration
5. Set up auditd rules
6. Install and configure Unbound
7. Enable fail2ban

> **Note:** After the script completes, manually replace the TLS certificate placeholder paths in `/etc/unbound/unbound.conf` with your actual Let's Encrypt certificate paths, then run `sudo systemctl reload unbound`.

---

## 8. Phase 6 — Verification & Compliance Checklist

### Functional tests

```bash
# Test plain DNS resolution (from the VM itself)
dig @127.0.0.1 www.google.com A

# Test DNSSEC validation
dig @127.0.0.1 sigfail.verteiltesysteme.net A
# Expect: SERVFAIL (DNSSEC failure caught)

# Test from Qingdao client (DoT)
kdig -d @<VM_PUBLIC_IP> +tls-ca +tls-host=dns.example.com www.google.com

# Test rate limiting (should receive REFUSED after threshold)
for i in $(seq 1 1100); do dig @127.0.0.1 test${i}.example.com; done
```

### Security checks

```bash
# Verify Unbound hides version info
dig @127.0.0.1 version.bind chaos txt
# Expect: REFUSED or empty answer

# Confirm firewall rules
sudo ufw status verbose

# Check auditd is running
sudo systemctl status auditd
sudo ausearch -k dns_config_changes

# Verify BBR is active
sysctl net.ipv4.tcp_congestion_control
# Expect: net.ipv4.tcp_congestion_control = bbr

# Check fail2ban status
sudo fail2ban-client status sshd
```

### CIS / PCI-DSS compliance checklist

| Control | Requirement | Status |
|---|---|---|
| CIS 1.1 | Filesystem partitions configured | Manual |
| CIS 3.3.2 | TCP syncookies enabled | ✅ `sysctl` |
| CIS 3.5 | Firewall configured (UFW) | ✅ `deploy.sh` |
| CIS 5.2 | SSH hardened | ✅ `deploy.sh` |
| CIS 6.2 | Packages up to date | ✅ `deploy.sh` |
| PCI-DSS Req. 1 | Firewall rules documented & minimal | ✅ UFW |
| PCI-DSS Req. 2 | No vendor defaults (version hidden) | ✅ Unbound |
| PCI-DSS Req. 6 | Protect against known vulnerabilities | ✅ Rate-limit |
| PCI-DSS Req. 8 | Unique IDs, MFA (SSH key auth) | ✅ SSH config |
| PCI-DSS Req. 10 | Audit log all access | ✅ auditd |

---

## 9. Memory & Resource Reference

### Unbound cache size formula

```
rrset-cache-size  = Total_DNS_cache_budget × 0.67
msg-cache-size    = Total_DNS_cache_budget × 0.33

For 1 GB RAM:
  Total_DNS_cache_budget ≈ 192 MB
  rrset-cache-size = 128 MB
  msg-cache-size   =  64 MB
```

### Monitoring commands

```bash
# Live Unbound statistics
sudo unbound-control stats_noreset | grep -E 'total|cache'

# Memory usage
free -h
ps aux --sort=-%mem | head -10

# DNS query rate
sudo unbound-control stats_noreset | grep 'num.queries'
```

---

## 10. Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Unbound fails to start | Config syntax error | `sudo unbound-checkconf` |
| High memory usage | Cache sizes too large | Reduce `rrset-cache-size` to 64m |
| DNS resolution slow | BBR not active | `sysctl net.ipv4.tcp_congestion_control` |
| Queries refused from Qingdao | access-control ACL | Add your IP/CIDR to `access-control: X.X.X.X/24 allow` |
| DoT not working | Missing/expired TLS cert | `certbot renew && systemctl reload unbound` |
| SSH connection dropped | fail2ban ban | `sudo fail2ban-client set sshd unbanip <your-ip>` |

---

## File Structure

```
dns/
├── README.md                    # This guide
├── config/
│   ├── unbound.conf             # Unbound optimized configuration
│   └── 99-dns-optimize.conf     # Sysctl network optimization
└── scripts/
    └── deploy.sh                # Automated deployment script
```

---

*Licensed under MIT. Contributions welcome.*