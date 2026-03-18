# Public DNS Server Deployment Guide

> **Target:** Azure B2ast (2 vCPU / 1 GB RAM) — Japan East region  
> **Client Location:** Qingdao, China  
> **Stack:** Unbound + DoT (port 853) + UFW + fail2ban + auditd  
> **Compliance:** CIS Benchmarks (Ubuntu 22.04) · PCI-DSS v4.0  
> **Nginx:** Install separately with OWASP ModSecurity CRS for the DoH reverse proxy

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [Quick Start — Automated Deployment](#3-quick-start--automated-deployment)
4. [Phase 1 — System Security Hardening](#4-phase-1--system-security-hardening)
5. [Phase 2 — UFW Firewall (runs before sysctl)](#5-phase-2--ufw-firewall)
6. [Phase 3 — Network & Kernel Optimisation](#6-phase-3--network--kernel-optimisation)
7. [Phase 4 — Unbound DNS Configuration](#7-phase-4--unbound-dns-configuration)
8. [Phase 5 — DNS over TLS Setup](#8-phase-5--dns-over-tls-setup)
9. [Phase 6 — Verification & Compliance Checklist](#9-phase-6--verification--compliance-checklist)
10. [Memory & Resource Reference](#10-memory--resource-reference)
11. [Troubleshooting](#11-troubleshooting)
12. [File Structure](#12-file-structure)

---

## 1. Architecture Overview

```
Qingdao Client
     │
     │  Encrypted DoT (TCP :853)  ─── or ───  DoH via Nginx (:443 + OWASP CRS)
     ▼
Azure Japan East — B2ast VM (2 vCPU / 1 GB RAM)
┌──────────────────────────────────────────────────────────┐
│  UFW Firewall  (22/tcp · 53/tcp+udp · 853/tcp · 443/tcp) │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Unbound (recursive resolver)                      │  │
│  │  · 2 threads (one per vCPU)                       │  │
│  │  · msg-cache 64 MB + rrset-cache 128 MB           │  │
│  │  · QNAME minimisation (privacy, RFC 7816)         │  │
│  │  · DNSSEC validation                              │  │
│  │  · Rate-limit 1000 QPS/zone (anti-amplification)  │  │
│  │  · Serve-expired 1 h (China–Japan resilience)     │  │
│  └────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐ │
│  │  Nginx + OWASP ModSecurity CRS (user-installed)     │ │
│  │  Reverse proxy for DNS over HTTPS (:443 → :8053)   │ │
│  └──────────────────────────────────────────────────────┘ │
│  fail2ban · auditd · AppArmor                            │
└──────────────────────────────────────────────────────────┘
     │
     │  Plain UDP/TCP (inside Azure datacenter)
     ▼
  Root / TLD / Authoritative servers
```

### Why this stack?

| Concern | Solution |
|---|---|
| Cross-border DNS poisoning | DoT (port 853) end-to-end encryption; Nginx DoH with OWASP CRS |
| 1 GB RAM OOM risk | Unbound cache strictly capped at ~192 MB total; `vm.overcommit_memory=0` |
| High latency (China–Japan) | BBR congestion control + UDP/TCP buffer tuning |
| CIS Benchmark compliance | SSH hardening, UFW, auditd, AppArmor, sysctl hardening |
| PCI-DSS logging requirement | auditd rules, syslog forwarding, `log-queries: yes` |
| DNS amplification attacks | Rate-limiting (1000 QPS/zone, 100 QPS/IP) + access-control ACLs |
| nf_conntrack sysctl ordering | UFW enabled **before** sysctl so module is loaded when keys apply |

---

## 2. Prerequisites

- **OS:** Ubuntu 22.04 LTS (kernel 5.15, Unbound ≥ 1.13)
- **Azure NSG inbound rules** — open before deploying:

  | Port | Protocol | Purpose |
  |------|----------|---------|
  | 22 | TCP | SSH management |
  | 53 | TCP + UDP | Plain DNS |
  | 853 | TCP | DNS over TLS (DoT) |
  | 443 | TCP | DNS over HTTPS via Nginx (DoH) |
  | 80 | TCP | ACME HTTP-01 challenge (temporary, during `setup-tls.sh`) |

- A **domain name** with an A record pointing to the VM's public IP (required for TLS)
- Root / sudo access
- SSH public key authentication configured **before** running `deploy.sh`
  (password auth will be disabled by the script)

---

## 3. Quick Start — Automated Deployment

```bash
# 1. Clone the repository on the target VM
git clone --depth 1 https://github.com/hyangyao/dns.git
cd dns

# 2. Full deployment: packages, UFW, sysctl, SSH, auditd, Unbound, fail2ban
sudo bash scripts/deploy.sh

# 3. Whitelist your client IP in Unbound
sudo nano /etc/unbound/unbound.conf
# Uncomment and set: access-control: <YOUR_IP>/32 allow
sudo systemctl reload unbound

# 4. Enable DNS over TLS (requires a domain pointing to this server)
sudo bash scripts/setup-tls.sh dns.example.com admin@example.com

# 5. Verify the full deployment
sudo bash scripts/health-check.sh
```

> **Nginx + OWASP CRS (DoH):** Install Nginx and OWASP ModSecurity Core Rule Set
> separately. See [Phase 5 §5.3](#53-doh-via-nginx-reference-config) for the
> reverse-proxy configuration reference.

---

## 4. Phase 1 — System Security Hardening

### 4.1 Packages installed by deploy.sh

| Package | Purpose |
|---------|---------|
| `unbound` | Recursive DNS resolver |
| `ufw` | Uncomplicated firewall |
| `fail2ban` | Brute-force protection |
| `auditd` | Kernel-level audit logging (PCI-DSS Req. 10) |
| `apparmor-profiles` | Mandatory access control |
| `certbot` | Let's Encrypt TLS certificate management |
| `dnsutils` | `dig`, `nslookup` for verification |
| `curl`, `jq` | Utilities used by scripts |

### 4.2 SSH hardening (CIS Section 5.2 / PCI-DSS Req. 8)

Written to `/etc/ssh/sshd_config.d/99-hardened.conf`:

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
```

The script validates with `sshd -t` before restarting to prevent lockouts.

> ⚠️ Ensure your SSH public key is in `~/.ssh/authorized_keys` **before** running
> `deploy.sh` — password authentication will be permanently disabled.

### 4.3 auditd rules (PCI-DSS Req. 10)

Written to `/etc/audit/rules.d/dns-server.rules`:

| Rule | Trigger |
|------|---------|
| `-w /etc/unbound/ -p wa` | Any write or attribute change to Unbound config |
| `-w /etc/passwd -p wa` | Identity file changes |
| `-w /etc/ssh/sshd_config -p wa` | SSH configuration changes |
| `-w /etc/sudoers -p wa` | Privilege escalation config changes |
| `-a always,exit … execve uid=0` | Every root command execution |

### 4.4 fail2ban (PCI-DSS Req. 8)

```ini
[DEFAULT]
bantime  = 3600    # 1-hour ban
findtime = 600     # 10-minute detection window
maxretry = 5       # 5 failures triggers a ban

[sshd]
enabled = true
```

---

## 5. Phase 2 — UFW Firewall

> **Ordering note:** `deploy.sh` enables UFW **before** applying sysctl settings.
> UFW's activation loads the `nf_conntrack` netfilter module into the kernel.
> The `net.netfilter.nf_conntrack_*` sysctl keys in `99-dns-optimize.conf`
> require this module to be present — applying them before UFW causes errors.

Rules applied by `deploy.sh`:

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH
ufw allow 53/tcp    # DNS TCP
ufw allow 53/udp    # DNS UDP
ufw allow 853/tcp   # DoT
ufw allow 443/tcp   # DoH (Nginx)
ufw enable
```

> **PCI-DSS Req. 1.3:** Only ports explicitly required for business purposes are
> opened. Remove any rules added by cloud provider defaults.

---

## 6. Phase 3 — Network & Kernel Optimisation

Applied automatically by `deploy.sh` from `config/99-dns-optimize.conf`:

| Parameter | Value | Reason |
|---|---|---|
| `tcp_congestion_control` | `bbr` | Reduces latency on lossy China–Japan links (1–5% packet loss) |
| `default_qdisc` | `fq` | Required companion queue discipline for BBR |
| `rmem_max` / `wmem_max` | `4 MB` | Matches Unbound `so-rcvbuf`/`so-sndbuf`; prevents DNS query drops |
| `tcp_syncookies` | `1` | SYN flood mitigation (CIS 3.3.2) |
| `ip_forward` | `0` | Prevents routing/amplification attacks (PCI-DSS Req. 1) |
| `disable_ipv6` | `1` | Reduces attack surface (CIS 3.1.1); re-enable if needed |
| `nf_conntrack_max` | `131072` | Prevents "table full" drops under high DNS UDP query load |
| `vm.swappiness` | `10` | Strongly prefers RAM over swap |
| `vm.overcommit_memory` | `0` | Heuristic mode — rejects unserviceable allocations on 1 GB host |

---

## 7. Phase 4 — Unbound DNS Configuration

### Memory budget (1 GB RAM)

| Component | Allocation |
|---|---|
| OS kernel + system services | ~300 MB |
| Unbound `msg-cache-size` | 64 MB |
| Unbound `rrset-cache-size` | 128 MB |
| Unbound `key-cache-size` + infra-cache | ~20 MB |
| Unbound threads + overhead | ~32 MB |
| fail2ban + auditd + sshd | ~50 MB |
| **Total used** | **~594 MB** |
| **Safety headroom** | **~406 MB** |

### Thread & slab tuning (2 vCPUs)

```
num-threads: 2          # one thread per vCPU
msg-cache-slabs: 2      # power of 2 ≥ num-threads; reduces mutex contention
rrset-cache-slabs: 2
infra-cache-slabs: 2
key-cache-slabs: 2
```

### Security settings

| Setting | Value | Standard |
|---|---|---|
| `hide-identity` | `yes` | CIS DNS 2.1 — prevents fingerprinting |
| `hide-version` | `yes` | CIS DNS 2.1 — prevents version enumeration |
| `qname-minimisation` | `yes` | RFC 7816 — minimises upstream query data |
| `harden-glue` | `yes` | Prevents cache poisoning via glue records |
| `harden-dnssec-stripped` | `yes` | Rejects responses stripping DNSSEC signatures |
| `harden-below-nxdomain` | `yes` | RFC 8020 — NXDOMAIN cut for subdomains |
| `harden-algo-downgrade` | `yes` | Prevents DNSSEC algorithm downgrade attacks |
| `use-caps-for-id` | `yes` | 0x20 encoding — Kaminsky attack mitigation |
| `ratelimit` | `1000` | Anti-amplification per zone (PCI-DSS Req. 6) |
| `ip-ratelimit` | `100` | Anti-amplification per client IP |
| `do-ip6` | `no` | Disabled to match sysctl; re-enable if IPv6 needed |

> **Note on `harden-referral-path`:** Intentionally **not** enabled. It causes
> false DNSSEC failures on legitimate domains whose NS referral paths are
> unsigned — common with large CDN and cloud providers.

### Access control

The default config refuses all external sources. Add your client IP:

```bash
# Edit /etc/unbound/unbound.conf:
access-control: 1.2.3.4/32 allow    # your Qingdao IP

sudo systemctl reload unbound
```

### Remote control (Unix socket — no key files needed)

```bash
sudo unbound-control stats_noreset
sudo unbound-control reload
sudo unbound-control flush_zone example.com
```

---

## 8. Phase 5 — DNS over TLS Setup

### 5.1 Automated (recommended)

```bash
sudo bash scripts/setup-tls.sh dns.example.com admin@example.com
```

This script: opens port 80 temporarily → runs `certbot --standalone` → closes
port 80 → patches `unbound.conf` to activate DoT → validates and reloads Unbound
→ installs a daily renewal cron job.

### 5.2 Manual DoT setup

```bash
# 1. Obtain certificate (port 80 must be reachable)
sudo ufw allow 80/tcp
sudo certbot certonly --standalone --non-interactive --agree-tos \
    --email admin@example.com -d dns.example.com
sudo ufw delete allow 80/tcp

# 2. In /etc/unbound/unbound.conf, uncomment:
#    interface: 0.0.0.0@853
#    tls-service-key: "/etc/letsencrypt/live/dns.example.com/privkey.pem"
#    tls-service-pem: "/etc/letsencrypt/live/dns.example.com/fullchain.pem"
#    tls-min-version: "TLSv1.2"

# 3. Validate and reload
sudo unbound-checkconf /etc/unbound/unbound.conf
sudo systemctl reload unbound
```

### 5.3 DoH via Nginx reference config

Install Nginx with OWASP ModSecurity CRS separately, then use:

```nginx
# /etc/nginx/sites-available/doh
server {
    listen 443 ssl http2;
    server_name dns.example.com;

    ssl_certificate     /etc/letsencrypt/live/dns.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dns.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;

    # Proxy DoH to Unbound's DoH listener (configure Unbound on 127.0.0.1:8053)
    location /dns-query {
        proxy_pass       http://127.0.0.1:8053;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_http_version 1.1;
        proxy_read_timeout 30s;
    }
}
```

### 5.4 Certificate auto-renewal

`setup-tls.sh` installs `/etc/cron.d/certbot-renew-unbound`:

```cron
0 3 * * * root certbot renew --quiet --deploy-hook "systemctl reload unbound"
```

---

## 9. Phase 6 — Verification & Compliance Checklist

### Automated health check

```bash
sudo bash scripts/health-check.sh
```

Verifies: Unbound status · DNS resolution · DNSSEC validation · version hiding ·
access-control · UFW rules · fail2ban · auditd · SSH hardening · BBR · memory
budget · DoT listener · DNSSEC trust anchor freshness.

### Manual functional tests

```bash
# Plain DNS resolution
dig @127.0.0.1 www.google.com A

# DNSSEC validation (expect SERVFAIL — bad signature caught)
dig @127.0.0.1 sigfail.verteiltesysteme.net A

# Version hiding (expect empty or REFUSED)
dig @127.0.0.1 version.bind chaos txt

# DoT from Qingdao client
kdig -d @<VM_PUBLIC_IP> +tls-ca +tls-host=dns.example.com www.google.com

# Unbound statistics
sudo unbound-control stats_noreset | grep -E 'total|cache|num'

# BBR confirmation
sysctl net.ipv4.tcp_congestion_control
```

### CIS / PCI-DSS compliance matrix

| Control | Requirement | Implemented by |
|---|---|---|
| CIS 3.3.2 | TCP syncookies enabled | `99-dns-optimize.conf` |
| CIS 3.5 | Host firewall configured | UFW in `deploy.sh` |
| CIS 5.2 | SSH hardened | `deploy.sh` phase 4 |
| CIS 6.2 | Packages up-to-date | `deploy.sh` phase 1 |
| CIS DNS 2.1 | Server version/identity hidden | `unbound.conf` |
| PCI-DSS Req. 1 | Firewall rules documented & minimal | UFW in `deploy.sh` |
| PCI-DSS Req. 2 | No vendor defaults | `unbound.conf` |
| PCI-DSS Req. 4 | TLS 1.2+ in transit | DoT `tls-min-version: "TLSv1.2"` |
| PCI-DSS Req. 6 | Protect against attacks (rate-limit) | `unbound.conf` |
| PCI-DSS Req. 8 | Key-based auth, fail2ban | `deploy.sh` phases 4 & 7 |
| PCI-DSS Req. 10 | Audit all access | `auditd` + `log-queries: yes` |

---

## 10. Memory & Resource Reference

### Cache sizing formula

```
Total cache budget ≈ 19% of RAM
  rrset-cache-size = budget × 0.67  →  128 MB  (actual RR records)
  msg-cache-size   = budget × 0.33  →   64 MB  (full DNS responses)
  key-cache-size                    →   16 MB  (DNSSEC keys)
```

Upgrade to 2 GB? Safely double all three values.

### Monitoring

```bash
# Unbound stats
sudo unbound-control stats_noreset | grep -E 'total|cache|num'

# Memory overview
free -h && ps aux --sort=-%mem | head -5

# Audit log search
sudo ausearch -k dns_config_changes --start today
sudo ausearch -k root_commands --start today | tail -20
```

---

## 11. Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Unbound fails to start | Config syntax error | `sudo unbound-checkconf /etc/unbound/unbound.conf` |
| High memory usage | Cache sizes too large | Reduce `rrset-cache-size` to 64m, `msg-cache-size` to 32m |
| DNS queries refused | access-control ACL | `access-control: X.X.X.X/32 allow` in `unbound.conf` |
| DNS resolution slow | BBR not active | `sysctl net.ipv4.tcp_congestion_control` → should be `bbr` |
| DoT not working | Missing/expired TLS cert | `sudo bash scripts/setup-tls.sh <domain> <email>` |
| SSH connection locked out | fail2ban ban | `sudo fail2ban-client set sshd unbanip <your-ip>` |
| `sysctl: nf_conntrack` errors | Module not loaded | Ensure UFW is enabled: `ufw status` |
| `unbound-control` fails | Socket not found | `sudo systemctl restart unbound` |
| DNSSEC SERVFAIL on valid domain | Clock skew | `sudo timedatectl set-ntp true` |
| Syslog filling disk | `log-queries: yes` on busy server | Set `log-queries: no` if disk space is limited |

---

## 12. File Structure

```
dns/
├── README.md                        # This guide
├── config/
│   ├── unbound.conf                 # Unbound: 1 GB RAM, 2 vCPU, CIS/PCI-DSS hardened
│   └── 99-dns-optimize.conf         # Sysctl: BBR, UDP buffers, nf_conntrack, OOM tuning
└── scripts/
    ├── deploy.sh                    # Full automated deployment (run first)
    ├── setup-tls.sh                 # Enable DNS over TLS after cert is provisioned
    └── health-check.sh             # Post-deployment verification & compliance check
```

---

*Licensed under MIT. Contributions welcome.*
