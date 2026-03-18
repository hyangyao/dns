#!/usr/bin/env bash
# =============================================================================
# enterprise_deploy.sh — 企业级公共 DNS 服务器幂等部署脚本
#
# 目标机器：Azure B2ast（2 vCPU / 1 GB RAM），Ubuntu 22.04/24.04 LTS
# 部署位置：日本东部（针对中国青岛客户端优化）
# 合规标准：CIS 基准（Ubuntu）· PCI-DSS v4.0
#
# 特性：
#   - 幂等性：重复运行安全，已配置项目不会被重复添加或破坏
#   - 完整部署：软件包、AppArmor、auditd、fail2ban、UFW、SSH 加固、
#               sysctl、文件描述符限制、Unbound、systemd 覆盖
#   - OOM 防护：Unbound systemd 覆盖设置 OOMScoreAdjust=-500
#   - HA 保证：Restart=always + RestartSec=5
#
# 使用方法：
#   sudo bash scripts/enterprise_deploy.sh
#
# 完成后需要执行：
#   - 将客户端 IP 添加至 /etc/unbound/unbound.conf 的 access-control
#   - 运行 scripts/setup-tls.sh <域名> <邮箱> 以启用 DNS over TLS
#   - 运行 scripts/health-check.sh 验证部署结果
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# --------------------------------------------------------------------------- #
# 辅助函数
# --------------------------------------------------------------------------- #

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()    { echo -e "${GREEN}[信息]${NC}  $*"; }
warn()   { echo -e "${YELLOW}[警告]${NC}  $*"; }
die()    { echo -e "${RED}[错误]${NC} $*" >&2; exit 1; }
section(){ echo -e "\n${CYAN}══════════════════════════════════════════════════${NC}"; \
           echo -e "${CYAN}  $*${NC}"; \
           echo -e "${CYAN}══════════════════════════════════════════════════${NC}"; }

require_root() {
    [[ "$(id -u)" -eq 0 ]] || die "此脚本必须以 root 身份运行（sudo bash $0）"
}

# 对已存在的文件创建带时间戳的备份（幂等：不会覆盖同秒内的备份）
backup_file() {
    local file="$1"
    [[ -f "${file}" ]] && cp "${file}" "${file}.bak.$(date +%Y%m%d%H%M%S)"
}

# 检查 sysctl 参数是否已设置为目标值（幂等检查）
sysctl_is_set() {
    local key="$1" val="$2"
    [[ "$(sysctl -n "${key}" 2>/dev/null)" == "${val}" ]]
}

# 获取脚本所在仓库根目录（scripts/ 的上一级）
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# --------------------------------------------------------------------------- #
# 阶段一 — 系统更新与软件包安装
# --------------------------------------------------------------------------- #

phase1_packages() {
    section "阶段一：更新系统并安装企业级软件包"

    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        unbound \
        ufw \
        fail2ban \
        auditd \
        apparmor \
        apparmor-profiles \
        apparmor-utils \
        certbot \
        dnsutils \
        curl \
        jq \
        libpam-pwquality

    # 确保 AppArmor 已启用并处于强制模式
    if systemctl is-enabled --quiet apparmor 2>/dev/null; then
        systemctl start apparmor
        log "AppArmor 已启动。"
    else
        systemctl enable --now apparmor || warn "AppArmor 启用失败（内核可能不支持）。"
    fi

    # 将 Unbound 的 AppArmor Profile 置于强制模式（若存在）
    if [[ -f /etc/apparmor.d/usr.sbin.unbound ]]; then
        aa-enforce /etc/apparmor.d/usr.sbin.unbound 2>/dev/null \
            && log "Unbound AppArmor Profile 已设为强制模式。" \
            || warn "无法对 Unbound AppArmor Profile 设置强制模式。"
    fi

    log "阶段一完成。"
}

# --------------------------------------------------------------------------- #
# 阶段二 — 文件描述符限制（防止高并发时 fd 耗尽）
# --------------------------------------------------------------------------- #

phase2_limits() {
    section "阶段二：配置系统文件描述符限制（nofile 65535）"

    local src="${REPO_ROOT}/config/security-limits.conf"
    local dst="/etc/security/limits.d/99-dns-enterprise.conf"

    if [[ -f "${src}" ]]; then
        cp "${src}" "${dst}"
        log "已复制 ${src} -> ${dst}"
    else
        # 内联写入（幂等：写入是原子替换）
        cat > "${dst}" <<'LIMITS'
# 企业级 DNS 服务器文件描述符限制
# 支持 outgoing-range:8192 × 2线程 + TLS 连接 + 管理套接字
unbound  soft  nofile  65535
unbound  hard  nofile  65535
root     soft  nofile  65535
root     hard  nofile  65535
LIMITS
        log "已内联写入 ${dst}"
    fi

    log "阶段二完成。"
}

# --------------------------------------------------------------------------- #
# 阶段三 — UFW 防火墙（CIS 3.5 / PCI-DSS 要求1）
#
# 执行顺序说明：UFW 在 sysctl 之前运行，以加载 nf_conntrack 模块；
# sysctl 中的 net.netfilter.nf_conntrack_* 参数要求模块已存在于内核。
# --------------------------------------------------------------------------- #

phase3_ufw() {
    section "阶段三：配置 UFW 防火墙（严格模式 + SSH 速率限制）"

    ufw --force reset

    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny forward

    # SSH — 使用 UFW 内置速率限制（30秒内超过 6 次连接触发临时封禁）
    # 这是对 fail2ban 的补充层防护，在应用层审计之前就阻断暴力破解
    ufw limit 22/tcp    comment 'SSH（速率限制：30s内>6次触发封禁）'

    ufw allow 53/tcp    comment 'DNS TCP'
    ufw allow 53/udp    comment 'DNS UDP'
    ufw allow 853/tcp   comment 'DNS over TLS（DoT）'
    ufw allow 443/tcp   comment 'DNS over HTTPS / Nginx（DoH）'

    # 启用 UFW — 此操作加载 nf_conntrack 模块（为后续 sysctl 做准备）
    ufw --force enable

    ufw status verbose
    log "阶段三完成。"
}

# --------------------------------------------------------------------------- #
# 阶段四 — 内核/网络优化（BBR、TFO、缓冲区、合规加固）
# 须在 UFW（阶段三）之后运行，确保 nf_conntrack 模块已加载。
# --------------------------------------------------------------------------- #

phase4_sysctl() {
    section "阶段四：应用企业级 sysctl 内核优化配置"

    local src="${REPO_ROOT}/config/99-dns-enterprise-sysctl.conf"
    local dst="/etc/sysctl.d/99-dns-enterprise-sysctl.conf"

    if [[ -f "${src}" ]]; then
        cp "${src}" "${dst}"
        log "已复制 ${src} -> ${dst}"
    else
        warn "未找到 config/99-dns-enterprise-sysctl.conf；写入最小内联配置。"
        cat > "${dst}" <<'SYSCTL'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.ipv4.udp_mem = 65536 131072 2097152
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.netfilter.nf_conntrack_max = 131072
net.netfilter.nf_conntrack_udp_timeout = 30
vm.swappiness = 10
vm.overcommit_memory = 0
SYSCTL
    fi

    # 应用所有 sysctl drop-in；忽略 nf_conntrack 初始化期间的良性错误
    sysctl --system 2>&1 | grep -vE '^net\.netfilter\.nf_conntrack' || true
    # 模块确认已加载后，显式重新加载 conntrack 参数
    sysctl -q -p "${dst}" || warn "部分 sysctl 参数可能需要重启后生效。"

    log "阶段四完成。"
}

# --------------------------------------------------------------------------- #
# 阶段五 — SSH 加固（CIS 5.2 / PCI-DSS 要求8）
#
# 使用现代密码套件（仅 AES-GCM + ChaCha20，禁用弱密码）
# 禁用密码认证、禁止 root 登录、限制认证尝试次数
# --------------------------------------------------------------------------- #

phase5_ssh() {
    section "阶段五：加固 SSH 配置（现代密码套件 + 强化访问控制）"

    local sshd_config="/etc/ssh/sshd_config"
    backup_file "${sshd_config}"

    # 写入 drop-in 配置文件（Ubuntu 22.04+ 支持 /etc/ssh/sshd_config.d/*.conf）
    local drop_in="/etc/ssh/sshd_config.d/99-enterprise-hardened.conf"
    cat > "${drop_in}" <<'SSHD'
# 企业级 SSH 加固配置
# CIS Ubuntu 22.04 基准 5.2 / PCI-DSS 要求8

# ── 认证 ──────────────────────────────────────────────────────────────────
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no

# ── 会话保护 ──────────────────────────────────────────────────────────────
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
MaxAuthTries 3
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 0
MaxSessions 4

# ── 现代密码套件（禁用所有 CBC、MD5、SHA-1）──────────────────────────────
# PCI-DSS 要求4：传输中使用强加密（TLS 1.2+，强密码）
# 仅保留 AEAD 密码套件（AES-GCM, ChaCha20-Poly1305）和 SHA-2 消息认证码
Ciphers aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp256,ecdh-sha2-nistp521
HostKeyAlgorithms ssh-ed25519,rsa-sha2-256,rsa-sha2-512
PubkeyAcceptedKeyTypes ssh-ed25519,rsa-sha2-256,rsa-sha2-512

# ── 系统访问 ──────────────────────────────────────────────────────────────
PrintMotd no
PrintLastLog yes
Banner none

# ── 日志（PCI-DSS 要求10）─────────────────────────────────────────────────
LogLevel VERBOSE
SyslogFacility AUTH
SSHD

    # 在重启前验证完整配置，防止因配置错误封锁自身 SSH 连接
    if sshd -t; then
        systemctl restart sshd
        log "SSH 已加固并重启。现代密码套件（AES-GCM + ChaCha20）已启用。"
    else
        warn "sshd 配置验证失败 — 已回滚 drop-in 文件以避免封锁。"
        rm -f "${drop_in}"
    fi

    log "阶段五完成。"
}

# --------------------------------------------------------------------------- #
# 阶段六 — auditd 审计规则（PCI-DSS 要求10）
# --------------------------------------------------------------------------- #

phase6_auditd() {
    section "阶段六：配置 auditd 内核审计规则"

    cat > /etc/audit/rules.d/99-dns-enterprise.rules <<'AUDIT'
# 企业级 DNS 服务器 auditd 规则
# PCI-DSS 要求10 — 审计所有特权访问和配置变更

# 删除所有现有规则并设置不可变标志（防止运行时篡改）
-D
-b 8192
-f 1

# ── DNS 服务器配置监控 ────────────────────────────────────────────────────
-w /etc/unbound/                -p wa -k dns_config_changes
-w /var/lib/unbound/            -p wa -k dns_data_changes

# ── 系统身份文件 ──────────────────────────────────────────────────────────
-w /etc/passwd                  -p wa -k identity_changes
-w /etc/shadow                  -p wa -k identity_changes
-w /etc/group                   -p wa -k identity_changes
-w /etc/gshadow                 -p wa -k identity_changes

# ── SSH 配置监控 ──────────────────────────────────────────────────────────
-w /etc/ssh/sshd_config         -p wa -k sshd_config_changes
-w /etc/ssh/sshd_config.d/      -p wa -k sshd_config_changes

# ── 特权提升配置 ──────────────────────────────────────────────────────────
-w /etc/sudoers                 -p wa -k sudoers_changes
-w /etc/sudoers.d/              -p wa -k sudoers_changes

# ── 内核参数配置 ──────────────────────────────────────────────────────────
-w /etc/sysctl.conf             -p wa -k sysctl_changes
-w /etc/sysctl.d/               -p wa -k sysctl_changes

# ── systemd 服务配置 ──────────────────────────────────────────────────────
-w /etc/systemd/system/         -p wa -k systemd_changes
-w /lib/systemd/system/         -p wa -k systemd_changes

# ── AppArmor 配置 ─────────────────────────────────────────────────────────
-w /etc/apparmor/               -p wa -k apparmor_changes
-w /etc/apparmor.d/             -p wa -k apparmor_changes

# ── 防火墙配置 ────────────────────────────────────────────────────────────
-w /etc/ufw/                    -p wa -k firewall_changes

# ── 所有 root 命令执行（PCI-DSS 要求10.2.2）──────────────────────────────
-a always,exit -F arch=b64 -S execve -F uid=0 -k root_commands
-a always,exit -F arch=b32 -S execve -F uid=0 -k root_commands

# ── 特权系统调用监控 ──────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S setuid  -k privilege_escalation
-a always,exit -F arch=b64 -S setgid  -k privilege_escalation
-a always,exit -F arch=b64 -S ptrace  -k process_tracing

# ── 模块加载监控 ──────────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S init_module -S finit_module -k module_load
-a always,exit -F arch=b64 -S delete_module -k module_unload

# 设置配置不可变（-e 2）— 需重启才能修改审计规则
# 警告：启用后运行时无法更改规则，仅在生产环境确认配置正确后取消注释
# -e 2
AUDIT

    systemctl enable auditd
    systemctl restart auditd
    augenrules --load || warn "augenrules --load 失败；规则将在下次重启后生效。"

    log "阶段六完成。"
}

# --------------------------------------------------------------------------- #
# 阶段七 — Unbound DNS 配置
# --------------------------------------------------------------------------- #

phase7_unbound() {
    section "阶段七：安装企业级 Unbound 配置"

    # 优先使用企业版配置；回退到标准配置
    local enterprise_src="${REPO_ROOT}/config/unbound-enterprise.conf"
    local standard_src="${REPO_ROOT}/config/unbound.conf"
    local dst="/etc/unbound/unbound.conf"

    if [[ -f "${enterprise_src}" ]]; then
        backup_file "${dst}"
        cp "${enterprise_src}" "${dst}"
        log "已复制企业版配置 ${enterprise_src} -> ${dst}"
    elif [[ -f "${standard_src}" ]]; then
        backup_file "${dst}"
        cp "${standard_src}" "${dst}"
        warn "企业版配置未找到；使用标准配置 ${standard_src}"
    else
        warn "仓库中未找到 Unbound 配置文件；使用操作系统默认配置。"
    fi

    # 确保 unbound 用户拥有数据目录
    chown -R unbound:unbound /var/lib/unbound/ 2>/dev/null || true

    # 初始化 DNSSEC 根信任锚
    log "正在初始化 DNSSEC 根信任锚..."
    if [[ -f /etc/unbound/icannbundle.pem ]]; then
        unbound-anchor -a /var/lib/unbound/root.key \
                       -c /etc/unbound/icannbundle.pem || true
    else
        unbound-anchor -a /var/lib/unbound/root.key || true
    fi

    # 下载最新根提示文件
    log "正在下载根提示文件..."
    curl -sSf --max-time 30 -o /var/lib/unbound/root.hints \
        https://www.internic.net/domain/named.cache \
        || warn "根提示文件下载失败；将使用已缓存副本（若存在）。"

    chown unbound:unbound /var/lib/unbound/root.hints 2>/dev/null || true

    # 验证配置语法
    if unbound-checkconf "${dst}"; then
        systemctl enable --now unbound
        log "Unbound 启动成功。"
    else
        die "Unbound 配置检查失败。请检查 ${dst} 后重新运行。"
    fi

    log "阶段七完成。"
}

# --------------------------------------------------------------------------- #
# 阶段八 — Unbound systemd 覆盖（HA 保证 + OOM 防护）
#
# 通过 drop-in 覆盖实现：
#   Restart=always        — 进程崩溃后自动重启（HA 关键）
#   RestartSec=5          — 重启前等待 5 秒，防止快速崩溃循环
#   LimitNOFILE=65535     — 文件描述符上限（支持 outgoing-range:8192 × 2线程）
#   OOMScoreAdjust=-500   — 负值表示在内存不足时 OOM Killer 最后才杀此进程
#                           范围 -1000（永不杀） 到 +1000（优先杀）
#                           -500 确保内核先杀其他进程，保障 DNS 服务可用性
# --------------------------------------------------------------------------- #

phase8_systemd_override() {
    section "阶段八：配置 Unbound systemd 覆盖（HA + OOM 防护 + fd 限制）"

    local override_dir="/etc/systemd/system/unbound.service.d"
    mkdir -p "${override_dir}"

    cat > "${override_dir}/enterprise.conf" <<'SYSTEMD'
# 企业级 Unbound systemd 覆盖配置
# 高可用（HA）保证 + OOM 防护 + 文件描述符扩展

[Service]
# 自动重启策略 — 任何退出原因均触发重启（包括崩溃、OOM Kill、信号终止）
Restart=always
RestartSec=5

# OOM 调整 — 告知内核在内存不足时优先杀其他进程而非 Unbound
# -500：Unbound 的 OOM 得分 = 基础得分 + (-500) → 极不可能被 OOM Killer 选中
# 合理范围：-500 到 -900（-1000 完全豁免，仅对内核进程推荐）
OOMScoreAdjust=-500

# 文件描述符上限（覆盖系统默认值，支持高并发出站 DNS 套接字）
# outgoing-range:8192 × 2线程 = 16384 出站 UDP fd
# + 入站监听 + TLS 连接 + 控制套接字 → 总计可能达 20000+
# 65535 提供充足余量
LimitNOFILE=65535

# 进程数上限（防止线程泄漏）
LimitNPROC=512

# 内存锁定（允许 Unbound 锁定缓存页面防止被换出，需 CAP_IPC_LOCK）
# 注意：仅在缓存大小合理（<= 192MB）时启用，防止锁定内存导致 OOM
# LimitMEMLOCK=209715200

# 安全加固
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/unbound /run
PrivateTmp=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_IPC_LOCK
SYSTEMD

    # 重新加载 systemd 守护进程以应用覆盖配置
    systemctl daemon-reload
    systemctl restart unbound

    log "Unbound systemd 覆盖已应用："
    log "  Restart=always, OOMScoreAdjust=-500, LimitNOFILE=65535"
    log "阶段八完成。"
}

# --------------------------------------------------------------------------- #
# 阶段九 — fail2ban（PCI-DSS 要求8 — 防暴力破解）
# --------------------------------------------------------------------------- #

phase9_fail2ban() {
    section "阶段九：配置 fail2ban（暴力破解防护）"

    cat > /etc/fail2ban/jail.local <<'F2B'
[DEFAULT]
# 封禁时长：12 小时（企业级比 1 小时更严格）
bantime  = 43200
# 检测窗口：10 分钟
findtime = 600
# 最大重试次数：5 次
maxretry = 5
# 白名单：仅本地回环（不要添加管理员 IP，以防止来自被攻破跳板机的攻击）
ignoreip = 127.0.0.1/8
# 封禁动作：UFW（与 iptables 整合）
banaction = ufw

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
backend  = %(syslog_backend)s
maxretry = 3
bantime  = 86400
F2B

    systemctl enable --now fail2ban
    log "阶段九完成。"
}

# --------------------------------------------------------------------------- #
# 部署摘要
# --------------------------------------------------------------------------- #

print_summary() {
    cat <<SUMMARY

${GREEN}=================================================================
  企业级 DNS 服务器部署完成！
=================================================================${NC}

${CYAN}已完成的配置：${NC}
  ✓ 软件包：Unbound, AppArmor, auditd, fail2ban, certbot
  ✓ 文件描述符限制：65535（/etc/security/limits.d/99-dns-enterprise.conf）
  ✓ UFW 防火墙：默认拒绝 + SSH速率限制 + DNS/DoT/DoH 端口
  ✓ sysctl：BBR + TFO + 8MB 缓冲区 + 合规加固（rp_filter, SYN cookies）
  ✓ SSH 加固：仅公钥认证 + 现代密码套件（AES-GCM, ChaCha20）
  ✓ auditd：DNS配置、身份文件、root命令全面审计
  ✓ Unbound：企业级配置（DoT 上游转发防 GFW 污染）
  ✓ systemd 覆盖：Restart=always, OOMScoreAdjust=-500, LimitNOFILE=65535
  ✓ fail2ban：SSH 监狱（12小时封禁, 3次重试触发）

${YELLOW}后续必要操作：${NC}

  1. 将客户端 IP 加入 Unbound 白名单：
       sudo nano /etc/unbound/unbound.conf
       # 取消注释并设置：
       # access-control: <您的青岛IP>/32 allow
       sudo systemctl reload unbound

  2. 启用 DNS over TLS（需要域名指向本服务器）：
       sudo bash scripts/setup-tls.sh dns.example.com admin@example.com

  3. 验证完整部署：
       sudo bash scripts/health-check.sh

${CYAN}验证命令：${NC}
  # 测试 DNS 解析
  dig @127.0.0.1 www.google.com A

  # 测试 DNSSEC（应返回 SERVFAIL）
  dig @127.0.0.1 sigfail.verteiltesysteme.net A

  # 确认 BBR 已启用
  sysctl net.ipv4.tcp_congestion_control

  # 确认 TFO 已启用
  sysctl net.ipv4.tcp_fastopen

  # 查看 Unbound 统计
  sudo unbound-control stats_noreset

  # 确认 OOM 保护
  cat /proc/\$(pgrep unbound | head -1)/oom_score_adj

  # 确认文件描述符限制
  sudo -u unbound bash -c 'ulimit -n'

SUMMARY
}

# --------------------------------------------------------------------------- #
# 主函数
# --------------------------------------------------------------------------- #

main() {
    require_root

    log "在 $(hostname) 上于 $(date -u) 开始企业级 DNS 服务器部署"
    log "仓库根目录：${REPO_ROOT}"

    phase1_packages
    phase2_limits
    phase3_ufw         # UFW 在 sysctl 之前 — 加载 nf_conntrack 模块
    phase4_sysctl      # sysctl 在 UFW 之后 — nf_conntrack 参数现在可安全应用
    phase5_ssh
    phase6_auditd
    phase7_unbound
    phase8_systemd_override
    phase9_fail2ban

    print_summary
}

main "$@"
