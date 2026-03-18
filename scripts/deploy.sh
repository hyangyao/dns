#!/usr/bin/env bash
# =============================================================================
# deploy.sh — 公共DNS服务器（Unbound + DoT/DoH）部署脚本
#
# 目标机器：Azure B2ast（2 vCPU / 1 GB RAM），Ubuntu 22.04/24.04 LTS
# 部署位置：日本东部（针对中国青岛客户端优化）
# 合规标准：CIS 基准（Ubuntu）· PCI-DSS v4.0
#
# 使用方法：
#   sudo bash scripts/deploy.sh
#
# 完成后需要执行：
#   - 将您的客户端 IP 添加至 /etc/unbound/unbound.conf 的访问控制部分
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
NC='\033[0m'

log()  { echo -e "${GREEN}[信息]${NC}  $*"; }
warn() { echo -e "${YELLOW}[警告]${NC}  $*"; }
die()  { echo -e "${RED}[错误]${NC} $*" >&2; exit 1; }

require_root() {
    [[ "$(id -u)" -eq 0 ]] || die "此脚本必须以 root 身份运行（sudo bash $0）"
}

# 对已存在的文件创建带时间戳的备份
backup_file() {
    local file="$1"
    [[ -f "${file}" ]] && cp "${file}" "${file}.bak.$(date +%Y%m%d%H%M%S)"
}

# 检测脚本所在仓库根目录（scripts/ 的上一级）
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# --------------------------------------------------------------------------- #
# 阶段一 — 系统更新与软件包安装
# --------------------------------------------------------------------------- #

phase1_packages() {
    log "阶段一：更新系统并安装软件包..."

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

    log "阶段一完成。"
}

# --------------------------------------------------------------------------- #
# 阶段二 — UFW 防火墙规则（CIS 3.5 / PCI-DSS 要求1）
# 必须在 phase3_sysctl 之前运行，以便 UFW 加载 nf_conntrack 模块；
# sysctl 配置中的 net.netfilter.nf_conntrack_* 参数要求该模块已存在于内核中。
# --------------------------------------------------------------------------- #

phase2_ufw() {
    log "阶段二：配置 UFW 防火墙..."

    ufw --force reset

    ufw default deny incoming
    ufw default allow outgoing

    ufw allow 22/tcp    comment 'SSH'
    ufw allow 53/tcp    comment 'DNS TCP'
    ufw allow 53/udp    comment 'DNS UDP'
    ufw allow 853/tcp   comment 'DNS over TLS（DoT）'
    ufw allow 443/tcp   comment 'DNS over HTTPS / Nginx（DoH）'

    # 启用 UFW — 此操作会将 nf_conntrack 网络过滤模块加载到内核
    ufw --force enable

    ufw status verbose
    log "阶段二完成。"
}

# --------------------------------------------------------------------------- #
# 阶段三 — 内核/网络优化（BBR、缓冲区调优）
# 在 UFW（阶段二）之后运行，以确保 nf_conntrack 模块已加载。
# --------------------------------------------------------------------------- #

phase3_sysctl() {
    log "阶段三：应用 sysctl 网络优化配置..."

    local src="${REPO_ROOT}/config/99-dns-optimize.conf"
    local dst="/etc/sysctl.d/99-dns-optimize.conf"

    if [[ -f "${src}" ]]; then
        cp "${src}" "${dst}"
        log "已复制 ${src} -> ${dst}"
    else
        warn "未找到 config/99-dns-optimize.conf；正在写入最小内联配置。"
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

    # 应用所有 sysctl drop-in 文件。屏蔽模块尚未完全初始化时产生的
    # nf_conntrack 参数错误；其余错误正常显示以辅助排查问题。
    sysctl --system 2>&1 | grep -vE '^net\.netfilter\.nf_conntrack' || true
    # 模块确认已加载后，显式重新加载 conntrack 相关参数
    sysctl -q -p "${dst}" || warn "部分 sysctl 设置可能需要重启后生效。"

    log "阶段三完成。"
}

# --------------------------------------------------------------------------- #
# 阶段四 — SSH 加固（CIS 第5.2节 / PCI-DSS 要求8）
# --------------------------------------------------------------------------- #

phase4_ssh() {
    log "阶段四：加固 SSH 配置..."

    local sshd_config="/etc/ssh/sshd_config"

    # 修改前先备份原始文件
    backup_file "${sshd_config}"

    # 写入 drop-in 文件（Ubuntu 22.04+ 会读取 /etc/ssh/sshd_config.d/*.conf）
    local drop_in="/etc/ssh/sshd_config.d/99-hardened.conf"
    cat > "${drop_in}" <<'SSHD'
# CIS Ubuntu 22.04 SSH 加固 — PCI-DSS 要求8
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

    # 在重启前验证完整的 sshd 配置（主文件 + 所有 drop-in 文件），
    # 防止意外封锁自身 SSH 连接
    if sshd -t; then
        systemctl restart sshd
        log "SSH 已加固并重启。"
    else
        warn "sshd 配置测试失败 — 已回滚 drop-in 文件以避免封锁。"
        rm -f "${drop_in}"
    fi

    log "阶段四完成。"
}

# --------------------------------------------------------------------------- #
# 阶段五 — auditd 规则（PCI-DSS 要求10）
# --------------------------------------------------------------------------- #

phase5_auditd() {
    log "阶段五：配置 auditd 规则..."

    cat > /etc/audit/rules.d/dns-server.rules <<'AUDIT'
# PCI-DSS 要求10 — 审计所有特权访问和配置变更

# 监控 Unbound 配置
-w /etc/unbound/ -p wa -k dns_config_changes

# 监控身份文件
-w /etc/passwd  -p wa -k identity_changes
-w /etc/shadow  -p wa -k identity_changes
-w /etc/group   -p wa -k identity_changes

# 监控 SSH 配置
-w /etc/ssh/sshd_config   -p wa -k sshd_config_changes
-w /etc/ssh/sshd_config.d -p wa -k sshd_config_changes

# 监控 sudoers
-w /etc/sudoers    -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# 监控 sysctl 配置
-w /etc/sysctl.conf  -p wa -k sysctl_changes
-w /etc/sysctl.d/    -p wa -k sysctl_changes

# 记录所有 root 命令执行
-a always,exit -F arch=b64 -S execve -F uid=0 -k root_commands
AUDIT

    systemctl enable auditd
    # 使用 restart（而非 start）以确保新规则文件被完整加载
    systemctl restart auditd
    # 将规则加载到运行中的内核
    augenrules --load || warn "augenrules --load 失败；规则将在下次重启后生效。"

    log "阶段五完成。"
}

# --------------------------------------------------------------------------- #
# 阶段六 — Unbound DNS 配置
# --------------------------------------------------------------------------- #

phase6_unbound() {
    log "阶段六：安装 Unbound 配置..."

    local src="${REPO_ROOT}/config/unbound.conf"
    local dst="/etc/unbound/unbound.conf"

    if [[ -f "${src}" ]]; then
        backup_file "${dst}"
        cp "${src}" "${dst}"
        log "已复制 ${src} -> ${dst}"
    else
        warn "仓库中未找到 config/unbound.conf；使用操作系统默认配置。"
    fi

    # 确保 unbound 用户拥有其数据目录
    chown -R unbound:unbound /var/lib/unbound/ 2>/dev/null || true

    # 初始化/刷新 DNSSEC 根信任锚
    log "正在初始化 DNSSEC 根信任锚..."
    if [[ -f /etc/unbound/icannbundle.pem ]]; then
        unbound-anchor -a /var/lib/unbound/root.key \
                       -c /etc/unbound/icannbundle.pem || true
    else
        unbound-anchor -a /var/lib/unbound/root.key || true
    fi

    # 下载最新根提示文件
    log "正在下载根提示文件..."
    curl -sSf -o /var/lib/unbound/root.hints \
        https://www.internic.net/domain/named.cache \
        || warn "根提示文件下载失败；将使用已缓存的副本。"

    chown unbound:unbound /var/lib/unbound/root.hints 2>/dev/null || true

    # 启动前验证配置
    if unbound-checkconf "${dst}"; then
        systemctl enable --now unbound
        log "Unbound 启动成功。"
    else
        die "Unbound 配置检查失败。请检查 ${dst} 后重新运行。"
    fi

    log "阶段六完成。"
}

# --------------------------------------------------------------------------- #
# 阶段七 — fail2ban
# --------------------------------------------------------------------------- #

phase7_fail2ban() {
    log "阶段七：配置 fail2ban..."

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
    log "阶段七完成。"
}

# --------------------------------------------------------------------------- #
# 部署摘要
# --------------------------------------------------------------------------- #

print_summary() {
    cat <<SUMMARY

${GREEN}=============================================================
  部署完成！
=============================================================${NC}

后续必要操作：
  1. 将您的客户端 IP 添加至 /etc/unbound/unbound.conf：
       access-control: <您的IP>/32 allow
     然后重载 Unbound：
       sudo systemctl reload unbound

  2. 拥有域名后启用 DNS over TLS（DoT）：
       sudo bash scripts/setup-tls.sh dns.example.com admin@example.com

  3. 运行健康检查以验证所有功能正常：
       sudo bash scripts/health-check.sh

验证命令：
  # 测试普通 DNS 解析
  dig @127.0.0.1 www.google.com A

  # 测试 DNSSEC（应返回 SERVFAIL — 验证功能正常）
  dig @127.0.0.1 sigfail.verteiltesysteme.net A

  # 查看 Unbound 统计信息
  sudo unbound-control stats_noreset

  # 确认防火墙规则
  sudo ufw status verbose

SUMMARY
}

# --------------------------------------------------------------------------- #
# 主函数
# --------------------------------------------------------------------------- #

main() {
    require_root

    log "在 $(hostname) 上于 $(date -u) 开始 DNS 服务器部署"
    log "仓库根目录：${REPO_ROOT}"

    phase1_packages
    phase2_ufw        # UFW 在 sysctl 之前 — 加载 nf_conntrack 模块
    phase3_sysctl     # sysctl 在 UFW 之后 — nf_conntrack 参数现在可安全应用
    phase4_ssh
    phase5_auditd
    phase6_unbound
    phase7_fail2ban

    print_summary
}

main "$@"
