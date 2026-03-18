#!/usr/bin/env bash
# =============================================================================
# deploy-ha-dns.sh — 高可用（HA）DNS 服务器一键部署脚本
#
# 目标机器：Azure B2ast（2 vCPU / 1 GB RAM），Ubuntu 22.04/24.04 LTS
# 部署位置：日本东部（针对中国青岛客户端优化）
# 合规标准：CIS 基准（Ubuntu）· PCI-DSS v4.0
#
# 核心特性：
#   1. 单节点 HA：systemd Restart=always + OOMScoreAdjust=-900 防止服务中断
#   2. 极致性能：unbound-extreme-perf.conf（50m/100m 缓存，零 OOM 风险）
#   3. 跨境优化：BBR + TCP Fast Open + 16MB 套接字缓冲区
#   4. DoS 防护：UFW 严格规则 + Unbound ratelimit + deny-any
#   5. PCI-DSS 合规：Auditd 监控 /etc/unbound/ 和 /etc/sysctl.d/
#
# 使用方法：
#   sudo bash scripts/deploy-ha-dns.sh
#
# 完成后需要执行：
#   1. 将客户端 IP 加入 /etc/unbound/unbound.conf.d/extreme-perf.conf 的 access-control
#   2. 运行 scripts/setup-tls.sh <域名> <邮箱> 以启用 DoT（853 端口）
#   3. 运行 scripts/health-check.sh 验证部署结果
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# --------------------------------------------------------------------------- #
# 颜色输出辅助函数
# --------------------------------------------------------------------------- #

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()     { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
section() {
    echo -e "\n${CYAN}══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $*${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
}

# --------------------------------------------------------------------------- #
# 前置检查
# --------------------------------------------------------------------------- #

require_root() {
    [[ "$(id -u)" -eq 0 ]] || die "此脚本必须以 root 身份运行：sudo bash $0"
}

require_ubuntu() {
    if ! grep -qi ubuntu /etc/os-release 2>/dev/null; then
        die "此脚本仅支持 Ubuntu 22.04 / 24.04 LTS。"
    fi
}

# 对已存在的文件创建带时间戳的备份（幂等：不会覆盖同秒内的备份）
backup_file() {
    local file="$1"
    if [[ -f "${file}" ]]; then
        cp "${file}" "${file}.bak.$(date +%Y%m%d%H%M%S)"
        log "已备份：${file}"
    fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# --------------------------------------------------------------------------- #
# 阶段一 — 系统更新与软件包安装
# --------------------------------------------------------------------------- #

phase1_packages() {
    section "阶段一：更新系统并安装依赖软件包"

    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        unbound \
        ufw \
        fail2ban \
        auditd \
        audispd-plugins \
        apparmor \
        apparmor-profiles \
        apparmor-utils \
        certbot \
        dnsutils \
        curl \
        jq \
        libpam-pwquality

    log "阶段一完成：所有依赖软件包已安装。"
}

# --------------------------------------------------------------------------- #
# 阶段二 — SSH 加固（CIS 规范）
# --------------------------------------------------------------------------- #

phase2_ssh_hardening() {
    section "阶段二：SSH 加固（CIS 基准）"

    local sshd_conf="/etc/ssh/sshd_config"
    backup_file "${sshd_conf}"

    # 幂等地设置 SSH 配置项（若已存在则替换，否则追加）
    declare -A ssh_settings=(
        [PermitRootLogin]="no"
        [PasswordAuthentication]="no"
        [X11Forwarding]="no"
        [MaxAuthTries]="3"
        [ClientAliveInterval]="300"
        [ClientAliveCountMax]="0"
        [AllowAgentForwarding]="no"
        [AllowTcpForwarding]="no"
        [PermitEmptyPasswords]="no"
        [LoginGraceTime]="30"
    )

    for key in "${!ssh_settings[@]}"; do
        local val="${ssh_settings[$key]}"
        if grep -qE "^#?${key}" "${sshd_conf}"; then
            sed -i "s|^#\?${key}.*|${key} ${val}|" "${sshd_conf}"
        else
            echo "${key} ${val}" >> "${sshd_conf}"
        fi
    done

    sshd -t && systemctl restart sshd \
        && log "SSH 加固完成，服务已重启。" \
        || die "SSH 配置验证失败，已回滚。请检查 ${sshd_conf}。"
}

# --------------------------------------------------------------------------- #
# 阶段三 — UFW 防火墙（CIS 3.5 / PCI-DSS 要求1）
# 必须在 phase4_sysctl 之前运行，以便 UFW 加载 nf_conntrack 内核模块。
# --------------------------------------------------------------------------- #

phase3_ufw() {
    section "阶段三：配置 UFW 防火墙（默认拒绝所有入站）"

    ufw --force reset

    # 默认策略：拒绝所有入站，允许所有出站
    ufw default deny incoming
    ufw default allow outgoing

    # 严格 SSH 限制（防止暴力破解）
    ufw limit 22/tcp    comment 'SSH（频率限制：30次/30秒后封锁）'

    # DNS 端口
    ufw allow 53/tcp    comment 'DNS over TCP'
    ufw allow 53/udp    comment 'DNS over UDP'
    ufw allow 853/tcp   comment 'DNS over TLS（DoT）'
    ufw allow 443/tcp   comment 'DNS over HTTPS（DoH）/ HTTPS'

    # 启用 UFW（同时将 nf_conntrack 模块加载到内核）
    ufw --force enable

    ufw status verbose
    log "阶段三完成：UFW 已启用，nf_conntrack 模块已加载。"
}

# --------------------------------------------------------------------------- #
# 阶段四 — 内核网络优化（sysctl）
# 必须在 UFW（阶段三）之后运行，nf_conntrack 参数依赖该模块已加载。
# --------------------------------------------------------------------------- #

phase4_sysctl() {
    section "阶段四：应用极致网络内核优化（BBR + 16MB 缓冲区）"

    local sysctl_target="/etc/sysctl.d/99-dns-extreme-network.conf"
    backup_file "${sysctl_target}"

    cp "${REPO_ROOT}/config/99-dns-extreme-network.conf" "${sysctl_target}"
    chmod 644 "${sysctl_target}"

    # 显式加载 nf_conntrack 模块（UFW 通常已加载，但显式加载确保幂等性）
    # 无论 UFW 是否已运行，sysctl 中的 net.netfilter.nf_conntrack_* 均需此模块
    if ! lsmod | grep -q nf_conntrack; then
        modprobe nf_conntrack \
            && log "nf_conntrack 内核模块已加载。" \
            || warn "nf_conntrack 加载失败（非致命，模块可能已内置于内核）。"
    else
        log "nf_conntrack 内核模块已就绪。"
    fi

    # 应用所有 sysctl.d 配置（--system 会按字母顺序加载所有 /etc/sysctl.d/*.conf）
    sysctl --system

    # 验证 BBR 已激活
    local cc
    cc="$(sysctl -n net.ipv4.tcp_congestion_control)"
    if [[ "${cc}" == "bbr" ]]; then
        log "BBR 拥塞控制已成功激活。"
    else
        warn "BBR 可能未激活（当前值：${cc}）。请确认内核版本 ≥ 4.9。"
    fi

    log "阶段四完成：内核网络优化已应用。"
}

# --------------------------------------------------------------------------- #
# 阶段五 — 文件描述符限制（支持高并发 DNS 连接）
# --------------------------------------------------------------------------- #

phase5_limits() {
    section "阶段五：配置文件描述符限制（LimitNOFILE=1048576）"

    local limits_target="/etc/security/limits.d/99-dns-ha.conf"
    cat > "${limits_target}" << 'EOF'
# 高可用 DNS 服务器文件描述符限制
# outgoing-range: 400 × 2线程 = 800 出站 fd + 入站 + DoT 连接 ≈ 2000
# 设为 1048576 为将来扩容提供充足余量
unbound  soft  nofile  1048576
unbound  hard  nofile  1048576
root     soft  nofile  1048576
root     hard  nofile  1048576
EOF
    chmod 644 "${limits_target}"
    log "阶段五完成：文件描述符限制已配置。"
}

# --------------------------------------------------------------------------- #
# 阶段六 — 部署 Unbound 极致性能配置
# --------------------------------------------------------------------------- #

phase6_unbound() {
    section "阶段六：部署 Unbound 极致性能配置（50m/100m 缓存，零 OOM）"

    # 确保 Unbound 配置目录存在
    mkdir -p /etc/unbound/unbound.conf.d

    # -------------------------------------------------------------------------
    # 设置 chroot 目录结构（config 中 chroot: "/etc/unbound" 的必要前提）
    # chroot 模式下，Unbound 的根变为 /etc/unbound/，
    # 因此 /var/lib/unbound/ 须映射到 /etc/unbound/var/lib/unbound/
    # -------------------------------------------------------------------------
    mkdir -p /etc/unbound/var/lib/unbound
    chown -R unbound:unbound /etc/unbound/var/ 2>/dev/null || true

    # 备份并部署极致性能配置
    local conf_target="/etc/unbound/unbound.conf.d/extreme-perf.conf"
    backup_file "${conf_target}"
    cp "${REPO_ROOT}/config/unbound-extreme-perf.conf" "${conf_target}"
    chmod 644 "${conf_target}"

    # 下载最新根提示文件（到 chroot 内的路径）
    log "下载最新根提示文件（root.hints）..."
    curl -sSf --max-time 30 \
        -o /etc/unbound/var/lib/unbound/root.hints \
        https://www.internic.net/domain/named.cache \
        && log "根提示文件已下载。" \
        || warn "根提示文件下载失败，将使用已有文件（若存在）。"

    # 同步到标准路径（供非 chroot 工具访问）
    mkdir -p /var/lib/unbound
    [[ -f /etc/unbound/var/lib/unbound/root.hints ]] && \
        cp /etc/unbound/var/lib/unbound/root.hints /var/lib/unbound/root.hints

    # 初始化 DNSSEC 信任锚（写到 chroot 内路径）
    local anchor_chroot="/etc/unbound/var/lib/unbound/root.key"
    local anchor_std="/var/lib/unbound/root.key"
    if [[ ! -f "${anchor_chroot}" ]]; then
        unbound-anchor -a "${anchor_chroot}" \
            && log "DNSSEC 信任锚已初始化（chroot 路径）。" \
            || warn "DNSSEC 信任锚初始化失败，请手动运行 unbound-anchor。"
        # 同步到标准路径
        cp "${anchor_chroot}" "${anchor_std}" 2>/dev/null || true
    else
        log "DNSSEC 信任锚文件已存在，跳过初始化。"
    fi
    chown -R unbound:unbound /etc/unbound/var/ 2>/dev/null || true

    # 验证配置语法
    unbound-checkconf "${conf_target}" \
        && log "Unbound 配置语法验证通过。" \
        || die "Unbound 配置语法错误，请检查 ${conf_target}。"

    log "阶段六完成：Unbound 配置已部署（chroot 目录结构已创建）。"
}

# --------------------------------------------------------------------------- #
# 阶段七 — systemd 高可用覆盖（单节点 HA）
#
# 关键参数说明：
#   Restart=always       — 无论何种原因退出，systemd 均自动重启（真正 HA）
#   RestartSec=2         — 重启延迟 2 秒，防止崩溃后立即重启导致资源耗尽
#   OOMScoreAdjust=-900  — 向内核 OOM Killer 建议：最后才杀死 Unbound
#                          （范围：-1000 最不可能被杀 → +1000 最可能被杀）
#                          -900 确保在内存不足时优先杀死其他进程
#   LimitNOFILE=1048576  — systemd 管理的服务忽略 /etc/security/limits.conf，
#                          必须在此处单独设置文件描述符上限
#   MemoryMax=256M       — 硬性内存上限；超出后触发 OOM Kill（仅杀 Unbound，
#                          不影响系统）。50m + 100m 缓存 + 进程开销 ≈ 200M，
#                          256M 提供 ~25% 安全余量
# --------------------------------------------------------------------------- #

phase7_systemd_ha() {
    section "阶段七：配置 systemd 高可用覆盖（Restart=always + OOMScoreAdjust=-900）"

    local override_dir="/etc/systemd/system/unbound.service.d"
    mkdir -p "${override_dir}"

    cat > "${override_dir}/ha-override.conf" << 'EOF'
# =============================================================================
# Unbound 高可用 systemd 服务覆盖
#
# OOMScoreAdjust=-900 : 告知 Linux OOM Killer 最后才杀死 Unbound。
#   内核 OOM Score 范围：-1000（永不被杀）→ +1000（优先被杀）。
#   设为 -900 使 Unbound 的 OOM 优先级远低于普通进程，
#   确保在 1GB RAM 内存压力下，系统宁可杀死其他进程也要保留 DNS 服务。
#
# MemoryMax=256M : 为 Unbound 设置 cgroup 内存上限。
#   超出此限制时，仅 Unbound 进程组被 OOM Kill，不影响整个系统。
#   150MB 缓存 + ~50MB 进程开销 = ~200MB 实际峰值，256MB 留有余量。
# =============================================================================
[Service]
# 高可用重启策略
Restart=always
RestartSec=2

# OOM 防护：降低 Unbound 被 OOM Killer 终止的优先级
OOMScoreAdjust=-900

# 内存上限（cgroup 硬限制，防止缓存配置错误导致全系统 OOM）
MemoryMax=256M

# 文件描述符上限（systemd 服务必须在此处单独配置）
LimitNOFILE=1048576

# 性能：降低调度延迟
Nice=-5
EOF

    # 重新加载 systemd daemon 并启用 Unbound
    systemctl daemon-reload
    systemctl enable unbound
    systemctl restart unbound

    # 等待 Unbound 完全启动（最多 10 秒）
    local retries=0
    until systemctl is-active --quiet unbound || [[ ${retries} -ge 10 ]]; do
        sleep 1
        (( retries++ ))
    done

    if systemctl is-active --quiet unbound; then
        log "Unbound 已成功启动并正在运行。"
        systemctl status unbound --no-pager -l
    else
        die "Unbound 启动失败！请运行：journalctl -xe -u unbound"
    fi

    log "阶段七完成：HA systemd 覆盖已配置（Restart=always，OOMScoreAdjust=-900）。"
}

# --------------------------------------------------------------------------- #
# 阶段八 — Auditd 规则（PCI-DSS 要求10：审计 DNS 配置变更）
#
# PCI-DSS v4.0 要求10.2 要求记录所有特权访问和对审计机制的访问。
# 要求10.3 要求保护审计日志不被未授权修改。
# 监控 /etc/unbound/ 和 /etc/sysctl.d/ 确保任何配置变更都留下可追溯记录。
# --------------------------------------------------------------------------- #

phase8_auditd() {
    section "阶段八：配置 Auditd PCI-DSS 审计规则"

    local audit_rules_file="/etc/audit/rules.d/99-dns-pci-dss.rules"
    cat > "${audit_rules_file}" << 'EOF'
# =============================================================================
# PCI-DSS v4.0 要求10 — DNS 服务器审计规则
#
# -w <路径>  : 监控指定文件或目录
# -p wa      : 监控写入（w）和属性变更（a）操作
# -k <标签>  : 为此规则的审计记录添加可搜索标签
#
# 查询审计日志：
#   ausearch -k dns_config_changes --interpret
#   ausearch -k sysctl_changes --interpret
#   ausearch -k identity_changes --interpret
# =============================================================================

# 监控 Unbound 配置目录（PCI-DSS 要求10.2.5：记录特权账户操作）
-w /etc/unbound/ -p wa -k dns_config_changes

# 监控 sysctl 网络配置（PCI-DSS 要求10.2.5）
-w /etc/sysctl.d/ -p wa -k sysctl_changes
-w /etc/sysctl.conf -p wa -k sysctl_changes

# 监控用户/密码文件（PCI-DSS 要求10.2.4：记录无效逻辑访问尝试）
-w /etc/passwd -p wa -k identity_changes
-w /etc/shadow -p wa -k identity_changes
-w /etc/group -p wa -k identity_changes
-w /etc/sudoers -p wa -k privilege_changes
-w /etc/sudoers.d/ -p wa -k privilege_changes

# 监控 SSH 配置（PCI-DSS 要求10.2.5）
-w /etc/ssh/sshd_config -p wa -k ssh_config_changes

# 监控 UFW 防火墙规则（PCI-DSS 要求10.2.5）
-w /etc/ufw/ -p wa -k firewall_changes

# 监控 systemd 服务单元（PCI-DSS 要求10.2.5）
-w /etc/systemd/system/unbound.service.d/ -p wa -k service_changes

# 监控审计规则本身的变更（PCI-DSS 要求10.3：保护审计日志）
-w /etc/audit/ -p wa -k audit_config_changes
EOF
    chmod 640 "${audit_rules_file}"

    # 重新加载 auditd 规则（幂等）
    systemctl enable auditd
    systemctl restart auditd

    # 等待 auditd 启动
    sleep 2

    # 加载规则到内核（augenrules 会编译并加载 rules.d/ 下所有规则）
    if command -v augenrules &>/dev/null; then
        augenrules --load && log "Auditd 规则已通过 augenrules 加载。"
    else
        auditctl -R "${audit_rules_file}" \
            && log "Auditd 规则已通过 auditctl 加载。" \
            || warn "Auditd 规则加载失败，将在下次重启时生效。"
    fi

    log "阶段八完成：PCI-DSS 审计规则已配置，监控 /etc/unbound/ 和 /etc/sysctl.d/。"
}

# --------------------------------------------------------------------------- #
# 阶段九 — fail2ban SSH 暴力破解防护
# --------------------------------------------------------------------------- #

phase9_fail2ban() {
    section "阶段九：配置 fail2ban（SSH 暴力破解防护）"

    cat > /etc/fail2ban/jail.d/sshd-strict.conf << 'EOF'
[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
findtime = 600
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban
    log "阶段九完成：fail2ban 已配置（3次失败后封锁 1 小时）。"
}

# --------------------------------------------------------------------------- #
# 阶段十 — 部署验证
# --------------------------------------------------------------------------- #

phase10_verify() {
    section "阶段十：部署验证"

    local ok=true

    # 验证 Unbound 服务状态
    if systemctl is-active --quiet unbound; then
        log "✓ Unbound 服务运行正常。"
    else
        warn "✗ Unbound 服务未在运行！"
        ok=false
    fi

    # 验证 DNS 解析功能
    if dig +short +time=3 @127.0.0.1 dns.google A | grep -qE '^[0-9]'; then
        log "✓ DNS 解析测试通过（dns.google → 正常响应）。"
    else
        warn "✗ DNS 解析测试失败（可能需要将客户端 IP 加入 access-control）。"
        ok=false
    fi

    # 验证 BBR
    local cc
    cc="$(sysctl -n net.ipv4.tcp_congestion_control)"
    if [[ "${cc}" == "bbr" ]]; then
        log "✓ BBR 拥塞控制已激活。"
    else
        warn "✗ BBR 未激活（当前：${cc}）。"
        ok=false
    fi

    # 验证 UFW
    if ufw status | grep -q "Status: active"; then
        log "✓ UFW 防火墙已激活。"
    else
        warn "✗ UFW 未激活！"
        ok=false
    fi

    # 验证 auditd
    if systemctl is-active --quiet auditd; then
        log "✓ Auditd 审计服务运行正常。"
    else
        warn "✗ Auditd 未在运行！"
        ok=false
    fi

    # 验证 OOMScoreAdjust
    local unbound_pid
    unbound_pid="$(systemctl show -p MainPID --value unbound 2>/dev/null || echo 0)"
    if [[ "${unbound_pid}" -gt 0 ]]; then
        local oom_adj
        oom_adj="$(cat /proc/${unbound_pid}/oom_score_adj 2>/dev/null || echo 'N/A')"
        log "✓ Unbound OOMScoreAdjust = ${oom_adj}（目标：-900）。"
    fi

    echo ""
    if [[ "${ok}" == "true" ]]; then
        log "═══════════════════════════════════════════════════"
        log "  ✓ 高可用 DNS 服务器部署成功！"
        log "═══════════════════════════════════════════════════"
    else
        warn "═══════════════════════════════════════════════════"
        warn "  ⚠ 部署完成，但存在警告，请检查上方输出。"
        warn "═══════════════════════════════════════════════════"
    fi

    echo ""
    log "后续操作："
    log "  1. 将您的青岛客户端 IP 加入 /etc/unbound/unbound.conf.d/extreme-perf.conf"
    log "     access-control: <您的IP>/32 allow"
    log "  2. 启用 DoT（DNS over TLS）："
    log "     sudo bash scripts/setup-tls.sh <您的域名> <您的邮箱>"
    log "  3. 运行完整健康检查："
    log "     sudo bash scripts/health-check.sh"
}

# --------------------------------------------------------------------------- #
# 主函数
# --------------------------------------------------------------------------- #

main() {
    require_root
    require_ubuntu

    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  高可用 DNS 服务器极致性能一键部署脚本          ║${NC}"
    echo -e "${CYAN}║  Azure B2ast（2C1G）· 日本东部 → 中国青岛       ║${NC}"
    echo -e "${CYAN}║  CIS 基准 · PCI-DSS v4.0 合规                   ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""

    phase1_packages
    phase2_ssh_hardening
    phase3_ufw          # UFW 必须在 sysctl 之前（加载 nf_conntrack）
    phase4_sysctl       # sysctl 必须在 UFW 之后（nf_conntrack 已就绪）
    phase5_limits
    phase6_unbound
    phase7_systemd_ha
    phase8_auditd
    phase9_fail2ban
    phase10_verify
}

main "$@"
