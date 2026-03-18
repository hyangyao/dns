#!/usr/bin/env bash
# =============================================================================
# deploy-unbound.sh — Unbound DNS 服务器部署脚本
#
# 目标机器：Azure B2ast（2 vCPU / 1 GB RAM），Ubuntu 22.04/24.04 LTS
# 部署区域：日本东部（针对中国青岛客户端优化）
# 合规标准：CIS DNS 基准 · PCI-DSS v4.0
#
# 前提条件：
#   OS 加固（SSH、用户账户、Nginx）已完成，本脚本仅部署 Unbound 及
#   DNS 专用网络内核调优，不涉及 SSH、fail2ban、auditd 等 OS 层工具。
#
# 使用方法：
#   sudo bash deploy-unbound.sh
#
# 完成后建议操作：
#   1. 将客户端 IP 添加至 /etc/unbound/unbound.conf 的 access-control 段
#   2. 重载 Unbound：sudo systemctl reload unbound
#   3. 验证：dig @127.0.0.1 www.google.com A
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

log()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

require_root() {
    [[ "$(id -u)" -eq 0 ]] || die "此脚本必须以 root 身份运行（sudo bash $0）"
}

backup_if_exists() {
    local file="$1"
    [[ -f "${file}" ]] && cp "${file}" "${file}.bak.$(date +%Y%m%d%H%M%S)"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --------------------------------------------------------------------------- #
# 阶段一 — 安装 Unbound
# --------------------------------------------------------------------------- #

phase1_install() {
    log "阶段一：安装 Unbound..."

    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        unbound \
        dnsutils \
        curl

    log "阶段一完成。"
}

# --------------------------------------------------------------------------- #
# 阶段二 — 应用 DNS 专用 sysctl 网络参数
#
# 仅含跨境 DNS 传输优化（BBR、缓冲区）参数，
# 不包含 OS 安全加固参数（已由运营团队单独管理）。
# --------------------------------------------------------------------------- #

phase2_sysctl() {
    log "阶段二：应用 DNS 网络内核调优参数..."

    local src="${SCRIPT_DIR}/sysctl-dns.conf"
    local dst="/etc/sysctl.d/99-dns.conf"

    if [[ -f "${src}" ]]; then
        cp "${src}" "${dst}"
        log "已复制 ${src} -> ${dst}"
    else
        die "未找到 ${src}，请确认仓库完整克隆后重试。"
    fi

    # 应用新增的 sysctl 参数（仅目标文件，避免误触其他 drop-in 配置）
    sysctl -q -p "${dst}" || warn "部分 sysctl 参数可能需要重启后生效。"

    log "阶段二完成。"
}

# --------------------------------------------------------------------------- #
# 阶段三 — 安装 Unbound 配置文件并初始化 DNSSEC
# --------------------------------------------------------------------------- #

phase3_unbound_config() {
    log "阶段三：安装 Unbound 配置并初始化 DNSSEC..."

    local src="${SCRIPT_DIR}/unbound.conf"
    local dst="/etc/unbound/unbound.conf"

    if [[ -f "${src}" ]]; then
        backup_if_exists "${dst}"
        cp "${src}" "${dst}"
        log "已复制 ${src} -> ${dst}"
    else
        die "未找到 ${src}，请确认仓库完整克隆后重试。"
    fi

    # 确保 Unbound 数据目录权限正确
    chown -R unbound:unbound /var/lib/unbound/ 2>/dev/null || true

    # 初始化 / 刷新 DNSSEC 根信任锚
    log "正在初始化 DNSSEC 根信任锚..."
    if [[ -f /etc/unbound/icannbundle.pem ]]; then
        unbound-anchor -a /var/lib/unbound/root.key \
                       -c /etc/unbound/icannbundle.pem || true
    else
        unbound-anchor -a /var/lib/unbound/root.key || true
    fi

    # 下载最新根提示文件
    log "正在下载根提示文件（root.hints）..."
    curl -sSf -o /var/lib/unbound/root.hints \
        https://www.internic.net/domain/named.cache \
        || warn "根提示文件下载失败；将使用已缓存副本（若存在）。"

    chown unbound:unbound /var/lib/unbound/root.hints 2>/dev/null || true

    # 启动前验证配置语法
    if unbound-checkconf "${dst}"; then
        log "Unbound 配置语法检查通过。"
    else
        die "Unbound 配置检查失败，请检查 ${dst} 后重新运行。"
    fi

    log "阶段三完成。"
}

# --------------------------------------------------------------------------- #
# 阶段四 — Systemd 服务覆盖（高可用配置）
#
# LimitNOFILE=65535：     允许 Unbound 保持足够多的并发文件描述符
# Restart=always：        进程崩溃或被 OOM 杀死后自动重启
# RestartSec=2：          重启等待间隔（秒），避免快速崩溃循环
# OOMScoreAdjust=-500：   降低被 OOM Killer 优先杀死的概率（-1000 为完全保护，
#                         -500 在保护 Unbound 的同时避免阻塞 OS 回收内存）
# --------------------------------------------------------------------------- #

phase4_systemd_override() {
    log "阶段四：配置 Unbound systemd 服务覆盖（高可用）..."

    local override_dir="/etc/systemd/system/unbound.service.d"
    mkdir -p "${override_dir}"

    cat > "${override_dir}/ha-override.conf" <<'OVERRIDE'
[Service]
# 高可用文件描述符限制（支持大量并发 DNS 连接）
LimitNOFILE=65535

# 崩溃自动恢复（进程崩溃、被信号终止或被 OOM Killer 杀死均触发重启）
Restart=always
RestartSec=2

# OOM 优先级调整：-500 显著降低被内核 OOM Killer 选中的概率，
# 在 1 GB 内存机器上保障 Unbound 在内存压力下优先存活。
OOMScoreAdjust=-500
OVERRIDE

    systemctl daemon-reload
    log "阶段四完成。"
}

# --------------------------------------------------------------------------- #
# 阶段五 — 启动并启用 Unbound
# --------------------------------------------------------------------------- #

phase5_enable() {
    log "阶段五：启动并启用 Unbound..."

    systemctl enable unbound
    systemctl restart unbound

    # 等待服务稳定启动
    sleep 2

    if systemctl is-active --quiet unbound; then
        log "Unbound 已成功启动。"
    else
        die "Unbound 启动失败，请检查日志：journalctl -u unbound -n 50 --no-pager"
    fi

    log "阶段五完成。"
}

# --------------------------------------------------------------------------- #
# 部署摘要
# --------------------------------------------------------------------------- #

print_summary() {
    cat <<SUMMARY

${GREEN}=================================================================
  Unbound DNS 部署完成
=================================================================${NC}

已完成操作：
  ✓ 安装 Unbound（+ dnsutils、curl）
  ✓ 应用 DNS 网络内核调优（BBR、8MB 缓冲区、TCP Fast Open）
  ✓ 安装 Unbound 配置（32m/64m/16m/16m 缓存，2 线程，速率限制）
  ✓ 配置 systemd 高可用覆盖（LimitNOFILE=65535，OOMScoreAdjust=-500）
  ✓ Unbound 已启动并设置为开机自启

后续必要操作：
  1. 将您的客户端 IP 添加至 /etc/unbound/unbound.conf：
       access-control: <YOUR_CLIENT_IP>/32 allow
     然后重载 Unbound：
       sudo systemctl reload unbound

  2. 启用 DNS over TLS（DoT）— 需要有效 TLS 证书：
     在 /etc/unbound/unbound.conf 中取消注释以下行并填写证书路径：
       interface: 0.0.0.0@853
       tls-service-key: "/path/to/privkey.pem"
       tls-service-pem: "/path/to/fullchain.pem"
     然后：sudo systemctl reload unbound

验证命令：
  # 测试普通 DNS 解析
  dig @127.0.0.1 www.google.com A

  # 测试 DNSSEC 验证（应返回 SERVFAIL — 表示验证功能正常）
  dig @127.0.0.1 sigfail.verteiltesysteme.net A

  # 确认 ANY 查询被禁用（应返回 HINFO 或 REFUSED）
  dig @127.0.0.1 www.google.com ANY

  # 查看实时运行统计
  sudo unbound-control stats_noreset

  # 查看 Unbound 日志
  journalctl -u unbound -n 50 --no-pager

SUMMARY
}

# --------------------------------------------------------------------------- #
# 主函数
# --------------------------------------------------------------------------- #

main() {
    require_root

    log "开始在 $(hostname) 上部署 Unbound DNS 服务（$(date -u)）"
    log "脚本目录：${SCRIPT_DIR}"

    phase1_install
    phase2_sysctl
    phase3_unbound_config
    phase4_systemd_override
    phase5_enable

    print_summary
}

main "$@"
