#!/usr/bin/env bash
# =============================================================================
# setup-tls.sh — 申请 Let's Encrypt 证书并启用 Unbound DoT
#
# 此脚本执行以下步骤：
#   1. 在 UFW 中临时开放 80 端口以完成 ACME HTTP-01 验证
#   2. 通过 certbot --standalone 获取 TLS 证书
#   3. 在 UFW 中关闭 80 端口
#   4. 修改 /etc/unbound/unbound.conf 以激活 853 端口上的 DoT
#   5. 验证并重载 Unbound
#   6. 安装证书自动续期的 cron 任务
#
# 使用方法：
#   sudo bash scripts/setup-tls.sh <域名> <邮箱>
#
# 示例：
#   sudo bash scripts/setup-tls.sh dns.example.com admin@example.com
#
# 前提条件：
#   - deploy.sh 已运行完成
#   - 域名的 A 记录指向本服务器的公网 IP
#   - 80 端口必须可从互联网访问（Azure NSG 需放行）
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

# --------------------------------------------------------------------------- #
# 参数验证
# --------------------------------------------------------------------------- #

usage() {
    echo "用法：sudo bash scripts/setup-tls.sh <域名> <邮箱>"
    echo "  域名  — 指向本服务器的完全限定域名"
    echo "  邮箱  — Let's Encrypt 到期通知的联系邮箱"
    exit 1
}

[[ $# -eq 2 ]] || usage
DOMAIN="$1"
EMAIL="$2"

# 基本格式验证
[[ "${DOMAIN}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]] \
    || die "无效的域名：${DOMAIN}"
[[ "${EMAIL}" =~ ^[^@]+@[^@]+\.[^@]+$ ]] \
    || die "无效的邮箱地址：${EMAIL}"

CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
UNBOUND_CONF="/etc/unbound/unbound.conf"

# --------------------------------------------------------------------------- #
# 预检查
# --------------------------------------------------------------------------- #

preflight() {
    log "执行预检查..."

    command -v certbot   &>/dev/null || die "未找到 certbot。请先运行 deploy.sh。"
    command -v ufw       &>/dev/null || die "未找到 ufw。请先运行 deploy.sh。"
    command -v unbound   &>/dev/null || die "未找到 unbound。请先运行 deploy.sh。"
    [[ -f "${UNBOUND_CONF}" ]]       || die "未找到 Unbound 配置文件：${UNBOUND_CONF}"

    # 确认域名解析到本机公网 IP
    local server_ip
    server_ip="$(curl -sf --max-time 5 https://api.ipify.org || echo 'unknown')"
    local domain_ip
    domain_ip="$(dig +short "${DOMAIN}" A | tail -1 || echo 'unknown')"

    if [[ "${server_ip}" == "unknown" || "${domain_ip}" == "unknown" ]]; then
        warn "无法验证 DNS：服务器IP=${server_ip}，${DOMAIN}=${domain_ip}"
        warn "继续执行 — 如域名不可达，certbot 会报告错误。"
    elif [[ "${server_ip}" != "${domain_ip}" ]]; then
        warn "${DOMAIN} 解析到 ${domain_ip}，但本服务器 IP 为 ${server_ip}。"
        warn "若域名未指向本服务器，ACME 验证将会失败。"
        read -rp "是否仍要继续？[y/N] " confirm
        [[ "${confirm}" =~ ^[Yy]$ ]] || die "已中止。"
    else
        log "域名 ${DOMAIN} 正确解析到 ${server_ip}。"
    fi

    log "预检查通过。"
}

# --------------------------------------------------------------------------- #
# 步骤一 — 获取 TLS 证书
# --------------------------------------------------------------------------- #

obtain_certificate() {
    log "正在为 ${DOMAIN} 获取 TLS 证书..."

    # 临时开放 80 端口以完成 ACME HTTP-01 验证
    log "临时开放 80 端口以完成 ACME 验证..."
    ufw allow 80/tcp comment 'ACME HTTP-01 验证（临时）'

    # 运行 certbot；即使 certbot 失败，trap 也会关闭 80 端口
    trap 'log "正在关闭 80 端口..."; ufw delete allow 80/tcp 2>/dev/null || true' EXIT

    certbot certonly \
        --standalone \
        --preferred-challenges http \
        --non-interactive \
        --agree-tos \
        --email "${EMAIL}" \
        -d "${DOMAIN}"

    # 立即关闭 80 端口（trap 也会触发，但显式处理更清晰）
    log "正在关闭 80 端口..."
    ufw delete allow 80/tcp 2>/dev/null || true
    trap - EXIT

    [[ -f "${CERT_DIR}/fullchain.pem" ]] \
        || die "certbot 运行后未找到证书：${CERT_DIR}/fullchain.pem"

    log "证书已获取：${CERT_DIR}"
}

# --------------------------------------------------------------------------- #
# 步骤二 — 在 Unbound 配置中启用 DoT
# --------------------------------------------------------------------------- #

enable_dot() {
    log "正在 Unbound 配置中启用 DNS over TLS..."

    # 修改前创建带时间戳的备份；保存精确文件名以便验证失败时安全回滚
    local backup_ts
    backup_ts="${UNBOUND_CONF}.bak.$(date +%Y%m%d%H%M%S)"
    cp "${UNBOUND_CONF}" "${backup_ts}"

    # 取消注释 DoT 接口指令
    sed -i "s|^    # interface: 0\.0\.0\.0@853$|    interface: 0.0.0.0@853|" \
        "${UNBOUND_CONF}"

    # 取消注释并填入 TLS 证书指令
    sed -i "s|^    # tls-service-key: .*$|    tls-service-key: \"${CERT_DIR}/privkey.pem\"|" \
        "${UNBOUND_CONF}"
    sed -i "s|^    # tls-service-pem: .*$|    tls-service-pem: \"${CERT_DIR}/fullchain.pem\"|" \
        "${UNBOUND_CONF}"
    sed -i "s|^    # tls-min-version: .*$|    tls-min-version: \"TLSv1.2\"|" \
        "${UNBOUND_CONF}"

    # 验证修改后的配置语法是否正确
    if unbound-checkconf "${UNBOUND_CONF}"; then
        log "Unbound 配置验证通过。"
    else
        warn "Unbound 配置验证失败 — 正在恢复备份。"
        cp "${backup_ts}" "${UNBOUND_CONF}" 2>/dev/null || true
        die "DoT 启用已中止。请手动修复配置后重试。"
    fi

    # 重载 Unbound 以应用变更
    systemctl reload unbound
    log "Unbound 已重载，DoT 在 853 端口生效。"
}

# --------------------------------------------------------------------------- #
# 步骤三 — 安装证书自动续期 cron 任务
# --------------------------------------------------------------------------- #

install_renewal_cron() {
    log "正在安装证书自动续期 cron 任务..."

    cat > /etc/cron.d/certbot-renew-unbound <<CRON
# 每日续期 Let's Encrypt 证书；成功后重载 Unbound
# 由 scripts/setup-tls.sh 于 $(date -u +%Y-%m-%dT%H:%M:%SZ) 添加
0 3 * * * root certbot renew --quiet --deploy-hook "systemctl reload unbound"
CRON

    chmod 644 /etc/cron.d/certbot-renew-unbound
    log "cron 任务已安装至 /etc/cron.d/certbot-renew-unbound"
}

# --------------------------------------------------------------------------- #
# 步骤四 — 验证 DoT 是否正常工作
# --------------------------------------------------------------------------- #

verify_dot() {
    log "正在验证 853 端口的 DoT..."

    # 等待 Unbound 绑定新套接字
    sleep 2

    if command -v kdig &>/dev/null; then
        if kdig -d @127.0.0.1 +tls-ca +tls-host="${DOMAIN}" \
                www.google.com A &>/dev/null; then
            log "通过 kdig 验证 DoT 成功。"
        else
            warn "kdig DoT 测试失败 — 请检查 Unbound 日志：journalctl -u unbound -n 50"
        fi
    else
        # 回退到 openssl s_client
        if echo | openssl s_client -connect "127.0.0.1:853" \
                -servername "${DOMAIN}" &>/dev/null 2>&1; then
            log "853 端口 TLS 握手成功。"
        else
            warn "TLS 握手测试失败 — 请检查 Unbound 日志：journalctl -u unbound -n 50"
        fi
    fi
}

# --------------------------------------------------------------------------- #
# 部署摘要
# --------------------------------------------------------------------------- #

print_summary() {
    cat <<SUMMARY

${GREEN}=============================================================
  DoT 设置完成！
=============================================================${NC}

  域名    ：${DOMAIN}
  证书目录：${CERT_DIR}
  DoT端口 ：853（已激活）

从您的青岛客户端测试：
  # 使用 kdig（knot-dnsutils）
  kdig -d @<服务器IP> +tls-ca +tls-host=${DOMAIN} www.google.com

  # 使用 systemd-resolved
  resolvectl query --protocol=dot --server=<服务器IP> www.google.com

配置您的 DNS 客户端：
  - Android 9+：私人DNS → ${DOMAIN}
  - iOS 14+：  设置 → 通用 → VPN与设备管理 → DNS
  - Windows：  PowerShell: Add-DnsClientDohServerAddress ...
  - Linux（systemd-resolved）：DNS=${DOMAIN}  DNSOverTLS=yes

证书续期：
  每日 03:00 UTC 通过 cron 自动续期。
  手动续期：certbot renew --deploy-hook "systemctl reload unbound"

SUMMARY
}

# --------------------------------------------------------------------------- #
# 主函数
# --------------------------------------------------------------------------- #

main() {
    require_root

    log "于 $(date -u) 开始在 $(hostname) 上为 ${DOMAIN} 设置 DoT"

    preflight
    obtain_certificate
    enable_dot
    install_renewal_cron
    verify_dot

    print_summary
}

main "$@"
