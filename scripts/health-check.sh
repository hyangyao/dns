#!/usr/bin/env bash
# =============================================================================
# health-check.sh — 部署后验证与合规检查
#
# 验证所有服务是否正常运行，并确认系统满足
# CIS 基准和 PCI-DSS 要求。
#
# 使用方法：
#   sudo bash scripts/health-check.sh
#
# 退出码：0 = 全部检查通过，1 = 一个或多个检查失败
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

# --------------------------------------------------------------------------- #
# 辅助函数
# --------------------------------------------------------------------------- #

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass() { echo -e "  ${GREEN}[通过]${NC} $*"; (( PASS++ )) || true; }
fail() { echo -e "  ${RED}[失败]${NC} $*"; (( FAIL++ )) || true; }
warn() { echo -e "  ${YELLOW}[警告]${NC} $*"; (( WARN++ )) || true; }
header() { echo -e "\n${CYAN}▶ $*${NC}"; }

require_root() {
    [[ "$(id -u)" -eq 0 ]] || { echo "请以 root 身份运行：sudo bash scripts/health-check.sh"; exit 1; }
}

# --------------------------------------------------------------------------- #
# 检查1 — Unbound 服务
# --------------------------------------------------------------------------- #

check_unbound_service() {
    header "Unbound 服务"

    if systemctl is-active --quiet unbound; then
        pass "Unbound 正在运行。"
    else
        fail "Unbound 未运行。请检查：journalctl -u unbound -n 50"
        return
    fi

    if systemctl is-enabled --quiet unbound; then
        pass "Unbound 已设置为开机启动。"
    else
        fail "Unbound 未设置为开机启动。"
    fi

    if unbound-checkconf /etc/unbound/unbound.conf &>/dev/null; then
        pass "Unbound 配置语法有效。"
    else
        fail "Unbound 配置存在语法错误：unbound-checkconf /etc/unbound/unbound.conf"
    fi
}

# --------------------------------------------------------------------------- #
# 检查2 — DNS 解析
# --------------------------------------------------------------------------- #

check_dns_resolution() {
    header "DNS 解析"

    if ! command -v dig &>/dev/null; then
        warn "未找到 dig（请安装 dnsutils）。跳过 DNS 解析测试。"
        return
    fi

    # 普通 UDP 解析
    if dig +short +timeout=5 @127.0.0.1 www.google.com A &>/dev/null; then
        pass "普通 UDP DNS 解析 www.google.com：正常"
    else
        fail "普通 UDP DNS 解析失败。请检查 Unbound 日志。"
    fi

    # DNSSEC 验证 — sigfail.verteiltesysteme.net 必须返回 SERVFAIL
    local result
    result="$(dig +short +timeout=5 @127.0.0.1 sigfail.verteiltesysteme.net A 2>/dev/null || true)"
    local rcode
    rcode="$(dig +timeout=5 @127.0.0.1 sigfail.verteiltesysteme.net A 2>/dev/null \
             | grep -oP 'NOERROR|SERVFAIL|NXDOMAIN|REFUSED' | head -1 || true)"

    if [[ "${rcode}" == "SERVFAIL" ]]; then
        pass "DNSSEC 验证：对无效签名正确返回 SERVFAIL。"
    else
        fail "DNSSEC 验证：期望 SERVFAIL，实际返回 '${rcode}'。DNSSEC 可能配置有误。"
    fi

    # DNSSEC 正向测试 — google.com 应解析并带有 AD 标志
    local ad_flag
    ad_flag="$(dig +timeout=5 @127.0.0.1 google.com A 2>/dev/null \
               | grep -c 'flags:.*ad' || true)"
    if [[ "${ad_flag}" -gt 0 ]]; then
        pass "google.com 的 DNSSEC AD 标志存在（已验证的响应）。"
    else
        warn "google.com 的 DNSSEC AD 标志不存在。可能表示 DNSSEC 未完全激活。"
    fi
}

# --------------------------------------------------------------------------- #
# 检查3 — 版本隐藏（CIS DNS 2.1 / PCI-DSS 要求2）
# --------------------------------------------------------------------------- #

check_version_hiding() {
    header "版本与身份隐藏（CIS DNS 2.1）"

    if ! command -v dig &>/dev/null; then
        warn "未找到 dig。跳过版本隐藏测试。"
        return
    fi

    local version_answer
    version_answer="$(dig +short @127.0.0.1 version.bind chaos txt 2>/dev/null || true)"
    if [[ -z "${version_answer}" ]]; then
        pass "version.bind 查询返回为空（版本已隐藏）。"
    else
        fail "version.bind 返回：'${version_answer}' — 请在 unbound.conf 中设置 hide-version: yes"
    fi

    local id_answer
    id_answer="$(dig +short @127.0.0.1 id.server chaos txt 2>/dev/null || true)"
    if [[ -z "${id_answer}" ]]; then
        pass "id.server 查询返回为空（身份已隐藏）。"
    else
        fail "id.server 返回：'${id_answer}' — 请在 unbound.conf 中设置 hide-identity: yes"
    fi
}

# --------------------------------------------------------------------------- #
# 检查4 — 访问控制（防放大攻击）
# --------------------------------------------------------------------------- #

check_access_control() {
    header "访问控制（防放大攻击）"

    if ! command -v dig &>/dev/null; then
        warn "未找到 dig。跳过访问控制测试。"
        return
    fi

    # 回环地址必须被允许
    if dig +short +timeout=3 @127.0.0.1 www.google.com A &>/dev/null; then
        pass "回环地址（127.0.0.1）查询被允许。"
    else
        fail "回环地址查询被拒绝 — 请检查 unbound.conf 中的 access-control"
    fi

    # 检查配置中默认策略是否为 'refuse'
    if grep -q "access-control: 0\.0\.0\.0/0 refuse" /etc/unbound/unbound.conf; then
        pass "默认 access-control 为 'refuse'（防放大攻击）。"
    else
        warn "默认 access-control 可能不是 'refuse' — 请检查 unbound.conf"
    fi
}

# --------------------------------------------------------------------------- #
# 检查5 — UFW 防火墙（CIS 3.5 / PCI-DSS 要求1）
# --------------------------------------------------------------------------- #

check_ufw() {
    header "UFW 防火墙（CIS 3.5 / PCI-DSS 要求1）"

    if ufw status | grep -q "^Status: active"; then
        pass "UFW 已激活。"
    else
        fail "UFW 未激活。"
        return
    fi

    local ufw_rules
    ufw_rules="$(ufw status numbered)"

    for port_proto in "22/tcp" "53/tcp" "53/udp" "853/tcp" "443/tcp"; do
        # 同时匹配端口号和协议，避免误判
        # （例如：22/udp 已开放不应满足 22/tcp 的检查）
        if echo "${ufw_rules}" | grep -qE "\b${port_proto}\b"; then
            pass "UFW 已开放端口 ${port_proto}。"
        else
            fail "UFW 缺少端口 ${port_proto} 的规则。"
        fi
    done

    if ufw status | grep -q "deny (incoming)"; then
        pass "UFW 默认入站策略为 DENY。"
    else
        fail "UFW 默认入站策略不是 DENY。"
    fi
}

# --------------------------------------------------------------------------- #
# 检查6 — fail2ban（PCI-DSS 要求8）
# --------------------------------------------------------------------------- #

check_fail2ban() {
    header "fail2ban（PCI-DSS 要求8）"

    if systemctl is-active --quiet fail2ban; then
        pass "fail2ban 正在运行。"
    else
        fail "fail2ban 未运行。"
        return
    fi

    if fail2ban-client status sshd &>/dev/null; then
        pass "fail2ban sshd 监狱已激活。"
    else
        fail "fail2ban sshd 监狱未激活。请检查 /etc/fail2ban/jail.local"
    fi
}

# --------------------------------------------------------------------------- #
# 检查7 — auditd（PCI-DSS 要求10）
# --------------------------------------------------------------------------- #

check_auditd() {
    header "auditd（PCI-DSS 要求10）"

    if systemctl is-active --quiet auditd; then
        pass "auditd 正在运行。"
    else
        fail "auditd 未运行。"
        return
    fi

    if auditctl -l 2>/dev/null | grep -q "dns_config_changes"; then
        pass "DNS 配置变更审计规则已加载。"
    else
        warn "内核中未找到 DNS 配置审计规则。请运行：augenrules --load"
    fi

    if auditctl -l 2>/dev/null | grep -q "root_commands"; then
        pass "root 命令执行审计规则已加载。"
    else
        warn "root 命令审计规则未找到。请运行：augenrules --load"
    fi
}

# --------------------------------------------------------------------------- #
# 检查8 — SSH 加固（CIS 5.2 / PCI-DSS 要求8）
# --------------------------------------------------------------------------- #

check_ssh() {
    header "SSH 加固（CIS 5.2 / PCI-DSS 要求8）"

    if systemctl is-active --quiet sshd; then
        pass "sshd 正在运行。"
    else
        fail "sshd 未运行。"
    fi

    # 读取 sshd 的有效配置
    local sshd_effective
    sshd_effective="$(sshd -T 2>/dev/null || true)"

    declare -A expected=(
        [permitrootlogin]="no"
        [passwordauthentication]="no"
        [x11forwarding]="no"
        [maxauthtries]="3"
    )

    for key in "${!expected[@]}"; do
        local actual
        actual="$(echo "${sshd_effective}" | grep -i "^${key} " | awk '{print $2}' || true)"
        if [[ "${actual,,}" == "${expected[$key],,}" ]]; then
            pass "sshd ${key}=${actual}（期望值：${expected[$key]}）。"
        else
            fail "sshd ${key}='${actual}' — 期望 '${expected[$key]}'。请检查 sshd_config。"
        fi
    done
}

# --------------------------------------------------------------------------- #
# 检查9 — 内核/网络优化（BBR、sysctl）
# --------------------------------------------------------------------------- #

check_sysctl() {
    header "内核优化（BBR、sysctl）"

    local cc
    cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'unknown')"
    if [[ "${cc}" == "bbr" ]]; then
        pass "BBR 拥塞控制已激活。"
    else
        fail "BBR 未激活（当前：${cc}）。请检查 /etc/sysctl.d/99-dns-optimize.conf"
    fi

    local qdisc
    qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo 'unknown')"
    if [[ "${qdisc}" == "fq" ]]; then
        pass "默认队列规则为 fq（BBR 所需）。"
    else
        fail "默认队列规则为 '${qdisc}' — BBR 需要设置为 'fq'。"
    fi

    if [[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" == "0" ]]; then
        pass "IP 转发已禁用（CIS / PCI-DSS 要求1）。"
    else
        fail "IP 转发已启用 — 请禁用：sysctl net.ipv4.ip_forward=0"
    fi

    if [[ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" == "1" ]]; then
        pass "SYN Cookie 已启用（CIS 3.3.2）。"
    else
        fail "SYN Cookie 未启用 — 请设置 net.ipv4.tcp_syncookies=1"
    fi
}

# --------------------------------------------------------------------------- #
# 检查10 — 内存预算
# --------------------------------------------------------------------------- #

check_memory() {
    header "内存预算（1 GB RAM 防内存溢出）"

    local total_mb
    total_mb="$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)"
    local avail_mb
    avail_mb="$(awk '/MemAvailable/ {printf "%.0f", $2/1024}' /proc/meminfo)"
    local used_mb=$(( total_mb - avail_mb ))

    echo "    总内存    ：${total_mb} MB"
    echo "    已用      ：${used_mb} MB"
    echo "    可用      ：${avail_mb} MB"

    if [[ "${avail_mb}" -gt 200 ]]; then
        pass "可用内存（${avail_mb} MB）高于 200 MB 安全阈值。"
    else
        fail "可用内存（${avail_mb} MB）过低。存在内存溢出风险。请减小缓存大小。"
    fi

    # 检查 Unbound 缓存配置
    local msg_cache rrset_cache
    msg_cache="$(grep -oP '(?<=msg-cache-size:\s)\S+' /etc/unbound/unbound.conf 2>/dev/null || echo 'N/A')"
    rrset_cache="$(grep -oP '(?<=rrset-cache-size:\s)\S+' /etc/unbound/unbound.conf 2>/dev/null || echo 'N/A')"
    echo "    Unbound msg-cache-size  ：${msg_cache}"
    echo "    Unbound rrset-cache-size：${rrset_cache}"
    pass "已从配置读取 Unbound 缓存大小（请确认合计不超过 192m）。"
}

# --------------------------------------------------------------------------- #
# 检查11 — DoT 状态
# --------------------------------------------------------------------------- #

check_dot() {
    header "DNS over TLS（DoT）状态"

    if ss -tlnp 2>/dev/null | grep -q ":853 "; then
        pass "Unbound 正在监听 853 端口（DoT 已激活）。"
        # 验证 TLS 证书路径是否存在
        local key_path pem_path
        key_path="$(grep -oP '(?<=tls-service-key:\s")[^"]+' /etc/unbound/unbound.conf 2>/dev/null || true)"
        pem_path="$(grep -oP '(?<=tls-service-pem:\s")[^"]+' /etc/unbound/unbound.conf 2>/dev/null || true)"
        if [[ -f "${key_path:-/nonexistent}" ]]; then
            pass "TLS 私钥存在：${key_path}"
        else
            fail "TLS 私钥不存在：${key_path}"
        fi
        if [[ -f "${pem_path:-/nonexistent}" ]]; then
            pass "TLS 证书存在：${pem_path}"
        else
            fail "TLS 证书不存在：${pem_path}"
        fi
    else
        warn "Unbound 未在 853 端口监听。DoT 尚未启用。"
        warn "启用 DoT 请运行：sudo bash scripts/setup-tls.sh <域名> <邮箱>"
    fi
}

# --------------------------------------------------------------------------- #
# 检查12 — DNSSEC 根信任锚
# --------------------------------------------------------------------------- #

check_trust_anchor() {
    header "DNSSEC 根信任锚"

    if [[ -f /var/lib/unbound/root.key ]]; then
        local key_age_days
        key_age_days=$(( ( $(date +%s) - $(stat -c %Y /var/lib/unbound/root.key) ) / 86400 ))
        if [[ "${key_age_days}" -lt 30 ]]; then
            pass "root.key 存在，距今 ${key_age_days} 天。"
        else
            warn "root.key 已有 ${key_age_days} 天。建议刷新：unbound-anchor -a /var/lib/unbound/root.key"
        fi
    else
        fail "root.key 不存在。请运行：unbound-anchor -a /var/lib/unbound/root.key"
    fi

    if [[ -f /var/lib/unbound/root.hints ]]; then
        local hints_age_days
        hints_age_days=$(( ( $(date +%s) - $(stat -c %Y /var/lib/unbound/root.hints) ) / 86400 ))
        if [[ "${hints_age_days}" -lt 90 ]]; then
            pass "root.hints 存在，距今 ${hints_age_days} 天。"
        else
            warn "root.hints 已有 ${hints_age_days} 天。请刷新：curl -sSo /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache"
        fi
    else
        fail "root.hints 不存在：/var/lib/unbound/root.hints"
    fi
}

# --------------------------------------------------------------------------- #
# 汇总
# --------------------------------------------------------------------------- #

print_summary() {
    local total=$(( PASS + FAIL + WARN ))
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "  结果：${GREEN}${PASS} 通过${NC}  ${RED}${FAIL} 失败${NC}  ${YELLOW}${WARN} 警告${NC}  （共 ${total} 项）"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [[ "${FAIL}" -gt 0 ]]; then
        echo -e "  ${RED}需要处理：请在投入生产前检查上述「失败」项目。${NC}"
        return 1
    elif [[ "${WARN}" -gt 0 ]]; then
        echo -e "  ${YELLOW}请检查上述警告项目。部署可运行但尚未完全优化。${NC}"
        return 0
    else
        echo -e "  ${GREEN}所有检查已通过。服务器可投入生产使用。${NC}"
        return 0
    fi
}

# --------------------------------------------------------------------------- #
# 主函数
# --------------------------------------------------------------------------- #

main() {
    require_root

    echo -e "${CYAN}================================================================"
    echo "  DNS 服务器健康检查 — $(hostname) — $(date -u)"
    echo -e "================================================================${NC}"

    check_unbound_service
    check_dns_resolution
    check_version_hiding
    check_access_control
    check_ufw
    check_fail2ban
    check_auditd
    check_ssh
    check_sysctl
    check_memory
    check_dot
    check_trust_anchor

    print_summary
}

main "$@"
