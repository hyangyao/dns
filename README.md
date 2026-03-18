# 公共DNS服务器部署指南

> **目标机器：** Azure B2ast（2 vCPU / 1 GB RAM）— 日本东部区域  
> **客户端位置：** 中国青岛  
> **技术栈：** Unbound + DoT（853端口）+ UFW + fail2ban + auditd  
> **合规标准：** CIS基准（Ubuntu 22.04）· PCI-DSS v4.0  
> **Nginx：** 请单独安装并配置 OWASP ModSecurity CRS（用于DoH反向代理）

---

## 目录

1. [架构概览](#1-架构概览)
2. [前提条件](#2-前提条件)
3. [快速开始 — 自动化部署](#3-快速开始--自动化部署)
4. [阶段一 — 系统安全加固](#4-阶段一--系统安全加固)
5. [阶段二 — UFW防火墙（在sysctl之前运行）](#5-阶段二--ufw防火墙)
6. [阶段三 — 网络与内核优化](#6-阶段三--网络与内核优化)
7. [阶段四 — Unbound DNS配置](#7-阶段四--unbound-dns配置)
8. [阶段五 — DNS over TLS设置](#8-阶段五--dns-over-tls设置)
9. [阶段六 — 验证与合规检查清单](#9-阶段六--验证与合规检查清单)
10. [内存与资源参考](#10-内存与资源参考)
11. [故障排查](#11-故障排查)
12. [文件结构](#12-文件结构)

---

## 1. 架构概览

```
青岛客户端
     │
     │  加密DoT（TCP :853）  ─── 或 ───  通过Nginx的DoH（:443 + OWASP CRS）
     ▼
Azure 日本东部 — B2ast虚拟机（2 vCPU / 1 GB RAM）
┌──────────────────────────────────────────────────────────┐
│  UFW防火墙（22/tcp · 53/tcp+udp · 853/tcp · 443/tcp）   │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Unbound（递归解析器）                              │  │
│  │  · 2个线程（每个vCPU一个）                         │  │
│  │  · msg-cache 64 MB + rrset-cache 128 MB            │  │
│  │  · QNAME最小化（隐私保护，RFC 7816）               │  │
│  │  · DNSSEC验证                                      │  │
│  │  · 速率限制1000 QPS/区（防放大攻击）               │  │
│  │  · 过期记录服务1小时（中日链路韧性）               │  │
│  └────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────┐ │
│  │  Nginx + OWASP ModSecurity CRS（用户自行安装）      │ │
│  │  DoH反向代理（:443 → :8053）                       │ │
│  └──────────────────────────────────────────────────────┘ │
│  fail2ban · auditd · AppArmor                            │
└──────────────────────────────────────────────────────────┘
     │
     │  普通UDP/TCP（Azure数据中心内部）
     ▼
  根服务器 / 顶级域 / 权威服务器
```

### 为何选择此技术栈？

| 关注点 | 解决方案 |
|---|---|
| 跨境DNS污染 | DoT（853端口）端到端加密；带OWASP CRS的Nginx DoH |
| 1 GB RAM内存溢出风险 | Unbound缓存严格上限约192 MB；`vm.overcommit_memory=0` |
| 高延迟（中日链路） | BBR拥塞控制 + UDP/TCP缓冲区调优 |
| CIS基准合规 | SSH加固、UFW、auditd、AppArmor、sysctl加固 |
| PCI-DSS日志要求 | auditd规则、syslog转发、`log-queries: yes` |
| DNS放大攻击 | 速率限制（1000 QPS/区，100 QPS/IP）+ ACL访问控制 |
| nf_conntrack sysctl顺序 | UFW在sysctl**之前**启用，确保模块加载后再应用参数 |

---

## 2. 前提条件

- **操作系统：** Ubuntu 22.04 LTS（内核5.15，Unbound ≥ 1.13）
- **Azure NSG入站规则** — 部署前请开放以下端口：

  | 端口 | 协议 | 用途 |
  |------|----------|---------|
  | 22 | TCP | SSH管理 |
  | 53 | TCP + UDP | 普通DNS |
  | 853 | TCP | DNS over TLS（DoT） |
  | 443 | TCP | 通过Nginx的DNS over HTTPS（DoH） |
  | 80 | TCP | ACME HTTP-01验证（临时，执行`setup-tls.sh`期间） |

- 一个**域名**，其A记录指向虚拟机的公网IP（TLS证书申请所需）
- root/sudo权限
- SSH公钥认证须在运行`deploy.sh`**之前**完成配置（脚本将禁用密码认证）

---

## 3. 快速开始 — 自动化部署

```bash
# 1. 在目标虚拟机上克隆仓库
git clone --depth 1 https://github.com/hyangyao/dns.git
cd dns

# 2. 完整部署：软件包、UFW、sysctl、SSH、auditd、Unbound、fail2ban
sudo bash scripts/deploy.sh

# 3. 将您的客户端IP加入Unbound白名单
sudo nano /etc/unbound/unbound.conf
# 取消注释并设置：access-control: <您的IP>/32 allow
sudo systemctl reload unbound

# 4. 启用DNS over TLS（需要域名已指向本服务器）
sudo bash scripts/setup-tls.sh dns.example.com admin@example.com

# 5. 验证完整部署
sudo bash scripts/health-check.sh
```

> **Nginx + OWASP CRS（DoH）：** 请单独安装Nginx和OWASP ModSecurity核心规则集。
> DoH反向代理配置参考见[阶段五 §5.3](#53-doh通过nginx的参考配置)。

---

## 4. 阶段一 — 系统安全加固

### 4.1 deploy.sh安装的软件包

| 软件包 | 用途 |
|---------|---------|
| `unbound` | 递归DNS解析器 |
| `ufw` | 简易防火墙 |
| `fail2ban` | 暴力破解防护 |
| `auditd` | 内核级审计日志（PCI-DSS要求10） |
| `apparmor-profiles` | 强制访问控制 |
| `certbot` | Let's Encrypt TLS证书管理 |
| `dnsutils` | `dig`、`nslookup`验证工具 |
| `curl`、`jq` | 脚本使用的通用工具 |

### 4.2 SSH加固（CIS第5.2节 / PCI-DSS要求8）

写入`/etc/ssh/sshd_config.d/99-hardened.conf`：

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

脚本会在重启之前使用`sshd -t`验证配置，防止意外封锁自身连接。

> ⚠️ 运行`deploy.sh`**之前**，请确保SSH公钥已添加至`~/.ssh/authorized_keys` — 密码认证将被永久禁用。

### 4.3 auditd规则（PCI-DSS要求10）

写入`/etc/audit/rules.d/dns-server.rules`：

| 规则 | 触发条件 |
|------|---------|
| `-w /etc/unbound/ -p wa` | Unbound配置文件的任何写入或属性变更 |
| `-w /etc/passwd -p wa` | 身份文件变更 |
| `-w /etc/ssh/sshd_config -p wa` | SSH配置变更 |
| `-w /etc/sudoers -p wa` | 特权提升配置变更 |
| `-a always,exit … execve uid=0` | 每条root命令执行 |

### 4.4 fail2ban（PCI-DSS要求8）

```ini
[DEFAULT]
bantime  = 3600    # 封禁1小时
findtime = 600     # 10分钟检测窗口
maxretry = 5       # 5次失败触发封禁

[sshd]
enabled = true
```

---

## 5. 阶段二 — UFW防火墙

> **执行顺序说明：** `deploy.sh`在应用sysctl设置**之前**先启用UFW。
> UFW启用时会将`nf_conntrack`网络过滤模块加载到内核中。
> `99-dns-optimize.conf`中的`net.netfilter.nf_conntrack_*` sysctl参数
> 要求该模块已存在——在UFW启用之前应用这些参数会导致错误。

`deploy.sh`应用的规则：

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH
ufw allow 53/tcp    # DNS TCP
ufw allow 53/udp    # DNS UDP
ufw allow 853/tcp   # DoT
ufw allow 443/tcp   # DoH（Nginx）
ufw enable
```

> **PCI-DSS要求1.3：** 仅开放业务所需端口。删除云服务商默认添加的任何规则。

---

## 6. 阶段三 — 网络与内核优化

由`deploy.sh`自动从`config/99-dns-optimize.conf`应用：

| 参数 | 值 | 原因 |
|---|---|---|
| `tcp_congestion_control` | `bbr` | 降低有丢包的中日链路延迟（1–5%丢包率） |
| `default_qdisc` | `fq` | BBR所需的配套队列规则 |
| `rmem_max` / `wmem_max` | `4 MB` | 与Unbound的`so-rcvbuf`/`so-sndbuf`匹配，防止DNS查询丢包 |
| `tcp_syncookies` | `1` | SYN洪水防护（CIS 3.3.2） |
| `ip_forward` | `0` | 防止路由/放大攻击（PCI-DSS要求1） |
| `disable_ipv6` | `1` | 缩小攻击面（CIS 3.1.1）；如需IPv6可重新启用 |
| `nf_conntrack_max` | `131072` | 防止高DNS UDP查询负载下出现"表已满"丢包 |
| `vm.swappiness` | `10` | 强烈优先使用内存而非交换空间 |
| `vm.overcommit_memory` | `0` | 启发式模式——拒绝1 GB主机上明显无法满足的内存分配 |

---

## 7. 阶段四 — Unbound DNS配置

### 内存预算（1 GB RAM）

| 组件 | 分配量 |
|---|---|
| 操作系统内核 + 系统服务 | 约300 MB |
| Unbound `msg-cache-size` | 64 MB |
| Unbound `rrset-cache-size` | 128 MB |
| Unbound `key-cache-size` + 基础架构缓存 | 约20 MB |
| Unbound线程 + 额外开销 | 约32 MB |
| fail2ban + auditd + sshd | 约50 MB |
| **已用合计** | **约594 MB** |
| **安全余量** | **约406 MB** |

### 线程与分片调优（2个vCPU）

```
num-threads: 2          # 每个vCPU一个线程
msg-cache-slabs: 2      # 2的幂次且≥num-threads；减少互斥锁竞争
rrset-cache-slabs: 2
infra-cache-slabs: 2
key-cache-slabs: 2
```

### 安全设置

| 设置 | 值 | 标准 |
|---|---|---|
| `hide-identity` | `yes` | CIS DNS 2.1 — 防止指纹识别 |
| `hide-version` | `yes` | CIS DNS 2.1 — 防止版本枚举 |
| `qname-minimisation` | `yes` | RFC 7816 — 最小化上游查询数据 |
| `harden-glue` | `yes` | 防止通过胶水记录进行缓存投毒 |
| `harden-dnssec-stripped` | `yes` | 拒绝剥离DNSSEC签名的响应 |
| `harden-below-nxdomain` | `yes` | RFC 8020 — NXDOMAIN子域名截断 |
| `harden-algo-downgrade` | `yes` | 防止DNSSEC算法降级攻击 |
| `use-caps-for-id` | `yes` | 0x20编码 — Kaminsky攻击缓解措施 |
| `ratelimit` | `1000` | 每区反放大攻击（PCI-DSS要求6） |
| `ip-ratelimit` | `100` | 每个客户端IP的反放大攻击 |
| `do-ip6` | `no` | 已禁用以匹配sysctl设置；如需IPv6可重新启用 |

> **关于`harden-referral-path`的说明：** 已有意**不**启用此选项。对于NS委派路径未签名的合法域名（大型CDN和云服务商普遍存在此情况），启用该选项会产生DNSSEC误报失败。

### 访问控制

默认配置拒绝所有外部来源。请添加您的客户端IP：

```bash
# 编辑 /etc/unbound/unbound.conf：
access-control: 1.2.3.4/32 allow    # 您的青岛IP

sudo systemctl reload unbound
```

### 远程控制（Unix套接字 — 无需密钥文件）

```bash
sudo unbound-control stats_noreset
sudo unbound-control reload
sudo unbound-control flush_zone example.com
```

---

## 8. 阶段五 — DNS over TLS设置

### 5.1 自动化方式（推荐）

```bash
sudo bash scripts/setup-tls.sh dns.example.com admin@example.com
```

此脚本执行：临时开放80端口 → 运行`certbot --standalone` → 关闭80端口 →
修改`unbound.conf`激活DoT → 验证并重载Unbound → 安装每日续期cron任务。

### 5.2 手动DoT设置

```bash
# 1. 获取证书（80端口须可从互联网访问）
sudo ufw allow 80/tcp
sudo certbot certonly --standalone --non-interactive --agree-tos \
    --email admin@example.com -d dns.example.com
sudo ufw delete allow 80/tcp

# 2. 在 /etc/unbound/unbound.conf 中取消注释：
#    interface: 0.0.0.0@853
#    tls-service-key: "/etc/letsencrypt/live/dns.example.com/privkey.pem"
#    tls-service-pem: "/etc/letsencrypt/live/dns.example.com/fullchain.pem"
#    tls-min-version: "TLSv1.2"

# 3. 验证并重载
sudo unbound-checkconf /etc/unbound/unbound.conf
sudo systemctl reload unbound
```

### 5.3 DoH通过Nginx的参考配置

请单独安装带OWASP ModSecurity CRS的Nginx，然后使用：

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

    # 将DoH代理到Unbound的DoH监听端口（在127.0.0.1:8053上配置Unbound）
    location /dns-query {
        proxy_pass       http://127.0.0.1:8053;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_http_version 1.1;
        proxy_read_timeout 30s;
    }
}
```

### 5.4 证书自动续期

`setup-tls.sh`安装`/etc/cron.d/certbot-renew-unbound`：

```cron
0 3 * * * root certbot renew --quiet --deploy-hook "systemctl reload unbound"
```

---

## 9. 阶段六 — 验证与合规检查清单

### 自动化健康检查

```bash
sudo bash scripts/health-check.sh
```

验证项目：Unbound状态 · DNS解析 · DNSSEC验证 · 版本隐藏 · 访问控制 · UFW规则 ·
fail2ban · auditd · SSH加固 · BBR · 内存预算 · DoT监听端口 · DNSSEC信任锚新鲜度。

### 手动功能测试

```bash
# 普通DNS解析
dig @127.0.0.1 www.google.com A

# DNSSEC验证（应返回SERVFAIL — 捕获到错误签名）
dig @127.0.0.1 sigfail.verteiltesysteme.net A

# 版本隐藏（应返回空或REFUSED）
dig @127.0.0.1 version.bind chaos txt

# 从青岛客户端测试DoT
kdig -d @<VM公网IP> +tls-ca +tls-host=dns.example.com www.google.com

# Unbound统计信息
sudo unbound-control stats_noreset | grep -E 'total|cache|num'

# BBR确认
sysctl net.ipv4.tcp_congestion_control
```

### CIS / PCI-DSS 合规矩阵

| 控制项 | 要求 | 实现方式 |
|---|---|---|
| CIS 3.3.2 | 启用TCP syncookies | `99-dns-optimize.conf` |
| CIS 3.5 | 配置主机防火墙 | `deploy.sh`中的UFW |
| CIS 5.2 | SSH加固 | `deploy.sh`阶段四 |
| CIS 6.2 | 软件包保持最新 | `deploy.sh`阶段一 |
| CIS DNS 2.1 | 隐藏服务器版本/身份 | `unbound.conf` |
| PCI-DSS要求1 | 防火墙规则记录完整且最小化 | `deploy.sh`中的UFW |
| PCI-DSS要求2 | 无供应商默认配置 | `unbound.conf` |
| PCI-DSS要求4 | 传输中使用TLS 1.2+ | DoT `tls-min-version: "TLSv1.2"` |
| PCI-DSS要求6 | 防护攻击（速率限制） | `unbound.conf` |
| PCI-DSS要求8 | 密钥认证，fail2ban | `deploy.sh`阶段四及七 |
| PCI-DSS要求10 | 审计所有访问 | `auditd` + `log-queries: yes` |

---

## 10. 内存与资源参考

### 缓存大小计算公式

```
总缓存预算 ≈ RAM的19%
  rrset-cache-size = 预算 × 0.67  →  128 MB  （实际RR记录）
  msg-cache-size   = 预算 × 0.33  →   64 MB  （完整DNS响应）
  key-cache-size                   →   16 MB  （DNSSEC密钥）
```

升级到2 GB内存？可安全地将以上三个值翻倍。

### 监控命令

```bash
# Unbound统计
sudo unbound-control stats_noreset | grep -E 'total|cache|num'

# 内存概览
free -h && ps aux --sort=-%mem | head -5

# 审计日志搜索
sudo ausearch -k dns_config_changes --start today
sudo ausearch -k root_commands --start today | tail -20
```

---

## 11. 故障排查

| 现象 | 可能原因 | 解决方案 |
|---|---|---|
| Unbound无法启动 | 配置语法错误 | `sudo unbound-checkconf /etc/unbound/unbound.conf` |
| 内存占用过高 | 缓存大小过大 | 将`rrset-cache-size`减至64m，`msg-cache-size`减至32m |
| DNS查询被拒绝 | access-control ACL | 在`unbound.conf`中添加`access-control: X.X.X.X/32 allow` |
| DNS解析缓慢 | BBR未激活 | `sysctl net.ipv4.tcp_congestion_control` → 应显示`bbr` |
| DoT不工作 | TLS证书缺失/过期 | `sudo bash scripts/setup-tls.sh <域名> <邮箱>` |
| SSH连接被封锁 | fail2ban封禁 | `sudo fail2ban-client set sshd unbanip <您的IP>` |
| `sysctl: nf_conntrack`错误 | 模块未加载 | 确认UFW已启用：`ufw status` |
| `unbound-control`失败 | 套接字不存在 | `sudo systemctl restart unbound` |
| 有效域名出现DNSSEC SERVFAIL | 时钟偏差 | `sudo timedatectl set-ntp true` |
| syslog磁盘占满 | 繁忙服务器上`log-queries: yes` | 磁盘空间有限时设置`log-queries: no` |

---

## 12. 文件结构

```
dns/
├── README.md                        # 本指南
├── config/
│   ├── unbound.conf                 # Unbound：1 GB RAM，2 vCPU，CIS/PCI-DSS加固
│   └── 99-dns-optimize.conf         # sysctl：BBR、UDP缓冲区、nf_conntrack、OOM调优
└── scripts/
    ├── deploy.sh                    # 完整自动化部署（优先运行）
    ├── setup-tls.sh                 # 证书申请完成后启用DNS over TLS
    └── health-check.sh             # 部署后验证与合规检查
```

---

*基于MIT协议授权。欢迎贡献。*
