# 公共DNS服务器企业级部署指南

> **目标机器：** Azure B2ast（2 vCPU / 1 GB RAM）— 日本东部区域  
> **客户端位置：** 中国青岛  
> **技术栈：** Unbound + DoT（853端口）+ UFW + fail2ban + auditd + AppArmor  
> **合规标准：** CIS基准（Ubuntu 22.04）· PCI-DSS v4.0  
> **Nginx：** 请单独安装并配置 OWASP ModSecurity CRS（用于DoH反向代理）

---

## 目录

1. [架构概览](#1-架构概览)
2. [前提条件](#2-前提条件)
3. [快速开始 — 企业级自动化部署](#3-快速开始--企业级自动化部署)
4. [阶段一 — 系统安全加固](#4-阶段一--系统安全加固)
5. [阶段二 — UFW防火墙（在sysctl之前运行）](#5-阶段二--ufw防火墙)
6. [阶段三 — 网络与内核优化](#6-阶段三--网络与内核优化)
7. [阶段四 — Unbound DNS配置](#7-阶段四--unbound-dns配置)
8. [阶段五 — DNS over TLS设置](#8-阶段五--dns-over-tls设置)
9. [阶段六 — 验证与合规检查清单](#9-阶段六--验证与合规检查清单)
10. [内存与资源参考（精确数学推导）](#10-内存与资源参考精确数学推导)
11. [跨境网络优化（青岛↔日本链路）](#11-跨境网络优化青岛日本链路)
12. [CIS与PCI-DSS合规实现详解](#12-cis与pci-dss合规实现详解)
13. [故障排查](#13-故障排查)
14. [文件结构](#14-文件结构)

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

## 3. 快速开始 — 企业级自动化部署

```bash
# 1. 在目标虚拟机上克隆仓库
git clone --depth 1 https://github.com/hyangyao/dns.git
cd dns

# 2. 企业级完整部署（推荐）：
#    软件包、AppArmor、UFW+SSH速率限制、sysctl(BBR+TFO+8MB缓冲)、
#    SSH现代密码套件加固、auditd、Unbound企业配置、
#    systemd覆盖(Restart=always, OOMScoreAdjust=-500, LimitNOFILE=65535)、fail2ban
sudo bash scripts/enterprise_deploy.sh

# 若需标准部署（向后兼容）：
# sudo bash scripts/deploy.sh

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

### 4.1 软件包列表

| 软件包 | 用途 |
|---------|---------|
| `unbound` | 递归DNS解析器 |
| `ufw` | 简易防火墙 |
| `fail2ban` | 暴力破解防护 |
| `auditd` | 内核级审计日志（PCI-DSS要求10） |
| `apparmor` + `apparmor-profiles` + `apparmor-utils` | 强制访问控制（MAC） |
| `certbot` | Let's Encrypt TLS证书管理 |
| `dnsutils` | `dig`、`nslookup`验证工具 |
| `curl`、`jq` | 脚本使用的通用工具 |
| `libpam-pwquality` | PAM密码复杂度（CIS 5.4） |

### 4.2 SSH加固（CIS第5.2节 / PCI-DSS要求8）

写入`/etc/ssh/sshd_config.d/99-enterprise-hardened.conf`：

```text
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
MaxAuthTries 3
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 0

# 现代密码套件（仅AEAD，禁用CBC/MD5/SHA-1）— PCI-DSS要求4
Ciphers aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512
HostKeyAlgorithms ssh-ed25519,rsa-sha2-256,rsa-sha2-512

LogLevel VERBOSE
```

脚本会在重启之前使用`sshd -t`验证配置，防止意外封锁自身连接。

> ⚠️ 运行`enterprise_deploy.sh`**之前**，请确保SSH公钥已添加至`~/.ssh/authorized_keys` — 密码认证将被永久禁用。

### 4.3 AppArmor强制访问控制（CIS 1.6 / PCI-DSS要求6）

AppArmor是Linux内核的强制访问控制（MAC）模块。即使攻击者利用Unbound的漏洞获取代码执行权限，AppArmor Profile也将其行为限制在预定义范围内：

```bash
# 查看Unbound的AppArmor状态
sudo aa-status | grep unbound

# 将Unbound Profile设置为强制模式（enterprise_deploy.sh自动完成）
sudo aa-enforce /etc/apparmor.d/usr.sbin.unbound

# 查看AppArmor拒绝日志（排查问题用）
sudo journalctl -k | grep apparmor | grep DENIED
```

AppArmor与`ProtectSystem=strict`（systemd沙箱）形成纵深防御：
- AppArmor：限制Unbound可访问的文件路径和系统调用
- systemd：限制Unbound可写入的目录（仅`/var/lib/unbound`和`/run`）

### 4.4 auditd规则（PCI-DSS要求10）

写入`/etc/audit/rules.d/99-dns-enterprise.rules`：

| 规则 | 触发条件 |
|------|---------|
| `-w /etc/unbound/ -p wa` | Unbound配置文件的任何写入或属性变更 |
| `-w /etc/passwd -p wa` | 身份文件变更 |
| `-w /etc/ssh/sshd_config -p wa` | SSH配置变更 |
| `-w /etc/sudoers -p wa` | 特权提升配置变更 |
| `-w /etc/apparmor.d/ -p wa` | AppArmor Profile变更 |
| `-w /etc/systemd/system/ -p wa` | systemd服务配置变更 |
| `-a always,exit … execve uid=0` | 每条root命令执行 |
| `-a always,exit … setuid/setgid` | 特权提升系统调用 |
| `-a always,exit … init_module` | 内核模块加载 |

### 4.5 fail2ban（PCI-DSS要求8）

```ini
[DEFAULT]
bantime  = 43200   # 封禁12小时（企业级）
findtime = 600     # 10分钟检测窗口
maxretry = 5       # 5次失败触发封禁
banaction = ufw    # 通过UFW执行封禁

[sshd]
enabled  = true
maxretry = 3       # SSH监狱更严格：3次触发
bantime  = 86400   # 封禁24小时
```

---

## 5. 阶段二 — UFW防火墙

> **执行顺序说明：** `enterprise_deploy.sh`在应用sysctl设置**之前**先启用UFW。
> UFW启用时会将`nf_conntrack`网络过滤模块加载到内核中。
> `99-dns-enterprise-sysctl.conf`中的`net.netfilter.nf_conntrack_*` sysctl参数
> 要求该模块已存在——在UFW启用之前应用这些参数会导致错误。

`enterprise_deploy.sh`应用的规则：

```bash
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward        # 拒绝转发（防止成为路由器）
ufw limit 22/tcp                # SSH速率限制（30s内>6次触发封禁）
ufw allow 53/tcp    # DNS TCP
ufw allow 53/udp    # DNS UDP
ufw allow 853/tcp   # DoT
ufw allow 443/tcp   # DoH（Nginx）
ufw enable
```

> **UFW速率限制SSH说明：** `ufw limit 22/tcp`使用iptables的hashlimit模块实现：30秒内同一来源IP连接超过6次时，新连接被临时丢弃。这是fail2ban之前的第一道防线，完全在内核态执行，不消耗额外内存。

> **PCI-DSS要求1.3：** 仅开放业务所需端口。删除云服务商默认添加的任何规则。

---

## 6. 阶段三 — 网络与内核优化

由`enterprise_deploy.sh`自动从`config/99-dns-enterprise-sysctl.conf`应用：

| 参数 | 值 | 原因 |
|---|---|---|
| `tcp_congestion_control` | `bbr` | 降低有丢包的中日链路延迟（1–5%丢包率） |
| `default_qdisc` | `fq` | BBR所需的配套队列规则 |
| `tcp_fastopen` | `3` | 客户端+服务端均启用TFO，节省一个RTT（≈70ms）握手时延 |
| `rmem_max` / `wmem_max` | `8 MB` | 匹配青岛-日本链路BDP（100Mbps×100ms≈1.2MB），8MB提供充足余量 |
| `udp_mem` | 65536/131072/2097152 | UDP缓冲区页数限制，防止DNS突发丢包 |
| `netdev_max_backlog` | `5000` | NIC接收队列深度，防止软中断处理前丢包 |
| `tcp_syncookies` | `1` | SYN洪水防护（CIS 3.3.2） |
| `ip_forward` | `0` | 防止路由/放大攻击（PCI-DSS要求1） |
| `rp_filter` | `1` | 严格模式反向路径过滤（防IP欺骗）（CIS 3.3.7） |
| `accept_redirects` | `0` | 拒绝ICMP重定向（防路由表篡改）（CIS 3.3.1） |
| `send_redirects` | `0` | 不发送ICMP重定向 |
| `accept_source_route` | `0` | 禁用源路由（防绕过防火墙） |
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
| `unwanted-reply-threshold` | `10000` | 异常响应计数阈值（超过触发日志告警） |
| `so-reuseport` | `yes` | 多线程共享端口，内核负载均衡，消除单套接字瓶颈 |
| `edns-buffer-size` | `1232` | 防止跨境链路IP分片（IPv6最小MTU 1280-40-8=1232） |
| `minimal-responses` | `yes` | 最小化响应包大小，减少跨境丢包概率 |
| `serve-expired` | `yes` | 上游不可达时提供过期缓存，应对GFW干扰 |
| `serve-expired-ttl` | `86400` | 过期记录最长服务24小时（跨境容灾） |
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
| CIS 1.6 | 强制访问控制（MAC） | AppArmor（enterprise_deploy.sh阶段一） |
| CIS 3.1.1 | 禁用IPv6（缩小攻击面） | `99-dns-enterprise-sysctl.conf` |
| CIS 3.3.1 | 拒绝ICMP重定向 | `99-dns-enterprise-sysctl.conf` |
| CIS 3.3.2 | 启用TCP syncookies | `99-dns-enterprise-sysctl.conf` |
| CIS 3.3.7 | 反向路径过滤（rp_filter=1） | `99-dns-enterprise-sysctl.conf` |
| CIS 3.5 | 配置主机防火墙 | enterprise_deploy.sh中的UFW |
| CIS 5.2 | SSH加固 | enterprise_deploy.sh阶段五 |
| CIS 6.2 | 软件包保持最新 | enterprise_deploy.sh阶段一 |
| CIS DNS 2.1 | 隐藏服务器版本/身份 | `unbound-enterprise.conf` |
| PCI-DSS要求1 | 防火墙规则记录完整且最小化 | enterprise_deploy.sh中的UFW |
| PCI-DSS要求2 | 无供应商默认配置 | `unbound-enterprise.conf` |
| PCI-DSS要求4 | 传输中使用TLS 1.2+ | DoT `tls-min-version: "TLSv1.2"` + SSH现代密码套件 |
| PCI-DSS要求6 | 防护攻击（速率限制） | `unbound-enterprise.conf` |
| PCI-DSS要求8 | 密钥认证，fail2ban | enterprise_deploy.sh阶段五及九 |
| PCI-DSS要求10 | 审计所有访问 | `auditd` + `log-queries: yes` |

---

## 10. 内存与资源参考（精确数学推导）

### 缓存大小计算公式

```
总缓存预算 ≈ RAM的19%
  rrset-cache-size = 预算 × 0.67  →  128 MB  （实际RR记录）
  msg-cache-size   = 预算 × 0.33  →   64 MB  （完整DNS响应）
  key-cache-size                   →   16 MB  （DNSSEC密钥）
```

**为什么是这个比例？**

Unbound内部存储模型中：
- **rrset-cache**：存储实际的DNS资源记录（A、AAAA、MX、CNAME等），每个条目包含RRset数据。这是真正占用内存的"数据体"。
- **msg-cache**：存储完整DNS响应的"骨架"，每条msg-cache条目通过引用计数指向多个rrset-cache条目，本身只存储元数据（响应标志、TTL、指针列表）。

因此，一条msg-cache条目可能引用3-5条rrset-cache条目（例如A记录+NS记录+SOA记录）。这解释了为什么rrset-cache约需msg-cache的2倍空间：每单位msg-cache空间对应约2倍的rrset-cache数据。

升级到2 GB内存？可安全地将以上三个值翻倍：
```
msg-cache-size:   128m
rrset-cache-size: 256m
key-cache-size:    32m
```

### systemd 覆盖参数说明

| 参数 | 值 | 说明 |
|---|---|---|
| `Restart=always` | — | 任何原因退出后自动重启（崩溃、OOM Kill、信号） |
| `RestartSec=5` | 5秒 | 重启前等待，防止快速崩溃循环 |
| `LimitNOFILE=65535` | — | 文件描述符上限（支持8192出站端口×2线程） |
| `OOMScoreAdjust=-500` | — | OOM调整值。内核OOM得分=基础得分+调整值；-500使Unbound在内存不足时最后被杀死 |
| `ProtectSystem=strict` | — | /etc和/usr以只读方式挂载，防止Unbound修改系统文件 |
| `PrivateTmp=yes` | — | Unbound获得独立的/tmp命名空间，防止符号链接攻击 |
| `NoNewPrivileges=yes` | — | 禁止Unbound通过execve获取新特权 |

### 监控命令

```bash
# Unbound统计
sudo unbound-control stats_noreset | grep -E 'total|cache|num'

# 内存概览
free -h && ps aux --sort=-%mem | head -5

# 确认OOM保护生效
cat /proc/$(pgrep unbound | head -1)/oom_score_adj  # 应输出-500

# 确认文件描述符限制
sudo -u unbound bash -c 'ulimit -n'  # 应输出65535

# 审计日志搜索
sudo ausearch -k dns_config_changes --start today
sudo ausearch -k root_commands --start today | tail -20
```

---

## 11. 跨境网络优化（青岛↔日本链路）

### 链路特征与挑战

| 特征 | 典型值 | 挑战 |
|---|---|---|
| 往返时延（RTT） | 50–120 ms | 慢启动阶段带宽利用率低 |
| 丢包率 | 1–5% | CUBIC拥塞控制过度反应（降窗口至70%） |
| GFW DNS污染 | 普通UDP/53 | 注入伪造IP，导致解析到错误地址 |
| MTU不一致 | 1280–1500 字节 | EDNS0大包被分片/丢弃 |

### TCP 拥塞控制 — BBR vs CUBIC

**CUBIC**（传统，默认）在有丢包时表现：
```
吞吐量 ≈ 1.22 × MSS / (RTT × √丢包率)
       ≈ 1.22 × 1460 / (0.075 × √0.03)
       ≈ 145,000 字节/秒 ≈ 1.2 Mbps（在3%丢包+75ms RTT下）
```

**BBR**（现代，本方案）工作原理：
- 测量瓶颈带宽（BtlBW）和最小RTT，以此为基础控制发送速率
- 不将丢包视为拥塞信号（中国-日本链路上大量丢包是随机的，非拥塞引起）
- 在相同链路条件下实测吞吐量比CUBIC高3-30倍

### TCP Fast Open（TFO）— 节省握手往返时间

```
传统TCP连接建立：
  客户端 ──SYN──▶ 服务器           # 第1次RTT（约75ms）
  客户端 ◀──SYN-ACK── 服务器
  客户端 ──ACK+数据──▶ 服务器       # 第2次RTT才能发送DNS查询

TFO连接建立（第2次之后）：
  客户端 ──SYN+TFO Cookie+DNS查询──▶ 服务器   # 首字节立即携带
  客户端 ◀──SYN-ACK+DNS响应── 服务器           # 节省≈75ms
```

`net.ipv4.tcp_fastopen = 3`：同时在客户端（1）和服务端（2）启用TFO，对所有TCP连接（包括DoT:853）生效。

### EDNS0缓冲区大小选择

```
IPv6最小MTU:        1280 字节
- IPv6报头:          -40 字节
- UDP报头:            -8 字节
= 最大安全DNS载荷:  1232 字节
```

设置`edns-buffer-size: 1232`确保在任何IPv4/IPv6路径上都不会触发IP分片。使用1232而非传统的512，可在不分片的前提下传输更多DNS数据（如较长的DNSSEC签名响应）。

### 上游 DoT 转发（防 GFW DNS 污染）

```
客户端（青岛）
    │ UDP 53（加密：与本地Unbound通信安全）
    ▼
本地 Unbound（Azure日本 :53）
    │ TCP 853（TLS加密）— GFW无法注入伪造响应
    ▼
Cloudflare/Google DoT（1.1.1.1:853, 8.8.8.8:853）
    │ 真实权威解析结果
    ▼
本地 Unbound（缓存结果 + DNSSEC验证）
    │ 响应客户端
    ▼
客户端（青岛）
```

关键配置（`unbound-enterprise.conf`）：
```text
forward-zone:
    name: "."
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 8.8.8.8@853#dns.google
    forward-tls-upstream: yes   # 强制使用TLS，不降级到明文
```

---

## 12. CIS与PCI-DSS合规实现详解

### AppArmor — CIS 1.6（强制访问控制）

AppArmor在内核态实现最小权限原则（Principle of Least Privilege）。即使Unbound存在零日漏洞被利用，攻击者也只能在AppArmor允许的范围内操作：

```bash
# 查看Unbound的AppArmor配置文件位置
cat /etc/apparmor.d/usr.sbin.unbound

# 典型限制：
#   - 只能读取 /etc/unbound/、/var/lib/unbound/
#   - 只能写入 /var/lib/unbound/（缓存文件）
#   - 只能监听53/853端口（通过CAP_NET_BIND_SERVICE）
#   - 不能访问 /etc/shadow、/root/、其他用户目录

# 验证强制模式
sudo aa-status | grep unbound  # 应显示"enforce"
```

### auditd — PCI-DSS要求10（完整审计跟踪）

PCI-DSS要求10明确要求"追踪和监控对网络资源和持卡人数据的所有访问"。对于DNS服务器：

```bash
# 查看今日DNS配置变更
sudo ausearch -k dns_config_changes --start today

# 查看所有root命令执行（PCI-DSS 10.2.2）
sudo ausearch -k root_commands --start today | aureport -c

# 查看特权提升（PCI-DSS 10.2.5）
sudo ausearch -k privilege_escalation --start today

# 生成合规报告
sudo aureport --summary --start this-week
```

### SSH密码套件 — PCI-DSS要求4（强加密传输）

PCI-DSS要求4.2.1规定传输中数据必须使用"强密码学"保护，禁止使用已知弱密码：

| 禁用的算法 | 原因 |
|---|---|
| `aes128-cbc`, `aes256-cbc` | CBC模式易受BEAST/Lucky13攻击 |
| `hmac-md5`, `hmac-sha1` | MD5/SHA-1已被破解，不符合FIPS 140-2 |
| `diffie-hellman-group1-sha1` | 1024位DH密钥长度不足 |
| `ssh-dss` | DSA密钥被NIST淘汰 |

| 允许的算法 | 安全理由 |
|---|---|
| `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com` | AEAD模式，同时提供加密+认证 |
| `chacha20-poly1305@openssh.com` | 现代流密码，对ARM/低功耗设备友好 |
| `hmac-sha2-256-etm`, `hmac-sha2-512-etm` | EtM（先加密后MAC）模式，更安全 |
| `curve25519-sha256` | 椭圆曲线DH，128位安全性，计算高效 |
| `ssh-ed25519` | Ed25519签名，现代椭圆曲线，安全性高 |

### 文件描述符限制 — 高并发基础

企业级Unbound配置的文件描述符需求：

```
outgoing-range: 8192    per thread
num-threads: 2          threads
────────────────────────────────
出站UDP套接字:          16,384 fd
DoT连接（入站TCP）:      ~5,000 fd（估算）
Unbound内部管理套接字:     ~100 fd
安全余量:                ~1,000 fd
─────────────────────────────────
总计估算需求:           ~22,484 fd
设置上限:                65,535 fd（充足余量）
```

双重配置确保生效（PAM和systemd分别管理不同进程的限制）：
1. `/etc/security/limits.d/99-dns-enterprise.conf` — PAM管理的Shell启动进程
2. `/etc/systemd/system/unbound.service.d/enterprise.conf` — systemd管理的服务进程

---

## 13. 故障排查

| 现象 | 可能原因 | 解决方案 |
|---|---|---|
| Unbound无法启动 | 配置语法错误 | `sudo unbound-checkconf /etc/unbound/unbound.conf` |
| 内存占用过高 | 缓存大小过大 | 将`rrset-cache-size`减至64m，`msg-cache-size`减至32m |
| DNS查询被拒绝 | access-control ACL | 在`unbound.conf`中添加`access-control: X.X.X.X/32 allow` |
| DNS解析缓慢 | BBR未激活 | `sysctl net.ipv4.tcp_congestion_control` → 应显示`bbr` |
| DoT不工作 | TLS证书缺失/过期 | `sudo bash scripts/setup-tls.sh <域名> <邮箱>` |
| SSH连接被封锁（fail2ban） | 暴力破解触发封禁 | `sudo fail2ban-client set sshd unbanip <您的IP>` |
| SSH连接被封锁（UFW限速） | 短时间内连接过多 | 等待60秒后重试；或临时`sudo ufw delete limit 22/tcp` |
| `sysctl: nf_conntrack`错误 | 模块未加载 | 确认UFW已启用：`ufw status` |
| `unbound-control`失败 | 套接字不存在 | `sudo systemctl restart unbound` |
| 有效域名出现DNSSEC SERVFAIL | 时钟偏差 | `sudo timedatectl set-ntp true` |
| syslog磁盘占满 | 繁忙服务器上`log-queries: yes` | 磁盘空间有限时设置`log-queries: no` |
| Unbound被OOM Killer杀死 | 内存不足 | 先查日志：`sudo journalctl -u unbound --since "1 hour ago" \| grep -i oom`；再确认OOM保护是否生效：`systemctl show unbound \| grep OOMScore` |
| AppArmor拒绝Unbound操作 | Profile限制过严 | `sudo journalctl -k \| grep "apparmor.*DENIED"` 查看被拒绝的操作 |
| `outgoing-range`不生效 | fd上限不足 | 确认`LimitNOFILE=65535`已通过systemd override应用 |

---

## 14. 文件结构

```
dns/
├── README.md                              # 企业级部署指南（本文件）
├── config/
│   ├── unbound.conf                       # 标准Unbound配置（向后兼容）
│   ├── unbound-enterprise.conf            # 企业级Unbound配置（推荐）
│   │                                      #   - so-reuseport, edns-buffer-size:1232
│   │                                      #   - serve-expired-ttl:86400, minimal-responses
│   │                                      #   - outgoing-range:8192, DoT上游转发
│   ├── 99-dns-optimize.conf               # 标准sysctl优化（向后兼容）
│   ├── 99-dns-enterprise-sysctl.conf      # 企业级sysctl配置
│   │                                      #   - BBR+TFO+8MB缓冲区
│   │                                      #   - rp_filter=1, ICMP加固, IPv6禁用
│   └── security-limits.conf              # 文件描述符限制（nofile 65535）
└── scripts/
    ├── deploy.sh                          # 标准自动化部署（向后兼容）
    ├── enterprise_deploy.sh               # 企业级幂等部署脚本（推荐）
    │                                      #   - AppArmor强制模式
    │                                      #   - UFW+SSH速率限制
    │                                      #   - 现代SSH密码套件
    │                                      #   - systemd覆盖（Restart=always,
    │                                      #     OOMScoreAdjust=-500, LimitNOFILE=65535）
    ├── setup-tls.sh                       # 证书申请完成后启用DNS over TLS
    └── health-check.sh                    # 部署后验证与合规检查
```

---

*基于MIT协议授权。欢迎贡献。*
