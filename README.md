# 公共 DNS 服务器部署教程

> 适用环境：Azure 日本东区 / B2as_v2（2 vCPU · 1 GiB RAM） · Ubuntu 22.04 LTS  
> 使用软件：**Unbound**（轻量递归解析器，适合低内存机型）  
> 面向用户：中国青岛（延迟参考值约 50–80 ms）

---

## 目录

1. [前置准备](#1-前置准备)
2. [系统初始化](#2-系统初始化)
3. [安装 Unbound](#3-安装-unbound)
4. [核心配置（针对 1 GiB 内存优化）](#4-核心配置)
5. [DNSSEC 验证](#5-dnssec-验证)
6. [防火墙与 Azure NSG](#6-防火墙与-azure-nsg)
7. [系统级调优（双核 / 低内存）](#7-系统级调优)
8. [设为开机自启并测试](#8-设为开机自启并测试)
9. [监控与日志](#9-监控与日志)
10. [客户端使用方法](#10-客户端使用方法)
11. [常见问题排查](#11-常见问题排查)

---

## 1. 前置准备

### 1.1 Azure 侧操作

| 步骤 | 说明 |
|------|------|
| 创建公网 IP | 在 Azure 门户为虚拟机分配**静态公网 IPv4**，记下该地址（以下用 `<YOUR_IP>` 代替）。 |
| 网络安全组 (NSG) | 入站规则：开放 UDP 53、TCP 53；出站：全放通。 |
| 磁盘 | 默认 30 GiB OS 盘足够；无需额外数据盘。 |
| 操作系统 | Ubuntu 22.04 LTS（Azure Marketplace 免费镜像）。 |

> **B2as_v2 规格**：2 AMD vCPU、1 GiB RAM、突增型。Unbound 在此规格下稳定运行每秒约 5,000–10,000 QPS。

### 1.2 SSH 登录

```bash
ssh -i ~/.ssh/your_key.pem azureuser@<YOUR_IP>
```

---

## 2. 系统初始化

```bash
# 更新软件包索引并升级
sudo apt update && sudo apt upgrade -y

# 安装必要工具
sudo apt install -y curl vim htop net-tools dnsutils ufw

# 设置时区（日本标准时间）
sudo timedatectl set-timezone Asia/Tokyo

# 确认系统 resolved 不占用 53 端口（Ubuntu 22.04 默认 systemd-resolved 监听 127.0.0.53）
sudo systemctl disable --now systemd-resolved
sudo rm -f /etc/resolv.conf
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

> 禁用 `systemd-resolved` 是为了让 Unbound 独占 UDP/TCP 53 端口。

---

## 3. 安装 Unbound

```bash
sudo apt install -y unbound

# 验证版本
unbound -V
```

下载最新 IANA 根锚点（用于 DNSSEC）：

```bash
sudo curl -o /var/lib/unbound/root.hints \
  https://www.internic.net/domain/named.root

# 设置正确权限
sudo chown unbound:unbound /var/lib/unbound/root.hints
```

---

## 4. 核心配置

覆盖默认配置文件：

```bash
sudo mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.bak
sudo tee /etc/unbound/unbound.conf > /dev/null << 'EOF'
server:
    ###########################################################
    # 基础监听设置
    ###########################################################
    interface: 0.0.0.0
    interface: ::0
    port: 53
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes

    # 只允许合法来源（开放递归，酌情收紧）
    access-control: 0.0.0.0/0 allow
    access-control: ::/0 allow

    ###########################################################
    # 内存优化（1 GiB 机型关键参数）
    ###########################################################
    # 使用 2 个线程对应 2 vCPU
    num-threads: 2

    # 每线程消息缓存（总 ~16 MB）
    msg-cache-slabs: 4
    msg-cache-size: 8m

    # 每线程 RRset 缓存（总 ~16 MB）
    rrset-cache-slabs: 4
    rrset-cache-size: 8m

    # key 缓存（DNSSEC 用，约 4 MB）
    key-cache-slabs: 4
    key-cache-size: 4m

    # 负缓存（节省上游查询）
    neg-cache-size: 2m

    # 每线程最大并发 TCP 连接数（防止内存爆炸）
    outgoing-num-tcp: 20
    incoming-num-tcp: 50

    # 文件描述符数量（配合系统 ulimit）
    outgoing-range: 512
    num-queries-per-thread: 512

    ###########################################################
    # 性能调优
    ###########################################################
    # 预取即将到期的缓存条目（降低用户感知延迟）
    prefetch: yes
    prefetch-key: yes

    # 最小 TTL（避免频繁回源）
    cache-min-ttl: 300
    cache-max-ttl: 86400

    # 使用 SO_REUSEPORT（多线程性能更好）
    so-reuseport: yes

    # 增大 UDP 收发缓冲区
    so-rcvbuf: 4m
    so-sndbuf: 4m

    # 隐藏版本信息（安全加固）
    hide-version: yes
    hide-identity: yes

    ###########################################################
    # DNSSEC
    ###########################################################
    auto-trust-anchor-file: "/var/lib/unbound/root.key"

    ###########################################################
    # 根提示
    ###########################################################
    root-hints: "/var/lib/unbound/root.hints"

    ###########################################################
    # 防滥用：速率限制
    ###########################################################
    # 同一客户端 IP 每秒最大查询数
    ratelimit: 100
    ratelimit-slabs: 4
    ratelimit-size: 4m

    # 防止 NXDOMAIN 放大攻击
    ip-ratelimit: 200
    ip-ratelimit-slabs: 4
    ip-ratelimit-size: 4m

    ###########################################################
    # 日志（轻量模式，避免磁盘 I/O 成为瓶颈）
    ###########################################################
    verbosity: 1
    logfile: "/var/log/unbound/unbound.log"
    log-queries: no      # 开启会显著增加磁盘 I/O，生产环境建议关闭
    log-replies: no

    ###########################################################
    # 隐私保护（QNAME minimisation）
    ###########################################################
    qname-minimisation: yes

    ###########################################################
    # 拒绝 DNS-over-UDP 的超大响应（防放大攻击）
    ###########################################################
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes
    harden-algo-downgrade: yes
    use-caps-for-id: yes          # 0x20 编码混淆（防污染）

    ###########################################################
    # 私有地址保护（拒绝解析私有 IP）
    ###########################################################
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
EOF
```

创建日志目录并赋权：

```bash
sudo mkdir -p /var/log/unbound
sudo chown unbound:unbound /var/log/unbound
```

初始化 DNSSEC 根锚点（首次运行需要）：

```bash
sudo -u unbound unbound-anchor -a /var/lib/unbound/root.key
```

验证配置语法：

```bash
sudo unbound-checkconf
# 期望输出：unbound-checkconf: no errors in /etc/unbound/unbound.conf
```

---

## 5. DNSSEC 验证

配置文件已启用 `auto-trust-anchor-file`，Unbound 会自动验证所有支持 DNSSEC 的域名。  
验证是否生效（部署后执行）：

```bash
# 应返回带 "ad" 标志的响应（Authenticated Data）
dig @<YOUR_IP> dnssec-failed.org | grep -E "status:|flags:"
# 期望：status: SERVFAIL（说明 DNSSEC 验证工作正常，该域名故意配置错误）

dig @<YOUR_IP> cloudflare.com | grep -E "status:|flags:"
# 期望：status: NOERROR，flags 含 ad
```

---

## 6. 防火墙与 Azure NSG

### 6.1 操作系统防火墙（UFW）

```bash
# 允许 SSH（防止锁门）
sudo ufw allow 22/tcp

# 允许 DNS 查询
sudo ufw allow 53/udp
sudo ufw allow 53/tcp

# 允许 Unbound 远程控制（仅本机）
# 无需对外开放 8953

# 启用防火墙
sudo ufw enable
sudo ufw status verbose
```

### 6.2 Azure NSG 入站规则

在 Azure 门户 → 网络安全组 → 入站安全规则，添加：

| 优先级 | 名称 | 协议 | 目标端口 | 动作 |
|--------|------|------|----------|------|
| 100 | allow-dns-udp | UDP | 53 | 允许 |
| 110 | allow-dns-tcp | TCP | 53 | 允许 |
| 120 | allow-ssh | TCP | 22 | 允许 |

---

## 7. 系统级调优

### 7.1 内核网络参数

```bash
sudo tee /etc/sysctl.d/99-dns-tuning.conf > /dev/null << 'EOF'
# 增大 UDP 缓冲区（Unbound 配置中 so-rcvbuf/so-sndbuf 需要此支持）
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576

# 减少 TIME_WAIT 端口占用
net.ipv4.tcp_tw_reuse = 1

# 防止 SYN flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048

# 连接跟踪表（DNS 服务器高并发场景）
net.netfilter.nf_conntrack_max = 131072
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 60
EOF

sudo sysctl --system
```

### 7.2 文件描述符限制

```bash
sudo tee /etc/security/limits.d/99-unbound.conf > /dev/null << 'EOF'
unbound  soft  nofile  65536
unbound  hard  nofile  65536
EOF
```

### 7.3 systemd 服务调优

```bash
sudo mkdir -p /etc/systemd/system/unbound.service.d
sudo tee /etc/systemd/system/unbound.service.d/override.conf > /dev/null << 'EOF'
[Service]
LimitNOFILE=65536
# 使用 CPU 亲和性绑定到全部核心
CPUAffinity=0 1
# 限制内存上限，防止 OOM 导致系统不稳定（1GiB 机型保留 256 MiB 给 OS）
MemoryMax=768M
Restart=on-failure
RestartSec=5s
EOF

sudo systemctl daemon-reload
```

### 7.4 交换分区（1 GiB 内存保底）

```bash
# 创建 512 MiB swap，防止内存不足时 OOM Killer 杀掉 Unbound
sudo fallocate -l 512M /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# 降低 swappiness（尽量用物理内存）
echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.d/99-dns-tuning.conf
sudo sysctl vm.swappiness=10
```

---

## 8. 设为开机自启并测试

```bash
# 启动 Unbound 并设为开机自启
sudo systemctl enable --now unbound

# 查看运行状态
sudo systemctl status unbound

# 本机功能测试
dig @127.0.0.1 www.baidu.com
dig @127.0.0.1 www.google.com
dig @127.0.0.1 cloudflare.com AAAA

# 从青岛远程测试（在本地机器上执行）
# dig @<YOUR_IP> www.baidu.com
# nslookup www.baidu.com <YOUR_IP>
```

查看 Unbound 统计信息：

```bash
sudo unbound-control stats_noreset | head -30
```

---

## 9. 监控与日志

### 9.1 日志轮转

```bash
sudo tee /etc/logrotate.d/unbound > /dev/null << 'EOF'
/var/log/unbound/unbound.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        systemctl kill -s HUP unbound
    endscript
}
EOF
```

### 9.2 简易监控脚本

```bash
sudo tee /usr/local/bin/dns-monitor.sh > /dev/null << 'EOF'
#!/bin/bash
echo "=== Unbound 状态 ==="
systemctl is-active unbound

echo "=== 缓存命中率 ==="
sudo unbound-control stats_noreset | grep -E "^total\.(num|cachehits|cachemiss)"

echo "=== 内存使用 ==="
ps aux | grep unbound | grep -v grep | awk '{print "RSS:", $6/1024 "MB"}'

echo "=== 请求速率（最近60秒）==="
sudo unbound-control stats_noreset | grep "total.num.queries"
EOF

sudo chmod +x /usr/local/bin/dns-monitor.sh
```

执行监控：

```bash
sudo /usr/local/bin/dns-monitor.sh
```

### 9.3 cron 定时检查（可选）

```bash
# 每5分钟检查一次 Unbound 是否存活，宕机自动重启
echo "*/5 * * * * root systemctl is-active --quiet unbound || systemctl restart unbound" \
  | sudo tee /etc/cron.d/unbound-watchdog
```

---

## 10. 客户端使用方法

将以下 DNS 地址填入客户端网卡设置 / 路由器 DNS 配置：

```
首选 DNS：<YOUR_IP>
备用 DNS：1.1.1.1   （Cloudflare，作为 fallback）
```

### Windows（命令行）

```powershell
netsh interface ip set dns "以太网" static <YOUR_IP>
netsh interface ip add dns "以太网" 1.1.1.1 index=2
```

### macOS / Linux

```bash
# /etc/resolv.conf（临时）
nameserver <YOUR_IP>
nameserver 1.1.1.1
```

### 路由器

在路由器管理页面 → WAN 设置 → 手动 DNS，填入 `<YOUR_IP>`。

---

## 11. 常见问题排查

| 现象 | 排查命令 | 常见原因 |
|------|---------|---------|
| Unbound 无法启动 | `sudo journalctl -u unbound -n 50` | 配置语法错误；53 端口被占用 |
| 53 端口被占用 | `sudo ss -tulnp &#124; grep :53` | systemd-resolved 未彻底禁用 |
| 解析超时 | `dig @127.0.0.1 google.com +time=5` | 防火墙出站规则阻断 UDP 53 |
| 内存持续增长 | `sudo unbound-control dump_cache \| wc -l` | 缓存未设上限，增大 `cache-min-ttl` |
| DNSSEC 验证失败 | `sudo unbound-anchor -v` | 根锚点文件损坏，重新下载 |
| 日本→青岛延迟高 | `mtr <YOUR_IP>` | 正常现象，约 50–80 ms，可接受 |

### 重置统计计数器

```bash
sudo unbound-control stats
```

### 手动刷新缓存

```bash
sudo unbound-control flush_zone .
```

### 查看当前缓存条目数

```bash
sudo unbound-control dump_cache | wc -l
```

---

## 性能预估（B2as_v2 · 1 GiB）

| 指标 | 预估值 |
|------|--------|
| 冷启动内存占用 | ~60 MB |
| 稳定运行内存占用 | ~150–250 MB（视缓存大小） |
| 最大 QPS（UDP，无缓存） | ~5,000 QPS |
| 最大 QPS（缓存命中） | ~15,000–20,000 QPS |
| 青岛→日本东区延迟 | 约 50–80 ms（首次查询），缓存命中 <5 ms |

> 若流量超过 10,000 QPS，建议升级至 B2ms（2 vCPU · 8 GiB）或在 Azure CDN / Traffic Manager 前加一层负载均衡。

---

## 参考资料

- [Unbound 官方文档](https://unbound.docs.nlnetlabs.nl/)
- [Unbound 配置参考（nlnetlabs）](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)
- [DNSSEC 根锚点（IANA）](https://www.iana.org/dnssec/files)
- [Azure B 系列突增型虚拟机](https://learn.microsoft.com/zh-cn/azure/virtual-machines/bv2-series)
