# Unbound DNS 企业级部署指南

> **目标机器：** Azure B2ast（2 vCPU / 1 GB RAM）— 日本东部  
> **服务对象：** 中国青岛客户端  
> **技术栈：** Unbound（递归解析器）+ DoT/DoH 就绪  
> **合规标准：** CIS DNS 基准 · PCI-DSS v4.0  
> **前提条件：** OS 加固（SSH、用户账户）及 Nginx 已按 CIS 规范完成，本指南聚焦 Unbound 与 DNS 网络层。

---

## 目录

1. [快速开始](#1-快速开始)
2. [RAM 与 CPU 资源优化](#2-ram-与-cpu-资源优化)
3. [跨境网络调优（日本↔青岛）](#3-跨境网络调优日本青岛)
4. [DNS 层安全与合规（CIS / PCI-DSS）](#4-dns-层安全与合规cis--pci-dss)
5. [文件说明](#5-文件说明)
6. [部署后验证](#6-部署后验证)
7. [故障排查](#7-故障排查)

---

## 1. 快速开始

```bash
# 克隆仓库（在目标虚拟机上执行）
git clone --depth 1 https://github.com/hyangyao/dns.git
cd dns

# 一键部署 Unbound（含 sysctl 调优和 systemd 高可用覆盖）
sudo bash deploy-unbound.sh

# 添加青岛客户端 IP 至访问控制白名单
sudo nano /etc/unbound/unbound.conf
# 取消注释并填写：access-control: <YOUR_CLIENT_IP>/32 allow
sudo systemctl reload unbound

# 启用 DNS over TLS（需要 TLS 证书就绪）
# 在 unbound.conf 中取消注释 DoT 相关行并填写证书路径后：
# sudo systemctl reload unbound
```

---

## 2. RAM 与 CPU 资源优化

### 2.1 内存缓存分配（防 OOM）

1 GB 总内存机器必须严格控制 Unbound 缓存上限，为 OS 和 Unbound 进程自身的堆栈、工作内存留出充足余量。

| 参数 | 设定值 | 说明 |
|---|---|---|
| `msg-cache-size` | **32 MB** | 存储完整 DNS 响应；约为 rrset-cache 的一半 |
| `rrset-cache-size` | **64 MB** | 存储 DNS 记录集（最大缓存区） |
| `key-cache-size` | **16 MB** | 存储 DNSSEC 密钥材料 |
| `neg-cache-size` | **16 MB** | 存储否定响应（NXDOMAIN / NODATA） |
| **总缓存预算** | **128 MB** | 约占 1 GB 的 13%，安全无 OOM 风险 |

**Unbound 内存预算模型（1 GB 机器）：**

```
OS 内核与系统进程        ~200 MB
Unbound 进程堆（2 线程） ~100 MB
DNS 缓存（以上4项）      ~128 MB
可用余量（突发缓冲）      ~572 MB
─────────────────────────────────
合计                     1 024 MB
```

> **为何不使用 64m/128m（旧版配置）？**  
> 1 GB 机器在高负载时，OS 加 Unbound 进程本身已消耗约 300 MB，  
> 128m msg-cache + 128m rrset-cache 总缓存超过 256 MB，加上进程堆内存，  
> 在内存突发时极易触发 OOM Killer。**32m/64m 是适合此机型的保守安全值。**

### 2.2 CPU 线程与分片调优（2 vCPU）

| 参数 | 设定值 | 说明 |
|---|---|---|
| `num-threads` | **2** | 每个 vCPU 一个线程，充分利用 2 核算力 |
| `msg-cache-slabs` | **2** | 消息缓存分片数（≥ num-threads，取 2 的幂次） |
| `rrset-cache-slabs` | **2** | RRset 缓存分片数 |
| `infra-cache-slabs` | **2** | 基础架构缓存分片数（RTT 追踪） |
| `key-cache-slabs` | **2** | DNSSEC 密钥缓存分片数 |

**分片（Slabs）的作用：**  
Unbound 的缓存由多个互斥锁保护的分片构成。当 `num-threads=2` 时，设置 `*-slabs: 2` 使两个线程各自主要操作独立的分片，减少锁争用，提升并发吞吐量。

### 2.3 高负载并发配置

| 参数 | 设定值 | 说明 |
|---|---|---|
| `so-reuseport` | **yes** | 内核在多线程间均衡分发 UDP 包，消除单线程瓶颈 |
| `outgoing-range` | **4096** | 每线程最大出站并发查询数（受文件描述符限制） |
| `num-queries-per-thread` | **2048** | 每线程入站请求队列深度 |

> `LimitNOFILE=65535`（在 systemd 覆盖中设置）确保操作系统层面允许 Unbound 保持足够多的文件描述符以支撑上述并发参数。

---

## 3. 跨境网络调优（日本↔青岛）

中日跨境链路具有以下特征：
- **高 RTT**（往返延迟通常 50–100 ms，高峰期可超 200 ms）
- **轻度丢包**（BGP 路由切换、海底光缆拥塞）
- **IP 分片风险**（路径 MTU 不一致，UDP 大包易被丢弃）

### 3.1 Unbound 层跨境优化

| 参数 | 设定值 | 优化原理 |
|---|---|---|
| `serve-expired: yes` | — | 上游不可达时继续提供已过期的缓存记录，避免解析中断 |
| `serve-expired-ttl` | **86400**（24h） | 过期记录最长服务时长；覆盖中日链路中断场景 |
| `prefetch: yes` | — | TTL 剩余 10% 时主动刷新，高命中热门记录无需等待过期 |
| `prefetch-key: yes` | — | DNSSEC 密钥同步预取，防止验证链因密钥过期断链 |
| `edns-buffer-size` | **1232** | RFC 8900 推荐值；防止跨境路径 IP 分片引发 UDP 丢包 |

**`edns-buffer-size: 1232` 的工程依据：**

```
标准以太网帧 MTU          = 1500 字节
IPv4 头                  =   20 字节
UDP 头                   =    8 字节
可用 DNS 载荷            = 1472 字节
PPPoE / VPN / GRE 开销  ≈  240 字节（保守估算）
安全 EDNS 缓冲区上限     = 1232 字节  ← 此处设定值
```

在 Azure → 青岛的跨境路径上，经过多个运营商的隧道和中间设备，1232 字节可以在绝大多数场景下避免 IP 分片，从而减少 DNS 响应丢失和重试。

### 3.2 内核 sysctl 层跨境优化（`sysctl-dns.conf`）

| 参数 | 设定值 | 优化原理 |
|---|---|---|
| `net.ipv4.tcp_congestion_control` | **bbr** | BBR 拥塞控制：高延迟轻丢包场景下比 CUBIC 有更高吞吐量 |
| `net.core.default_qdisc` | **fq** | Fair Queue 队列规则：BBR 的配套调度器，公平分配发送时隙 |
| `net.ipv4.tcp_fastopen` | **3** | 客户端+服务端同时启用 TFO，减少 DoT/DoH 握手 RTT |
| `net.core.rmem_max` | **8388608**（8MB） | 接收缓冲区上限；减少跨境突发流量下的 UDP 丢包 |
| `net.core.wmem_max` | **8388608**（8MB） | 发送缓冲区上限 |
| `net.ipv4.udp_rmem_min` | **16384**（16KB） | 每 UDP 套接字最小缓冲保障，防止高并发时分配失败 |
| `net.ipv4.udp_wmem_min` | **16384**（16KB） | 同上（发送方向） |
| `net.core.netdev_max_backlog` | **5000** | 网卡入站队列长度；DNS 流量突发时减少驱动层丢包 |

**BBR 为何适合日本→青岛链路？**

传统 CUBIC 依赖丢包事件触发拥塞控制窗口收缩。跨境链路在拥塞前期有时表现为 RTT 升高而非立即丢包，CUBIC 会持续加速直至触发丢包后大幅退让，导致抖动。BBR 通过持续估算瓶颈带宽和 RTT 来驱动拥塞窗口，更平滑地适应跨境链路的动态特性。

**TCP Fast Open（`tcp_fastopen=3`）如何提速 DoT/DoH？**

标准 TCP 握手：`SYN → SYN-ACK → ACK → 数据`（1.5 RTT 延迟后才能发送数据）  
TCP Fast Open：客户端在 `SYN` 包中携带 Cookie 和数据，将首次数据到达时延缩短至 0.5 RTT。  
对于青岛到日本的 ~80 ms RTT，每次新建 DoT 连接节省约 80 ms 握手时间。

---

## 4. DNS 层安全与合规（CIS / PCI-DSS）

### 4.1 身份隐藏（CIS DNS 2.1 / PCI-DSS 要求2）

| 参数 | 设定值 | 合规意义 |
|---|---|---|
| `hide-identity: yes` | — | 禁止通过 `id.server` / `hostname.bind` CHAOS 查询获取主机名 |
| `hide-version: yes` | — | 禁止通过 `version.bind` CHAOS 查询获取 Unbound 版本号 |
| `identity: ""` | — | 即使 `hide-identity` 被绕过，也不返回有意义的字符串 |

PCI-DSS 要求2（"消除供应商默认配置"）明确要求不得暴露系统软件版本信息，  
以防攻击者针对已知 CVE 精准定向攻击。

### 4.2 缓存投毒防护（CIS DNS / PCI-DSS 要求6）

| 参数 | 设定值 | 防护原理 |
|---|---|---|
| `harden-glue: yes` | — | 拒绝粘合记录与权威区响应不一致的回答（防止委派污染） |
| `harden-dnssec-stripped: yes` | — | 对已签名域，拒绝不含 RRSIG 的响应（防 DNSSEC 剥离攻击） |
| `harden-algo-downgrade: yes` | — | 拒绝将 DNSSEC 算法降级至弱算法的响应（防降级攻击） |
| `harden-below-nxdomain: yes` | — | 拒绝 NXDOMAIN 父域下的假冒子域正面回答 |
| `use-caps-for-id: yes` | — | 0x20 随机大小写（Kaminsky 变体攻击缓解，RFC 5452） |
| `qname-minimisation: yes` | — | RFC 7816：仅向上游发送最小必要的查询名称，减少隐私泄露 |

**Kaminsky 攻击（0x20）原理简述：**  
攻击者通过向递归解析器发送大量伪造响应尝试污染缓存。`use-caps-for-id` 在出站查询中随机混合大小写（如 `wWw.GoOgLe.CoM`），权威服务器会原样返回，而伪造响应难以猜中正确的大小写序列，大幅降低投毒成功率。

### 4.3 禁用 ANY 查询（CIS DNS / PCI-DSS 要求6 — DNS 放大攻击防护）

```ini
deny-any: yes
```

**ANY 查询的放大攻击危害：**  
DNS ANY 查询会触发解析器返回所有类型的 DNS 记录（A、AAAA、MX、TXT、NS 等），  
单个 ANY 查询（~40 字节）可能触发超过 3000 字节的响应（放大因子 >75×）。  
攻击者通过伪造受害者源 IP 发送 ANY 查询，将解析器变成流量放大武器（DNS 放大 DDoS）。  

`deny-any: yes` 使 Unbound 对 ANY 类型查询返回 HINFO 记录（RFC 8482 合规），  
彻底消除此放大向量，同时对合法客户端影响极小（现代浏览器和操作系统不发送 ANY 查询）。

### 4.4 速率限制（PCI-DSS 要求6 — 反 DDoS）

| 参数 | 设定值 | 说明 |
|---|---|---|
| `ratelimit` | **1000** | 每个权威区每秒最大查询次数；超出后对该区域返回 REFUSED |
| `ip-ratelimit` | **100** | 每个客户端 IP 每秒最大查询次数（防单源滥用） |

### 4.5 DoT / DoH 就绪（PCI-DSS 要求4 — 传输加密）

PCI-DSS 要求4 规定持卡人数据在公共网络传输时必须加密。DNS 查询可能泄露用户访问行为，  
在跨境（日本→青岛）传输中明文 DNS 尤其面临中间人嗅探和 DNS 污染风险。

**DoT 启用步骤（证书就绪后）：**

1. 在 `/etc/unbound/unbound.conf` 中取消注释以下行：
   ```ini
   interface: 0.0.0.0@853
   tls-service-key: "/etc/letsencrypt/live/YOUR_DOMAIN/privkey.pem"
   tls-service-pem: "/etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem"
   tls-port: 853
   tls-min-version: "TLSv1.2"
   ```
2. 重载 Unbound：`sudo systemctl reload unbound`
3. 在防火墙（Azure NSG + UFW）中开放 853/tcp

**TCP Fast Open + BBR 对 DoT 的协同增益：**  
DoT 每次新建连接都需要 TLS 握手（额外 1–2 RTT）。`tcp_fastopen=3` 减少 TCP 三次握手时延，  
BBR 优化握手期间的拥塞窗口，二者协同使青岛客户端的 DoT 首查时延降低约 20–40%。

### 4.6 DNSSEC 验证链

```ini
auto-trust-anchor-file: "/var/lib/unbound/root.key"
```

Unbound 作为验证型解析器（Validating Resolver），对所有支持 DNSSEC 的域名验证签名链，  
确保从根区（.）到目标域名的完整信任链完整性。`deploy-unbound.sh` 在部署时自动通过  
`unbound-anchor` 初始化根信任锚并下载最新根提示文件。

### 4.7 日志与审计（PCI-DSS 要求10）

```ini
use-syslog: yes
log-queries: yes
log-replies: yes
log-servfail: yes
```

DNS 查询日志通过 syslog 持久化，供安全审计和异常检测使用。  
高流量生产环境可将 `log-queries`/`log-replies` 设为 `no` 以降低 I/O 负载，  
但 PCI-DSS 审计场景建议保持开启并配合日志轮转（`logrotate`/`rsyslog`）。

---

## 5. 文件说明

| 文件 | 路径 | 用途 |
|---|---|---|
| `unbound.conf` | 仓库根目录 | Unbound 主配置（部署后复制至 `/etc/unbound/unbound.conf`） |
| `sysctl-dns.conf` | 仓库根目录 | DNS 专用内核网络参数（部署后复制至 `/etc/sysctl.d/99-dns.conf`） |
| `deploy-unbound.sh` | 仓库根目录 | 一键部署脚本（安装、sysctl、systemd 覆盖、启动 Unbound） |
| `config/unbound.conf` | `config/` | 扩展版 Unbound 配置（供参考） |
| `scripts/deploy.sh` | `scripts/` | 完整部署脚本（含 UFW、auditd 等 OS 层工具） |

---

## 6. 部署后验证

```bash
# 验证基础解析功能
dig @127.0.0.1 www.google.com A

# 验证 DNSSEC（应返回 SERVFAIL — 表示验证链正常拒绝签名失败的域名）
dig @127.0.0.1 sigfail.verteiltesysteme.net A

# 验证 ANY 查询被禁用（应返回 HINFO 而非完整记录集）
dig @127.0.0.1 www.google.com ANY

# 验证身份信息已隐藏（应返回 REFUSED 或空响应）
dig @127.0.0.1 version.bind CHAOS TXT
dig @127.0.0.1 id.server CHAOS TXT

# 查看 Unbound 实时统计（不重置计数器）
sudo unbound-control stats_noreset

# 查看 systemd 覆盖是否生效
systemctl show unbound | grep -E 'LimitNOFILE|OOMScoreAdjust|Restart'

# 验证内核 sysctl 参数已应用
sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc \
       net.ipv4.tcp_fastopen net.core.rmem_max net.core.wmem_max
```

---

## 7. 故障排查

### Unbound 无法启动

```bash
# 检查配置语法
sudo unbound-checkconf /etc/unbound/unbound.conf

# 查看最近日志
journalctl -u unbound -n 50 --no-pager
```

### DNS 解析返回 SERVFAIL

```bash
# 检查 DNSSEC 根信任锚状态
ls -la /var/lib/unbound/root.key

# 手动刷新根信任锚
sudo unbound-anchor -a /var/lib/unbound/root.key

# 刷新根提示文件
sudo curl -o /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache
sudo chown unbound:unbound /var/lib/unbound/root.hints
sudo systemctl restart unbound
```

### 跨境延迟高 / 解析超时

```bash
# 确认 BBR 已激活
sysctl net.ipv4.tcp_congestion_control
# 预期输出：net.ipv4.tcp_congestion_control = bbr

# 检查 Unbound serve-expired 命中率
sudo unbound-control stats_noreset | grep expired

# 测试 serve-expired 行为（停止上游时是否仍返回缓存）
sudo unbound-control flush www.google.com
dig @127.0.0.1 www.google.com A +stats | grep "Query time"
```

### OOMScoreAdjust 验证

```bash
# 查看 Unbound 进程的 OOM 分数
cat /proc/$(pgrep -f unbound | head -1)/oom_score_adj
# 预期输出：-500
```
