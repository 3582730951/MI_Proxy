# Sing-box Next 运维面板与智能调度系统开发计划

> 目标：基于 `fscarmen/sing-box` 的能力边界，重新设计并实现一个更工程化、可观测、低资源占用、可安全验收、可持续运维的 Sing-box 全家桶控制面板。本文档面向 Codex / GPT-5.5 辅助开发流程、后端/前端/DevOps/安全测试团队使用。
>
> 重要边界：本文档只用于合法、合规、授权网络环境中的代理节点管理、可观测性、路由优化和隐私保护。所谓“0 漏洞”在工程上不能被绝对证明，验收目标定义为“发布时无已知高危/严重漏洞、无可复现阻断级漏洞、关键安全控制通过多工具与人工复测”。
同时需要注意的是,这里的BBR+智能调度是需要采集所部署的vps的cpu/内存/还有根据链接进来的ip结合vps自己网卡公网ip做动态的算法选择和优化，同时你还要考虑做链接目标的ip缓存，避免每一次新连接的ip都去找地区这种
---

注意:测试必须要在cmd-》wsl->ubuntu->docker创建容器（ubuntu22.04 0依赖开始），同时项目需要实现，如果端口被占用的话，可以采用灵活的动态切换
前端UI参考example里面的图片

## 1. 背景与基线分析

当前参考项目 `fscarmen/sing-box` 是面向 VPS 的 Sing-box 一键多协议脚本，README 中列出能力包括 Sing-box for VPS 运行脚本、无交互安装、Argo Tunnel、Cloudflare API 自动创建 Argo、Docker / Docker Compose 安装、多协议配置和订阅输出等。项目更接近“安装器 + 配置生成脚本 + 订阅输出器”，不是完整的多租户 Web 控制平面。

本项目不做简单复制，而是重构为：

1. **控制平面**：统一管理节点、协议、路由规则、WARP 出口池、证书、订阅、策略、用户与审计。
2. **数据平面**：轻量 Agent 管理 sing-box、内核参数、BBR/拥塞控制、WireGuard/WARP、系统指标采集。
3. **可视化运维面板**：全链路指标、日志、链路质量、成本、容量、告警、变更历史、订阅规则命中率可视化。
4. **智能调度引擎**：基于延迟、丢包、出口质量、CPU/内存/FD/连接数、区域、站点策略和故障状态进行出站选择。
5. **安全发布门禁**：SAST、SCA、DAST、IaC、容器镜像、SBOM、模糊测试、渗透测试、红队复测、供应链签名全部纳入 CI/CD。

---

## 2. 总体目标

### 2.1 产品目标

构建一个名为 `sing-box-next-panel` 的系统，满足：

- 保留原项目一键部署、多协议、订阅生成、Argo/WARP 集成、Docker 部署能力。
- 增加完整 Web UI，所有核心运维数据图表化、面板化、可钻取。
- 增加分布式 Agent，支持多 VPS、多区域、多出口、多配置版本统一管理。
- 增加自动化路由规则生成与校验，避免中国大陆网站、域名和 IP 段误走代理出口。
- 增加 WARP 出口池，支持多个 WARP WireGuard profile，按站点策略、健康状态和负载选择出口。
- 增加低资源占用运行模式，适配 512MB/1GB 小内存 VPS。
- 增加高并发稳定性验证、容量模型、自动扩缩容建议和故障应急预案。
- 增加工程级安全门禁，使发布版本达到“无已知阻断漏洞”标准。



---

## 3. 架构设计

### 3.1 逻辑架构

```text
Browser / Mobile Web
        |
        v
Next.js / React Admin UI
        |
        v
API Gateway / BFF
        |
        +-------------------------------+
        |                               |
        v                               v
Core Control Plane                 Observability API
- Node registry                    - Metrics query
- User/RBAC                        - Logs query
- Policy engine                    - Traces query
- Subscription compiler            - Alert API
- Warp pool manager
- Config versioning
- Audit log
        |
        v
PostgreSQL + Redis + Object Storage
        |
        v
Lightweight Node Agent on each VPS
- sing-box lifecycle
- config render/apply/rollback
- sysctl / BBR tuning
- WARP WireGuard profile manager
- metrics/log collector
- health probe
        |
        v
sing-box / nftables / systemd / WireGuard / Kernel TCP stack
```

### 3.2 推荐技术栈

| 层级 | 推荐技术 | 选择理由 |
|---|---|---|
| 前端 | Next.js + React + TypeScript + TanStack Query + ECharts/Recharts | 快速构建可视化面板，类型安全，SSR/SPA 均可 |
| 后端 | Go + Fiber/Gin 或 Rust Axum | 低内存、高并发、易做单文件部署 |
| Agent | Go 静态二进制 | 低资源占用，适合 VPS，便于 systemd 管理 |
| 数据库 | PostgreSQL | 强一致、审计、配置版本、策略关系建模 |
| 缓存/队列 | Redis / Valkey | 节点心跳、任务队列、实时状态 |
| 指标 | Prometheus remote-write 或 VictoriaMetrics | 资源占用可控，适合多节点指标 |
| 日志 | Loki / Vector / OpenTelemetry Collector | 轻量日志采集与查询 |
| 安全扫描 | Semgrep、CodeQL、Gitleaks、Trivy、Grype、Syft、OWASP ZAP | 覆盖源码、依赖、镜像、密钥、DAST、SBOM |
| 压测 | k6、wrk、vegeta、tc/netem、toxiproxy | 覆盖 HTTP API、订阅生成、配置下发、网络故障 |

---

## 4. 模块拆分

### 4.1 Control Plane

#### 4.1.1 Node Registry

功能：

- 节点注册、心跳、在线状态。
- 节点标签：区域、供应商、CPU、内存、带宽、协议、出口类型。
- 节点密钥轮换。
- 节点运行版本、sing-box 版本、Agent 版本、内核版本、拥塞控制状态采集。

验收：

- 1,000 个节点模拟心跳，控制面 99p API 延迟 < 300ms。
- 节点离线 30 秒内状态变更，2 分钟内触发告警。
- Agent 重启后能恢复任务状态，不重复执行危险任务。

#### 4.1.2 Policy Engine

功能：

- 策略优先级：直连中国大陆站点 > 私有地址 > 广告/恶意域名拦截 > 指定站点 WARP > 默认代理 > fallback。
- 支持 domain、domain_suffix、domain_keyword、domain_regex、geoip、rule_set、ip_cidr、process_name、port、protocol 等规则维度。
- 规则编译前进行冲突检测、覆盖率分析、命中率预估。
- 支持灰度发布：1%、5%、20%、50%、100%。
- 支持配置版本、差异对比、一键回滚。

验收：

- 10 万条规则编译时间 < 5 秒。
- 100 万条域名测试集分类准确率达到验收阈值。
- 规则发布失败时不会影响当前运行配置。

#### 4.1.3 Subscription Compiler

功能：

- 输出 sing-box、Clash Meta、Shadowrocket、v2rayN、NekoBox 等常见客户端订阅。
- 支持按用户、设备、区域、协议、出口策略生成订阅。
- 支持订阅令牌：短 token、长期 token、只读 token、一次性 token。
- 支持订阅访问审计、速率限制、防爆破。
- 支持订阅规则“避开中国大陆网站和域名”的自动生成与测试。

验收：

- 订阅生成 99p < 500ms。
- 订阅接口 1,000 RPS 时错误率 < 0.1%。
- 订阅 token 泄漏后可单独吊销，不影响其他用户。

#### 4.1.4 WARP Pool Manager

功能：

- 不依赖 Cloudflare 官方 WARP 客户端脚本，优先支持开源 WireGuard profile 生成工具或标准 WireGuard 配置导入。
- 支持多个 WARP profile：`warp-01`、`warp-02`、`warp-03`……
- 每个 WARP 出口独立健康检查：连通性、延迟、丢包、出口 ASN、IPv4/IPv6、DNS、HTTP 状态。
- 按站点策略启用 WARP，明确排除 Google Scholar / 谷歌学术相关域名，避免误走 WARP。
- 支持出口池负载均衡：least-latency、least-error、weighted-round-robin、sticky-by-domain、sticky-by-user。
- 支持出口异常自动摘除、冷却、恢复探测。

合规边界：

- 仅用于合法网络访问、隐私保护和链路质量优化。
- 不提供规避封禁、规避执法、规避风控特征库的对抗性方案。
- 所有 WARP profile 来源必须符合 Cloudflare 和相关工具的许可与服务条款。

验收：

- WARP 出口池中任意 1 个出口故障，30 秒内自动摘除。
- 指定站点策略命中率 > 99.9%。
- Google Scholar 域名测试集 100% 不命中 WARP 策略。
- WARP 出口切换不导致控制面配置生成失败。

---

## 5. 订阅规则与中国大陆站点直连策略

### 5.1 设计原则



核心原则：
以下的直连是指(非vps直连)而是订阅规则地直连
1. **大陆优先直连**：CN geoip、geosite-cn、常见中国大陆 CDN、运营商、政务、银行、支付、电商、视频、教育、地图、游戏、应用市场默认直连。
2. **私有地址直连**：RFC1918、localhost、link-local、ULA、运营商内网地址直连。
3. **DNS 防污染与防泄漏并重**：国内域名使用可信国内 DNS；非国内域名使用独立 DNS 策略；DNS 查询路径与流量路径一致。
4. **规则先白名单后代理**：所有明确大陆站点必须在代理规则之前命中 direct。
5. **订阅可测试**：每次规则更新必须跑域名分类回归测试。
6. **透明审计**：UI 展示每条流量命中哪个规则、为何选择 direct / proxy / warp。

### 5.2 规则优先级

建议编译顺序：

```text
1. ip_is_private / private CIDR -> direct
2. 中国大陆域名 rule-set -> direct
3. 中国大陆 IP rule-set -> direct
4. 中国大陆 CDN / 云厂商补充规则 -> direct
5. 用户自定义 direct 规则 -> direct
6. 明确排除 WARP 的域名，例如 Google Scholar -> proxy 或 direct，由用户策略决定
7. 指定需要 WARP 的站点集合 -> warp-pool
8. 用户自定义 proxy 规则 -> selected proxy
9. AI / Streaming / Developer / Social 分类规则 -> selected proxy
10. final -> selected proxy 或 direct，由部署模式决定
```

### 5.3 中国大陆直连规则来源

推荐支持多源合并，并在 UI 显示规则来源与更新时间：

- sing-box 官方 geosite / geoip 数据库。
- Loyalsoldier v2ray-rules-dat 或同类社区规则源。
- MetaCubeX / mihomo rule-providers 兼容规则源。
- 项目内置补充：银行、支付、政务、教育、运营商、云服务商、CDN。
- 用户自定义规则。

### 5.4 Google Scholar 排除策略

硬编码安全排除列表：

```yaml
warp_exclude:
  - scholar.google.com
  - scholar.googleusercontent.com
  - citations.google.com
  - academic.google.com
  - google.com/scholar
```

编译规则时：

- `warp_exclude` 的优先级必须高于 `warp_include`。
- 任意 `domain_suffix: google.com` 的粗粒度规则不得覆盖 `scholar.google.com` 的排除规则。
- CI 中加入 Google Scholar 专项测试。

### 5.5 订阅规则测试集

建立 `tests/rules/domain-classification/`：

```text
cn-direct.txt
cn-bank-direct.txt
cn-gov-direct.txt
cn-cdn-direct.txt
private-ip-direct.txt
warp-include.txt
warp-exclude-google-scholar.txt
proxy-default.txt
conflict-cases.txt
```

每条样例格式：

```csv
domain,expected_outbound,reason
www.taobao.com,direct,cn-ecommerce
www.gov.cn,direct,cn-government
scholar.google.com,proxy,warp-exclude
example-warp-target.com,warp-pool,user-warp-include
```

验收指标：

- 中国大陆域名直连测试集准确率 100%。
- 中国大陆 IP 测试集准确率 100%。
- Google Scholar 排除测试集准确率 100%。
- 规则冲突必须在发布前阻断。
- 规则更新后必须生成 diff 报告：新增、删除、覆盖、冲突、命中变化。

---

## 6. 前端 UI 与全数据可视化

### 6.1 信息架构

导航结构：

```text
Overview
Nodes
Routes & Rules
Subscriptions
WARP Pool
Protocols
Traffic
Observability
Security
Deployments
Incidents
Settings
```

### 6.2 Overview 总览

组件：

- 全局健康分：Healthy / Degraded / Critical。
- 在线节点数、离线节点数、告警数。
- 总连接数、活跃连接数、新建连接速率。
- 总流量、上行/下行速率。
- CPU、内存、磁盘、FD、网络 PPS。
- 99p API 延迟、订阅生成延迟、配置下发延迟。
- 出口质量排行榜：延迟、丢包、错误率、带宽。
- 最近变更与回滚入口。

### 6.3 Nodes 节点页

必须可视化：

- 节点地图或区域分布。
- 节点资源折线图：CPU、内存、负载、磁盘、网络。
- sing-box 进程状态、重启次数、配置版本。
- 内核参数：BBR 状态、队列算法、最大 FD、端口范围。
- 协议入站统计：VLESS、VMess、Hysteria2、TUIC、Trojan 等。
- Agent 日志与操作审计。

### 6.4 Routes & Rules 路由页

必须可视化：

- 规则命中漏斗：direct / proxy / warp / block / fallback。
- 中国大陆直连命中率。
- WARP 命中率与站点分布。
- 规则冲突矩阵。
- 域名测试工具：输入域名/IP，展示命中规则链。
- 规则版本 diff。

### 6.5 WARP Pool 页

必须可视化：

- WARP profile 列表、健康状态、出口 IP/ASN、IPv4/IPv6 状态。
- 每个 WARP 出口延迟、丢包、HTTP 成功率。
- 站点到出口的调度结果。
- 自动摘除/恢复事件。
- Google Scholar 排除规则状态。

### 6.6 Security 页

必须可视化：

- 漏洞扫描结果：SAST、SCA、DAST、容器、IaC。
- SBOM 依赖树与许可证风险。
- Secrets 扫描结果。
- CVE 严重程度分布。
- 安全门禁状态：Pass / Fail / Waived。
- 豁免记录：责任人、原因、过期时间、补救计划。

### 6.7 Incidents 应急页

必须可视化：

- 当前事件列表。
- 影响范围：节点、用户、区域、协议、订阅。
- 时间线：发现、确认、缓解、恢复、复盘。
- 一键执行 Runbook：切换出口、回滚配置、暂停发布、禁用 WARP profile、限流订阅接口。

---

## 7. 低资源占用优化

### 7.1 Agent 优化

- 单静态二进制，无 Python/Node 运行时依赖。
- 常驻内存目标：< 40MB RSS。
- 指标采集默认 15s 间隔，低配模式 60s 间隔。
- 日志本地 ring buffer，异常时再上报。
- 配置 diff apply，不重复重启 sing-box。
- 使用 systemd watchdog。

### 7.2 Control Plane 优化

- 热路径缓存：订阅模板、规则编译产物、节点状态。
- PostgreSQL 索引：node_id、tenant_id、config_version、created_at。
- 大量指标不写 PostgreSQL，进入时序库。
- 订阅生成支持 ETag / Last-Modified / gzip / brotli。
- 前端图表按需加载，长列表虚拟滚动。

### 7.3 sing-box 与系统参数

- 自动检测内核支持的拥塞控制算法：bbr、bbr2、cubic。
- 低配 VPS 默认限制日志级别为 warn。
- 自动调整 `nofile`、`somaxconn`、`tcp_fastopen`、`ip_local_port_range`。
- UDP 协议启用独立限速与连接保护。
- 对 Hysteria2 / TUIC 连接数设置软限制，避免小机型 OOM。

---

## 8. BBR+ 智能调度

### 8.1 能力定义

BBR+ 调度不是只开启一个 sysctl，而是结合：

- 内核拥塞控制能力探测。
- NIC 队列算法探测。
- 节点实时 RTT / loss / retransmits。
- sing-box outbound 成功率。
- 协议类型与流量画像。
- VPS 资源余量。

### 8.2 调度策略

出口评分：

```text
score = w1 * normalized_latency
      + w2 * packet_loss
      + w3 * error_rate
      + w4 * cpu_pressure
      + w5 * memory_pressure
      + w6 * connection_pressure
      + w7 * recent_failures
```

选择 score 最低的可用出口。

策略模式：

- `stable`：优先稳定，减少切换。
- `performance`：优先低延迟高吞吐。
- `low-resource`：优先低 CPU/内存消耗。
- `cost-aware`：优先低带宽成本节点。
- `manual`：管理员固定指定。

### 8.3 验收

- 50% 出口故障时，系统仍能保持可用。
- 出口故障切换 30 秒内完成。
- 同域名 sticky 策略不频繁漂移。
- 低配节点内存压力超过 85% 时自动降级采集频率和连接上限。

---

## 9. 安全设计

### 9.1 身份认证

- 管理端支持 OIDC / OAuth2 / Passkey / TOTP。
- API token 分 scope、过期时间、IP allowlist。
- Agent 使用 mTLS 或 Noise 协议认证。
- 所有敏感操作二次确认。

### 9.2 授权模型

RBAC：

- Owner：全权限。
- Admin：节点、规则、订阅管理。
- Operator：查看与执行 runbook。
- Auditor：只读审计。
- Developer：开发环境权限。

ABAC：

- 按 tenant、region、node_tag、environment 进一步限制。

### 9.3 密钥与配置安全

- 数据库敏感字段 envelope encryption。
- 订阅 token 哈希存储。
- WARP private key 加密存储。
- 配置下发只发送节点必要子集。
- 审计日志不可篡改，至少追加写。

### 9.4 网络安全

- 管理面默认不暴露公网，建议放在 VPN / Zero Trust / mTLS 网关后。
- API Gateway 强制 TLS 1.3。
- CORS 白名单。
- CSRF 防护。
- 严格 CSP。
- rate limit：登录、订阅、配置下发、Agent 注册。

---

## 10. “0 已知漏洞”验证计划

### 10.1 安全目标定义

发布版本必须满足：

- 无 Critical / High CVE 未修复项。
- 无可复现认证绕过、权限提升、RCE、SQL 注入、命令注入、SSRF、任意文件读写、密钥泄漏。
- 无默认弱口令。
- 无明文存储敏感密钥。
- 无未授权订阅读取。
- 无未授权节点控制。
- 所有安全豁免必须有负责人、过期时间、补救计划。

### 10.2 工具链

| 类型 | 工具 | 阻断条件 |
|---|---|---|
| SAST | CodeQL、Semgrep | High/Critical 阻断 |
| SCA | Dependabot、OSV-Scanner、Grype | High/Critical 阻断 |
| Secret Scan | Gitleaks、TruffleHog | 任意真实密钥阻断 |
| Container Scan | Trivy、Grype | High/Critical 阻断 |
| IaC Scan | Checkov、tfsec、kics | High/Critical 阻断 |
| DAST | OWASP ZAP baseline/full scan | High/Critical 阻断 |
| API Fuzz | Schemathesis、RESTler | 崩溃、5xx 激增、认证绕过阻断 |
| SBOM | Syft SPDX/CycloneDX | 缺失 SBOM 阻断 |
| License | FOSSA 或 ScanCode | 不兼容许可证阻断 |
| Supply Chain | cosign、SLSA provenance | 未签名 release 阻断 |

### 10.3 手工安全测试清单

认证：

- 登录爆破限制。
- TOTP 重放。
- Session fixation。
- JWT alg=none、kid 注入。
- Cookie Secure / HttpOnly / SameSite。

授权：

- 横向越权：A tenant 读取 B tenant 节点。
- 垂直越权：Operator 执行 Owner 操作。
- IDOR：通过猜测 ID 读取订阅/配置。

输入：

- SQL 注入。
- 命令注入：节点脚本参数、sysctl 参数、路径参数。
- SSRF：订阅转换、规则源下载、Webhook。
- Path traversal：日志下载、配置导出。
- XSS：节点名、规则描述、告警消息。

供应链：

- 构建环境密钥隔离。
- GitHub Actions 最小权限。
- Release artifact 签名。
- Docker image digest pinning。

### 10.4 发布门禁

```text
Gate 1: 单元测试通过率 100%
Gate 2: 集成测试通过率 100%
Gate 3: 规则分类测试通过率 100%
Gate 4: SAST/SCA/Secret/Container/IaC 无阻断项
Gate 5: DAST 无 High/Critical
Gate 6: 压测达到 SLO
Gate 7: 故障演练通过
Gate 8: 人工安全复核签字
Gate 9: SBOM + provenance + cosign 签名完成
Gate 10: Canary 24h 无 P0/P1
```

---

## 11. 高并发稳定性验证

### 11.1 容量模型

目标容量分层：

| 场景 | 节点数 | 在线用户 | 订阅 RPS | API RPS | 活跃连接 | 目标 |
|---|---:|---:|---:|---:|---:|---|
| Small | 10 | 1,000 | 50 | 100 | 10,000 | 单机控制面 |
| Medium | 100 | 20,000 | 500 | 1,000 | 200,000 | 控制面横向扩展 |
| Large | 1,000 | 200,000 | 2,000 | 5,000 | 2,000,000 | 分区、多副本、异步任务 |

### 11.2 压测范围

- 登录和鉴权。
- 节点心跳。
- 配置下发。
- 订阅生成。
- 规则编译。
- WARP 健康检查。
- 指标写入。
- 日志查询。
- 前端大盘加载。

### 11.3 压测工具

- k6：API 业务流。
- wrk / vegeta：订阅接口和静态资源。
- go test benchmark：规则编译器和调度器。
- tc/netem：延迟、丢包、抖动。
- toxiproxy：数据库、Redis、Agent 通道故障。
- chaos-mesh 或 LitmusChaos：Kubernetes 环境故障注入。

### 11.4 SLO

| 指标 | 目标 |
|---|---|
| 控制面 API 可用性 | 99.9% |
| 订阅接口可用性 | 99.95% |
| 节点心跳处理延迟 p99 | < 500ms |
| 订阅生成 p99 | < 800ms |
| 规则编译 p99 | < 10s |
| 配置下发成功率 | > 99.9% |
| UI 首屏 p95 | < 2.5s |
| 错误率 | < 0.1% |

### 11.5 稳定性测试矩阵

| 测试 | 方法 | 通过标准 |
|---|---|---|
| 峰值订阅 | 2,000 RPS，持续 30 分钟 | p99 < 800ms，错误率 < 0.1% |
| 节点心跳风暴 | 1,000 节点每 5 秒心跳 | 无队列堆积，状态准确 |
| 规则大更新 | 10 万条规则并发编译发布 | 不阻塞现有订阅和 API |
| 数据库主库重启 | toxiproxy / failover | 60 秒内恢复，数据不丢 |
| Redis 故障 | Redis 断开 5 分钟 | 核心 API 降级可用 |
| Agent 批量重启 | 30% Agent 同时重启 | 自动恢复，无重复危险操作 |
| WARP 出口故障 | 50% WARP profile 不可用 | 自动摘除，策略可用 |
| 内存压力 | 限制 Agent 内存 128MB | 不 OOM，自动降级 |
| 网络抖动 | 5% loss + 200ms RTT | 控制通道可恢复 |

---

## 12. 应急预案

### 12.1 事件分级

| 等级 | 定义 | 响应时间 |
|---|---|---|
| P0 | 大面积不可用、密钥泄漏、RCE、数据泄漏 | 15 分钟内响应 |
| P1 | 多区域故障、订阅不可用、配置错误影响大量用户 | 30 分钟内响应 |
| P2 | 单区域/单节点故障、性能明显下降 | 2 小时内响应 |
| P3 | 小范围 UI/指标/非核心问题 | 1 个工作日内响应 |

### 12.2 通用应急流程

1. 发现：告警、用户反馈、监控异常、CI 安全门禁失败。
2. 确认：值班人员确认影响范围和事件等级。
3. 止血：暂停发布、回滚配置、切换出口、限流、摘除异常节点。
4. 修复：定位根因，应用补丁或配置修正。
5. 验证：运行最小回归测试和健康检查。
6. 恢复：逐步解除限流、恢复发布。
7. 复盘：24-72 小时内完成 RCA。

### 12.3 Runbook

#### 12.3.1 错误规则导致大陆网站误走代理

触发条件：

- 中国大陆直连命中率突然下降。
- 大陆域名测试失败。
- 用户反馈国内站点异常。

操作：

1. 立即冻结规则发布。
2. 回滚到上一稳定规则版本。
3. 运行 `domain-classification` 回归测试。
4. 查看规则 diff，定位覆盖 direct 的 proxy / warp 规则。
5. 修复优先级后灰度 5%。
6. 观察 30 分钟后逐步放量。

#### 12.3.2 订阅接口高延迟

操作：

1. 开启订阅缓存强制模式。
2. 对异常 token / IP 限流。
3. 降低实时编译，使用最近稳定编译产物。
4. 检查数据库慢查询和 Redis 命中率。
5. 必要时横向扩容 API。

#### 12.3.3 WARP 出口池异常

操作：

1. 自动摘除失败率高的 WARP profile。
2. 将指定 WARP 站点 fallback 到普通代理出口或 direct，按用户策略决定。
3. 禁止新建 WARP profile，避免连锁故障。
4. 检查健康检查日志、DNS、WireGuard handshake。
5. 恢复后先进入冷却状态，再小流量灰度。

#### 12.3.4 Agent 批量离线

操作：

1. 检查控制面证书、Agent mTLS、时间同步。
2. 检查最近配置下发是否导致 Agent 崩溃。
3. 回滚 Agent 配置版本。
4. 批量 systemd restart，限制并发 5%。
5. 对无法恢复节点标记为 degraded，调度流量迁出。

#### 12.3.5 安全事件：密钥疑似泄漏

操作：

1. 立即吊销疑似 token / API key / Agent cert。
2. 暂停相关节点配置下发。
3. 轮换数据库加密密钥和订阅签名密钥。
4. 审计过去 7-30 天访问日志。
5. 生成影响范围报告。
6. 发布补丁并复测。

---

## 13. Codex 与 GPT-5.5 使用方案

### 13.1 Codex 工作模式

Codex 用于：

- 并行实现功能模块。
- 阅读仓库、回答代码问题。
- 修 bug。
- 自动生成 PR。
- PR 代码审查。
- 迁移、重构、测试补齐。
- CI 中执行可重复质量检查。

建议仓库结构：

```text
/AGENTS.md
/apps/web/AGENTS.md
/services/control-plane/AGENTS.md
/agent/AGENTS.md
/packages/rule-compiler/AGENTS.md
/security/AGENTS.md
/tests/AGENTS.md
```

### 13.2 根目录 AGENTS.md 要求

```markdown
# AGENTS.md

## Project Goal
Build a secure, observable, low-resource sing-box operations panel with rule compilation, WARP pool management, subscription generation, and node agents.

## Non-negotiable Constraints
- Never introduce unauthenticated admin APIs.
- Never log secrets, private keys, subscription tokens, or WARP private keys.
- All security-sensitive code must include tests.
- Any command execution must use allowlisted commands and structured args, never shell string concatenation.
- Rule changes must pass domain-classification tests.
- Google Scholar must never be routed through WARP.
- Mainland China domains and IP ranges must prefer direct routes.
- Every PR must update docs and tests.

## Required Commands
- pnpm test
- go test ./...
- pnpm lint
- pnpm typecheck
- make security-scan
- make rule-test
- make e2e

## PR Requirements
- Explain design choices.
- Include risk analysis.
- Include rollback plan.
- Include screenshots for UI changes.
- Include benchmark results for performance-sensitive changes.
```

### 13.3 Codex 任务拆分

每个 Codex 任务必须小而闭环：

1. `feat(rule-compiler): implement rule priority graph and conflict detector`
2. `feat(agent): add sing-box config apply with atomic rollback`
3. `feat(warp): add WireGuard profile registry and health probe`
4. `feat(ui): add route hit visualization dashboard`
5. `test(rules): add CN direct and Google Scholar WARP exclusion regression suite`
6. `security(api): add RBAC middleware with tenant isolation tests`
7. `perf(subscription): add ETag cache and benchmark`
8. `ops(ci): add CodeQL Semgrep Trivy Gitleaks ZAP gates`
9. `docs(runbook): add WARP pool failure and rule rollback procedures`
10. `chaos: add toxiproxy tests for database and Redis outages`

### 13.4 GPT-5.5 使用方式

GPT-5.5 用于更高层的复杂工作：

- 架构评审：检查模块边界、故障域、数据一致性。
- 威胁建模：STRIDE / LINDDUN / abuse case 分析。
- 安全审计：审查认证、授权、密钥、命令执行、SSRF、订阅暴露。
- 规则正确性：分析 direct/proxy/warp 优先级冲突。
- 压测结果解释：识别瓶颈并提出优化。
- 事故复盘：把日志、指标、时间线整理为 RCA。
- 复杂 PR 审查：结合 diff、测试结果、设计文档给出阻断意见。

### 13.5 推荐 AI 协作流程

```text
Issue Spec -> GPT-5.5 拆解设计 -> Codex 实现 PR -> CI 自动测试
      -> Codex PR Review -> GPT-5.5 架构/安全复核
      -> 人工 Review -> Canary -> 生产发布 -> GPT-5.5 复盘总结
```

### 13.6 AI 输出门禁

Codex 或 GPT-5.5 生成的代码必须满足：

- 不能直接合并到 main。
- 必须经过 CI。
- 必须至少一名人工 reviewer approve。
- 安全敏感 PR 必须安全负责人 approve。
- AI 生成的依赖新增必须走 SCA 和许可证检查。
- AI 生成的脚本不能包含 curl | bash 自动执行远程脚本模式。

---

## 14. 开发里程碑

### Phase 0：项目初始化，1 周

交付：

- Monorepo 初始化。
- CI/CD 基础流水线。
- AGENTS.md 分层指令。
- 基础安全扫描。
- 架构决策记录 ADR 模板。

验收：

- main 分支受保护。
- CI 至少包含 lint、test、typecheck、security scan。
- Codex 可创建 PR，自动审查可运行。

### Phase 1：核心控制面，2-3 周

交付：

- 用户/RBAC。
- 节点注册与心跳。
- 配置版本管理。
- 审计日志。
- Agent 最小可用版本。

验收：

- 100 节点模拟稳定运行 24 小时。
- 越权测试全部失败，即无法越权成功。

### Phase 2：规则与订阅，2-3 周

交付：

- 规则编译器。
- 中国大陆 direct 规则。
- WARP include/exclude 规则。
- Google Scholar 专项排除。
- 多客户端订阅输出。

验收：

- 规则测试集 100% 通过。
- 订阅压测 500 RPS 通过。

### Phase 3：WARP Pool 与智能调度，2-3 周

交付：

- 多 WARP profile 管理。
- 健康检查。
- 出口评分调度。
- 故障摘除与恢复。

验收：

- 50% WARP 出口故障仍可用。
- 指定站点策略命中率 > 99.9%。

### Phase 4：可视化运维面板，3-4 周

交付：

- Overview。
- Nodes。
- Routes & Rules。
- Subscriptions。
- WARP Pool。
- Security。
- Incidents。

验收：

- UI 首屏 p95 < 2.5s。
- 所有核心运维指标可视化。
- 关键操作都有审计日志。

### Phase 5：安全与稳定性硬化，2-4 周

交付：

- 完整安全扫描。
- DAST。
- API fuzz。
- 压测。
- 混沌测试。
- 应急 Runbook。

验收：

- 所有发布门禁通过。
- Canary 24 小时无 P0/P1。

---

## 15. 验收计划总表

| 类别 | 验收项 | 标准 |
|---|---|---|
| 功能 | 节点管理 | 注册、心跳、配置下发、回滚可用 |
| 功能 | 订阅生成 | 多客户端格式正确 |
| 功能 | 规则分类 | CN direct、WARP include、Scholar exclude 100% 通过 |
| 功能 | WARP Pool | 多 profile、健康检查、调度、摘除可用 |
| UI | 可视化 | 所有核心指标有图表和钻取 |
| 性能 | API | p99 < 目标 SLO |
| 性能 | 订阅 | 目标 RPS 下错误率 < 0.1% |
| 稳定性 | 故障注入 | DB/Redis/Agent/WARP 故障均有降级或恢复 |
| 安全 | SAST/SCA/DAST | 无阻断项 |
| 安全 | 渗透测试 | 无可复现高危漏洞 |
| 运维 | Runbook | P0/P1/P2/P3 全覆盖 |
| 发布 | SBOM/签名 | release artifact 完整可验证 |

---

## 16. CI/CD 建议

### 16.1 GitHub Actions 流水线

```yaml
name: ci
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pnpm install --frozen-lockfile
      - run: pnpm lint
      - run: pnpm typecheck
      - run: pnpm test
      - run: go test ./...
      - run: make rule-test

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: gitleaks detect --source .
      - run: semgrep ci
      - run: trivy fs --exit-code 1 --severity HIGH,CRITICAL .
      - run: syft . -o cyclonedx-json > sbom.json

  load-smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make docker-up-test
      - run: k6 run tests/load/subscription-smoke.js
```

### 16.2 发布流程

1. PR 合并到 main。
2. 自动构建 release candidate。
3. 生成 SBOM。
4. 镜像扫描。
5. cosign 签名。
6. 部署 staging。
7. DAST + 压测 + 规则测试。
8. Canary 5%。
9. 观察 24 小时。
10. 分批发布。

---

## 17. 数据库核心模型

```sql
users(id, email, name, role, created_at)
tenants(id, name, plan, created_at)
nodes(id, tenant_id, name, region, provider, status, agent_version, singbox_version, last_seen_at)
node_metrics(id, node_id, ts, cpu, memory, load_avg, rx_bps, tx_bps, connections)
configs(id, tenant_id, version, content_hash, content, created_by, created_at, status)
config_deployments(id, node_id, config_id, status, started_at, finished_at, error)
rules(id, tenant_id, priority, type, matcher, outbound, enabled, source, created_at)
rule_sets(id, tenant_id, name, source_url, checksum, updated_at)
subscriptions(id, tenant_id, user_id, token_hash, client_type, policy_id, expires_at)
warp_profiles(id, tenant_id, node_id, name, public_key, encrypted_private_key, status, last_probe_at)
warp_probe_results(id, warp_profile_id, ts, latency_ms, loss, http_success, exit_ip, asn)
audit_logs(id, tenant_id, actor_id, action, resource_type, resource_id, ip, user_agent, created_at)
incidents(id, tenant_id, severity, status, title, started_at, resolved_at)
```

---

## 18. API 草案

```http
POST   /api/v1/nodes/register
POST   /api/v1/nodes/{id}/heartbeat
GET    /api/v1/nodes
GET    /api/v1/nodes/{id}
POST   /api/v1/nodes/{id}/deploy-config
POST   /api/v1/nodes/{id}/rollback

GET    /api/v1/rules
POST   /api/v1/rules
POST   /api/v1/rules/compile
POST   /api/v1/rules/test-domain
POST   /api/v1/rules/publish
POST   /api/v1/rules/rollback

GET    /api/v1/subscriptions
POST   /api/v1/subscriptions
GET    /sub/{token}/{client_type}
POST   /api/v1/subscriptions/{id}/revoke

GET    /api/v1/warp/profiles
POST   /api/v1/warp/profiles
POST   /api/v1/warp/profiles/{id}/probe
POST   /api/v1/warp/profiles/{id}/disable

GET    /api/v1/metrics/overview
GET    /api/v1/logs
GET    /api/v1/audit-logs
GET    /api/v1/incidents
POST   /api/v1/incidents/{id}/runbook/{name}
```

---

## 19. 配置生成示例

### 19.1 路由片段示例

```json
{
  "route": {
    "auto_detect_interface": true,
    "rules": [
      {
        "ip_is_private": true,
        "outbound": "direct"
      },
      {
        "rule_set": ["geoip-cn", "geosite-cn", "cn-cdn", "cn-bank", "cn-gov"],
        "outbound": "direct"
      },
      {
        "domain_suffix": [
          "scholar.google.com",
          "scholar.googleusercontent.com",
          "citations.google.com"
        ],
        "outbound": "proxy-default"
      },
      {
        "rule_set": ["warp-include"],
        "outbound": "warp-pool"
      }
    ],
    "final": "proxy-default"
  }
}
```

### 19.2 WARP Pool 逻辑示例

```json
{
  "outbounds": [
    { "type": "wireguard", "tag": "warp-01" },
    { "type": "wireguard", "tag": "warp-02" },
    { "type": "wireguard", "tag": "warp-03" },
    {
      "type": "selector",
      "tag": "warp-pool",
      "outbounds": ["warp-01", "warp-02", "warp-03"]
    }
  ]
}
```

实际实现中，`warp-pool` 不应只依赖静态 selector，而应由控制面根据健康检查结果生成最新可用出口列表。

---

## 20. 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| 规则误判 | 访问异常、合规风险 | 规则测试集、灰度、回滚 |
| WARP profile 不稳定 | 指定站点不可用 | 健康检查、fallback、冷却 |
| 小 VPS OOM | 节点离线 | 低资源模式、连接上限、日志降级 |
| 安全漏洞 | 数据泄漏、节点被控 | 多层扫描、渗透测试、最小权限 |
| Codex 生成错误代码 | 质量风险 | CI、人工 review、GPT-5.5 复核 |
| 供应链污染 | 构建被植入 | lockfile、SBOM、签名、依赖审查 |
| 高并发订阅打爆 | 控制面不可用 | 缓存、限流、队列、横向扩展 |

---

## 21. Definition of Done

任一功能完成必须满足：

- 有设计说明或 ADR。
- 有单元测试。
- 有集成测试或 E2E 测试。
- 有安全影响分析。
- 有可观测性指标。
- 有失败回滚方案。
- 有文档。
- 通过 CI。
- 通过 Codex review。
- 关键模块通过 GPT-5.5 架构/安全复核。
- 通过人工 review。

---

## 22. 参考资料

- fscarmen/sing-box README：项目当前能力边界、安装方式、Argo / Docker / 多协议说明。
- sing-box 官方文档：route、route rule、rule_set、geoip/geosite、deprecated feature。
- Cloudflare WARP / WireGuard 相关开源工具：用于理解 WARP profile 管理方式，使用时必须遵守对应许可证和服务条款。
- OpenAI Codex 官方文档：Codex 可用于云端并行任务、GitHub PR、代码审查和 CI 质量门禁。
- OpenAI GPT-5.5 官方文档：适合复杂编码、工具型代理、长上下文检索、产品规格到计划、安全/架构复核等工作流。
