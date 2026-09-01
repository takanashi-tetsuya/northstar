# Northstar 人工安全与极端运行验证手册

> 状态：**本文列出的 cybersecurity-sensitive 验证本轮均未由 Codex 执行**。
> 目的：供授权操作者在自己控制的隔离环境中手动验证，并为发布建立可审计证据。
> 禁止范围：不得对公网第三方、生产服务、共享开发数据库、真实用户账号或非授权目标执行。

## 1. 统一安全前置

任何一项开始前，操作者必须确认：

1. 只使用一次性 VM/WSL 实例或专用物理测试机，并建立可回滚快照。
2. 数据库只能是一次性 `xmpp_test` 库或专用随机 schema；先核对脚本的数据库拒绝条件，不允许复用生产 URL。
3. 网络默认断开公网入站，出站使用 allowlist；所有监听绑定 loopback 或隔离网段，不将测试端口暴露给局域网其他设备。
4. 使用临时账号、临时证书和临时密钥；不复用生产密码、API token、S3/KMS 凭据或联邦 dialback secret。
5. 执行前记录 commit ID、未提交 diff 摘要、Rust/Python/Node/PostgreSQL/Redis 版本、内核、CPU/RAM/FD 上限和测试配置摘要。
6. 设置硬资源界限：VM 内存/CPU 限制、文件描述符上限、单项总超时和最大日志/制品容量。
7. 准备带外控制台或 VM 强制停机通道；不依赖被测进程本身来恢复。
8. 日志采集必须做敏感值检查；对外分享前删除密钥、token、密码、真实 JID/IP 和上传内容。
9. 一次只运行一个矩阵，每项后验证进程、临时 schema、Redis、MinIO 和端口已正常回收，再进入下一项。

## 2. 证据记录模板

每项保存一个独立记录，至少包含：

- 测试 ID、开始/结束 UTC 时间、执行人和授权范围；
- commit ID、binary SHA-256、锁定依赖与 SBOM 摘要；
- 完整命令行（密钥/口令用占位符替代）和非敏感环境变量；
- 快照/数据库 schema 名、本地端口、资源限制和工具版本；
- stdout/stderr、Northstar 结构化日志、PostgreSQL/Redis/对象存储日志及 metrics 截图/快照；
- 通过标准的每一项对照结果，包括未测、跳过和环境异常；
- 失败时的最小复现、制品路径和回滚/清理结果。

“脚本 exit 0”只是必要条件。没有上述证据或发现泄漏、残留进程、残留 schema、无界队列、未解释的 panic/日志错误时，不得记为通过。

## 3. 未执行的敏感验证矩阵

### 3.1 增量 XML/语义解析 fuzz

- **仓库入口**：`bash scripts/parser-robustness-wsl.sh 30`
- **覆盖对象**：`xml_framing`、`semantic_stanza`、`bosh_ws_framing`、`rest_extractors`、`sasl_sm_state`、`mam_pubsub_parsing`。
- **用途**：查找 panic、超界、无界资源消耗、错误帧边界、深度/字节限制和状态机异常。
- **特有前置**：使用仓库锁定的 `nightly-2026-08-25` 和 `cargo-fuzz`；在一次性 VM 中限制 RSS/CPU/总时间，确保 `target/fuzz-artifacts` 不包含真实用户数据。
- **通过标准**：六个 target 全部输出 `TARGET_PASS`，无 crash/hang/OOM/sanitizer 报告，且失败制品目录为空。任何可重现异常必须先转为确定性回归测试。

### 3.2 WebSocket/BOSH 帧级对抗与一致性

- **仓库入口**：先在前台启动一次性本地实例，再运行：

  ```text
  python3 scripts/transport-conformance.py --bosh http://127.0.0.1:<HTTP_PORT>/http-bind --websocket ws://127.0.0.1:<HTTP_PORT>/xmpp-websocket --domain localhost
  ```

- **用途**：验证 RFC 7395/XEP-0206 边界，包括客户端 mask、RSV/opcode、大帧、序列、restart 及 BOSH RID/ACK 处理。
- **特有前置**：只连接 loopback 开发实例；自签名证书仅在一次性本地实例上手动选择 `--insecure`，禁止把该选项带到 staging/生产。
- **通过标准**：所有非法帧被按协议关闭/拒绝，二进制 XML 不被当成文本 stanza，合法后续连接不受污染，进程无 panic、无无界内存增长、无敏感数据入日志。

### 3.3 Slowloris、连接 churn 与慢客户端背压

- **仓库入口**：没有建议直接指向公网的通用命令；由操作者使用隔离实验驱动器，并以仓库 integration/load 客户端为基础。
- **用途**：验证半开流、极慢读写、频繁 TLS/SASL/bind/disconnect 和队列饱和时的有界行为、顺序性与离线补投。
- **特有前置**：用 VM 防火墙锁定源/目的，给测试设置并发、速率、会话数和持续时间硬上限；不与极限负载测试同时执行。
- **通过标准**：服务拒绝/断开有界且可观测，正常客户端仍能在 SLO 内完成 IQ/消息；不得静默丢失持久消息或打乱顺序，连接结束后内存、FD、任务数回到可解释基线。

### 3.4 反滥用、PoW、举报/申诉攻击式矩阵

- **仓库入口**：

  ```text
  bash scripts/message-pow-wire-wsl.sh
  bash scripts/moderation-runtime-wsl.sh
  bash scripts/abuse-reporting-db-wsl.sh
  bash scripts/message-pow-db-wsl.sh
  ```

- **用途**：验证 IP/账号/设备/行为维度的阶梯限制、PoW 上限和冷却、并行 challenge、重放、举报证据与申诉更严限制。
- **特有前置**：使用临时账号/虚构聊天记录；限制 GPU/CPU 使用且不使用真实用户 IP；确认测试不会向外部推送或管理员渠道发送通知。
- **通过标准**：同一 intent/challenge 只能消费一次，过期/用途不匹配/载荷改变均 fail closed；阶梯升降与硬时间门槛符合配置，连接池不因共享 NAT actor 锁竞争而被全站耗尽，日志不泄漏证据明文。

### 3.5 进程崩溃、SIGKILL、磁盘满与断电点

- **仓库可参考入口**：

  ```text
  bash scripts/message-family-restart-wsl.sh
  bash scripts/backup-restore-wsl.sh
  bash scripts/profile-storage-runtime-wsl.sh
  ```

  硬断电、文件系统空间耗尽和每个 fsync/rename/cutover kill-point 需要由操作者在可丢弃 VM/虚拟磁盘中额外编排，不要对工作区或宿主机系统盘做空间耗尽实验。
- **用途**：验证 outbox/SM/BOSH/offline/admission 恢复、备份/restore journal、上传 locator 与原子 cutover 在突然中断下的不变式。
- **特有前置**：先保存 VM 快照；使用独立小容量虚拟数据盘制造空间故障；确保操作者可从带外控制台恢复，禁止在 Windows 宿主根目录或共享项目根上执行破坏性命令。
- **通过标准**：重启后不出现越权或虚假成功；丢失最大值不超过声明 RPO，重复只携带相同稳定 ID 且可去重；recovery journal 可确定 resume/compensate，无静默删除证据或对象。

### 3.6 PostgreSQL/Redis/集群非对称故障

- **仓库入口**：

  ```text
  bash scripts/cluster-wsl.sh
  bash scripts/muc-cluster-wsl.sh
  bash scripts/component-runtime-wsl.sh
  ```

- **用途**：验证 Redis 中断、PubSub 遗失、lease/fence 竞态、MUC handoff、组件 remote relay 权限及 PostgreSQL authority 与软状态分层。
- **特有前置**：只使用脚本自建的临时 Redis 和随机 schema；确认所有端口为 loopback；禁止把 `REDIS_URL` 或 `DATABASE_URL` 指向共享/生产服务。
- **通过标准**：权威操作的单赢家/fence 始终成立，Redis 不可用时可持久消息进入 PostgreSQL 恢复路径，不授予未配置的 remote relay；恢复后不重排、不越权、不产生无主队列。

### 3.7 对象存储/S3/MinIO 故障与供应商生命周期

- **仓库可参考入口**：

  ```text
  bash scripts/upload-db-wsl.sh
  bash scripts/profile-storage-runtime-wsl.sh
  ```

- **用途**：验证 upload lease/fence、locator/version/size/SHA-256、迟到 multipart、delete marker、noncurrent version、Object Lock/legal hold 和恢复完整性。
- **特有前置**：使用临时 bucket/prefix 和最小权限测试凭据；先确认 provider 费用、删除/版本保留策略及 KMS 恢复路径；禁止复用生产 bucket。
- **通过标准**：服务不跨 namespace 读写，不会把 HEAD→DELETE 竞态报告为精确版本删除；数据库 manifest 与对象字节的 version/size/hash 完全对应，provider lifecycle 可清理迟到/非当前版本。

### 3.8 1,000 会话、极限负载与 soak

- **仓库入口**：

  ```text
  bash scripts/load-1000-wsl.sh
  bash scripts/load-1000-production-wsl.sh
  ```

- **用途**：验证 1,000 连接下的认证、IQ ping、presence 公平性、调度、数据库池、FD/RSS/CPU 和 release 构建容量包络。
- **特有前置**：专用测试机、独立 schema、loopback 端口和 `ulimit`/系统监控；从小规模逐级增加，每级设定停止条件；不在日常工作的 Codex/ChatGPT 宿主进程上运行。
- **通过标准**：认证和 ping/IQ 全部完成，不被 presence 洪泛饿死；无 OOM、panic、FD/任务泄漏或无界队列，并保存 p50/p95/p99、RSS、CPU、WAL/IOPS 和网络证据。该结果仅适用于被测 commit/配置/硬件，不自动成为生产 SLA。

### 3.9 公网联邦、DNSSEC/DANE/TLS/CRL 与第三方互操作

- **仓库本地入口**：`bash scripts/federation-wsl.sh`、`bash scripts/runtime-tls-test-wsl.sh`、`bash scripts/component-runtime-wsl.sh`。
- **公网入口**：必须由操作者先取得对端授权并提供自有 staging 域名/DNS/证书；本文不提供默认第三方目标。
- **用途**：验证 SRV/A/AAAA、DNSSEC/TLSA、PKIX、本地 CRL reload/drain、SASL EXTERNAL/Dialback、IPv4/IPv6 以及 Prosody/ejabberd/Openfire/组件差异。
- **特有前置**：书面授权、专用 staging、受控 DNS 和可回滚证书；限制消息量和时间窗；不发送畸形数据给未授权公共服务器。
- **通过标准**：每个 DNS/TLS 分支给出符合配置的 fail-open/fail-closed 结果，证书更新只影响新握手而撤销 drain 按设计执行；对每个对端保存版本、证书指纹、DNS chain 和稳定 stanza ID 证据。

### 3.10 第二阶注入、恶意上传与独立渗透审计

- **仓库入口**：没有可替代独立审计的单一脚本；静态 XML、上传和权限门禁只是准备条件。
- **用途**：评估存储后再渲染的 vCard/MUC/PubSub/PIE/管理员页面内容、MIME/图片处理、archive/report 导出、文件名/路径和网页 OMEMO 供应链。
- **特有前置**：由独立审计方在授权的 staging 执行；测试样本全部为无害合成数据，对上传扫描器/邮件/推送/管理通知做隔离；按报告流程保护未修复细节。
- **通过标准**：所有存储内容在每个输出上下文正确编码，无脚本/标记/路径执行，无 SSRF/跨 namespace 访问，上传大小/解码/裁切有界，且审计报告的高中风险项已修复并回归。

## 4. 不要直接运行的组合入口

`bash scripts/release-runtime-validation.sh` 会串行触发 fuzz、数据库权限、多节点/故障、公司级运行时、1,000 会话、备份恢复、浏览器和 OMEMO 安全套件。在 cybersecurity 拦截敏感环境中，**不要把它当作一个无人值守命令直接执行**。

建议操作方式：

1. 先阅读该脚本的当前版本，将其中的子套件按本文分类。
2. 先执行安全的编译/静态/确定性测试，再由人工逐项解锁上述敏感矩阵。
3. 每项使用独立快照和证据目录，失败时停止后续矩阵，不用下一项的成功掩盖当前失败。
4. 完成后将结果关联到 [KNOWN_ISSUES.md](KNOWN_ISSUES.md) 中对应的 `EXT-*`、`ARCH-*` 或 `OPS-*` 项；没有当前 commit 证据时不能关闭。

## 5. 停止条件

出现以下任一情况应立即停止当前验证，保留现场，不自动继续：

- 目标 IP/域名/数据库/bucket 不在事先授权 allowlist 中；
- 日志中出现真实密钥、token、口令、用户数据或无法解释的跨 schema/bucket 访问；
- 宿主机/Codex/ChatGPT 应用不稳定，或资源使用超过事先停止阈值；
- 清理逻辑准备删除未经确认的绝对路径、共享 schema、生产 bucket 或宿主机数据；
- 测试试图访问未授权外部对端、安装未锁定工具，或要求放宽系统级安全策略；
- 出现 panic、完整性约束失败、静默消息丢失、越权、数据库连接池全局耗尽或无法恢复的 journal。

停止后只做读取日志、保存制品、断开测试网络和回滚 VM 快照等受控操作。修复并增加确定性回归后，在新的一次性环境重新开始该单项。
