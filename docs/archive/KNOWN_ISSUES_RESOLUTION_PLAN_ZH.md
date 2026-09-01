# Northstar 已知问题与文档缺口总解决计划

> **历史计划快照——不得作为当前 backlog、当前能力声明或当前发布门禁。**
> 当前问题以 [KNOWN_ISSUES.md](../KNOWN_ISSUES.md) 为唯一权威清单，当前发布步骤以
> [RELEASE_CHECKLIST.md](../RELEASE_CHECKLIST.md) 为准；本文件仅保留当时的计划与决策轨迹。
>
> 状态：实施与验收计划；仓库内可实现项以各节状态为准，外部发布门禁不因此视为完成
> 基线：2026-08-30 当前工作区
> 范围：`docs/KNOWN_ISSUES.md`，以及 README、架构、集群、生产运维、安全审计、组件协议证据、本地化文档和 `XEP_MATRIX.md` 中记录的剩余问题
> 原则：先校正文档事实，再修代码；每一项必须同时具备实现、自动化证据、运维说明和诚实的剩余边界，才允许从已知问题列表移除。

## 1. 结论

文档中的问题大部分能解决或显著改善，但不能全部归类为普通代码缺陷：

1. **可以工程化解决**：XML 结构化生成、PubSub/PEP 即时通知持久化、集群故障策略、集群命令签名、MUC 分布式状态机、共享上传、全局配额、逐记录 legal hold、REST MAM 对齐、备份签名/加密、指标直方图、Swagger UI 等。
2. **可以缩小风险但不能承诺绝对消除**：C2S/S2S/组件投递的 socket-write/数据库完成歧义、BOSH 单 stanza 确认、Carbons/headline 临时 fan-out、远端 MUC 恢复和已有 TLS 会话的证书更新。
3. **必须依赖外部环境或独立第三方**：真实公网 DNSSEC/DANE/IPv6、目标硬件容量、第三方服务器/客户端兼容性、独立安全审计、告警接收器和离机恢复演练。
4. **不应由服务器实现**：Jingle 媒体处理、ICE 连通性检查、TURN 数据面、移动平台推送数据面、端点信任判断、OMEMO 私钥托管和服务器证明用户解密后的明文真实性。
5. **已有实现、只是历史文档或当前说明落后**：普通 direct message 的 Redis 故障持久降级、S2S outbox、PostgreSQL Stream Management 恢复、生产反滥用密钥 fail-fast、后台 worker 监督、独立 metrics listener、浏览器 SASL2/SCRAM/FAST、OMEMO 制品可追溯、SHA-1 verifier 清理和 yanked 依赖门禁等。不得把这些内容重复立项。

因此，目标不是让 `KNOWN_ISSUES.md` 变空，而是让其中只保留真实、当前、可验证的边界。

### 当前执行进度（2026-08-30）

- P0 的六份当前文档已经按代码事实校正，三份历史报告已经加上不可覆盖当前 backlog 的醒目标识；
- CI 已加入文档一致性/本地链接/XEP 矩阵结构门禁，以及 `AppState` 公共字段和协议层直接 `db::` 依赖的单调架构预算；
- DUR-C2S 的 cluster envelope 已升级为显式 `volatile`/`durable_c2s` 投递契约：协议 v8 携带真实 PostgreSQL fence，接收端在写 socket 前校验对应 spool row 及 stanza payload；v7 仅保留受限旧版推断，无法安全表达该语义的消息 fail closed，不再从 stanza ID 猜测 durability；
- DUR-S2S-NOSTORE 已实现：跨域 `no-store` 只复用已经认证且当前可写的 S2S/bidi route，并等待有界 socket-write 结果；不会创建 S2S outbox、MAM、offline 或 personal-admission projection，缺少实时 route、背压、断线或超时均显式失败；
- 上述两项已加入精确单元回归和联邦数据库拒写探针。当前 checkout 的最终格式、全目标编译、严格 Clippy、735 项纯测试和仓库静态门禁已经统一通过；91 项隔离 PostgreSQL/Redis/证书/runtime fixture 按本轮边界未执行，本文不把它们写成已通过。
- DOC-009 已建立机器校验的 traceability index，当前覆盖全部计划 Issue ID 与每个 `Core` 矩阵条目，链接到实现、migration、自动化 harness 和权威文档；链接断裂、状态非法、条目缺失或 Core 无测试引用会使 CI 失败。
- ARCH-SVC 已把 PEP 原子 mutation/query、XEP-0060 高频查询、PubSub durable outbox 与 digest 生命周期移入私有 `PubSubService`，并加入私有连接池的 `SmService` 与 `BlockingService`；`AppState` 保持 32 个公开字段，协议层直接 `db::` 依赖由 1280 降至 1120，低于 1135 的 CI 上限。剩余垂直切片继续作为受量化门禁约束的架构债务，而不是伪装成已完全解耦。
- API-MAM、API-DOCS 与 ADMIN-AMBIGUITY 已完成实现和静态证据：REST history 复用 MAM 查询，自托管只读 Swagger UI，operation/target reconciliation 具备可审计的幂等闭环；旧 archive 无可靠 direction 字段的边界仍明确保留。

## 2. 文档权威顺序与问题生命周期

### 2.1 权威顺序

当前事实按以下顺序判断：

1. 当前代码、数据库 migration 和可复现测试；
2. `XEP_MATRIX.md` 的协议能力边界；
3. `docs/KNOWN_ISSUES.md` 的当前 backlog；
4. `README.md`、`docs/ARCHITECTURE.md`、`docs/PRODUCTION_OPERATIONS.md`、`docs/CLUSTERING.md`；
5. 专项证据文档，如 abuse、component、SASL2/FAST/Bind2 证据；
6. changelog 和历史验收报告。

`V1.1_VALIDATION_REPORT_ZH.md`、`SEVEN_TASK_IMPLEMENTATION_AND_VALIDATION_REPORT_ZH.md` 和早期交接手册是时间点快照，不得覆盖当前代码和矩阵。

### 2.2 每个问题的统一状态

后续在唯一 backlog 中为每项分配稳定 ID，并使用以下状态：

- `Confirmed`：当前代码中仍可复现或静态确认；
- `Planned`：方案和验收标准已确定；
- `Implemented`：代码已完成，但尚未通过全部门禁；
- `Verified-local`：自动化本地证据通过；
- `Verified-external`：目标环境或独立第三方证据通过；
- `Accepted-boundary`：标准、隐私或外部职责导致的永久边界；
- `Historical`：只保留在 changelog/归档，不再属于当前 backlog。

### 2.3 完成定义

一项问题只有同时满足以下条件才算完成：

- 实现和 migration 可前滚、可失败恢复；
- 关键失败点有自动化测试，而不只覆盖成功路径；
- 指标、告警和运维恢复步骤齐全；
- README、架构、生产运维、XEP 矩阵和 OpenAPI 同步；
- 不把本地测试写成公网认证或生产 SLA；
- 不扩大 OMEMO、组件、Redis、备份或管理员接口的信任边界。

### 2.4 本计划对其他文档的覆盖

| 来源 | 纳入本计划的内容 | 处理方式 |
| --- | --- | --- |
| `README.md` / `README.zh-TW.md` | `no-store`、即时通知、实验集群、浏览器密钥恢复、Swagger、公网/客户端证据和 1,000-session 边界 | DOC-001–009、WEB、API、外部验证阶段 |
| `XEP_MATRIX.md` | 所有 Partial、Experimental、Pass-through 和 Core profile 的诚实边界 | 第 9 节分类处理；不把端点职责误列为服务器 bug |
| `docs/ARCHITECTURE.md` | 应用服务抽取、C2S/BOSH/S2S 投递语义、PubSub post-commit、隐私模型 | ARCH-SVC、DUR-C2S、DUR-PUBSUB、永久边界 |
| `docs/PRODUCTION_OPERATIONS.md` | retention、反滥用 key、CRL/OCSP/AIA、metrics/alerts、备份、容量和上线门禁 | SEC、FED、DATA、OPS 和第 10/14 节 |
| `docs/CLUSTERING.md` | 本地 socket、Redis 非持久控制面、MUC 一致性、滚动升级、共享 upload | CLU-POLICY/SIGN/MUC/STORAGE/QUOTA/KEY/TEST |
| `docs/ABUSE_AND_MODERATION_PRODUCTION_AUDIT.md` | PoW action binding、moderation retention、OMEMO 明文证据和独立审查 | SEC-POW、DATA-HOLD、永久隐私边界和外部审计 |
| `docs/COMPONENT_PROTOCOL_EVIDENCE.md` | XEP-0114/0225 的认证和 at-least-once 边界 | FED-COMPONENT；保留标准固有限制 |
| `docs/SASL2_FAST_BIND2_EVIDENCE.md` | TLS/secret 连续性和 deliberate boundaries | 作为已实现证据；只在 FED-CERT/channel binding 改动后补回归 |
| `docs/openapi.yaml` | REST MAM 表达能力、operation reconciliation、文档 UI 和路由一致性 | API-MAM、ADMIN-AMBIGUITY、API-DOCS |
| `THIRD_PARTY_NOTICES.md` / `third_party/libomemo.js/README.md` | OMEMO JavaScript/WASM 的来源、SBOM、制品 hash、构建可复现性和网页分发信任边界 | WEB-SUPPLY-CHAIN；区分“制品来源可追溯”和“源码可逐字节重建” |
| `docs/LOCALIZATION.md` | 静态语言包只能证明结构完整，不能证明翻译质量 | 所有功能稳定后一次性更新并做母语抽样 |
| v1.1/七任务/早期交接报告 | 仍有价值的历史决策和已经过时的风险 | DOC-008；只归档，不直接生成 backlog |
| changelog | 已解决事项和 release 时间点行为 | Historical；不覆盖当前矩阵和 known issues |

## 3. P0：先修正文档事实

这一阶段不改变协议行为，但必须最先完成，否则后续会反复开发已经解决的事项。

| ID | 当前问题 | 应采取的动作 | 验收标准 |
| --- | --- | --- | --- |
| DOC-001 | README、架构、运维和 KNOWN_ISSUES 曾把 XEP-0334 `no-store` direct message 写成无条件拒绝 | 已改为：本地托管收件人的在线资源可通过易失路径接收，但绝不进入 MAM/spool/offline；所有在线路由均未接受时返回 `service-unavailable`。要求权限变化与邀请原子落库的特定 MUC 操作仍可拒绝；跨域语义单列为 DUR-S2S-NOSTORE | 四份文档语义一致；静态文档断言和 local/cluster wire test通过 |
| DOC-002 | “Redis Pub/Sub 故障会丢所有流量”过于宽泛 | 按可靠性分级：普通 direct message 有 PostgreSQL spool；mutation 引发的 PubSub/PEP 即时事件有 PostgreSQL recipient-snapshot outbox；MUC/presence/Carbons 仍可能易失；digest、S2S、component 有各自持久队列 | KNOWN_ISSUES、CLUSTERING、ARCHITECTURE 使用同一分类表 |
| DOC-003 | Generic PubSub 被写成不跨域 | 明确同域跨节点由 cluster route，跨域由认证 S2S；原即时通知 commit-to-route 缺口已由 DUR-PUBSUB 的 PostgreSQL event outbox 关闭 | 文档与 `XEP_MATRIX.md` 一致 |
| DOC-004 | “federation worker process-local”容易被理解为待发数据只在内存 | 区分活 socket/worker 所有权与 PostgreSQL outbox claim；节点退出后可接管，仍保留 at-least-once | 添加 claim/write/complete 状态图和故障边界 |
| DOC-005 | 集群测试覆盖被低估 | 列出已有 TLS/mTLS、冲突、跨节点 direct/Carbons/presence/roster/MUC、kick/ban、Redis pause、坏 ACK、版本偏差、lease takeover；只把真实未覆盖项留下 | 测试名称能从文档链接到脚本 |
| DOC-006 | “1000 用户”容易误读 | 明确现有脚本是 1,000 个已认证 session/resource 的连接与调度 envelope，且默认不发送 initial presence；不是典型 1,000 活跃用户业务模型或 SLA | README 和运维文档使用“1,000-session envelope” |
| DOC-007 | abuse HMAC 仍被描述为可能在生产随机生成 | 明确非 loopback/Redis 部署已要求 mounted secret；真实剩余风险是多节点挂载了不同 key 而没有 deployment key-ID 校验 | 文档指向 current/previous key 轮换流程 |
| DOC-008 | 历史报告容易被当作当前 backlog | 将两份 v1.1 时间点报告移入 `docs/archive/` 或加醒目历史横幅；当前 KNOWN_ISSUES 成为唯一 backlog | 历史文档首页声明“不得用于判断当前能力” |
| DOC-009 | 部分能力重复散落在 README、矩阵、运维和证据报告 | 增加自动生成/校验的 traceability index：Issue ID → 代码 → migration → 测试 → 文档 → 当前证据级别 | CI 在链接断裂、状态冲突或 Core 无测试引用时失败 |

## 4. P1：单机生产基线的核心安全与可靠性

### 4.1 CORE-XML：全部外发 XML 迁移为结构化构建

**问题**：传输、安全边界已使用 `xml_builder`，但 MUC、MIX、PubSub、PEP、discovery、commands 等域逻辑仍保留大量经过转义的字符串模板。当前未确认直接注入漏洞，但维护者以后少一次转义即可形成风险。

**方案**：

1. 扩展 namespace-aware typed stanza builder，静态限制 QName，属性和文本只允许原始值进入 builder；
2. 将 IQ/error → message/presence → MUC/MIX → PubSub/PEP → S2S/component 分批迁移；
3. 让 outbound API 接收结构化 stanza 或已 parse-validated 的不可变片段，不接收任意 XML 字符串；
4. 将 `attr_escape`/`xml_escape` 收口到 builder 内部；
5. CI 禁止新增 `format!("<...`、未验证 fragment 和 transport 边界字符串插值；
6. 增加 Unicode、引号、namespace reset、重复属性、恶意 fragment、超深嵌套的 property test、round-trip parse 和 fuzz corpus。

**验收**：安全/传输边界无动态 XML 拼接；剩余例外必须在 allowlist 中逐项解释；所有协议 runtime suite 通过。

### 4.2 CORE-JID：旧数据迁移审计工具

**问题**：原子 PRECIS/IDNA 迁移拒绝 malformed JID 和 canonical collision 是正确的安全行为，但旧数据库可能因此无法启动，且当前主要依赖人工读错误。

**状态（2026-08-30）**：实现完成；最终全树静态门禁已经统一通过。运行时故障注入仍按本文发布门禁单独执行。

**已实现方案**：增加独立的只读 `audit-identities --dry-run`，它在正常配置、日志、TLS、bootstrap 和 migration 之前运行；只创建一个默认只读的 PostgreSQL 连接，并在 `REPEATABLE READ READ ONLY` 快照中按当前 schema 动态发现可用表/列。报告覆盖 malformed、非规范值、PRECIS collision、A-label/U-label collision、复合键冲突、JSON 身份容器形状、会话 owner/resource 一致性，且列出数据库 FK 与代码语义引用图、受影响表和人工修复建议。默认 JSON 仅输出进程内随机盐生成的 report-local 指纹；只有显式 `--include-sensitive-values` 才包含原值/canonical 值。工具不读取 password/secret/stanza/message、举报正文或 PubSub/PEP/MIX payload，不运行 migration，不提供 `--apply`/自动合并；结束前还断言 PostgreSQL 未给事务分配 XID并回滚。完整边界与副本修复流程见 `docs/IDENTITY_AUDIT.md`。

**验收状态**：单元测试覆盖强制 dry-run、显式敏感模式、默认报告不泄露原值、PRECIS/IDNA 冲突分类和查询禁读列；隔离 PostgreSQL fixture 在当前 schema 写入 A-label/U-label 冲突，断言完整报告且审计前后行逐字节不变，并纳入 stateful database CI。工具对 0001–当前中不存在的后期表/列会记录为 skipped coverage 而非失败。静态/隔离门禁完成前不宣称生产数据库已实际执行。

### 4.3 DUR-C2S：缩小 C2S/BOSH 确认歧义

**问题**：普通 direct message 已用 durable delivery fence 关闭 queue-to-socket 丢失窗口，但 write 成功、数据库完成前崩溃仍可能重复；BOSH 目前保守保留 row。

**状态（2026-08-29）**：实现完成；隔离 PostgreSQL fixture 已加入现有 SM/offline-replay 门禁，最终总门禁与 crash-point runtime 验证待所有并行重构收敛后执行。

**已实现方案**：

- 对启用 XEP-0198 的 TCP/WebSocket/BOSH，每个计数 stanza 的未确认队列项携带准确的 `(recipient_id,message_id,claim_id)`；claim 转移、SM checkpoint 与 `<a/>` 完成在 PostgreSQL 事务中更新。只有客户端推进 `h`（包括 `<resume h>`）才删除 spool；断线、重启、resume 过期或不可恢复 teardown 只释放 owner，绝不提前完成消息；
- 对未由 SM 管理的 BOSH，将 durable delivery 先绑定到即将返回的 response RID，再把响应交给 HTTP 层。只有通过 RID、结构和可选 key-sequence 验证的后续请求才能用 `ack` 原子删除所覆盖的 spool；重复 RID 只重放缓存中的完全相同字节。过期 lease 不能复活，actor 退出或 lease 过期只释放消息供重投；
- 对无 SM 的 TCP/WebSocket，在首次暴露字节前取得或续期一个短期、精确的 offline claim；成功 socket write 后只用该 claim 完成 row，超时、断线或进程崩溃则由 lease 到期释放。socket write 仍只是服务器可观察边界，因此语义明确为携带稳定 ID 的 at-least-once，而不是客户端处理证明；
- 本地托管收件人的 `no-store` 仅走在线、易失、绝不落库的分支；cluster protocol v9 envelope 必须显式携带 volatile/durable 属性，并由接收端核对 PostgreSQL projection、Ed25519 节点权限及 key-bound process instance。仅为滚动升级保留的旧版 delivery contract 接收路径在无法精确匹配 fence 时拒绝；
- members-only direct/mediated MUC invitation 的 affiliation 与 offline row 先原子提交；本地与跨节点在线投递携带同一个 `DurableDelivery`，不能再在队列接收后删除。来自本地域或远端域的 mediated invite 均由 SM/BOSH/非 SM socket-write 的同一确认边界完成；
- retention、前台 TTL/容量清理会在锁住候选 offline row 后排除任意 SM/BOSH owner；过期 BOSH fence 必须先由 replay 原子接管。通用管理员清空在存在 transport owner 时返回冲突，不再利用级联静默中断投递；
- Carbons/headline 若要提高可靠性，只做 session-scoped、短 TTL fence，不能把已经离线的 Carbon 当离线消息长期补投。

**验收状态**：Rust 单元测试覆盖 SM counter/重复 ACK/回绕和 BOSH byte-identical RID replay；新增隔离 PostgreSQL 测试覆盖 claim→SM fence→`<a/>`、`<resume h>`、非恢复 teardown 释放，无 SM socket 的 write 前 claim 与精确完成，以及 BOSH response RID bind、错误 RID 不完成、有效 ACK 完成、active owner 不可窃取、过期 lease 不可续期且可重新 claim。MUC fixture 另外覆盖本地及远端来源 mediated invite 入队后断线仍保留 row、只有传输确认才完成；retention fixture 覆盖 SM/BOSH owner 在 retention/TTL/admin clear 下均受保护、release 后才可删除。fixture 已接入 `scripts/sm-db-wsl.sh`、`scripts/offline-replay-db-wsl.sh`、`scripts/muc-db-wsl.sh` 与 `scripts/retention-db-wsl.sh`。本轮遵照“只进行静态检查”，不宣称已对当前 checkout 执行 socket kill、BOSH HTTP runtime、CSI 或 Gajim 验证；这些仍是最终生产验证门禁。

### 4.4 DUR-S2S-NOSTORE：跨域 `no-store` 不进入持久 outbox

**状态（2026-08-30）**：实现完成；最终全树静态门禁已经统一通过，跨域实时路由与断线故障注入仍属于运行时发布门禁。

**已实现语义**：在具备认证且可写的现有 S2S/bidi route 时执行有界 volatile send；调用方等待实际 socket write 完成，且不创建 outbox、MAM、offline 或 personal-admission projection。没有可接受的实时路由、发生背压、断线或超时时，向发送方返回可重试的 `wait/service-unavailable`。队列中的 volatile envelope 若调用方已超时或撤销，会在写入前被丢弃，不能悄悄回退到 durable outbox。需要持久历史 mutation 的 retraction 以及必须原子修改权限的 members-only direct invite 与显式 `no-store` 组合会被拒绝。

**验收状态**：Rust 单元回归覆盖 volatile envelope 无 outbox fence、只在 socket write 后确认以及取消/超时不写出；联邦 fixture 已加入数据库 trigger，任何带唯一标记的 `s2s_outbox` 写入都会使测试硬失败，并同时断言两端 outbox/MAM/offline/admission 均为零。普通可存储消息继续走严格顺序 durable outbox。fixture 已完成静态语法检查，但本轮遵照“只进行静态检查”的指令，不宣称已执行当前 checkout 的联邦 runtime 测试。

### 4.5 DUR-PUBSUB：PubSub/PEP 即时通知 outbox

**问题**：节点 mutation 已经事务提交，但普通即时通知在 commit 后只尝试一次；此窗口崩溃会永久丢通知。digest 和远端 S2S 已持久，不代表本地即时通知持久。

**方案**：

1. 建立 `pubsub_event_outbox`/统一 notification outbox；
2. 在节点 mutation 事务中写入不可变 recipient snapshot、稳定 event ID、payload digest、目标域/账号、到期时间；
3. worker 使用 lease、`SKIP LOCKED`、指数退避、容量上限、dead-letter/终态指标；
4. 同域本机/跨节点投递和远端 S2S projection 都以同一 event ID 幂等；
5. 对高频 PEP 提供合并策略，但设备列表、密钥 bundle 等安全敏感节点不得错误合并；
6. 明确订阅改变与已提交 recipient snapshot 的顺序语义。

**验收**：在 commit、claim、route、ack、delete 每个点 kill；允许稳定 ID 重复，不允许缺失；10 万 backlog 下验证公平、配额、TTL 和数据库 I/O。

**当前实现状态（静态/隔离数据库阶段）**：migration `0085` 已加入 mutation 同事务 recipient snapshot outbox、稳定 event/delivery ID、精确 payload bytes 与 SHA-256 绑定、按来源与收件人独立的流序号（单个离线订阅者不会阻塞整节点）、64 分片及目标域容量、TTL、dead-letter 和 payload 最小化。worker 使用 `SKIP LOCKED`、fenced lease、目标域交错的有界 batch、指数退避、lease takeover 与终态指标；Redis 不参与权威状态。publish/retract/purge/delete/config/collection、subscription/affiliation/authorization、PEP publish/owner mutation、legacy bookmarks 和 vCard/avatar projection 已迁移到原 mutation 事务。digest 通过 source delivery ID 幂等投影并保留事件时 show-values snapshot。OMEMO/legacy Axolotl 的 devices/bundle/prekey 节点在应用与数据库约束中禁止 coalesce；默认没有任何节点启用 coalesce。事件 audience 在请求线性化点冻结，之后的 unsubscribe 不追溯取消已接受事件；需要生成 SubID/兼容投影的并发路径在事务锁内验证 snapshot，不一致即回滚。已提供 Rust 单元与 ignored isolated-PG fixture；按本轮指令没有执行 server/GUI/runtime kill lab，因此 10 万 backlog、真实 route/kill-point 和目标硬件 I/O 仍是发布门禁，不能仅凭当前静态证据宣称完成生产验证。详细不变量见 `docs/PUBSUB_EVENT_OUTBOX.md`。

### 4.6 SEC-POW：PoW challenge 绑定 action intent

**问题**：现有 challenge 绑定 actor/action/有效期，但签发时未绑定最终 method、path 和 body；消费仍与幂等 mutation 原子化，因此不能增加免费操作次数，但可以把已完成的同 action challenge 换到另一 payload。

**方案**：定义 v2 action intent，签名内容包含 HTTP method/XMPP action、规范化 path、canonical body digest、actor、subject、难度、issued/expires、nonce 和 key ID。旧客户端保留有期限的 v1 兼容窗口，网页客户端升级后生产模式强制 v2。

**验收**：body/path/method/subject 任一字节变化均不能复用；相同幂等请求可安全重试；key rotation 和旧 challenge 到期行为明确。

### 4.7 SEC-BACKUP：备份真实性、机密性与防回滚

**问题**：同目录 SHA-256 只能检测意外损坏；能替换备份的攻击者也能替换 checksum。

**状态（2026-08-30）**：v2 manifest 携带单调 generation/sequence、完整制品摘要、Ed25519 签名和 age 加密；生产脚本及 base Compose 现在默认同时强制签名、age、持久 sequence/floor、私有 scratch 与 file-backed 分权数据库 URL，缺少任一能力会在访问数据库或生成明文之前失败。backup 与 restore 都使用容器内无 TCP 的一次性 PostgreSQL 验证 dump，不再要求生产 migrator 具备 `CREATEDB`；legacy 只剩单一、明确警告的 `development-legacy` 入口。恢复在任何切换前验证固定公钥、密文与明文摘要、展开预算、数据库 migration 和上传引用；`ALLOW_CONNECTIONS=false` 后若仍有 peer 会明确失败并要求先停止所有客户端，不调用 `pg_terminate_backend`。数据库替换、migrator-owned `public`、共享 ACL/default-privilege policy 与同文件系统上传切换仍由 maintenance fence、精确 fsync journal 及统一补偿状态机保护，数据库 ACL 在重新开放前原子收敛。`SIGKILL`/断电后的 journal 仍需人工恢复；restore 必须先停止 Northstar；rollback retention 默认明文，生产应使用加密卷。本轮只做静态/离线验证，最终容器内 age 与临时 PostgreSQL 流程仍需在发布制品上实际演练。

**方案**：

- 生成规范化 manifest，包含 schema generation、备份序号、时间、Northstar commit、数据库/object-store 范围和所有 digest；
- 使用 minisign/Ed25519 或组织 KMS/HSM 签名；恢复只信固定公钥；
- 使用 age/KMS 做离机加密，签名私钥与备份主机分离；
- 保存单调 generation 或受保护的最新备份索引，发现回滚；
- restore 在任何写入前验证签名、解密、完整性、版本和上传 metadata/object 对账。

**验收**：换包、篡改 checksum、截断、旧备份回滚、错 key、缺对象、重复对象和离机恢复演练均有自动/操作证据。

### 4.8 ARCH-SVC：按垂直切片抽取应用服务

**问题**：`AppState` 暴露大量数据库、网络、缓存和密钥能力，多个大型协议模块直接决定事务与副作用，扩大权限面并增加故障测试难度。

**当前改善和量化基线**：API control/cursor keyring、`UploadStore`、FAST/Dialback 密钥已经从公开字段收口为私有能力；敏感密钥使用 `Zeroizing`，这是有效的最小权限和内存生命周期改善。`PubSubService`、`SmService` 与 `BlockingService` 已继续收回高频事务和策略能力，但当前 `AppState` 仍有 32 个公开字段；`src/xmpp/protocol/mix.rs` 当前约 6,047 行，并存在 289 处直接 `db::` 引用。精确数字会随开发变化，验收关注的是公开能力面和直接数据库依赖持续下降，而不是只拆文件。

**方案**：不要一次性重写。按 Messaging → PubSub → MUC → Federation → Upload → Moderation → Auth 建立窄接口；协议层只解析、授权上下文组装和 XMPP error mapping；应用服务拥有事务、outbox、幂等与审计；密钥和存储字段私有化。

**验收**：每迁移一个垂直切片，保留 wire compatibility；可注入 fake store/clock/router；事务和 post-commit 副作用只有一个所有者；`AppState` 公共能力持续减少；协议模块不再直接获得通用 `PgPool`，只调用按领域授权的应用服务；CI 输出每个协议模块的行数、公开 `AppState` 字段和 `db::` 直接依赖趋势，防止重新耦合。

## 5. P1：实验集群晋升路线

在本节全部完成前，Redis 多节点模式继续标记为 Experimental，单进程仍是受支持生产基线。

**第一批当前状态（静态/纯单元阶段）**：CLU-POLICY、CLU-SIGN、CLU-KEY
已经落入源码与 migration `0088`；CLU-TEST 已建立不启动 Redis/PG/server
的故障矩阵和签名/epoch/lease 模型。按本轮约束没有执行真实 Redis、PostgreSQL、
server 或 GUI；CLU-MUC、CLU-STORAGE、CLU-QUOTA、真实 nemesis、滚动二进制和
soak 仍是未完成的晋升门禁，因此不能把 cluster 从 Experimental 提升。

### 5.1 CLU-POLICY：显式 Redis 故障策略

新增 `CLUSTER_FAILURE_POLICY=fail_closed|durable_direct_only`：

- `fail_closed`：控制面失联后停止新 bind/resume/MUC join/admin mutation，readiness 变 503；安全 lease 窗结束后由受监督 critical worker 退出，避免 split-brain；
- `durable_direct_only`：普通 direct message 只允许进入 PostgreSQL spool；拒绝 `no-store`、MUC mutation 和依赖 Redis 权威的操作；只要 PostgreSQL key/instance authority 健康，可长期保持该受限状态等待 Redis 恢复，不因 Redis 安全窗单独退出；
- PostgreSQL key/instance authority 失联时，两种策略都立即 fail-fast；
- Redis 恢复后按 peer key/instance authority → node lease → full-JID owner/connection lease → occupant epoch → 新 listener generation 的顺序 reconciliation，再恢复 ready。

新增 control-plane up/degraded/outage seconds/durable fallback/lease timeout 指标。

### 5.2 CLU-SIGN：集群命令应用层签名

Redis TLS、ACL、mTLS 只保护连接，不能阻止持有 publish 权限的错误主体构造合法 JSON 命令。

每节点使用 file-only Ed25519 key，protocol v9 envelope 覆盖 protocol version、domain namespace、source/destination node、channel、command kind、event/request ID、issued/expires、payload digest、key ID/key epoch，以及与 key epoch 独立的 exact connection UUID/instance epoch；命令与 ACK 全部签名。接收端验证 public-key allowlist、最小权限 command ACL、节点身份、channel、有效期、payload digest、replay、PostgreSQL current/previous key authority 和 exact key-bound process instance lease。

预部署 `staged_next` 只允许作为下一步 DB activation 的材料，绝不作为 wire authority；即使 staged/previous 私钥持有人从总线观察并复制当前 UUID/instance epoch，也会因 instance row 绑定了不同 key ID/epoch 而被拒绝。接收 authority 使用 PostgreSQL 剩余租期换算本地 monotonic deadline 的有界批量缓存，未知/过期/错 node/错 channel 一律 fail closed。

签名不能阻止一个已经完全失陷的合法节点滥用自身权限，因此还要按 command/domain 做最小权限 ACL。

### 5.3 CLU-MUC：PostgreSQL 权威的 MUC control/event 状态机

新增：

- `muc_control_operations`：operation ID、room/config version、动作、target JID/nick、target connection UUID/epoch、状态、到期；
- `muc_delivery_outbox`/`cluster_events`：room sequence、stable event ID、目标节点、claim token、TTL；
- affiliation/ban/destroy/config mutation、operation row、archive/outbox 在同一事务提交；
- Redis 仅唤醒，消费者即使错过 publish 仍可从 PostgreSQL cursor/lease 追上；
- presence/typing 继续作为有界软状态，通过 snapshot/lease/reconciliation 收敛，而不是无限持久化。

必须保持以下不变量：已 ban actor 不能在陈旧节点发言；延迟 kick 不能踢复用 nickname 的新连接；destroy 后旧缓存不能复活房间；同一 operation 只改变一次 durable state，通知可以用稳定 ID 重复。

### 5.4 CLU-STORAGE：共享 S3-compatible UploadStore

当前 `UploadStore` 抽象存在，但只有 local backend。增加 `local|s3`：stage object → 流式 hash/size → fenced DB claim → 幂等 promote/copy → metadata commit → reconciliation。对象存储没有原子 rename，不能假装 PostgreSQL 和 S3 是同一事务。

验收包括节点 A 上传/节点 B 下载、stage/copy/DB commit 各点 kill、重复 PUT、超时、凭据轮换、删除/retention 中断和 MinIO 双节点 fixture。共享 POSIX 只有在验证 atomic rename、fsync、locking 和一致性后才能列为支持。

### 5.5 CLU-QUOTA：deployment-wide 容量账本

增加 `MAX_ACCOUNTS_TOTAL`、`MAX_MUC_ROOMS_TOTAL`、`MAX_MUC_ROOMS_PER_OWNER`、deployment-wide live sessions/per-account sessions。远端创建者目前纳入全局房间上限；按远端域单独分配预算仍属于后续可选策略，而不是绕过全局上限的缺口。

使用事务容量 ledger/fenced lease，不在创建路径运行大表 `COUNT(*)`。创建、删除、房间过期/destroy 与计数同事务；已有数据超过新 cap 时只拒绝新增并告警，绝不自动删除。

**当前实现状态（静态/隔离数据库阶段）**：migration `0090` 已实现 account、MUC room、live binding 和 retained SM row 四套 PostgreSQL 权威账本；64 个固定 shard 的 hard budget 总和严格等于 deployment cap，新分配从稳定 UUID-byte shard 开始进行有界 cyclic probe，成功只锁一个计数行，热路径不做 `COUNT/SUM`。永久实体由 `AFTER INSERT/DELETE` trigger 与对象事务绑定；同账号 room/session 使用独立 owner row，所有路径统一 global→owner 锁序，owner transfer 按 UUID 排序。live binding 使用稳定 `lease_id`，connection ID 在 SM resume 中原子转移而不重复计数；关键 heartbeat、过期 `SKIP LOCKED` 回收、Drop、SM suspend/revoke、账号级联和房间 destroy 均为幂等或 fail closed。`DEPLOYMENT_CAPACITY_EPOCH` 使 PostgreSQL 保存的完整配置成为多节点 authority；同 epoch 异配置、回退、跳代、降额低于总量/owner/shard usage 都拒绝启动。迁移保守计算全部尚未物理删除的 SM rows（包括等待 fenced teardown 的 expired row）。纯单元测试与 ignored isolated-PG fixture 已加入；遵照本轮静态限制未执行数据库、多节点 crash 或 1,000-session runtime，因此这些仍是发布门禁。完整不变量见 `docs/DEPLOYMENT_CAPACITY.md`。

### 5.6 CLU-KEY：cluster signing key/instance authority

PostgreSQL 与既有 abuse key authority 并列、但完全分离地保存不泄露 secret 的 cluster current/previous/staged-next key ID、public-key fingerprint 和 rotation epoch；私钥只从权限受限文件载入并存于 `Zeroizing`。`cluster_node_instances` 以数据库时钟保存 `(domain,node_id) -> UUID, monotonic instance_epoch, signing_key_id/key_epoch, lease_until`，claim/heartbeat/release 都做 exact fencing；append-only 历史只记录 claim/release ownership 与其 key generation，普通 30 秒 heartbeat 只更新 current row，避免永久无界审计增长。

轮换使用 prepare → activate → retire：prepare 只登记 epoch+1 public key，不改变 signer；activate 只允许逐代晋升并保留旧 current 为 previous；retire 在新 current 拥有活跃 fenced instance 且超过 cache/envelope grace 后才可执行。启动顺序将 retire 延后到 claim 成功后，避免“先删 previous、后因 duplicate node claim 失败”使仍存活节点被全网拒绝。clean shutdown 先停止并 drain signed publish，再立即 release；drain 超时则保留 lease 等待自然过期。

### 5.7 CLU-TEST：故障模型和晋升门禁

增加 Toxiproxy/network namespace 或等价 nemesis，覆盖：

- 单向/双向节点分区和 split-brain；
- Redis 可达/PG 不可达及反向组合；
- MUC admin 的 commit/publish/ACK kill point；
- 当前版与上一正式版二进制混跑；
- expand schema → rolling binary → contract schema；
- Redis Sentinel/Cluster/托管 failover；
- 共享 object store 故障。

可用 TLA+ 或等价状态机模型检查关键不变量，但不得声称穷尽任意基础设施的所有 interleaving。

当前静态模型已覆盖 Redis/PG 单向组合、两种 policy 的长期/退出条件、过期/篡改/重放/错 channel/错 node/rolling-version、previous/staged 复制 instance tuple、duplicate node、lease takeover 与恢复次序。ignored PostgreSQL fixture 记录 claim/heartbeat/release/clean takeover 的后续运行证据入口；本轮没有把这些静态断言表述成真实故障实验通过。

**集群晋升门禁**：明确 RPO/RTO；全部不变量测试通过；24–72 小时 soak 无未解释丢失/乱序；慢节点 backlog 有 TTL/配额/隔离；安全评审通过；运维完成目标 Redis/PG/object-store 资格测试。

## 6. P2：联邦、TLS 和组件

### 6.1 FED-REVOCATION：撤销信息与现有连接处置

**状态（2026-08-29）**：本地签名 CRL bundle 路径、单调 TLS generation 和现有证书认证连接的精确 drain 已实现。C2S SASL EXTERNAL（包括尚未 bind 的已认证流）、入站 S2S SASL EXTERNAL、出站 S2S SASL EXTERNAL 都记录完整 peer DER chain、leaf issuer/serial/SHA-256、握手 generation 和精确 connection cancellation token。reload 只对新快照下得到明确 `CertRevoked` 的连接发出取消；过期、续期、信任根变化、CRL 不适用或其他验证失败不会变成全局踢线。XEP-0487 pin 在配置 CRL 时不能覆盖 PKIX/CRL 失败。DANE-EE 按 RFC 7673 替代 PKIX，因此 CA CRL 对纯 DANE-EE 授权链并不自动适用。

管理操作结果持久记录 previous/current generation、检查数和分方向 drain 数；结构化安全日志记录每个被取消连接的 issuer/serial/fingerprint/generation，Prometheus 暴露存量与累计 recheck/drain。代码仍不盲目访问证书给出的 AIA/CRL URL。纯单元门禁已覆盖 exact token、ABA guard、仅 `CertRevoked` 可 drain 以及 pin/CRL 优先级；使用部署 CA 的真实在线轮换仍是发布门禁。

优先级如下：

1. 支持 stapled OCSP 或由独立运维进程生成的签名撤销 bundle；
2. 如实现 CRL distribution point/AIA fetch，必须异步、有界、缓存、代理/allowlist 控制、拒绝私网/特殊地址并防 DNS rebinding，不能在握手热路径盲目访问证书提供的 URL；
3. ~~记录连接的 issuer/serial/fingerprint/TLS generation；reload 后对明确被吊销的 C2S EXTERNAL/S2S peer 提供精确 drain；~~ 已实现；
4. 普通证书续期不默认踢掉所有现有连接。

已有 TLS 会话不能原地换用新证书；只能保留到重连或由显式管理员动作断开，这是 TLS 语义而非可“修掉”的 bug。

### 6.2 FED-CERT：Ed25519 证书与 channel binding 能力解耦

**状态（2026-08-30）**：实现完成并通过最终全树静态门禁，外部证书矩阵仍是发布门禁。Ed25519 leaf key 现在经过与 RSA/ECDSA 相同的链、用途、SAN 与有效期验证，但不再因 `tls-server-end-point` 缺少单一 RFC 5929 digest 而被整体拒绝。证书信任与 binding capability 已分开；每条连接只广告实际存在的 endpoint/exporter binding，SCRAM-PLUS/FAST 不会伪造或替换缺失的类型。

纯单元测试覆盖 exporter-only、endpoint-only、两者皆无和非法长度；最终外部验收仍需覆盖 RSA、ECDSA、Ed25519、TLS 1.2/1.3、C2S/S2S/Direct TLS/STARTTLS 和实际 feature advertisement。

### 6.3 FED-S2S：只实现有产品价值的可选 S2S 扩展

- 多连接池、general multi-domain stream multiplexing、XEP-0288 additional-domain target piggyback 属于大改；只有正式进入多 hosted-domain/高联邦吞吐路线时才实现；
- 当前单域目标下保留“未支持”比为了清空表格而增加攻击面更正确；
- 必须补 Prosody、ejabberd、Openfire 等多 peer、多个 CA、IPv4/IPv6、SRV fallback、Direct TLS、Dialback、DANE 的 staging matrix。

### 6.4 FED-COMPONENT：组件重复投递边界

XEP-0114 和 XEP-0225 都没有 application stanza ACK。对自有组件可定义可选 ACK/幂等扩展，但标准组件仍是稳定 XEP-0359 ID 的 at-least-once。XEP-0114 共享密钥在协议上是明文认证材料，应只在 loopback、mTLS 私网隧道或等价受保护通道使用。

截至本计划基线，[XEP-0225](https://xmpp.org/extensions/xep-0225.html)、[XEP-0343](https://xmpp.org/extensions/xep-0343.html)、[XEP-0357](https://xmpp.org/extensions/xep-0357.html)、[XEP-0408](https://xmpp.org/extensions/xep-0408.html) 的官方规范状态均为 Deferred；[XEP-0487](https://xmpp.org/extensions/xep-0487.html) 为 Experimental。它们不应成为默认生产依赖，只能作为明确 opt-in profile，并持续跟踪官方规范变化。

### 6.5 FED-BOSH：可选 BOSH profile

optional multi-stream、压缩 HTTP body、active response media types、obsolete non-SASL authid 和 HTTP-authenticated SASL EXTERNAL 不是核心上线阻断项。只有目标客户端明确需要且威胁模型可接受时逐项实现；默认继续最小、安全 profile。

## 7. P2：数据生命周期、API、可观测性与后台

| ID | 方案 | 验收重点 |
| --- | --- | --- |
| DATA-RETENTION | **已实现，待隔离数据库总门禁**：per-user/room policy 只能在管理员全局上限内缩短；延长需 admin；个人 MAM、共享 MUC MAM、offline、terminal report evidence 在锁候选的同一 SQL snapshot 解析有效策略；audit 独立采用 30–36500 日的强制有限策略 | cutoff/并发的纯单元与 ignored PG fixture 已加入；本轮仅静态检查，不宣称真实生产库/restore 已演练 |
| DATA-HOLD | **已实现，待隔离数据库总门禁**：`legal_holds`、四类 exact link 与四类受控 scope；exact row lock、scope SHARE barrier、cleanup `NOT EXISTS active hold` 与 DB trigger 双保险；离线 ACK 原子保存 server-visible stanza；账号删除/room destroy fail closed；创建/查看/逐页导出/释放 RBAC、幂等、审计且历史不可改。0092 增加固定 15 分钟且不可续期的 export lease，scope 以 DB `snapshot_at` 冻结集合，签名游标绑定 admin/hold/snapshot/keyset/跨页 SHA-256 根；有效 lease 期间 release fail closed，完成或过期后自动解除 | released hold 只有能在一页完整返回时才允许导出，否则 409，不伪造稳定 continuation；release 后原 cutoff 清理；OMEMO archive/offline 只导出 ciphertext，加密 report 的用户明文被省略；法律权限与外部验证仍是部署边界 |
| DATA-AUDIT | **已实现，待隔离数据库总门禁**：audit insert-only trigger、专用 bounded cleanup gate、每页访问审计；首屏在短 SHARE barrier 下固定 DB `snapshot_at/snapshot_max_id`，后续 `id>after_id AND id<=snapshot_max_id`，本次导出的 access audit 因 id 更大不会进入自身集合。签名游标携带连续 SHA-256 根，未完成 lease 暂时阻止相应范围被 retention 删除，完成/过期立即解除 | 每页需要新 Idempotency-Key；游标/lease 15 分钟不续期；链根需由外部 KMS/HSM/WORM 锚定；DB owner/superuser 仍是明确外部信任边界，不能把链 hash 误称为独立签名 |
| API-MAM | REST history 复用 XMPP MAM 查询对象，补 `start/end`、before/after ID、IDs、reverse/flip、metadata、方向过滤和相同 cursor authorization | XMPP 与 REST 对同一授权查询返回等价边界 |
| API-DOCS | 自托管固定版本 Swagger UI 和 OpenAPI，不引用 CDN；严格 CSP；`Try it out` 默认关闭或仅开发/admin 模式 | 无 token 落入第三方脚本、localStorage 或 URL；OpenAPI 路由一致性 CI |
| OPS-METRICS | 已增加 auth、DB、routing、outbox、Redis、upload 的固定桶 latency histogram，并在关键服务边界接入 RAII 计时；所有序列无 label，JID/用户名/domain/request ID/trace ID 均禁止进入指标；Grafana 展示 p95，Prometheus 仅在有流量时告警。当前 text endpoint 不声称支持 OpenMetrics exemplar | 固定桶使进程内存与时序基数有界；静态与单元门禁验证累计 bucket、`+Inf`、sum/count 及无隐私 label；最终负载门禁需验证采集开销与阈值 |
| OPS-ALERT | 为现有 Prometheus rules 配置 Alertmanager/托管接收器，执行真实通知演练 | 记录发送、接收、升级、静默和恢复证据 |
| UPLOAD-DELETE | 增加用户单对象删除，验证 owner/reference/state，使用 durable cleanup queue 和 audit | 并发下载、重复删除、object store timeout、账号删除 |
| UPLOAD-SCAN | 只扫描服务端可见的未加密上传；OMEMO 密文不能由服务器做有意义的明文恶意内容扫描。可选浏览器加密前客户端扫描 | 文档明确隐私边界，不制造“已扫描密文”的假安全 |
| ADMIN-AMBIGUITY | 对可能已提交但响应丢失的管理命令提供 operation reconciliation UI/API | 管理员能按 operation ID 查询最终结果，不重复施加动作 |

**API-MAM / API-DOCS / ADMIN-AMBIGUITY 当前实现状态（静态检查阶段）**：
`/api/v1/history` 已改为直接构造并调用与 XMPP 相同的
`MamArchiveQuery`，在同一 repeatable-read/XEP-0191 可见性边界内支持
bare/full `with`、时间、before/after ID、ID 集合和有界 RSM
first/last/before/after/index/max/flip；旧版 newest-first cursor 与原响应字段继续保留，
并新增稳定的 `complete/count/first_index/first/last` 元数据。历史 schema 没有可信
direction，故接口明确拒绝该未知参数而不是伪造不完整筛选，本轮也不猜测回填旧记录。
`/api/openapi.yaml` 提供仓库中受审的同一契约，`/api/docs` 自托管并固定
Swagger UI 5.32.14；制品、许可证、npm provenance 与 SHA-256 由 CI 校验，专用
CSP 只允许同源资源，授权输入、所有 submit method、credential persistence 和外部
validator 均关闭。原有 operation journal/reconciliation 状态机经复核后补齐管理页
operation-ID 精确查询、target status 分页、target 证据详情，并将“仍有 indeterminate
target”或“target 阻止成功”的父级 reconciliation 从内部错误改为可幂等重放的
`409 Conflict`。最终 Rust 静态总门禁已通过（格式、全目标检查、严格 Clippy 和 735 项纯测试）；本轮未执行服务或 PostgreSQL runtime。

## 8. P2/P3：浏览器 OMEMO 与客户端恢复

### 8.1 WEB-KEY-MIGRATION

当前不托管 OMEMO 私钥是正确的。浏览器 profile 丢失仍会导致无法解密只发给旧设备的历史密文。

**状态（2026-08-30）**：一次性“设备移动”已实现并通过最终全树静态门禁，双浏览器外部验收仍是发布门禁。实现没有把密钥托管到服务器：浏览器用固定参数 Argon2id（64 MiB、3 次、p=1）与 AES-256-GCM 在本地生成最大 44 MiB 的版本化包，服务器只保存包 SHA-256、单调 generation 和一次性 consumer UUID。导出完成后源设备冻结并断开；导入原子推进永久 high-water fence 并切断全部 live/SM 路径；旧浏览器在初始化/重连前必须核对 fence，发现其他 consumer 后排空写入并擦除 sealed state、不可导出 wrapping key 与本地加密 outbox。导入会把所有联系人身份重置为需人工重新验证。完整格式、失败恢复和信任边界见 `OMEMO_DEVICE_TRANSFER.md`。

这仍不是“随时恢复的备份”：它复制的是一次冻结的精确 Double Ratchet 状态，因此只允许 move，不能让源/目标并行使用；已经被前向保密删除的旧密钥不会复活。修改过的客户端或离线副本是否真实擦除，服务器无法证明。同源网页分发信任与双浏览器/崩溃点 runtime 验收仍是发布边界。

优先顺序：

1. 可信旧设备到新设备的端到端设备迁移；
2. 导出身份和必要恢复材料的版本化加密包，而不是盲目克隆正在变化的 ratchet state；
3. 独立恢复口令，Argon2id KDF、AEAD、随机 salt/nonce、格式版本、完整性、回滚保护和明确的设备重新信任；
4. 恢复包默认只在用户本地保存；若以后提供服务器备份，也必须是服务器不可解密的 ciphertext，且接受元数据/可用性信任边界；
5. 单独进行密码学设计审查和跨版本迁移测试。

### 8.2 WEB-INTEROP

记录 Gajim、Conversations、Dino、Monal、Smack 等客户端的版本、OS、证书、Northstar commit/binary hash、场景和脱敏 trace。至少覆盖一对一/群聊 OMEMO、多设备、bundle rotation、trust change、文件、MAM/离线恢复和设备删除。

服务器始终不能证明用户提交给举报系统的 OMEMO 解密明文与 ciphertext 唯一对应。可以通过客户端签名、选择性披露密钥或可信设备证明增强证据，但这会改变隐私模型，必须另行产品/法律决策。

### 8.3 WEB-SUPPLY-CHAIN：OMEMO/WASM 可追溯性与可复现构建

**已经完成的降低风险措施**：浏览器密码学制品已经固定为 `libomemo.js 2.0.2`、tag 名 `v2.0.2` 和 commit `df3d34cab03306d34d6ed0bf8b3a3db152173bb4`；源码归档的 PAX comment 绑定该 commit，保存完整上游源码归档、官方 npm 制品坐标和 registry SHA-1（因为 tarball bytes 未保存，不虚构 SHA-256）；CycloneDX 1.6 SBOM 记录依赖、制品 hash 与 rebuild qualification。`scripts/audit-libomemo-source.mjs` 在不执行上游代码的情况下验证 tar checksum/路径、344 个 lockfile registry package 的 integrity、build input hash 与 WASM section；`scripts/verify-libomemo-rebuild-qualification.mjs` 将 2.0.2 限定为唯一 provenance-only 例外并在版本/编译器声明漂移时 fail closed。由此，原来的“不知道二进制从哪里来”已经显著降低为明确、可验证的发行制品来源问题。注意：仓库没有 signed tag object/签名/信任记录，因此不能离线验证“签名 tag”这一更强声明。

**仍未关闭的部分**：上游 2.0.2 固定了 Node `v24.14.0`、lockfile 与 Rollup `4.62.2`，但没有记录 npm executable、Emscripten、LLVM 或 Binaryen 版本；WASM 没有任何 custom/`producers` section。官方 npm tarball bytes、registry attestation、signed tag object 和两个 clean rebuild 也不在仓库。源码归档中已有的 prebuilt WASM 只能证明 artifact hash 相同，不能证明 C source 生成了它。现有 hash CI 证明“仓库制品没有漂移”，不证明“源码必然生成该制品”。

**解决方案**：

1. 为下一次密码学核心升级固定完整构建容器 digest，包括 Node、npm、Emscripten、LLVM、Binaryen/`wasm-opt`、系统包、locale/timezone 和所有编译 flags；
2. 保存可离线验证的上游 tag 签名、源码 archive、npm tarball、lockfile、补丁和构建命令；
3. 在两个独立、干净 builder 中从源码构建两次，要求 JS/WASM hash 完全一致；
4. CI 不只校验 allowlist hash，还执行 source → artifact build 并与 vendored 制品逐字节比较；生成签名的 in-toto/SLSA provenance 和更新后的 CycloneDX SBOM；
5. 如果无法为上游 2.0.2 追溯出准确 Emscripten 工具链，不伪造“可复现”结论：继续把它标记为“官方制品已固定且来源可追溯，但不可从源码逐字节复现”，并迁移到能够 hermetic rebuild 的后续版本或由 Northstar 用固定工具链自行构建、签名和版本化的制品；
6. 每次升级需通过密码学回归、已知向量、跨设备会话、bundle/ratchet 和浏览器 E2E 测试，不能只因 hash 一致就认定密码学正确。

**同源网页客户端的永久信任边界**：服务器能够在用户下次加载时替换 HTML、JavaScript、WASM 或更新机制，因此网页 OMEMO 的实际信任根始终包含 Web 服务器、TLS/CDN、发布账号和静态资源流水线。hashed filename、CSP、SRI、签名 manifest 和透明日志能提高篡改可见性，但如果验证代码本身也由同一服务器动态下发，它们不能单独消除恶意服务器风险。

高风险部署应同时提供独立签名、可复现的桌面/移动/浏览器扩展客户端，或者让客户端从服务器之外预置 release public key 并验证更新。网页端仍应在文档中明确为“对传输和服务端存储提供 E2EE，但信任首次及后续加载的客户端代码分发链”，不能宣传成不信任其代码发布服务器。

**验收**：两个隔离 builder 生成相同字节；CI 能由源码重建并验证 vendored artifact；SBOM/provenance/签名可离线验证；篡改源码、lockfile、compiler image、WASM、SBOM 或 manifest 均失败；威胁模型和 UI/README 明确同源分发边界。即便完成，可复现构建与独立客户端只能缩小供应链风险，不能让动态网页在密码学上摆脱其代码分发方。

## 9. XEP_MATRIX 中 Partial、Experimental 和 Pass-through 的处理策略

`Partial` 不等于 bug，`Pass-through` 也不等于服务端应该保存端点状态。处理如下。

### 9.1 需要继续开发或建立更强证据

| 标准 | 计划 |
| --- | --- |
| RFC 6120/6121 | 补完整 error/state matrix、property/fuzz；建立多个服务端/客户端互操作矩阵。无法穷尽所有扩展组合 |
| RFC 6120 S2S | 按第 6 节补撤销、公网 DNS/DANE/IPv6、多 peer；多域 multiplex 仅在产品需要时做 |
| XEP-0045 | 完成 cluster MUC 状态机后，做 Prosody/ejabberd/Openfire 的 join/kick/ban/destroy/history/privacy 矩阵 |
| XEP-0054/XEP-0292 | 继续有界结构验证和互操作；RFC 6350/历史 vCard 每个字段的业务语义仍主要由端点负责 |
| XEP-0160 | 验证多客户端、联邦、过期、配额、SM/MAM/no-store 交互；保留加密归档政策边界 |
| XEP-0288 | 补第三方 bidi；additional-domain piggyback 依赖多域路线 |
| XEP-0357 | 提供参考 push gateway 和测试环境；APNs/FCM 等数据面仍外部运行 |
| XEP-0368 | 补真实 SRV、SNI、ALPN、IPv4/IPv6 和第三方 Direct TLS 证据 |
| XEP-0384 | 补 native client 互操作与安全的设备/密钥迁移 |
| XEP-0389 | 只实现真实客户端需要的 optional pattern，不为追求“全选项”扩大预认证面 |
| XEP-0447 | 按客户端需求增加 source method，并保持 URL/size/hash/metadata 安全边界 |

### 9.2 保持端点职责，不升级为服务器状态机

- XEP-0085 chat states、XEP-0333 markers、XEP-0444 reactions：服务器负责有界路由，不拥有用户的 typing/read/reaction 真值；
- XEP-0166/0167/0176、XEP-0343：服务器验证和路由 signalling，不终止 RTP/DTLS/SCTP、不做 ICE；
- XEP-0264、XEP-0446、XEP-0449：服务器不解码 thumbnail、不渲染媒体、不管理 sticker pack；
- XEP-0380、XEP-0420：加密标记/封装是端点声明，不是服务器对加密成功的证明；
- XEP-0434、XEP-0450：信任策略、签名和人工 fingerprint 判断属于端点；
- XEP-0448、XEP-0454：服务器存储 ciphertext，不能恢复文件 key；
- XEP-0215：Northstar 发现外部 STUN/TURN 并签发 coturn credentials，不运行 TURN 数据面；
- Jingle call state、simultaneous proposal tie-break 继续由客户端拥有。

### 9.3 Deferred/Experimental 协议

- XEP-0225：只作为强制 TLS 的实验组件兼容层；
- XEP-0343：只做有界 signalling 兼容，不宣称生产媒体能力；
- XEP-0357：依赖外部 push service；
- XEP-0408：保留 opt-in discovery association，除非有明确迁移产品需求，否则不实现复杂内容镜像；
- XEP-0487：保持 opt-in、fail-closed、无 ECH claim，并补真实公共服务器证据；
- 其他矩阵中标为 Experimental 的协议同样不得因为本地测试通过就升级成默认生产依赖。

每次 release 前重新核对官方 XMPP Standards Foundation 状态，而不是永久复制本计划日期的状态。

## 10. 外部验证和容量资格

### 10.1 目标硬件容量

建立 `capacity-profile`，记录 CPU、内存、存储、PostgreSQL、Redis、网络 RTT、TLS、日志级别、配置和业务混合。测试包括：

- 三轮冷启动和三轮热缓存；
- 1,000 个典型账号/资源，而不只是一账号 1,000 resource；
- presence、roster、OMEMO payload、MUC、MAM、upload、push 和 federation 混合；
- 24–72 小时 soak；
- CPU、RSS、allocator、Tokio 调度延迟、FD、PG query/WAL/IOPS、Redis、网络、p50/p95/p99、错误率和恢复时间。

结果只对被测 commit、二进制、配置、硬件和业务模型有效，不能推广成所有 Linux 单机的 1,000 人 SLA。

### 10.2 公网联邦和证书

在外部网络验证 authoritative DNSSEC、SRV/TLSA、PKIX、IPv4/IPv6、Direct TLS/STARTTLS、证书/CRL 轮换及多个独立 peer。保存命令输出、时间、commit、DNS chain、证书指纹和 peer 版本作为 release artifact。

### 10.3 独立审计

固定 release commit、binary digest、SBOM、部署拓扑和 threat model，委托独立方执行：

- RFC/XEP 协议审查；
- XML/parser 和 state-machine fuzz；
- REST/WebSocket/BOSH/S2S/component/Redis/object-store 渗透测试；
- 浏览器 OMEMO/第三方制品和恢复设计审查；
- 隐私、moderation evidence、legal hold 和运维权限复核。

高风险公网发布门禁：无未处理 P0/P1；P2 有明确书面接受；所有修复完成复测。内部测试不得写成外部认证。

## 11. 永久保留或只能缓解的诚实边界

| 边界 | 最终表述 |
| --- | --- |
| 任意 S2S/component exactly-once | 标准没有应用 stanza ACK；使用 durable outbox、稳定 XEP-0359 ID、顺序和去重做到 at-least-once，不承诺 exactly-once |
| 无 SM/receipt 的 C2S 应用处理证明 | socket write 不等于客户端已显示/处理；只能用 SM/receipt/endpoint dedupe 改善 |
| XEP-0114 共享密钥 | 标准本身没有 TLS 协商；只允许受保护网络边界或改用更安全 profile |
| OMEMO 举报明文 | 服务端可证明 archive ciphertext/digest，不能证明用户提供的解密明文；始终标为 user-supplied/unverified |
| OMEMO 私钥、信任和 fingerprint | 属于端点；服务器不得伪造验证或默认 escrow |
| Jingle/ICE/TURN/push 数据面 | 属于客户端或外部服务；服务器只做发现、凭据和 signalling |
| TLS reload | 新连接使用新 material；旧连接只能等待重连或显式 drain，不能原地替换握手证书 |
| remote MUC SM resume | 缺少任意远端房间的可证明 ownership；最多实验性重新 join/确认，不宣称无缝恢复 |
| 公网互操作、容量与独立审计 | 必须在外部环境取得证据，不能由仓库代码自证 |
| 无限故障组合 | 可用模型检查和 fault injection 验证不变量，不能穷尽所有网络、云和时序组合 |

## 12. 已解决、不得重复开发的历史事项

以下内容应移入 changelog/历史报告，而不是当前 backlog：

- 增量 XML framing、depth/size/DTD 防护；
- RFC 7622/PRECIS/IDNA 集中 canonicalization 和原子身份迁移；
- durable S2S/component outbox 和稳定 XEP-0359 retry identity；
- PostgreSQL Stream Management resume；
- PubSub collection、digest 和 federated delivery profile；
- federated MUC、password、reserved nick、voice/admin controls 的已实现部分；
- MAM preference 和 retention；
- 账号删除、REST logout、跨节点 session teardown；
- metrics 已拆为默认 loopback 的独立 listener；
- worker registry、heartbeat 和 readiness supervision；
- 浏览器 SASL2 SCRAM-SHA-256、FAST、SM reconnect 与密码立即清除；
- OMEMO JavaScript/WASM 的发行制品来源、固定版本/commit、hash、SBOM 和 CI 漂移校验已经完成；Emscripten 未固定导致的源码逐字节重建，以及同源网页代码分发信任仍由 WEB-SUPPLY-CHAIN 跟踪，不能整体标为关闭；
- 禁用 SCRAM-SHA-1 时 nullable/清理 verifier；
- `cargo-deny` 对 yanked dependency fail；
- 上传配额和 retention；
- 管理 MUC、分页和 idempotent operation；
- TLS 保护的 XEP-0220 Dialback；
- Carbons 基本 sent/received 投递回归、CSI durable fence 和 origin-id 远端 projection 修复。

如果任一项后来回归，应以新的 Issue ID、最小复现和失败测试重新打开，而不是复用历史报告中的旧结论。

## 13. 推荐执行顺序、并行工作流与门禁

复杂度标记只表示相对工作量，不是日期承诺：S（小）、M（中）、L（大）、XL（跨版本）。

| 阶段 | 工作 | 复杂度 | 依赖/门禁 |
| --- | --- | --- | --- |
| 0 | DOC-001–009 文档真值和唯一 backlog | S | 立即执行；无代码行为改变 |
| 1A | CORE-XML、CORE-JID、ARCH-SVC 第一批垂直切片 | L | 静态检查、property/fuzz、wire regression |
| 1B | DUR-C2S、DUR-PUBSUB、SEC-POW | L | crash-point tests 和 migration fixture |
| 1C | SEC-BACKUP、REST MAM、metrics、Swagger、alerts | M | restore drill、API/metrics 安全测试 |
| 2 | retention/hold、upload delete、OMEMO key migration、WEB-SUPPLY-CHAIN hermetic rebuild | L | 法律/隐私、密码学和供应链设计评审 |
| 3 | CLU-POLICY/SIGN/MUC/STORAGE/QUOTA/KEY | XL | 单机基线稳定后；完成前 cluster 保持 Experimental |
| 4 | FED-REVOCATION/CERT、真实 S2S/component/client interop | L | 公网 staging 和多个独立实现 |
| 5 | target-hardware load/soak、backup restore、外部审计 | L（外部） | 固定 RC commit 与部署拓扑 |
| 6 | 一次性更新所有网页语言包并做母语抽样 | M | 所有功能和文案稳定后执行，避免反复翻译 |

可并行工作流：

- A：XML builder 与应用服务抽取；
- B：C2S/PubSub durability 与 crash testing；
- C：cluster state machine、共享存储和 fault lab；
- D：数据生命周期、API、监控、备份；
- E：客户端/联邦互操作和外部资格。

每个工作流必须使用不同模块边界，migration 编号由一个负责人串行分配，避免并行开发产生 schema 冲突。

## 14. 发布检查表

### 单机候选版本

- P0 文档真值完成；
- XML 新增路径全部 typed；旧例外有 allowlist；
- direct/CSI/SM/BOSH/PubSub crash tests 通过；
- 备份签名、加密、restore drill 通过；
- 浏览器密码学制品具备固定编译器容器、双独立 builder 的逐字节重建证据；若当前版本仍无法重建，release 文档必须保留未关闭风险且不得声称 reproducible build；
- 目标硬件容量和告警演练有证据；
- Gajim 和至少一个移动/库客户端互操作记录完整；
- 无未处理 P0/P1 安全问题。

### 多节点候选版本

- 单机门禁全部通过；
- Redis 故障策略、签名命令、MUC durable state machine、共享 upload 和 deployment quota 完成；
- partition/split-brain/rolling upgrade/managed failover/soak 通过；
- 明确 RPO/RTO 和降级行为；
- 外部审计覆盖集群控制面。

### 文档收尾

- `KNOWN_ISSUES.md` 只保留仍真实存在的边界；
- `XEP_MATRIX.md` 的 `Core` 必须有实现 profile 和自动化证据，不能解释为实现整个 XEP 的所有可选内容；
- README 不出现 “100%”“enterprise-ready”“all XMPP features” 等无法证明的表述；
- 历史报告归档；
- 按既定要求最后一次性生成和人工抽样全部本地静态语言包。
