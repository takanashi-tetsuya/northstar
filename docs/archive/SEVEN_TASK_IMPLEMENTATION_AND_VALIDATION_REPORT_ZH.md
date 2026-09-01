# Northstar v1.1 七项任务实现、审计与生产验证报告

> **Historical snapshot — 不得作为当前 backlog 或能力清单。** 标题中的 `v1.1` 是当时使用的旧内部标签，不是现行语义版本；正式版本史现将该基线归为 `v0.1`，当前开发线为 `v0.2.0`。本文只记录 2026-08-25 七项任务完成时的代码与测试证据；此后协议、migration、可靠性与安全边界继续发生变化。当前事实必须以实际代码、根目录 `XEP_MATRIX.md`、`docs/KNOWN_ISSUES.md`、`docs/ARCHITECTURE.md` 和 `docs/PRODUCTION_OPERATIONS.md` 为准。本文中的“仍未实现”或“已完成”都不能脱离对应时间点直接用于当前发布判断。

日期：2026-08-25（Asia/Tokyo）
代码基线：`rust-xmpp-server` 1.1.0
目标部署：单台 Linux 主机、PostgreSQL、约 1,000 个同时在线的客户端资源

## 1. 结论

七项任务已经按顺序完成，并在最终代码上重新执行静态检查、真实 PostgreSQL 集成、双域联邦、Redis 双实例、1,000 会话、备份还原、浏览器多设备 OMEMO 和 Gajim 现场测试。本轮没有发现仍未处理的已知 Critical/High 级代码漏洞；RustSec 扫描 294 个依赖、加载 1,226 条公告，没有报告已知漏洞。

这里的“完成”遵循 Northstar 的兼容性边界：XEP-0060 完成的是服务器实际公告的 leaf-node profile，而不是声称实现 XEP 中未公告的 collection、digest 等所有可选 profile；各协议的准确状态仍以 `XEP_MATRIX.md` 为准。测试结果是强开发证据，不是第三方安全认证，也不能把 localhost 自签环境等同于已经完成公网 DNS、公信 CA、外部网络和真实推送服务的上线验收。

## 2. 技术依据与实现方法

本轮没有复制 ejabberd、Prosody、Openfire 或 Gajim 的源代码。协议行为依据 XMPP Standards Foundation 的规范文本实现，互操作结果用 Gajim 和项目自带浏览器客户端验证。工程思路参考成熟服务器常见的边界分层：

- XML 流和 stanza 语义在 `src/xmpp/`；
- 持久化及事务一致性在 `src/db/`；
- 联邦认证、DNS 和连接复用在 `src/s2s/`；
- REST、管理与 WebSocket 入口在 `src/api/`；
- 进程内会话、缓存、信号量和撤销令牌在 `src/state.rs`；
- 可变部署值只通过 `src/config.rs`、`.env` 或 mounted secret 进入。

这样划分的目的，是让协议授权、数据库原子性、网络身份验证和资源上限分别有清晰责任，避免把安全判断散落在 HTTP/XMPP 各个入口。

规范入口：

- [XEP-0060 Publish-Subscribe](https://xmpp.org/extensions/xep-0060.html)
- [XEP-0352 Client State Indication](https://xmpp.org/extensions/xep-0352.html)
- [XEP-0357 Push Notifications](https://xmpp.org/extensions/xep-0357.html)
- [XEP-0191 Blocking Command](https://xmpp.org/extensions/xep-0191.html)
- [XEP-0359 Unique and Stable Stanza IDs](https://xmpp.org/extensions/xep-0359.html)
- [XEP-0215 External Service Discovery](https://xmpp.org/extensions/xep-0215.html)
- [XEP-0237 Roster Versioning](https://xmpp.org/extensions/xep-0237.html)
- [XEP-0184 Message Delivery Receipts](https://xmpp.org/extensions/xep-0184.html)
- [XEP-0115 Entity Capabilities](https://xmpp.org/extensions/xep-0115.html)
- [XEP-0220 Server Dialback](https://xmpp.org/extensions/xep-0220.html)

## 3. 任务 1：XEP-0060 与原有半成品协议路径

### 3.1 XEP-0060 leaf-node profile

主要代码：`src/xmpp/protocol/pubsub.rs`、`src/db/pubsub.rs`、`migrations/0014_pubsub.sql`、`migrations/0017_pubsub_profile.sql`。

工作流程：

1. 客户端发现 `pubsub.<domain>`，服务器只公告自己真正支持的 leaf-node features。
2. `create` 可由客户端指定 node，也可由服务器生成 UUID；同一个 IQ 可以携带 `configure` 表单。
3. 配置表单解析并验证 access model、publish model、最大 item 数、标题、说明、payload/删除/撤回通知、持久化和 last-item 策略。
4. 节点创建与 owner affiliation 在同一 PostgreSQL 事务中完成；按 owner 取 advisory transaction lock，避免并发请求绕过节点配额。
5. `publish` 支持原子多 item、服务器生成缺失 ID、继承 XML namespace、单 item 和单请求总大小限制、publish-options 前置条件，以及只有原发布者或 owner 才能覆盖 item。
6. 持久节点按 `max_items` 删除最旧数据；整个 owner 的 payload 总字节数在事务提交前再次计算，超额则回滚。
7. `items`、`retract`、`purge`、`delete`、subscribe/unsubscribe、pending authorization、owner subscriptions/affiliations、node discovery 和事件通知均经过授权检查。
8. 本地订阅者通过进程内或 Redis 节点路由接收事件；远程订阅者走 S2S federation router。

目的：OMEMO/头像所需的 PEP 不能代替通用 PubSub；把通用 leaf profile 独立实现，才能正确处理 owner、publisher、subscriber 三种权限和跨域通知，同时又不虚假公告 collection-node 等未实现能力。

### 3.2 PEP/OMEMO 一致性

主要代码：`src/xmpp/protocol/pep.rs`、`src/db/pep.rs`。

- 一次 publish 的所有 item 在一个事务中写入；任何 payload、ID 或 publish-options 无效时整批不落库。
- 缺失 item ID 由服务器生成并写回标准响应。
- 不存在的 node 返回 `item-not-found`，使 Gajim 能启动设备列表初始化，而不是把空列表误认为用户主动清空。
- OMEMO 2 devices 节点保留 `current`，bundle 节点允许每设备 item；支持撤回和 roster/presence access model。
- PEP node 数和账号总 payload 字节数均有并发安全配额。

### 3.3 “补全”的准确边界

这项任务修复的是 v1.1 已经公告但不完整的 PubSub/PEP 行为，并把未实现的可选 profile 从公告和文档中排除。它不把所有标为 `Partial` 的 XEP 自动改成 `Core`。例如 federated MUC、持久化 Stream Management resume、完整 PRECIS 和 collection PubSub 仍明确列在已知限制中。

## 4. 任务 2：实际生产形态验证

### 4.1 默认端口和真实 `.env`

使用实际 `.env` 前景启动服务器，确认监听：

- `5222`：C2S STARTTLS；
- `5223`：C2S Direct TLS；
- `5269`：S2S STARTTLS；
- `5270`：S2S Direct TLS；
- `8080`：HTTP、WebSocket、REST、监控和静态客户端。

服务器成功连接现有 PostgreSQL、检查迁移并启动所有 listener。未使用后台隐藏启动器；测试只保留并管理启动命令对应的精确进程会话。

### 4.2 严格 localhost 开发证书

原证书被审计出 `Basic Constraints: CA:TRUE`，不适合作为严格服务器证书。保留原文件不覆盖，新脚本 `scripts/generate-development-certificate.sh` 生成：

- RSA 3072；
- SHA-256 签名；
- `Basic Constraints: critical, CA:FALSE`；
- critical Digital Signature/Key Encipherment；
- critical TLS Web Server Authentication；
- SAN：localhost、conference/upload/pubsub.localhost、127.0.0.1、::1；
- 397 天有效期；
- 生成后核对 SAN、公私钥匹配和私钥可解析性。

这仍是 localhost 自签开发证书。公网必须使用真实域名、公信 CA 和原生 Linux `0400`/`0600` 私钥。WSL 的 `/mnt/c` 由 DrvFS 映射 Windows ACL，`stat` 显示 `777`，因此不能作为 Linux 生产权限合格证据。

### 4.3 Gajim 现场互操作

在用户授权下接受了新 localhost 证书。Gajim 的 test1、test2、test3 均完成认证并重新加入既有 members-only、non-anonymous 群聊。test2 实际发送 `Northstar v1.1 production validation 2026-08-25`：

- test1/test3 对应会话即时出现未读；
- Gajim 显示端到端加密消息；
- `scripts/production-encryption-probe.sh test2` 只读检查最新归档，确认 `encrypted=true`、包含 OMEMO namespace，归档类型为 MUC；
- 探针不输出消息正文或数据库凭据。

## 5. 任务 3：XEP-0352 与 XEP-0357

### 5.1 XEP-0352 Client State Indication

主要代码：`src/xmpp/protocol/csi.rs`、`src/xmpp/protocol.rs`。

- 认证并绑定后的客户端可发送 `active`/`inactive`；错误阶段或错误 namespace 被拒绝。
- inactive 时只合并可替代的 presence、PEP 和 chat-state 更新；普通 message、IQ、收件回执和其他关键 stanza 立即发送。
- 合并使用有界 keyed map，避免后台客户端造成无限内存增长。
- 恢复 active 时按确定顺序冲刷缓存，再恢复普通实时发送。

目的：减少移动端后台唤醒和无意义流量，又不延迟用户消息、协议应答或安全相关事件。

### 5.2 XEP-0357 Push Notifications

主要代码：`src/xmpp/protocol/misc.rs`、`src/db/pep.rs`、`src/state.rs`。

- 认证用户可 enable/disable service JID + node；data form options 在保存前验证。
- 离线投递后，对每个 subscription 生成最小元数据通知，不把正文或 OMEMO ciphertext 复制进 push payload。
- 本地 push service 走普通会话路由，远程 service 走 S2S。
- 每个通知保存短期 request ID、用户、service 和 node correlation；只接受匹配结果。
- 明确的 service error 会清理失效 subscription；超时 pending 项由维护任务删除。

边界：Northstar 实现 XMPP 服务器侧协议，不包含 APNs/FCM 网关；运营者必须部署独立 push service。

## 6. 任务 4：XEP-0191 与 XEP-0359

### 6.1 XEP-0191 Blocking Command

主要代码：`src/xmpp/protocol/blocking.rs`、`src/db/blocking.rs`、S2S inbound/local routing。

- blocklist 持久化，支持 get、block 多 JID、unblock 指定 JID 和 unblock-all。
- 匹配严格区分 full JID、bare JID、domain/resource 和 domain 四种形状，避免简单字符串前缀带来的越权匹配。
- 修改后向同账号所有已绑定资源推送 block/unblock event。
- 入站和出站的 message、presence 以及本地/跨域路径都执行阻止检查。
- 新 block 会发送必要的 unavailable 语义；unblock 后按当前 roster/presence 关系恢复可见性。

### 6.2 XEP-0359 Stable IDs

主要代码：`src/xmpp/xml_util.rs`、`src/db/archive.rs`、MUC/MAM routing。

- 客户端 `origin-id` 被保留，用于端到端去重。
- 客户端伪造、且声称由服务器/账号/房间签发的 `stanza-id` 会被替换。
- 服务器使用 UUID 产生稳定 ID，个人归档以账号 bare JID、MUC 归档以房间 JID 作为 `by`。
- 数据库主 ID、发送给客户端的 stable stanza ID 和 MAM result ID 保持一致。

目的：让重连、Carbons、MAM 与跨资源投递能够去重，同时不允许客户端冒充服务器签发权威 ID。

## 7. 任务 5：XEP-0215 与 XEP-0237

### 7.1 XEP-0215 External Service Discovery

主要代码：`src/xmpp/protocol/extdisco.rs`、`src/config.rs`。

- 通过 disco 公告 extdisco；按 `type` 过滤 STUN/TURN 服务。
- 普通查询只返回发现信息；明确请求 credentials 时才返回短效用户名/密码。
- TURN 用户名由过期 Unix 时间和服务器 HMAC-SHA256 派生的不透明用户句柄组成，不直接暴露账号名。
- 密码使用 coturn TURN REST API 兼容的 HMAC-SHA1(shared-secret, username) 后 Base64。
- TTL 可配置，shared secret 支持 mounted file，value/file 冲突会在启动前拒绝。

目的：与现有 coturn 部署直接兼容，同时减少把长期身份放入第三方 TURN 日志的隐私泄露。

### 7.2 XEP-0237 Roster Versioning

主要代码：`src/xmpp/protocol/roster.rs`、`src/db/roster.rs`、`migrations/0015_roster_version.sql`、`migrations/0018_roster_change_log.sql`。

- stream features 公告 roster versioning。
- 每次 roster 变化在 PostgreSQL 事务中递增单调版本并记录 change log。
- 客户端版本等于当前版本时返回空结果；落后版本可从变更日志补齐；首次或无法安全补齐时返回完整 roster。
- roster push 携带新版本，并通过本机或 Redis 跨节点发送到同账号资源。

目的：降低大 roster 的重复同步流量，同时让多资源和多进程实例看到一致版本。

## 8. 任务 6：XEP-0184、XEP-0115 与 XEP-0220

### 8.1 XEP-0184 Delivery Receipts

主要代码：`src/xmpp/xml_util.rs`、local/federated message routing。

- request 与 received 的数量、互斥关系、ID、属性、子节点和文本都严格验证。
- request 必须依附有 message ID 的消息；received 必须携带 ID。
- 服务器只路由客户端生成的回执，不声称替客户端生成“已送达”，也不产生回执循环。
- 独立 received 回执标记为 transient/no-store，不污染离线队列和 MAM。

### 8.2 XEP-0115 Entity Capabilities

主要代码：`src/xmpp/protocol/caps.rs`、`src/state.rs`。

- 观察 full-JID presence 的 SHA-1 caps 广告，向该 full JID 发 disco#info。
- canonicalization 对 identity、feature、XData FORM_TYPE/field/value 排序并拒绝重复、畸形或过大结果。
- 重新计算 hash，只有与广告 `ver` 相同才放入共享缓存；不受信的结果不能污染缓存。
- pending 查询、payload、children/value 数和共享 cache 都有上限及过期清理。
- 其他本地或跨域实体查询该 full JID 时，可由已验证缓存代答。

### 8.3 XEP-0220 Server Dialback

主要代码：`src/s2s/dialback.rs`、`src/s2s/inbound.rs`、`src/s2s/outbound.rs`、`src/s2s/tls.rs`。

- 所有 S2S 路径仍强制 TLS；SASL EXTERNAL + PKIX 域名验证优先。
- 只有 peer 无法使用 EXTERNAL 且双方启用 Dialback 时进入兼容后备。
- receiving server 建立新的权威 callback 到 asserted originating domain；不会相信同一未认证连接自行回答。
- key 使用 XEP-0185 HMAC-SHA256；比较使用常量时间算法。
- 精确关联 originating/receiving domain、stream ID、请求/响应 type，拒绝 unsolicited 或过期结果。
- callback 使用实际接收 service domain，修复 `pubsub.<domain>` 联邦时错误使用根域的问题。
- 权威验证并发限制为 64，所有连接/读写/握手有超时，inbound S2S 另有全局信号量。
- `DIALBACK_SECRET_FILE` 支持持久 mounted secret；Compose 默认由原始码目录外的
  `/etc/northstar/secrets/dialback_secret` 提供。

## 9. 任务 7：完整安全审计与生产硬化

### 9.1 修复的具体问题

| 问题 | 修复 | 目的 |
| --- | --- | --- |
| C2S 可无限建立连接 | 全局 semaphore、每 IP 计数、WebSocket 共用同一限制 | 抵抗连接耗尽 |
| 未认证连接可长期占位 | 默认 30 秒认证期限；STARTTLS handshake 15 秒超时 | 抵抗 slowloris/握手占位 |
| 同账号可无限绑定 resource/SM resume | 默认 64 resource；resumable session 同样受限 | 防止账号级内存耗尽 |
| S2S inbound 无总上限 | 默认 512 条共享 semaphore | 防止联邦握手耗尽 |
| caps/push/DNS pending map 可能积累 | 数量上限、TTL、60 秒维护清理 | 防止长期内存增长 |
| PubSub/PEP 可无限建 node/占存储 | owner/account advisory lock、节点数和总字节事务配额 | 防止并发绕过与磁盘 DoS |
| 离线 spool 无硬边界 | 默认每账号 1,000 条/100 MiB/30 天；事务内保留最新前缀 | 防止离线或联邦垃圾填满磁盘 |
| 修改密码只删 REST token | 取消所有 live session，删除 resumable session | 凭据轮换立即生效 |
| 管理员 disable 不踢在线客户端 | disable 后立即取消 live/resumable session；token 查询拒绝 disabled | 停权立即生效 |
| API 凭据响应可被缓存 | `/api/` 统一 `no-store, max-age=0` + `Pragma: no-cache` | 降低 token/隐私数据缓存 |
| HTTP 安全头不足 | CSP、nosniff、no-referrer、DENY frame、Permissions-Policy | 降低浏览器攻击面 |
| 服务器可能把自己的 service domain 当远端联邦 | federation policy 拒绝 root/conference/upload/pubsub 本地域 | 避免错误回环和策略绕过 |
| Dialback 未配置持久 secret | secret 生成脚本、Compose secret、release preflight | 多节点一致性及密钥治理 |
| localhost 证书为 CA | 新建严格 CA:FALSE RSA-3072 开发证书 | 缩小测试证书权限 |

### 9.2 代码级审计结果

- 生产代码没有 `unsafe` block。
- SQL 使用静态语句和 bind 参数；生产路径没有把不受信任输入拼进 SQL。
- XML 输入使用增量 tokenizer、depth tracking、1 MiB frame 限制，拒绝 DTD、mismatch、畸形 stream close 和过深嵌套。
- 输出 XML 仍有字符串组装，但使用统一 escaping；这仍列为中期重构方向，不能宣称完全消除未来漏 escape 风险。
- TLS 使用 rustls；S2S 外连验证系统/附加 CA chain 和目标域名。S2S server TLS 暂时接收可选的 presented certificate 完成握手，但 SASL EXTERNAL 在协议层重新做 PKIX + asserted-domain 验证；Dialback 则依靠权威 callback，不把“呈现任意证书”当认证成功。
- tracked-file 扫描没有 `.env`、私钥、证书、数据库或私钥 PEM；标准运行路径均已忽略。
- `cargo audit` 没有报告已知依赖漏洞。

## 10. 最终验证矩阵

| 验证 | 最终结果 |
| --- | --- |
| `cargo fmt --check` | 通过 |
| `cargo check --locked --offline` | 通过 |
| `cargo test --locked --offline` | 44/44 通过 |
| `cargo clippy --all-targets -- -D warnings` | 通过，0 warning |
| `scripts/release-preflight.sh` | 通过；许可证、敏感文件、格式、编译、44 项测试及 Clippy 汇总门禁通过 |
| release 优化构建 | 通过，约 2 分 01 秒 |
| RustSec | 294 dependencies / 1,226 advisories，0 已报告漏洞 |
| 本地 PostgreSQL 全集成 | 通过；含 REST/no-store、TLS、WebSocket、roster、PEP/PubSub 配额、OMEMO、MUC/MAM、CSI、Push、会话撤销 |
| 双域 SASL EXTERNAL 联邦 | 通过；含 PubSub/PEP、blocking、stable IDs、presence、双向和离线消息 |
| 双域强制 XEP-0220 Dialback | 通过；同一联邦矩阵全部通过 |
| Redis 双实例 | session 冲突/路由、ack、Carbons、versioned roster、全局 MUC/nick/broadcast 通过 |
| 1,000 session | 1,000 个同时认证资源保持在线，抽样 ping 通过；连接爬升 61.4 秒 |
| 备份/还原 | 私有 PostgreSQL、checksum、确认保护、数据库、uploads、pre-restore rollback 保留通过 |
| 浏览器 E2E | 同账号两个 OMEMO 设备 + peer、单聊、群聊、加密上传/下载、头像、管理后台、移动布局通过 |
| 网页静态和 i18n | 84 种语言可用；76 个本地机器翻译包；OMEMO/头像/PoW/i18n 检查通过 |
| Gajim 现场 | test1/test2/test3 登录和群聊加入成功；实际 OMEMO 发送与密文归档探针通过 |
| Docker Compose 展开 | 本机未运行：Windows 环境没有 Docker CLI；应由 CI/部署主机再次执行 `sudo docker compose config --quiet` |

## 11. 数据库迁移与重要新文件

- `0014_pubsub.sql`：通用 PubSub 基础表。
- `0015_roster_version.sql`：roster 单调版本。
- `0016_muc_mam_sender_index.sql`：MUC MAM sender/time 索引。
- `0017_pubsub_profile.sql`：leaf profile 配置、affiliation/subscription 等。
- `0018_roster_change_log.sql`：版本化 roster 增量日志。
- `src/xmpp/protocol/pubsub.rs`：XEP-0060 service。
- `src/xmpp/protocol/csi.rs`：XEP-0352。
- `src/xmpp/protocol/extdisco.rs`：XEP-0215。
- `src/xmpp/protocol/caps.rs`：XEP-0115。
- `src/s2s/dialback.rs`：XEP-0220/XEP-0185 key。
- `scripts/generate-development-certificate.sh`：严格 localhost 开发证书。
- `scripts/production-encryption-probe.sh`：不输出正文/凭据的归档密文探针。

## 12. 仍然存在的边界与上线条件

1. 没有独立第三方代码审计、协议互操作实验室或渗透测试；高风险公共服务上线前必须安排。
2. 当前现场验证域名是 localhost、自签证书、HTTP public URL；它证明程序路径和 Gajim 互操作，不证明公网 DNS、公信 CA、NAT/防火墙和外部 S2S 可达性。
3. RFC 7622/PRECIS 和完整国际化 JID canonicalization 尚未完成。
4. S2S 没有 PostgreSQL durable retry spool；进程崩溃或长时间远端故障可能丢失内存队列。
5. federated MUC、password room 和完整 MUC status/error matrix 仍未完成。
6. XEP-0198 resume 状态只在内存，进程重启后失效，且不恢复 MUC occupancy。
7. PubSub 未公告也未实现 collection nodes、digest scheduling 等选用 profile。
8. Push 需要外部 push service；TURN 需要外部 coturn；本轮只验证服务器侧 XMPP/凭据算法。
9. MAM 个人/群组历史尚无自动 retention/purge。离线队列已有硬边界，但长期历史必须配合磁盘监控、法律/用户策略和备份容量计划。
10. Redis 多节点仍属实验功能；正式基线是单进程。
11. WSL `/mnt/c` 私钥权限显示为 `777`。Windows ACL 限制了本机文件访问，但生产 Linux 必须把密钥放在原生文件系统并通过 `scripts/release-preflight.sh --production` 的 `0400/0600` 检查。

## 13. 公网上线前最后门禁

在真实 Linux 主机上执行：

```sh
sudo install -d -o root -g root -m 0700 /etc/northstar
sudo env NORTHSTAR_SECRET_DIR=/etc/northstar/secrets \
  sh scripts/create-production-secrets.sh
sudo sh scripts/release-preflight.sh --production
sudo docker compose config --quiet
```

此外必须从外部网络验证 A/AAAA、`_xmpp-client`、`_xmpps-client`、`_xmpp-server`、`_xmpps-server` SRV，检查实际 served certificate chain，并与至少一种除 Gajim/内置网页以外的独立客户端完成登录、OMEMO 单聊/群聊、MAM、文件上传和重连测试。
