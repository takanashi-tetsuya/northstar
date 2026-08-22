# Northstar XMPP Server 完整实现、审计与移交手册

最后审计日期：2026-08-21  
适用代码版本：当前工作区 `rust-xmpp-server 0.1.0`  
文档目的：让下一位开发者能够从代码事实出发接管项目，而不是依赖聊天记录、旧 README 或未经验证的交接报告。

## 1. 先读结论

Northstar 是一个从 Rust 源码自行实现的单机 XMPP 服务端，同时包含独立网页客户端、管理后台、REST API、PostgreSQL 持久化、文件上传、监控、日志、举报/申诉和自定义反滥用系统。服务端没有嵌入 Prosody、ejabberd、Converse.js 等完整服务器或 UI 框架。唯一明确引入、并需要单独履行许可证义务的 XMPP 客户端项目代码，是 `web/crypto` 下来自 [conversejs/libomemo.js](https://github.com/conversejs/libomemo.js) 的 GPL-3.0 OMEMO 密码核心及 Curve25519 WebAssembly。

项目不是“全部 XEP 完整实现”。XMPP 有数百个扩展，本项目实现的是一套可工作的、面向约一千在线资源的单机功能组合；不少 XEP 是实用子集。权威边界以本手册和 `XEP_MATRIX.md` 为准。

本轮审计确认 Gemini 报告中的 PEP、动态能力发现、MUC 默认非匿名以及配置重构等多数改动确实存在，但“完整支持 Dialback”“编译零错误”“所有 OMEMO 问题都只能是客户端缓存”等说法不成立。审计还发现并修复了 PEP 自动 ID、SCRAM 校验、MUC 真实 JID 泄露、Web 新账号 OMEMO 初始化、本地明文缓存、上传槽过期删除、配置样例密钥、Docker 配置、日志格式和翻译包缺项等问题。

本轮先用独立 schema、独立端口和只清理自身 PID 的脚本完成运行时验证，未触碰原 `18080` 实例；全部回归通过后，才使用会核对 `/proc/<pid>/exe` 的保数据脚本重启现有 Northstar 测试实例。重启后 Windows 侧 `/readyz` 返回 `ready`，`/client.html` 返回 HTTP 200。整个过程没有控制、结束或关闭 Codex/ChatGPT 应用。

### 状态词含义

| 状态 | 含义 |
| --- | --- |
| 已实现 | 代码路径存在，当前 Rust/网页静态检查可通过 |
| 部分实现 | 可完成主要流程，但没有覆盖标准的全部分支或全部第三方客户端 |
| 透传 | 服务器能路由这种 XML，但不维护对应的高级语义状态 |
| 仅有测试夹具 | 仓库有脚本，不能等同于本轮已经重新运行并通过 |
| 未实现 | 不应在服务发现或产品文案中宣称支持 |

## 2. Gemini 交接报告逐项核验

| 报告说法 | 审计结论 | 代码事实 |
| --- | --- | --- |
| PEP 发布遍历多个 `<item>` | 真 | `pep_publish` 遍历全部直接子项并逐项持久化、广播 |
| 缺少 item ID 时生成 UUID | 原先半真，现已修复 | 原代码只把 UUID 当数据库键，保存和广播的原 XML 仍可能没有 `id`；现会把 ID 写回 item XML |
| 发布成功总是返回空 IQ 才“标准” | 假 | 服务器分配 ID 时应把分配结果返回；现仅在客户端已给 ID 时返回空 result |
| 查询不存在的 PEP 节点返回 `item-not-found` | 真 | 本地 C2S 和本轮补齐的 S2S 代答路径都如此 |
| 代答其他用户 PEP 时补正确 `from` | 真 | 使用带来源的 IQ result/error 生成器 |
| disco#info 动态注入 PEP node 和 `+notify` | 真 | 查询 bare JID 时读取该用户已发布的节点后注入 |
| 新 MUC 默认非匿名 | 真 | `0004_muc.sql` 默认 `non_anonymous = TRUE` |
| MUC 总是广播真实 JID | 原先真但有隐私缺陷，现已修复 | 非匿名房间向全员公开；半匿名房间只向本人和 moderator 公开 |
| `envy` 集中配置 | 真 | `RawConfig` 由环境变量反序列化，`Config` 做规范化和复杂类型转换 |
| 配置已完全没有手工默认值/解析 | 假 | `config.rs` 仍有默认函数、域名/列表/URL/地址校验，这是必要业务逻辑，不是纯自动映射 |
| `.env.example` 包含配置 | 真，但原样例有问题 | 原文件带像真实账号的数据库口令；已改成安全占位，并补齐日志、额外根证书等字段 |
| `Config` 包装 `RawConfig` 并 Deref | 真 | 业务代码可直接读取 RawConfig 字段，同时使用规范化字段 |
| SASL 已合并到 `auth.rs` | 真 | PLAIN、SCRAM、密码哈希位于同一模块 |
| S2S 完整保留 DNS、TLS、Inbound/Outbound Dialback | 假 | DNS、TLS、入站、按域连接池存在；XEP-0220 Server Dialback 明确未实现 |
| abuse 模块独立保留 | 真 | PoW、事件窗口、处罚和冷却在 `src/abuse.rs` |
| `db_recovered.rs` 与 `split_output` 已删除 | 真 | 这两个指定残留不存在 |
| 项目已经干净、无历史残留 | 假 | 根目录仍有 scratch、旧日志、临时脚本、构建工具和恢复片段；因工作区没有 Git 历史，本轮未冒险批量删除未知归属文件 |
| `cargo check` 零错误零警告 | 报告生成时/本轮初审为假，现已达成 | 初审存在测试编译错误和 45 个警告；本轮修复后 Windows 全目标 check/test/clippy 零警告 |
| 如果仍看不到 OMEMO 指纹，绝对是 Gajim 缓存 | 假且危险 | 缓存可能影响结果，但本轮确实又发现服务端和网页端 OMEMO 初始化、PEP ID、S2S PEP 和 MUC 隐私问题 |

## 3. 总体架构与数据流

```text
标准 XMPP 客户端 ── TCP 5222 / STARTTLS ─┐
独立网页客户端 ── HTTPS/WSS / RFC 7395 ──┼─> ProtocolSession / XMPP handlers
远程 XMPP 域 ── TCP 5269 / S2S TLS ──────┘          │
                                                    ├─ 内存：在线资源、MUC occupant、SM、PoW
REST/管理后台/文件 PUT+GET ── HTTP 8080 ────────────┤
                                                    ├─ PostgreSQL：账号、关系、密文、房间、审计
                                                    └─ 本地目录：上传对象字节
```

单个 Tokio 进程承载三类监听器：C2S TCP、S2S TCP、HTTP/WebSocket。`AppState` 通过 `Arc` 共享数据库池、TLS 热加载器、在线会话表、房间成员表、联邦路由、上传存储、指标和反滥用状态。

PostgreSQL 是持久状态源；在线连接、SM 恢复、PoW 挑战和处罚阶梯只在内存中。服务器重启会保留账号、关系、归档、PEP、房间等数据库数据，但会清空在线状态、流恢复和临时限流处罚。

### 启动顺序

1. `dotenvy` 读取项目根目录 `.env`；已有进程不会自动重新读取。
2. `Config::from_env` 反序列化并校验所有配置。
3. 初始化 stderr 与滚动文件日志；格式可为 `text` 或 `json`。
4. 安装 rustls AWS-LC 密码提供者。
5. 建立 SQLx PostgreSQL 连接池。
6. 按文件名顺序执行嵌入式迁移。
7. 如果设置成对的 bootstrap 管理员变量，创建不存在的初始管理员；已有同名非管理员会让启动失败。
8. 构建联邦路由、应用状态、上传存储和 TLS 配置。
9. 启动每分钟一次的清理任务：REST 会话、未使用过期上传槽、过期离线消息、过期 PoW 挑战和 SM 恢复状态。
10. 并行监听 C2S、S2S 和 HTTP。任一主监听任务异常退出会让主进程进入关闭流程。
11. 收到 Ctrl-C/SIGTERM 后统一取消监听；HTTP 做短暂 graceful drain，随后进程退出。现有 XMPP 子连接没有逐连接发送最终 stream close。

## 4. 代码目录职责

| 路径 | 职责 |
| --- | --- |
| `src/main.rs` | 启动、日志、迁移、后台清理、关闭信号 |
| `src/config.rs` | `.env` 映射、默认值、配置校验、域策略 |
| `src/state.rs` | 单机共享内存状态和会话查询 |
| `src/auth.rs` | 用户名/密码规则、Argon2id、REST token、SASL PLAIN/SCRAM |
| `src/abuse.rs` | IP/账号/行为阶梯、PoW 挑战、硬等待、冷却 |
| `src/xmpp/mod.rs` | TCP/WS I/O、STARTTLS、帧读取和发送队列 |
| `src/xmpp/protocol.rs` | 单资源协议状态机、认证、绑定、session 生命周期 |
| `src/xmpp/protocol/*.rs` | discovery、roster、presence、message、PEP、MUC、MAM、SM 等分功能处理 |
| `src/xmpp/xml_util.rs` | XML 转义、JID/消息重写、标准 result/error 辅助函数 |
| `src/db/*.rs` | SQL 持久化；按 users/roster/archive/PEP/MUC/upload/reports/private 划分 |
| `src/s2s/*.rs` | SRV 解析、S2S TLS、入站认证、按远程域复用的出站连接 |
| `src/api/*.rs` | REST、WebSocket 升级、管理、举报、上传、健康检查 |
| `src/storage.rs` | 可替换上传存储接口；当前为本地磁盘原子写入 |
| `web/` | 完全本地加载的首页、用户客户端、管理后台、OMEMO、头像、i18n、PoW worker |
| `migrations/` | PostgreSQL 结构演进，启动时自动执行 |
| `scripts/` | 静态检查、WSL 验证、集成、联邦、浏览器和 1000 会话夹具 |

## 5. 配置系统

`RawConfig` 由 `envy` 根据字段名读取大写环境变量；`Config` 再把域名转小写、拆分可信代理/联邦列表、解析 DNS override，并生成默认公共 URL。空字符串的可选管理员名、公共 URL、bootstrap 账号和额外根证书会被视为未设置，便于 Docker Compose 传空值。

| 环境变量 | 默认值/要求 | 实际用途 |
| --- | --- | --- |
| `XMPP_DOMAIN` | `localhost` | JID 域、证书域、服务子域基础；按 DNS label 规则校验 |
| `DATABASE_URL` | 必填非空 | SQLx PostgreSQL URL；当前没有第二套独立 socket 配置字段 |
| `DATABASE_MAX_CONNECTIONS` | 32 | 连接池上限，必须大于 0 |
| `DATABASE_MIN_CONNECTIONS` | 2 | 不能大于上限 |
| `XMPP_BIND` | `0.0.0.0:5222` | C2S TCP |
| `S2S_BIND` | `0.0.0.0:5269` | 联邦 TCP |
| `HTTP_BIND` | `0.0.0.0:8080` | REST、静态网页、WebSocket |
| `TLS_CERT_PATH` / `TLS_KEY_PATH` | `certs/server.crt/key` | C2S 与 S2S 证书和未加密 PEM 私钥 |
| `PUBLIC_URL` | localhost 用 HTTP，否则域名 HTTPS | 上传 URL 和外部地址 |
| `OPEN_REGISTRATION` | true | 是否允许注册 |
| `INVITATION_REQUIRED` | false | REST 注册是否必须消费邀请码 |
| `REGISTRATION_RATE_PER_HOUR` | 20 | 全实例最近一小时新账号总量上限；名称虽像 IP 限制，实际是全局上限 |
| `REQUIRE_ENCRYPTED_ARCHIVE` | true | 只持久化可识别的加密消息；不禁止在线转发明文 |
| `SESSION_TTL_HOURS` | 168 | REST bearer 会话寿命，不是 XMPP 空闲断开时间 |
| `SM_RESUME_TIMEOUT_SECONDS` | 300 | XEP-0198 内存恢复窗口，1–86400 |
| `OFFLINE_MESSAGE_TTL_DAYS` | 30 | 未送达离线队列保留天数 |
| `TRUSTED_PROXY_IPS` | loopback | 只有这些直接对端才能让服务信任转发的客户端 IP |
| `UPLOAD_DIR` | `data/uploads` | 上传对象目录 |
| `UPLOAD_MAX_BYTES` | 25 MiB | XEP-0363 文件上限；与头像原图 50 MiB 是两个不同限制 |
| `POW_BASE_WORK_FACTOR` | 1024 | 基础 PoW 因子 |
| `POW_MAX_WORK_FACTOR` | 524288 | 封顶因子，必须不小于 base |
| `ABUSE_WINDOW_SECONDS` | 60 | 事件计数窗口 |
| `ABUSE_COOLDOWN_SECONDS` | 60 | 处罚每下降一级所需静默时间 |
| `ABUSE_MAX_WAIT_SECONDS` | 900 | 硬等待封顶 |
| `FEDERATION_ENABLED` | true | 是否启用 S2S |
| `FEDERATION_ALLOWLIST` / `DENYLIST` | 空 | 精确域或 `*.example.org`；deny 优先 |
| `FEDERATION_ALLOW_PRIVATE_IPS` | false | 是否允许 S2S DNS 指向私网/特殊地址，仅限受控测试 |
| `FEDERATION_DNS_OVERRIDES` | 空 | `domain=ip:port`，用于测试/内网 |
| `FEDERATION_EXTRA_ROOT_CERT_PATH` | 无 | 追加私有联邦 CA |
| `BOOTSTRAP_ADMIN_USERNAME/PASSWORD` | 无 | 必须同时设置；只负责首次创建，不会每次覆盖密码 |
| `LOG_DIR` | `logs` | 滚动日志目录 |
| `LOG_ROTATION` | daily | daily/hourly/minutely/never |
| `LOG_FORMAT` | text | text/json；Compose 默认 json |
| `LOG_RETENTION_FILES` | 30 | 文件数量保留上限 |
| `RUST_LOG` | info | tracing 过滤表达式 |

`.env.example` 是唯一规范样例；旧的重复 `env.example` 已删除，避免默认值和安全说明继续漂移。`.env` 可能含真实密码，绝不能提交或复制到手册。

## 6. 账号、密码、SASL 与 REST 会话

### 账号规则

- 用户名先 trim、转 ASCII 小写，只允许 3–64 字节的字母、数字、点、下划线和短横线。
- 这不是 RFC 8265 PRECIS UsernameCaseMapped 的完整 Unicode 实现，因此国际化 localpart 尚未支持。
- 新密码要求 10–1024 字节；当前错误文案说“字符”，对多字节 Unicode 不够精确。

### 密码存储

新建/改密时同时生成：

1. Argon2id PHC 字符串，供 REST 和 SASL PLAIN 校验。
2. 32 字节随机 SCRAM salt、可配置的 PBKDF2-HMAC-SHA-256 迭代次数（`SCRAM_ITERATIONS`，默认 600000），以及 StoredKey/ServerKey，供 SCRAM-SHA-256。

最多 8 个密码哈希/校验任务并发，CPU 工作放到 blocking worker，防止阻塞 Tokio I/O。未知但格式合法的用户名也会执行一次 dummy Argon2 校验，减弱按响应时间枚举用户的问题。

迁移 0011 以前的用户没有 SCRAM verifier，无法从 Argon2 哈希反推。这类用户第一次成功使用 PLAIN/REST 密码登录后，服务器用当次明文密码补写 SCRAM verifier；已有 verifier 低于当前 `SCRAM_ITERATIONS` 时也会在密码登录后升级。SCRAM-only 登录不会把密码交给服务器，因此不能自行升级。数据库泄漏时，攻击者仍可针对 SCRAM verifier 离线猜测，这是兼容 SCRAM 带来的安全权衡；默认 600000 次显著强于旧版 4096 次，但部署者仍应在目标服务器和移动客户端上 benchmark。

### SASL PLAIN

- TCP 只有在 STARTTLS 成功后才广告 PLAIN；WebSocket 的安全性依赖外层 HTTPS/WSS 反向代理。
- 解码 `authzid\0authcid\0password`，拒绝多余字段和非法 UTF-8。
- authcid 走统一用户名规范化。
- 非空 authzid 必须是同一用户、同一配置域且不能带 resource；不能借 PLAIN 代理成其他账户。
- 校验成功后才进入资源绑定阶段。

### SCRAM-SHA-256

实现遵循 [RFC 7677](https://www.rfc-editor.org/rfc/rfc7677) 的非 PLUS 机制：解析 GS2 header、转义用户名、拼接 client/server nonce、发 salt/iteration、校验 `c=`、完整 nonce 和 32 字节 proof，再返回 server signature。重复属性、未知 mandatory 扩展、错误 username escape、控制字符 nonce、错误 channel binding 都会失败。

网页客户端目前只实现 SASL PLAIN；SCRAM 主要供 Gajim 等原生客户端使用。

### REST bearer

- 登录生成 64 个随机字母数字字符。
- API 只返回一次明文 token；数据库只存 SHA-256 digest 和过期时间。
- 默认 168 小时，后台每分钟清理过期记录。
- 修改密码会撤销该用户全部 REST 会话，但不会立即踢掉已认证的 XMPP 长连接。
- 当前没有单独的 REST logout/revoke-current-token 端点；网页退出主要清除本地 token，服务器记录等过期或改密。

## 7. 注册的三条路径

### REST 注册

流程：检查开放注册 → 检查全局每小时账号上限 → 根据真实 IP 计算反滥用要求 → 校验 PoW（若要求）→ 校验用户名/密码 → 检查冲突 → 在数据库事务中原子消费邀请码 → 创建用户和 SCRAM verifier → 写审计与指标。

邀请码只有 REST JSON 有明确字段，所以 `INVITATION_REQUIRED=true` 时这是完整注册路径。

### XEP-0077 传统 IBR

仅允许未认证 TLS 会话 GET/SET username/password；邀请必填时不广告该能力并拒绝 GET。它没有邀请码/PoW 扩展字段，因此不适合 invitation-required 模式。历史兼容路径能强制创建短密码用户，并向其离线队列放弱密码运营提醒；这条行为不应被描述成“所有离线记录都必为 OMEMO 密文”。账号删除尚未实现。

### XEP-0389 预认证 IBR

支持 `urn:xmpp:ibr:0` 的注册表单和 credentials 提交，修复了 XML namespace 判断，并在发 credentials challenge 前检查 IP 反滥用和全局注册上限。它仍是部分实现：没有在 XEP-0389 表单中承载邀请 token 或 Northstar PoW proof。

## 8. C2S、WebSocket 与流管理

### TCP C2S

监听 5222，先读取 XML stream，广告 STARTTLS；TLS 完成后重开 stream，进行 SASL、重新开流、资源绑定。单个输入 frame 上限约 1 MiB。分帧器会跨网络读取保留不完整 UTF-8，按 XML token、引号和标签栈增量追踪结构，因此 Forwarding、Carbons、MAM 内层再次出现 `<message>` 时不会提前截断；DTD、错配标签、非法 stream close 和超过 256 层的嵌套会被拒绝。C2S、S2S 共用该分帧器，WebSocket 额外要求每个文本消息恰好包含一个完整 frame。

### RFC 7395 WebSocket

HTTP `/xmpp-websocket` 要求 `xmpp` 子协议，使用 `<open/>`/`<close/>` framing。与 TCP 共用 `ProtocolSession`，因此 roster、PEP、MUC、归档等服务端能力一致。网页客户端自己实现这条协议栈，不依赖 Converse.js。

### 资源绑定和路由选择

绑定后在线表键为 full JID。发往 bare JID 的单聊选择 `available=true` 且 priority 非负的最高优先级资源；发往 full JID 则精确匹配。它不是同时投递给所有普通资源；其余已启用 Carbons 的资源收到 sent/received carbon copy。

### XEP-0198 Stream Management

- 支持 enable、服务器入/出计数、客户端 `<r/>`、服务器 `<a/>`、断线后的 in-memory resume 和未确认 stanza 重放。
- `max` 和过期时间使用 `SM_RESUME_TIMEOUT_SECONDS`，不再硬编码 300。
- 状态每分钟清理，进程重启即丢失。
- transport 断开时当前实现会先移除 MUC occupant；SM 状态没有保存 `joined_rooms`，所以恢复 XMPP 流不等于恢复群房间成员身份。
- 网页客户端目前不启用 SM；功能主要面向原生客户端。

## 9. 联系人、订阅、Presence 与屏蔽

### Roster / RFC 6121

- GET 返回持久 roster；SET 可添加、改备注或 `subscription='remove'`。
- roster 更新 push 到同账号所有在线资源。
- subscribe/subscribed/unsubscribe/unsubscribed 更新双方 subscription，支持本地离线 pending 和跨域 pending。
- 数据库有 `groups JSONB` 列，但当前协议处理没有完整解析/返回分组，也没有 roster versioning。

### Presence

- 保存 available、show/status、priority；priority 限定 -128..127。
- 向有适当订阅关系的本地/远程联系人广播。
- 用户首次 available 时投递 pending 订阅和最多 500 条离线消息。
- 本轮删除了一个严重错误：旧代码会按 roster 项数量把用户自己的 unavailable presence 重复写入自己的离线消息队列。

### XEP-0191 Blocking

- PostgreSQL 持久化 bare/full JID 或域样式条目。
- 支持 blocklist、block、指定 unblock 和 unblock-all，并向请求过 blocklist 的其他资源 push。
- 消息进入归档/离线/本地或联邦路由前检查屏蔽；presence 也受抑制。
- 完整的复杂 JID 规范化和所有标准边缘时序仍需互操作测试。

## 10. 单聊、Carbons、离线和归档

### 消息处理顺序

1. 验证 from 为当前 full JID，解析目标域和 chat/groupchat 类型。
2. 群聊地址交给 MUC；远程域交给 federation router。
3. 判断是否是实际内容消息；receipt、chat state 等不计入消息 PoW burst。
4. 计算 IP、用户和跨动作 behavior actor 的反滥用要求；必要时验证 `<pow>`。
5. 从待路由 XML 中剥离所有直接 Northstar PoW 元素，避免把证明泄露给对方或归档。
6. 检查发送方/接收方 blocklist。
7. 判断 OMEMO/旧 axolotl 加密 envelope 和 XEP-0334 storage hints。
8. 在线路由、发 Carbons、归档、必要时离线排队和推送摘要。

### 加密归档策略

`REQUIRE_ENCRYPTED_ARCHIVE=true` 时：

- 在线明文仍能实时转发，服务器也能看到它，但不会写 MAM。
- 接收方离线时明文会被拒绝，而不是落离线库。
- 加密消息归档前移除 envelope 之外的客户端明文 sibling，如 body/subject/XHTML，并可加入通用“加密消息”fallback。
- XEP-0334 `no-store`/`no-permanent-store` 会阻止归档和离线持久化。
- 加密单聊通常分别为发送者和接收者写一份 owner archive。

离线消息按创建时间投递，单次最多 500；投递成功后删除。后台按 `OFFLINE_MESSAGE_TTL_DAYS` 删除过期未送达记录。

### MAM / XEP-0313 与 RSM

支持 `with`、`start`、`end`、max（封顶 100）、稳定 UUID cursor、before/after、count/index，并用 forwarded + delay 返回原存档 stanza。REST `/history` 是较简单的最近 200 条原始 stanza 接口。MAM preferences GET 固定 `always`，SET 只返回成功而不持久化；没有 per-user retention、去重策略或 MUC MAM。

### Carbons 与透传扩展

XEP-0280 可按资源 enable/disable，向同账号其他资源发 sent/received forwarded copy，并尊重 private 排除。Receipts、chat markers 和 reactions 能放在加密内容或普通 stanza 中路由，但服务器没有建立送达/已读/反应索引。

## 11. PEP：OMEMO 和头像的服务端基础

PEP 是按用户隔离的持久 node/item 存储，不是通用 PubSub 服务。

### 发布流程

1. 只允许已认证用户代表自己发布。
2. 读取 `<publish node='…'>`，遍历全部直接 `<item>`。
3. 没有 item 时允许无 payload 发布；每个 item ID 最长 1024 字节，单 item XML 最多 512 KiB。
4. 客户端未给 ID 时生成 UUID，并把 `id` 写回保存和事件广播使用的 XML。
5. PostgreSQL 事务 upsert 所有 item，并将每个 owner/node 裁剪到最近 100 项。
6. 给自己的其他资源和 roster subscription 为 `from`/`both` 的联系人广播 headline pubsub event。
7. 如果服务器分配了 ID，result 中返回 `<publish><item id='…'/>`；否则可返回空 IQ result。

这直接服务 OMEMO device list、bundle 和 XEP-0084 avatar data/metadata。

### 获取流程

1. 没有 `to` 时读取自己；bare `to` 指向本地用户时读取对方。
2. 对方不存在返回 `item-not-found`。
3. node 没有任何保存项也返回 `item-not-found`，而不是空 `<items/>`。这是触发 Gajim/网页端首次发布 device list 的关键差异。
4. 代答他人数据时 IQ `from` 必须是被查询的 bare JID。
5. S2S 入站查询使用同一语义；本轮补齐了空节点错误。

### 服务发现

对 bare JID 的 disco#info 除静态 PEP 身份外，会查数据库已有 node，并同时注入 `node` 与 `node+notify` feature。这样客户端能发现联系人已发布的 OMEMO2 device node。服务端不广告 generic PubSub、open access、publish-options 等未实现能力。

未实现：node 创建/删除配置、显式订阅管理、retract/purge、完整 access models、collection、通用 PubSub service。

权威标准：[XEP-0060](https://xmpp.org/extensions/xep-0060.html)、[XEP-0163](https://xmpp.org/extensions/xep-0163.html)。

## 12. 网页 OMEMO 2 如何工作

### 明确的软件来源

- UI、WebSocket XMPP 状态机、PEP 编排、消息格式、文件和页面由本仓库实现。
- X3DH/Double Ratchet 及 Curve25519 原语来自 vendored `libomemo.js`，许可证 GPL-3.0，见 `THIRD_PARTY_NOTICES.md`。
- 设计目标按 [XEP-0384 OMEMO 2](https://xmpp.org/extensions/xep-0384.html) 和 [XEP-0420 Stanza Content Encryption](https://xmpp.org/extensions/xep-0420.html)；“Gajim 能否初始化/看到设备”是互操作目标，不代表复制 Gajim 代码。

### 首次初始化

1. 在 IndexedDB 创建本机 identity key、signed prekey、100 个 one-time prekeys 和随机 device ID。
2. 读取自己的 `urn:xmpp:omemo:2:devices`。新账号收到 `item-not-found` 时现会当成空列表，而不是抛错中止。
3. 把本机 device ID 合入 device list 并发布。
4. 在 `urn:xmpp:omemo:2:bundles:<deviceId>` 发布 identity key、signed prekey/signature 和 prekeys。
5. 私钥和 sessions 永不上传；服务端只见公开 bundle。

### 单聊加密

1. 获取接收方设备列表和每个 bundle，也获取发送者自己的其他设备。
2. 用 libomemo 为每个目标设备建立或推进 Double Ratchet session，并分别包裹同一个内容密钥材料。
3. 消息内容按 SCE 构建；当前内容层使用 HKDF-SHA-256、AES-CBC 和截断 HMAC-SHA-256，48 字节 key/tag 材料由 OMEMO 分设备封装。
4. 发出 `urn:xmpp:omemo:2` envelope；服务器只路由/保存密文结构。
5. 收件设备找到自己的 `<key rid>`，通过 ratchet 解包并在内存中解密 SCE。

### 群聊加密

网页端根据房间 presence 中公开的真实 bare JID，收集当前在线成员设备，把内容密钥分别加密给这些设备。默认新房间是 non-anonymous，因此普通成员可以建立 JID→OMEMO device 对应。后来加入或当时离线、未被列入 envelope 的设备不能解密旧消息。

半匿名房间只向本人/moderator 公开真实 JID，所以普通成员无法可靠完成上述映射；这类房间不能宣称具备完整群 OMEMO 体验。

### 信任模型

首次看到 identity key 时采用 TOFU 并保存；相同 key 显示 trusted/TOFU，发生 key change 时标记 changed 并停止安全发送。界面可查看指纹并提示通过其他可信渠道比对，但目前没有持久的“用户已人工验证”状态、二维码互扫、多设备 key backup/export 或恢复流程。

本轮把此前硬编码 `trusted: true` 改成真实 TOFU/changed 状态，但这仍不是完整的人工验证系统。

### 浏览器本地数据

OMEMO identity、prekeys、sessions 和已知联系人 identity 持久存在 IndexedDB。消息明文不再持久保存：数据库版本升级到 2 时清空旧 `messages` store；新消息解密后只保留在当前内存，会话历史重新从 MAM 密文读取并本地解密。清浏览器数据会丢设备私钥，旧历史可能永久无法解密。

### 安全边界

- 服务器仍看得到 JID、设备 ID、时间、在线状态、近似大小、房间关系和上传 URL。
- 用户主动举报时，选中的消息会在浏览器解密后以明文发给管理员。
- 没有完成独立密码学审计，也没有在本轮重跑 Gajim/Conversations 等全矩阵互操作；不得把“静态通过”写成“密码学已认证”。

## 13. MUC 群聊

实现参考 [XEP-0045](https://xmpp.org/extensions/xep-0045.html)，范围仅限本地域 `conference.<domain>`。

### 创建和加入

- 向不存在房间发送 MUC presence 会创建临时房间，创建者为 owner。
- 默认 public、非持久、非 members-only、非 moderated、non-anonymous、上限 100。
- 校验 room localpart、nick、outcast、members-only affiliation、人数和 nick 冲突。
- 加入后向成员互发 occupant presence，再发最近最多 100 条房间历史和 subject。
- 空的非持久房间会删除；持久房间保留。

### 真实 JID 与隐私

- non-anonymous：presence 的 muc#user `<item jid='real-full-jid'>` 对所有成员可见，目的是让 OMEMO 群聊建立身份映射；本人 presence 含状态码 100/110。
- semi-anonymous：真实 JID 仅给本人和 moderator，普通 occupant 不应看到。本轮修复了旧代码对所有人泄露的缺陷。
- 修改 whois 后会更新内存 occupant 并重新广播符合新可见性规则的 presence。

### 消息与管理

- groupchat 广播给房内成员；private message/IQ 可按 room/nick 路由。
- moderated 房间限制 visitor 发言；subject 仅 moderator 可改。
- 支持配置 title、persistent、members-only、public、moderated、whois、2–1000 max users。
- 支持 owner/admin/member/outcast affiliation、moderator/participant/visitor/none role 列表和更新。
- outcast 会踢出；members-only 房取消成员身份时会踢；role none 用于 kick。
- 支持 mediated invite、`jabber:x:conference` direct invite 和 owner destroy。
- 加密房间消息保存到 `muc_messages`，加入时回放；它不是 XEP-0313 MUC MAM。

未实现或不完整：跨域 MUC、password-protected room、reserved nick、voice request、完整状态码/错误矩阵、完整 Web 房主设置界面。

## 14. 文件上传、加密附件和头像

### XEP-0363 上传槽

1. 已认证 XMPP 用户向 `upload.<domain>` 请求 filename/size/content-type。
2. 服务端检查大小和名称，创建 UUID、随机 bearer token 的 SHA-256 digest、15 分钟过期槽。
3. 返回 PUT URL、Authorization bearer header 和公开的 opaque GET URL。
4. PUT 必须 token、Content-Length、Content-Type 全部匹配，并且槽未用/未过期。
5. 存储层读取 `expected + 1`，可识别客户端多发字节；只在精确大小时把 `.part` 原子 rename 成最终对象。
6. 数据库标记 uploaded；若 DB 完成步骤失败会删除已写对象。
7. 过期清理只删除尚未上传的槽。已上传对象现在不会在 15 分钟后失效，但也没有长期 retention/垃圾回收策略。

GET URL 是 possession bearer，知道 URL 的任何人都能下载字节；服务端不扫描病毒、不做用户配额、不做对象过期删除。

### 网页加密附件

网页先用随机 AES-GCM 在浏览器加密文件，再把 ciphertext 上传。URL、key、IV、原文件名、MIME 和大小放进 OMEMO/SCE 加密消息。服务器能提供 ciphertext，但没有消息私钥时不能还原文件。

### 头像编辑器

- 原图最大 50 MiB，只在浏览器读取，不经过服务器原图接口。
- 优先 `createImageBitmap`，再尝试 WebCodecs `ImageDecoder` 和 `<img>` fallback；实际格式范围取决于浏览器 decoder。
- 防止解码炸弹：单边最大 32768 像素、总像素最大 120,000,000。
- 支持拖动裁切、1–4 倍缩放、滚轮、左右旋转、重置和圆形显示范围预览。
- 输出总是标准 JPEG；在 512→192 等尺寸和 0.92→0.36 等质量组合中尝试，直到严格小于 256 KiB。
- 最终同时发布 XEP-0084 avatar data/metadata PEP 和 `vcard-temp` photo。

这满足“本地转换不兼容原图”的大部分目标，但不是自带 RAW/HEIC/所有格式转码库；浏览器本身完全不能解码的格式仍会提示不支持。

## 15. 反滥用、PoW、举报、申诉和邀请

### 自定义阶梯模型

这是 Northstar 自定义扩展 `urn:northstar:pow:1`，不是 XMPP 标准。状态按 actor 保存于进程内 DashMap：IP、用户和 `behavior:*` 跨动作 actor 会一起参与，取其中最严格要求。

设当前超出免费 burst 的阶梯为 `n`、处罚级别为 `p`：

```text
work = clamp(action_base × n² × 2^p, 1, POW_MAX_WORK_FACTOR)
```

| 动作 | 免费 burst | action base | 额外规则 |
| --- | ---: | ---: | --- |
| registration | 1 | 0 | 主要依靠事件/时间限制；当前第一次不需 PoW |
| login | 5 次失败 | base | 成功前的未知/错误密码会累计 |
| message | 6 条内容消息 | base | 第 7 条进入 n=1；receipt/chat-state 不计内容消息 |
| report | 0 | 2×base | 第一次即要 proof |
| appeal | 0 | 8×base | 第一次即要 proof，且至少 15 秒硬等待 |

硬等待按 n=4/8/12/16 分别进入 2/10/30/120 秒台阶，再乘处罚倍数并受最大等待限制。错误、过期、重放或不匹配的 proof 会提高 `p`，处罚等待近似指数增长。活动停止后，事件先离开窗口，处罚每 `ABUSE_COOLDOWN_SECONDS` 下降一级。

### PoW 挑战

- challenge 包含 UUID、随机 prefix、work/max、step、hard wait、retry、cooldown 和提示。
- 同一 subject/action 后发 challenge 使前一个失效；challenge 一次使用，通常 120 秒或硬等待+30 秒过期。
- nonce 是最长 64 字节十进制字符串。
- 校验 `SHA-256(prefix || nonce)` 的前 64 位数值不大于 `u64::MAX/work_factor`。
- 浏览器在独立 worker 计算，不阻塞 UI，并明确显示难度、等待、最大约 8 秒目标和会逐级冷却。
- “中端手机约 8 秒”只是产品设计目标，不是按设备 benchmark 动态校准的保证。

### 邀请 token

- 管理员设置 label、1–100000 max uses、可选 1–8760 小时寿命。
- 生成 64 位随机 token，只在创建响应显示一次；DB 只存 SHA-256 digest。
- 注册事务用带 expiry/revoke/use_count 条件的原子 UPDATE 消费，避免并发超用。
- 管理员列表只看元数据，可 revoke，不能恢复 token 明文。

### 举报

- 登录用户选择类别：spam/harassment/threat/impersonation/illegal/other。
- 必须选择 1–20 条当前客户端可见聊天记录；每条 body 1–8000 字节，描述最多 4000。
- 浏览器明确提示：被选消息即使原来是 OMEMO，也会以明文交给管理员；未选消息不提交。
- 管理后台可查看队列和明文证据，把状态改成 submitted/reviewing/actioned/rejected/closed；结案状态必须填 resolution。

重要限制：证据是用户客户端提交的可编辑 JSON 文本，服务端只做结构/长度校验，没有把它密码学绑定到 MAM ciphertext、stanza ID 或发送方签名。因此它适合社区审核线索，不是不可抵赖的法证材料。

### 申诉

- 只有原举报人能对已处理举报申诉。
- 数据库 `UNIQUE(report_id)` 保证每份举报最多一次。
- 理由 20–4000 字节；管理员状态 submitted/reviewing/upheld/denied，终态必须有 resolution。
- appeal 使用 8×base、至少 15 秒等待和相同的指数处罚/阶梯冷却。

## 16. 其他 XMPP 功能

| 功能 | 运作方式 | 边界 |
| --- | --- | --- |
| XEP-0030 Discovery | 分 server/account/MUC/room/upload entity 广告实际 feature；PEP node 动态注入 | 没有全 XEP 自动注册框架 |
| XEP-0054 vCard | 每用户一份 `vcard-temp` XML，GET/SET，本地和部分 S2S 可取 | 单 payload 512 KiB，无字段级校验 |
| XEP-0084 Avatar | PEP data/metadata，网页同时写 vCard fallback | 依赖 PEP 子集 |
| XEP-0049 Private XML | 用 element name + namespace 作键，GET/SET 一个 namespaced child | name 255、namespace 1024、payload 512 KiB；无用户总配额 |
| XEP-0092 Version | 返回服务名、0.1.0、Linux | 字符串目前硬编码 |
| XEP-0199 Ping | IQ get 返回空 result | 核心实现 |
| XEP-0202 Time | 返回 UTC 和 `+00:00` | 不返回服务器本地时区偏移 |
| XEP-0203 Delay | 离线、MAM、MUC history 带 delay stamp | 部分场景 |
| XEP-0357 Push | 保存 service JID/node/options；离线时发布只含 message-count=1 的摘要 | 需要外部 push service；无持久重试 spool |
| XEP-0334 Hints | no-store/no-permanent-store 阻止 archive/offline | 其他 hints 主要透传 |
| XEP-0184/0333/0444 | receipt/marker/reaction 可路由或放在密文里 | 服务器不维护高级状态 |

## 17. S2S 联邦

### 出站

1. 从目标 JID 提取远程域，先过 enabled/allow/deny policy。
2. DNS 查询 `_xmpp-server._tcp` SRV，失败再用目标域 5269；支持 operator override 和短时 cache。
3. 默认拒绝 loopback、private、link-local、multicast 和特殊用途地址，降低 SSRF/内网探测风险。
4. 每个远程域创建一个容量 100 的 mpsc worker，并在 `s2s_outbound_connections` 复用，不是每 stanza 新连接。
5. 打开 stream、STARTTLS、用公共 roots 加可选私有 CA 验证证书链和 asserted domain，再使用 SASL EXTERNAL。
6. 在认证流上连续发送排队 stanza；连接失败会计数并尽力 bounce。

### 入站

监听 5269；检查目标是本地域、来源域通过策略，要求 STARTTLS。TLS 层允许对端先呈现证书，再由后续代码用 root store 和 claimed domain 做显式验证；SASL EXTERNAL 成功前不接受业务 stanza。认证后可处理本地 message/presence/roster 相关流量，以及 ping、vCard、PEP、disco 等部分 IQ。

### 明确未实现

- [XEP-0220 Server Dialback](https://xmpp.org/extensions/xep-0220.html)。只支持证书 + SASL EXTERNAL 的域可能无法与仍依赖 Dialback 的服务器互通。
- durable retry spool；进程/网络故障时没有数据库级跨域重试队列。
- federated MUC。
- 全部 S2S 错误、队列回压和证书部署组合的第三方互操作。

## 18. REST 与管理后台完整路由

| 方法和路径 | 权限 | 作用 |
| --- | --- | --- |
| GET `/healthz` | 公共 | 进程 liveness，只返回 HTTP handler 活着 |
| GET `/readyz` | 公共 | 执行 PostgreSQL `SELECT 1` |
| GET `/metrics` | 公共应用层 | Prometheus 文本；生产应由反代限制 |
| GET `/xmpp-websocket` | WebSocket | RFC 7395 升级 |
| GET `/api/v1/config` | 公共 | 域、注册、WebSocket、MUC、upload 等公开能力 |
| POST `/api/v1/register` | 公共/PoW | REST 注册和邀请码 |
| POST `/api/v1/login` | 公共/升级后 PoW | 返回 bearer |
| POST `/api/v1/anti-abuse/challenge` | registration 公共，其余 bearer | 发一次性挑战 |
| GET `/api/v1/me` | bearer | 当前账户资料 |
| PATCH `/api/v1/me/password` | bearer+旧密码 | 改密并撤销全部 REST session |
| GET `/api/v1/history` | bearer | 返回自己的最近 archive raw stanza |
| GET/POST `/api/v1/reports` | bearer | 自己的举报/创建举报 |
| POST `/api/v1/reports/{id}/appeals` | bearer | 对已处理举报申诉一次 |
| PUT `/api/v1/upload/{id}` | upload slot token | 精确写入对象 |
| GET `/uploads/{id}` | possession URL | 读取不可变对象 |
| GET `/api/v1/admin/stats` | admin bearer | DB 数量、在线数、联邦/abuse 指标 |
| GET/PATCH `/api/v1/admin/users[/{id}]` | admin bearer | 列表、enable/disable、升降管理员；禁止当前管理员自锁/自降权 |
| GET/PATCH `/api/v1/admin/reports[/{id}]` | admin bearer | 审核举报 |
| PATCH `/api/v1/admin/appeals/{id}` | admin bearer | 审核申诉 |
| GET/POST/DELETE `/api/v1/admin/invitations[/{id}]` | admin bearer | 列表、创建、撤销邀请 |
| POST `/api/v1/admin/tls/reload` | admin bearer | 重读证书/私钥并审计；只影响新握手 |

REST 契约在 `docs/openapi.yaml`。管理页面 token 放 `sessionStorage`；用户客户端的 REST token 只保留内存。登录后网页为自动重连暂存密码于页面内存，logout 会清除；崩溃 dump/恶意扩展仍属于浏览器威胁面。

管理员 disable 账号会阻止新的 REST/XMPP 认证，但当前结构没有按 user ID 取消已建立 XMPP socket 的控制通道，已在线资源可能持续到主动断开或进程重启。这是优先待修项。

## 19. 管理、审计、监控、日志和 TLS

### 审计日志

数据库 `audit_log` 保存 actor、action、target、JSON details、可选 IP 和时间。覆盖注册、改密、管理员用户修改、举报/申诉处理、邀请创建/撤销及 TLS reload。不是所有普通 XMPP 行为都审计，以免把聊天元数据无限写入。

### Prometheus 指标

包括 TCP/WS 连接、认证成功/失败、路由消息、离线存储、注册、联邦入/出/失败、PoW challenge、限流、举报和申诉等进程内计数。进程重启会归零；部分名为 connections 的字段是累计 counter，不是当前 gauge。`admin/stats` 另外查询用户、归档、离线、房间、上传、push、moderation 数量。

### 日志

`RUST_LOG` 控制过滤，stderr 和滚动文件同时输出；rotation 和保留数量可配置。`LOG_FORMAT=json` 输出结构化 JSON，`text` 输出可读文本。Compose 默认 JSON，原生 `.env.example` 默认 text。

本轮删除了 debug 日志中的完整 MUC/unsupported IQ/S2S reply XML，避免调高日志级别时直接记录消息正文、PEP 或 private XML。日志仍包含 JID、房间、目标域和错误元数据，必须按个人数据管理。

### TLS 热加载

`ReloadableTlsConfig` 用 ArcSwap 保存当前 C2S server config。管理员 reload 先完整解析证书链和私钥，成功后原子替换；已有 TLS 连接不变，新握手使用新证书。S2S acceptor/client config 的重建范围仍需注意：入站 listener 启动时构造的 acceptor 不会随 C2S ArcSwap 自动替换，不能把该端点理解为所有联邦连接的完整热更新。

## 20. 多语言系统

- 默认语言为 English。
- Recommended 固定包含 English、Simplified Chinese、中華民國語 / Traditional Chinese、Korean、Japanese、Spanish、French、German。
- 语言目录按英文名称字母顺序；输入每一个字符立即筛选，只显示匹配项；右侧 X 清空，放大镜手动再次触发搜索。
- 语言选择持久保存到浏览器 localStorage。
- 8 个维护语言直接在 `web/i18n.js`；其余 76 个在 `web/locales.generated.js`，共 84 种。
- Esperanto 和 Latin 保留；生成目录已经排除资料不足的若干语言。机器包用项目本地 MADLAD-400 GGUF 和 `scripts/generate-locales.mjs` 离线生成，固定并行数 2。
- 每个机器包现包含全部 330 个静态界面字符串；Yoruba 的模型病态重复输出已用本地 override 修正。
- 选择机器语言时页面持续显示“机器翻译，可能存在错误”。完整性检查只能证明 key 齐全、没有明显空值/病态重复，不能证明语言学准确；上线前应由母语审校。
- 生成模型文件未进入应用运行时，网页不会调用外部翻译服务。分发模型或衍生语言包前仍应核验所使用模型文件的确切来源和许可证。

## 21. PostgreSQL 数据模型

| 迁移/表 | 持久内容和关键约束 |
| --- | --- |
| 0001 `users` | 账号、Argon2 hash、admin/disabled、登录时间 |
| `api_sessions` | REST token digest、expiry，用户删除级联 |
| `roster_items` | 联系人、名称、subscription/ask、预留 groups JSON |
| `offline_messages` | recipient、sender、raw stanza、encrypted、时间 |
| `message_archive` | owner、peer、raw stanza、encrypted、stanza_id、时间 |
| `pep_items` | owner/node/item_id 主键、payload、更新时间 |
| `muc_rooms` | room localpart、owner、基础配置 |
| `audit_log` | 管理/安全事件 |
| 0002 `pending_presence_subscriptions` | 本地离线订阅请求 |
| 0003 `blocked_jids` | 每用户持久 blocklist |
| 0004 `muc_rooms` 扩展 | public/moderated/non_anonymous/max/subject |
| `muc_affiliations` | room+user 唯一 affiliation |
| `muc_messages` | 房间加入历史，含密文标记 |
| 0005 `upload_slots` | slot 元数据、token digest、expiry/uploaded |
| 0006 `vcards` | 每用户一份 vCard XML |
| 0007 `push_subscriptions` | service JID/node/options |
| 0008 `federated_presence_pending` | 远程 subscribe 等待本地用户上线 |
| 0009 `invitation_tokens` | token digest、uses、expiry、revoke |
| `abuse_reports` | 举报主体、分类、状态、处理人/结果 |
| `abuse_report_evidence` | 用户提交的 1–20 条明文证据 |
| `abuse_appeals` | report 唯一申诉、状态/结果 |
| 0010 indexes | 给审计、房间、上传、邀请、moderation 外键补索引 |
| 0011 users SCRAM 列 | salt/iteration/stored/server key；旧用户可为空并在成功密码登录后升级 |
| 0012 `private_xml` | user+element name+namespace 主键、XML payload |

迁移通过 `sqlx::migrate!` 嵌入二进制，启动自动执行。生产变更应先做 PostgreSQL 备份；当前没有 down migration。

## 22. Linux/Docker 部署

### Compose 结构

- PostgreSQL 17 Alpine：只在 Compose 网络内，带 healthcheck 和持久卷。
- Northstar：多阶段 Rust bookworm build，使用 `Cargo.lock` 和 `--locked`；最终 Debian slim、uid 10001、no-new-privileges，暴露 5222/5269/8080。
- Caddy：对外 80/443，反代 HTTP/WebSocket，配置 HSTS、CSP、nosniff、referrer/permissions policy。
- 证书目录只读挂载；上传和日志分别使用持久卷；8080 只绑定宿主 loopback。

复制 `.env.example` 后，Compose 还要求明确设置 `POSTGRES_PASSWORD` 和 `BOOTSTRAP_ADMIN_PASSWORD`，不能直接使用占位值。生产 DNS 至少应配置 A/AAAA 和需要时的 `_xmpp-client._tcp`、`_xmpp-server._tcp` SRV。

### 备份

至少同时备份 PostgreSQL 和 upload 卷。OMEMO 私钥只在用户浏览器，服务端备份无法恢复；需要另行设计加密 key backup 才能真正完成灾难恢复。

### 一千用户目标

`scripts/load-1000-wsl.sh`/Python 夹具可建立 1000 个实际 WebSocket 资源、检查 active session 指标并发 ping。本轮在当前 WSL/PostgreSQL 环境实测：1000 个同时认证会话全部保持，抽样 ping 通过，连接爬坡约 54.9 秒。这证明当前开发环境达到“单机千个在线资源”的基础连接目标，但不是生产容量证书；正式上线仍必须用生产 PostgreSQL、TLS、消息速率、MAM/PEP 数据量和日志设置重跑，并关注内存 session 表、每连接 512 项发送队列、DB 32 连接、联邦队列和 Argon2 并发 8。

## 23. 标准与实现依据

| 范围 | 权威依据/项目 | 为什么这样做 |
| --- | --- | --- |
| XML stream、TLS、SASL、bind、S2S | [RFC 6120](https://www.rfc-editor.org/rfc/rfc6120) | 保证标准客户端能建立基础会话 |
| roster、presence、资源优先级 | [RFC 6121](https://www.rfc-editor.org/rfc/rfc6121) | 标准即时消息语义 |
| WebSocket | [RFC 7395](https://www.rfc-editor.org/rfc/rfc7395) | 独立网页端无需浏览器直连 5222 |
| MUC | XEP-0045 | 房间、角色、真实 JID 和群 OMEMO 成员映射 |
| PEP/PubSub | XEP-0060、0163 | 保存 OMEMO device/bundle 和 avatar 节点 |
| 归档/分页 | XEP-0313、0059、0203 | 密文历史与稳定分页 |
| OMEMO/SCE | XEP-0384、0420 + libomemo.js | 端到端内容加密和成熟 ratchet 原语 |
| 上传 | XEP-0363 | 标准客户端可申请 slot，文件字节与 XMPP 分离 |
| Block/SM/Carbons | XEP-0191、0198、0280 | 多设备和弱网体验 |
| 注册 | XEP-0077、0389 + REST | 兼容原生客户端，同时让邀请/PoW 有结构化入口 |
| Push | XEP-0357 | 离线设备可由外部 push service 唤醒且摘要最小化 |
| 反滥用 | Northstar 自定义阶梯 | XMPP 没有标准 message PoW；用免费 burst 保持普通客户端兼容，再以 n²、硬等待和冷却压制持续 spam |
| 服务端架构 | Tokio + Axum + SQLx + rustls | 单进程异步 I/O、类型化 REST、PostgreSQL 事务和现代 TLS |

未发现服务端代码复制自 Prosody 或 ejabberd 的证据。它们可以作为以后互操作行为对照，但不能在没有代码/提交证据时写成“参照某项目实现”。

## 24. 本轮实际修复清单

1. 修复不可读的 `ibr.rs` Windows ACL，只修改该文件权限。
2. 修复测试中的 `hash_password` 参数，清理未使用代码和全部编译警告。
3. 加固 PLAIN authzid 与 SCRAM nonce、channel binding、proof、重复属性、UTF-8/escape 校验。
4. 增加完整 SCRAM 成功和错误通道绑定单元测试；旧用户成功密码登录后补 SCRAM verifier。
5. 未知用户执行 dummy Argon2，减弱登录 timing enumeration。
6. SM 使用配置 timeout 并清理过期状态；后台真正执行 offline TTL。
7. 删除错误的“给自己重复存 unavailable presence”逻辑。
8. 上传严格识别超长 body、清理失败临时对象、避免 15 分钟后删除已上传记录。
9. PEP 自动 ID 写回 XML、正确返回分配 ID、限制尺寸、每 node 保留 100 项、S2S 空节点返回 item-not-found。
10. 删除 discovery 未实现能力的过度广告；注册 feature 服从 open/invitation 配置。
11. 修复 XEP-0389 namespace 和注册前限流/指标/审计。
12. 修复半匿名 MUC 真实 JID 泄露和 whois 变更广播；完善 affiliation/role 后的 presence/kick 行为。
13. Web 新账号能从 PEP item-not-found 初始化 OMEMO；设备检查不再硬编码 trusted。
14. IndexedDB 不再持久保存解密消息明文，并清空旧 v1 message cache。
15. PoW 元素全部从转发/存档 stanza 移除，而不是只去掉第一个。
16. private XML 增加 name/namespace/payload 上限。
17. 修复 `.env.example` 的疑似真实凭证和字段缺项，删除漂移的旧 `env.example`。
18. Docker build 加 `Cargo.lock --locked`、EXPOSE 5269、传递全部主要配置，并持久化日志。
19. 真正实现 `LOG_FORMAT=text|json`，删除 debug 完整 XML 日志，TLS reload 增加审计。
20. 76 个机器语言包从 309 补到 330 个字符串，固定生成并行数 2，修复 Yoruba 病态重复；全部网页静态检查通过。
21. 统一 cancel token 停止三类监听，避免旧的“draining”日志与实际行为不符。
22. 删除会编译出硬编码测试数据库和弱密码的 `src/bin/reset_passwords.rs` 安全脚枪。
23. 修正 README、架构、XEP matrix 和 OpenAPI 中 S2S pooling、MUC、SM、JSON 日志、TLS route 等错误描述。
24. 把通用集成测试默认 schema/端口改为 `northstar_integration_it` 与 18480/16422/16425，显式传入测试连接参数，避免误删 `public` 或碰撞现有实例。
25. 修复集成夹具把共享 IP 的第 7 条消息 PoW 错判为路由故障的问题；夹具现在通过 REST 获取真实 challenge、遵守硬等待、计算 SHA-256 PoW 并把一次性 proof 放进 XMPP stanza，验证服务器转发前会剥离 proof。
26. 新增 `browser-e2e-wsl.sh`：使用 `northstar_browser_e2e_it`、18380/16322/16326 和严格 PID trap；同时等待 WSL 内与 Windows 宿主两侧 ready，测试地址显式作为命令行参数传给 Windows Node，避免环境变量丢失和 localhost 启动竞态。
27. 修复网页群成员弹窗只在打开瞬间渲染、成员变化后列表陈旧的问题；现在 presence 变化会同步刷新已打开弹窗，并用语言无关的 DOM 状态记录成员数。
28. 浏览器 E2E 不再依赖中文界面文字，并适配“选图后必须裁切/压缩再保存”的头像流程；本轮没有新增用户可见文字，因此最终多语言检查通过后无需重新生成静态语言包。

## 25. 当前验证结果

截至本手册编写时：

- Windows `cargo fmt --all`：通过。
- Windows `cargo check --all-targets --locked`：通过，0 个 crate 警告；工具链仅提示无法 canonicalize 用户目录，这是环境警告。
- Windows `cargo test --all-targets --locked`：10/10 通过。
- Windows `cargo clippy --all-targets --locked -- -D warnings`：通过。
- `check-i18n.mjs`：84 种语言通过。
- `check-locales.mjs`：76 个机器语言包通过。
- `check-avatar-editor.mjs`：通过。
- `check-abuse.mjs`：通过，浏览器实现能解 factor 512 测试 challenge。
- WSL Ubuntu `scripts/verify-wsl.sh all`：退出码 0；format check、locked/offline all-target check、10/10 tests 和 Clippy `-D warnings` 全部通过。
- 隔离本地集成：`northstar_integration_it`，18480/16422/16425；REST、管理、STARTTLS、WebSocket、roster、PEP/vCard 头像、消息路由、SM resume、Carbons、Blocking、MUC、HTTP Upload、XEP-0357 Push、分页 MAM、metrics 和 message PoW 闭环全部通过。
- 双域联邦：`federation_a_it`/`federation_b_it`；DNS override、S2S STARTTLS、私有测试 CA 校验、SASL EXTERNAL、跨域 PEP/vCard IQ、presence subscription、双向和离线 OMEMO 密文消息全部通过。
- 隔离浏览器 E2E：`northstar_browser_e2e_it`，18380/16322/16326；两个独立浏览器身份完成 OMEMO 单聊/群聊、加密附件上传/下载/解密、头像裁切压缩发布、管理后台和 390×844 移动布局，页面错误与核心资源加载失败均为 0。
- 单机负载：`northstar_load_1000`，18280/16222/16269；1000/1000 个同时认证 WebSocket 资源保持在线，抽样 ping 通过，连接爬坡约 54.9 秒。
- 已验证版本随后通过 `restart-browser-test-wsl.sh` 应用于保留数据库的 `18080` 测试实例；脚本只会停止 PID 文件中且 executable 与预期 Northstar binary 一致的进程。重启后 `/readyz=ready`、`/client.html=200`。

## 26. 未完善事项和优先级

### P0：公开部署前

1. 对 OMEMO/SCE 消息格式、libomemo 集成、随机数、密钥生命周期和文件 key 包装做独立密码学审计。
2. 用全新账号和清空缓存分别测试 Gajim、Conversations/Monal 等目标客户端；同时验证 PEP、direct/group OMEMO、MAM、多个设备和 key change。
3. 给 disable 用户增加 live session cancellation，确保管理禁用即时生效。
4. 决定举报证据可信度模型：若需法证价值，应把证据与服务器 archive ID/ciphertext hash、用户签名和时间戳绑定；这会改变端到端隐私边界，需产品决策。
5. 审核 GPL-3.0 前端组件分发、对应源码提供和整体许可证说明。

### P1：协议和可靠性

1. 选择是否实现 XEP-0220 Dialback；这决定可联邦服务器范围。
2. 增加数据库级 S2S retry spool、退避和死信处理。
3. 完整实现 PRECIS/JID internationalization、roster groups/versioning。
4. 补 MAM preferences、retention、MUC MAM 和去重策略。
5. 补 PEP retract/purge/config/access model，或继续严格限制广告范围。
6. 补 MUC password、voice request、reserved nick、完整错误/状态矩阵和 federated MUC。
7. 让 Web 客户端使用 SCRAM 和 SM，加入人工验证状态、二维码、加密 key backup/export。

### P1：运维和数据生命周期

1. 为已上传对象设计用户配额、恶意文件扫描、retention、孤儿对象对账和删除 API。
2. 为 archive、MUC history、audit、reports 定义保留/删除政策和数据主体请求流程。
3. `/metrics` 和 admin route 在生产反代上做私网/IP/mTLS 限制。
4. 给 Prometheus counter/gauge 命名和 restart semantics 做一次规范审查。
5. 把根目录 scratch、旧日志、恢复片段、安装器等迁出仓库；当前工作区没有 `.git`，先建立来源和备份再清理。

### P2：接口体验

1. 增加 REST logout/current-token revoke。
2. 管理后台补 MUC 管理、审计检索、分页、导出和更细权限。
3. 对 76 个机器语言包做母语抽样，低质量语言应删除或转人工包。
4. 改正密码“字符/字节”文案并增加密码强度/泄漏密码策略。

## 27. 接管者操作清单

1. 先阅读本手册、`XEP_MATRIX.md`、`ARCHITECTURE.md`、`THIRD_PARTY_NOTICES.md` 和 `docs/openapi.yaml`。
2. 确认 `.env` 与 `.env.example` 差异，不在终端/聊天输出任何 secret。
3. 在不重启生产实例前先运行：

   ```text
   cargo fmt --all -- --check
   cargo check --all-targets --locked
   cargo test --all-targets --locked
   cargo clippy --all-targets --locked -- -D warnings
   ```

4. WSL 离线验证：`scripts/verify-wsl.sh all`；只有缓存缺依赖时先显式执行 `fetch`。
5. 静态通过后再申请运行/重启授权。集成脚本应使用隔离端口和数据库，绝不能停止用户正在使用的实例或桌面应用。
6. 部署前备份数据库和上传卷，验证证书 SAN/权限、DNS SRV、Caddy、trusted proxies、联邦 allow/deny。
7. 重启后检查 `/healthz`、`/readyz`、`/metrics`、日志和管理员 stats，再做新账号 OMEMO/Gajim 冒烟。
8. 遇到 OMEMO 问题时同时抓服务端 PEP/disco XML、数据库 node/item、客户端日志和缓存状态；不能先验断言“只可能是客户端缓存”。

这份手册描述的是当前代码事实，不是对“所有 XMPP 协议都已完成”的市场承诺。任何新增 feature 都应同时更新代码、服务发现、XEP matrix、OpenAPI、静态/互操作测试和本手册。
