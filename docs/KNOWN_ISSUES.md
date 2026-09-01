# Northstar 当前剩余妥协、设计边界与发布门禁

> 基线：2026-09-02 当前工作区；迁移 `0126`–`0128`、XEP-0198 事件通知与 XEP-0115 observation 重构已经进入代码，但发布前仍须对最终提交重新保存完整门禁证据。
> 定位：这是当前唯一的剩余问题与妥协清单。已经解决的历史问题属于 changelog 或历史验收报告，不应继续出现在这里。
> 证据边界：仓库测试和静态检查不等于生产环境、公网互操作或独立安全认证。按用户要求，本轮没有执行可能触发 cybersecurity 拦截的 fuzz、畸形/对抗网络流量、故障注入、攻击式反滥用验证或极限负载；这些项目已移至 [MANUAL_SECURITY_VALIDATION.md](MANUAL_SECURITY_VALIDATION.md) 供授权操作者在隔离环境中手动执行。

## 如何理解下表

- **架构债务**：实现可工作，但内部边界仍不够理想；可以继续通过重构关闭。
- **刻意设计**：为了隐私、安全、资源上限或协议分层主动选择的行为；不应在没有新产品决策时“修掉”。
- **标准限制**：RFC/XEP 没有提供服务器单方面所需的确认或所有权证明；只能缓解，不能承诺不存在。
- **历史数据**：新数据可以改善，但旧数据没有足够事实可安全回填。
- **平台/上游限制**：受浏览器、第三方库或对象存储 API 约束。
- **运维信任边界**：代码无法替代密钥管理、数据库超级用户控制、WORM、KMS 或告警响应。
- **仅缺运行证据**：实现和测试定义已经存在，但必须在最终制品和目标环境实际执行后才能关闭。

“可关闭”表示能够通过代码或明确的验收工作移出本文件；“永久边界”表示只能持续缓解和准确声明。

## 剩余妥协总表

| ID | 妥协点 | 原因分类 | 是否可修复 | 当前行为与影响 | 关闭条件或必须保留的最终表述 |
| --- | --- | --- | --- | --- | --- |
| ARCH-XML | 已跟踪的运行时外发 XML 生成点已全部使用结构化构造边界，但门禁仍是静态启发式检查 | 已大幅缓解的架构债务 | **主运行时路径已关闭；审计范围可继续扩大** | `check-outbound-xml-construction.mjs` 对所有列入基线的协议、传输、联邦、组件、集群及相关服务生产文件报告 `current=0, baseline=0`。这阻止已知高风险文字字面量回归，但不是 XML 语义或注入安全证明；例如离线管理工具 `pie.rs` 仍有经转义审阅的专用序列化器，不在这个运行时门禁的全量声明内 | 保持每个运行时生成器的零基线，新增生成点必须纳入门禁；对 PIE 等专用序列化器单独建立 fragment/QName/转义不变式与恶意输入回归，不得将“静态基线为零”宣传为形式化安全证明 |
| ARCH-SVC | 应用服务边界已从协议层收回数据库权限，但 `AppState` 与服务/仓储层的能力划分仍可继续收紧 | 架构债务 | **可逐步关闭** | 最新纯静态门禁结果为 `AppState=9 public fields`，协议树为 `0 db authority refs / 0 db domain-model refs / 0 state.pool / 0 sqlx:: / 0 PgPool refs`。九个公开字段仍包括配置、通用数据库池、集群、会话/MUC 路由、指标、联邦、反滥用和 TLS 能力。协议层的直接持久化耦合已归零，但不代表 API、应用服务、工作器或仓储层已经按进程/数据库角色做到完全最小权限，也不证明事务与副作用的所有故障窗口已穷尽 | 继续将九个公开能力收窄为领域端口，分离 API/工作器/业务库角色并使事务由应用服务统一所有；CI 的 `9/0/0/0/0/0` 基线只能下降不能提高，并需增加服务/API 层的相应能力门禁 |
| ARCH-CLU | Redis 多节点控制面不是共识系统，活跃 socket/worker 仍属于单个进程 | 架构债务＋刻意范围 | **可显著改善，不能在现架构中证明为共识** | PostgreSQL 保存权威 fence、lease、outbox、key epoch 和 replay fence；Redis 只承担实时控制与唤醒。账号禁用、删除或改密在本节点立即撤销路由并同步撤销 durable SM；Redis 控制失败但 PostgreSQL 健康时，其他节点依赖下一次 30 秒 generation sweep 关闭旧 socket，因此存在约一个 sweep 的有界窗口。若 PostgreSQL 同时不可用，窗口可延长且安全关键 worker/readiness 必须反映故障。非对称分区、进程崩溃和短暂 authority cache 窗仍需要完整故障证明，因此多节点模式保持 `Experimental` | 若要晋升，需 durable revocation journal/ACK 或成熟共识与线性化控制面，并完成任意 Redis/PostgreSQL 分区、split-brain、滚动版本、schema expand/contract、SIGKILL、managed failover 和 RPO/RTO 验证；否则永久保留“实验性而非共识系统”，不得无条件声称跨节点“立即撤销” |
| ARCH-CLU-VOLATILE | 部分跨节点事件仍是软状态 | 架构债务＋刻意设计 | **按事件类型决定** | 可存储的 `normal`/`chat` direct message、文档列明的特定邀请、PubSub/PEP mutation、MUC 管理操作和已进入 durable admission 的 S2S/component message 有 PostgreSQL 持久投影；普通 MUC groupchat 只有 archive 加 best-effort Redis 实时扇出，普通 presence、MUC presence/typing、Carbons 及部分 roster/presence 通知在故障时可能丢失或稍后收敛 | 对必须可靠的事件建立有界 recipient-snapshot outbox、稳定 ID 和 ACK；presence/typing 等瞬态状态是否持久化必须先做产品与隐私决策，不能笼统承诺“集群零丢失” |
| ARCH-CLU-MUC | 混合 affiliation＋role、一次修改多个 role 的 MUC 管理 IQ 被原子拒绝 | 架构债务＋安全取舍 | **可关闭** | 服务器拒绝无法由一个现有事务安全表达的复杂形状，避免部分成功、错误受众和权限漂移；普通单类管理操作正常 | 建立统一的批量 operation/authorization/audience 事务模型，并通过回滚、重试、outbox、版本冲突和跨节点故障测试后再接受这些形状 |
| ARCH-DB-ROLE | runtime 对其余可变业务表仍是共享角色 | 架构债务＋运维信任 | **`users`、XEP-0133 与 session authority 边界已关闭；其余子系统尚未逐服务分权** | migration 0108 已把注册、登录 verifier 升级、改密、管理员状态/提权、会话撤销、删除、roster version 与 recovery generation 迁到 typed capability。runtime 对 `users` 只有 SELECT，连列级 INSERT/UPDATE/REFERENCES 也被清除；runtime 与独立 `northstar_commands` 均无法读取/写入 command session/keyed authority 表。专用 command role 无任何 relation/sequence 权限，只能执行 canonical manifest 的 `command` 分区。所有 definer 都必须以完整规范化签名进入独立 manifest、由 migrator 持有并 pin schema；grant reconciliation 和每次 runtime/command 启动都会按 ACL catalog 验证“owner＋唯一授权 workload”、无 grant option、无 PUBLIC/backup/未知/退役 grantee、无未登记 overload。session authority 还精确核对 trigger 的表、名字、function OID/signature、tgtype、启用状态、无 WHEN 和无额外项。伪 token、跨 command/target、过期、完成后 replay、旧 generation 和并发单赢家均有 DB 门禁 | 剩余妥协是同一个 runtime role 仍对非 `users` 的多数可变业务表有广泛 DML，且 command URL 与 runtime URL 仍位于同一 OS 进程（进程完全攻陷高于“任意 runtime SQL”威胁边界）。继续按认证、消息、MUC/PubSub、上传拆分应用服务/数据库能力；完整签名 manifest 的 exact allowlist 只能收窄、不能绕过或退回名字/数量门禁 |
| ARCH-MIGRATE-STORAGE | 缺少正式、可恢复的 Local→S3 数据迁移工具 | 架构债务 | **可关闭** | 当前只能按文档离线复制、校验 hash/version，再切换 locator；误操作风险由人工流程承担。本地存储本来就只支持单节点 | 实现 manifest 驱动、可中断恢复、可回滚的离线迁移器，并验证混合 namespace 拒绝、全量 version/size/SHA-256、断点恢复和权限边界 |
| ARCH-RESTORE | restore 遭遇 SIGKILL 或断电后仍需人工处理 fsync journal | 架构债务＋安全取舍 | **可关闭** | 数据库保持 fail-closed，不会假装恢复成功，但维护者必须判断 resume 或 compensate，恢复时间不完全自动化 | 提供独立诊断及确定性的 resume/compensate 工具，对每个 rename、fsync、数据库 cutover 和空间耗尽点执行掉电测试，且不得自动删除尚未判定的证据 |
| ARCH-OPTIONAL-XMPP | 若干低优先级可选协议形状没有实现 | 产品范围＋架构成本 | **可实现，但不阻塞当前 profile** | 不支持 BOSH multi-stream、通用 S2S multi-domain multiplex、additional-domain/target piggyback 和多条 pooled S2S stream；这些能力没有被广告 | 只有在出现明确互操作需求时逐项实现并建立第三方测试；在此之前必须继续写成“不支持”，不能用普通 stanza 转发冒充完整实现 |
| HIST-JID | 旧 JID 数据的 canonical collision 无法自动决定合并对象 | 历史数据＋刻意 fail-closed | **只能人工关闭每个实例** | `audit-identities --dry-run` 能只读检测格式问题和碰撞，但不能判断两个历史 principal 谁应保留；自动合并可能造成越权 | 在恢复副本上审计，由数据所有者逐项决定合并/重命名/删除，备份后停掉全部节点再迁移。工具不应自行猜测所有权 |
| HIST-MAM-DIRECTION | 旧 archive 行缺少权威消息方向 | 历史数据 | **新数据可修，旧数据不可无损回填** | REST MAM 对未知 `direction` 参数直接拒绝，而不是根据 JID 猜测后返回不完整结果 | 新 schema 从明确版本开始保存权威方向；API 对旧行返回 `unknown` 或提供版本化契约。不得伪造历史方向 |
| STD-FINAL-ACK | 任意 S2S、XEP-0114 和 XEP-0225 对端没有通用 application-stanza ACK | 标准限制 | **永久边界** | PostgreSQL outbox、严格顺序和稳定 XEP-0359 ID 把丢失风险降为 at-least-once；Northstar 入站 admission 会抑制精确重放，但无法强制任意第三方 peer 去重。socket write 成功、数据库完成前崩溃仍可能重复，`Cross-domain PubSub` 最终跨域传输也继承该边界 | 只有双方采用额外 ACK/幂等扩展时才能进一步收窄；对任意标准 peer 必须永久声明“at-least-once，可能稳定 ID 重复”，不得声称 exactly-once |
| STD-C2S-ACK | 服务器无法证明客户端已经显示或处理消息 | 标准限制 | **永久边界** | XEP-0198 和 BOSH ACK 前允许按稳定 ID 重放；无 SM 的 TCP/WebSocket 在成功写 socket 后完成。客户端可能已经收到字节但尚未确认 | 推荐 SM、receipts 和 endpoint stable-ID 去重。服务器只能证明传输边界，不能证明 UI 展示或用户阅读 |
| STD-COMPONENT | XEP-0114 没有 TLS 协商或应用 stanza ACK；XEP-0225 仍为 Deferred | 标准限制 | **不能在保持原协议时根治** | XEP-0114 的 SHA-1 handshake 不是传输加密，默认只能位于 loopback、VPN、mTLS 隧道或等价隔离网络；组件重试仍可能重复稳定 ID | 可停用 XEP-0114、用安全隧道或受审计替代协议；兼容模式下必须限制网络范围、保护 secret，并要求组件幂等 |
| STD-REMOTE-MUC-SM | XEP-0198 不恢复远端/federated MUC occupancy | 标准限制＋安全设计 | **需要跨服务器新协议才可改变** | 本地节点无法证明仍拥有远端房间中的 occupant，因而 fail-closed，不伪造无缝恢复 | 只有远端服务器共同实现可验证 ownership/resume 协议并通过互操作后才能改变；当前永久声明“需要重新加入，不能保证无缝恢复” |
| DESIGN-NOSTORE | `no-store`、signal-only、headline、Carbons、presence/typing 和部分 post-commit 通知是 `volatile`/best-effort | 刻意设计＋隐私语义 | **不应统一持久化** | `no-store` 不进入 MAM、spool 或 outbox；没有有界在线 route 时显式失败。瞬态状态可在背压、断线或集群故障中丢失，避免违反隐私承诺或形成无界积压 | 逐类定义可靠性；只有不违反 XEP-0334 和用户预期的类别才可增加持久 outbox。必须永久避免把 `no-store` 静默降级为存储 |
| DESIGN-PRIVACY | 匿名房间 MAM 的 sender filter 被拒绝 | 刻意隐私设计 | **不建议改变** | 对匿名历史按真实发送者过滤会成为身份 oracle；服务器宁可拒绝该查询形状 | 除非能证明不会泄露匿名身份并经过隐私审查，否则永久保留拒绝行为 |
| DESIGN-ENDPOINT | Jingle 媒体、ICE、TURN 数据面、call state、已读/反应渲染和 push 数据面不由核心服务器执行 | 刻意分层＋外部依赖 | **不是服务器缺陷** | Northstar 验证/路由 Jingle 与消息扩展，通过 XEP-0215 发现服务和签发 coturn 凭据；实际 STUN/TURN、媒体和 XEP-0357 push service 必须独立部署。Push 所依赖规范仍有 Deferred 范围 | 关闭的是部署门禁：配置真实服务并做端到端通话/推送测试；不能把核心服务器宣传为 TURN、媒体服务器或移动平台 push gateway |
| DESIGN-BOUNDS | 明确的持久容量、内存、并发、dead-letter、保留期与 fail-closed readiness 上限可能拒绝真正的新工作 | 刻意资源安全设计 | **不应取消；不得用它掩盖正确性缺陷** | MIX 在独立提交的完整 reconciliation 后才应用 `100,000` row/`256 MiB` 与 PAM `10,000` global/`64` per-account 硬上限；这些上限不决定 ACK、释放或锁所有权。Caps 的 observation 才是语义权威，cache 与有界 dispatcher 只保存可丢弃的复用数据/唤醒提示；提示饱和或 TTL 到期不删除 effect，federated resource 超限则在 presence 路由前显式返回 `resource-constraint`。其他持久队列同样在写入前执行明确 admission，避免磁盘、连接池、对象存储或恢复债务无界增长 | 用目标 SLO、告警、恢复与排空 runbook 验证参数。若必须增加上限、等待固定轮询/重试次数、依赖 cache 驻留或重复请求才能消除 false-full、丢 effect、错 owner，即属于待修架构缺陷而不是容量调优。保留上限的条件是拒绝可观测、语义完整、释放可线性化且恢复不依赖任意时间常数 |
| DESIGN-RETENTION | replay/idempotency tombstone、集群 operation journal 和审计在线窗口都有有限保留期 | 刻意资源与隐私设计 | **边界永久，期限可配置/审查** | 这些行支持在线重试而非永久 WORM 证据；到期后无法无限期识别旧 replay。legal hold 会阻止受保护内容删除 | 根据威胁模型和法规设置期限；需要永久证据时使用外部 WORM/签名锚定，不把在线 PostgreSQL 表宣传成永久取证系统 |
| DESIGN-UPLOAD-SCAN | 服务端无法对 OMEMO 加密附件做有意义的明文恶意内容扫描 | 密码学边界＋刻意 E2EE | **永久边界** | 服务器只能验证密文大小、类型声明、hash 和存储完整性；服务器端解密扫描会破坏 E2EE | 可在客户端加密前扫描，或对明确未加密上传接入扫描器；不得声称“密文已经完成恶意内容扫描” |
| DESIGN-OMEMO | OMEMO 私钥、信任决定和 fingerprint 验证属于端点；举报解密明文无法由服务器证明 | 标准/密码学边界 | **永久边界** | 服务端保存 PEP 公共材料和 archive ciphertext/digest，不托管私钥。举报中的解密文本必须标注为 `user-supplied/unverified`，所以 moderation 不是 zero knowledge | 保留人工指纹/QR 验证、设备撤销和密文证据链；服务器不得自动信任设备、伪造验证或宣称能证明用户解密结果 |
| DESIGN-TLS-RELOAD | TLS reload 不能原地替换现有连接已经协商的会话 | TLS 架构属性 | **只能缓解** | 新连接立即使用新证书、trust/CRL generation；旧连接继续使用原握手，只有明确证书撤销会触发精确 drain，普通续期不会无差别踢线 | 高风险轮换执行受控 connection drain；永久声明“reload 影响新握手，现有 TLS 会话需要重连或显式 drain” |
| PROFILE-REVOCATION | 证书撤销只支持本地、签名与 freshness 校验后的 PEM CRL，没有 OCSP 或在线 CRL/AIA 获取 | 产品范围＋网络安全取舍 | **可实现，不能靠运行测试关闭** | 当前 profile 避免盲目访问证书给出的 URL 和由此产生的 SSRF/可用性问题；CRL 的可靠获取与及时 reload 是运营者责任。DANE-EE 按其信任模型不使用 CA revocation | 若产品需要在线撤销，必须实现有界来源、重定向/地址策略、缓存、stapling/freshness、SSRF 防护和明确 fail policy；否则永久声明“仅本地 CRL，不支持 OCSP/在线 AIA” |
| PROFILE-XEP | `Partial`、`Pass-through`、`Experimental` 只表示明确实现的 profile，不是完整实现整个 XEP | 刻意产品范围＋规范成熟度 | **逐项可扩展** | XEP-0225、XEP-0357、XEP-0408、XEP-0487 等包含 Deferred/Experimental 边界；vCard4、现代媒体/信任扩展和 MIX/MUC coexistence 只实现矩阵声明的语义 | 以 [XEP_MATRIX.md](../XEP_MATRIX.md) 为唯一逐协议范围。只有实现、自动化证据、第三方互操作和规范状态均允许时才能升级标签；端点职责不得伪装成服务器状态机 |
| WEB-ORIGIN | 网页服务器和静态资源发布链始终位于浏览器 OMEMO 的 E2EE 信任根 | Web 平台架构＋运维信任 | **网页形态下永久存在** | 控制服务器、TLS/CDN 或发布凭据的一方可以在用户下次加载时替换验证代码；同源 CSP、SRI、hash 和签名 manifest 能提高可见性，但验证器也由同源下发时不能消除该风险 | 高风险部署提供独立签名的桌面/移动/浏览器扩展客户端和可验证更新/透明日志。网页客户端必须永久声明其代码分发方属于信任根 |
| WEB-PLATFORM | 浏览器没有 TLS exporter 或可靠 secure-memory/erase 能力 | 浏览器平台限制 | **当前 Web API 下不可根治** | 网页端不能实现真实 SCRAM-SHA-256-PLUS，只能使用 SASL2 SCRAM-SHA-256、FAST 和 SM；JavaScript 字符串无法保证清零，ArrayBuffer 擦除也只是 best-effort | 缩短密码/密钥生命周期、Worker 隔离、立即清表单并优先 FAST。要获得 channel binding 和可证明安全内存，需浏览器标准新增能力或使用原生客户端 |
| WEB-TRANSFER | OMEMO 恢复包是一次性设备 **move**，不是 escrow 或通用备份 | 刻意密码学设计＋平台限制 | **可改善 UX，不应改名为 backup** | 同一 Double Ratchet 状态不能在源/目标并行使用；弱包口令可被离线猜测，服务器限流无效；已因前向保密删除的旧密钥不能恢复，服务器也不能证明离线副本已物理擦除 | 使用高熵口令/安全设备通道、冻结 source、永久 generation fence 和重新验证联系人。若需要可恢复备份，必须另行设计并审计多设备/备份协议 |
| SUPPLY-WASM | `libomemo.js 2.0.2` 与 `hash-wasm` 已固定来源、hash 和 SBOM，但尚不能从源码逐字节复现最终 WASM/JS | 上游供应链限制 | **可通过升级或重建工程关闭** | 缺少精确 npm executable、Emscripten、LLVM/Binaryen 工具链、上游签名/attestation 和两个独立 builder 的同字节证据；当前 CI 只能证明 vendored artifact 未漂移 | 采用 digest-pinned、签名、无网络构建容器，两个隔离 builder 逐字节一致，部署字节、SBOM、provenance 和工具链报告可离线验证；完成前保持 `provenance-traced-not-reproducible` |
| PROVIDER-S3 | `object_store 0.14.1` 不能对 S3 noncurrent version 发出精确 version-qualified DELETE，晚完成 multipart 也受 provider lifecycle 影响 | 上游 API＋对象存储模型 | **应用侧不能完全关闭** | commit/scrub 阶段验证 version、size 和 SHA-256；delete 阶段只能先 HEAD 核对当前 version，再发出不带 version 的 DELETE，因此仍存在 provider 侧 HEAD→DELETE 边界，不能删除指定 noncurrent version。cleanup tombstone 处理晚出现的当前对象，但旧版本、delete marker 和未完成 multipart parts 仍可能占用存储 | 对选定 provider 审计并演练 version expiration、noncurrent/delete-marker lifecycle、abort multipart、Object Lock 和 legal hold；或升级到支持精确版本删除且经过测试的后端 API |
| OPS-S3-BACKUP | PostgreSQL 备份只保存对象 manifest，不包含 S3 对象字节 | 外部基础设施责任 | **通过部署验收关闭** | S3 部署必须结合 provider-native versioned snapshot/replication、KMS、Object Lock 和凭据备份；不能拿本地 tar 流程替代 | 在隔离 namespace 完整恢复数据库及对象，然后逐对象验证 version/size/SHA-256；记录 RPO/RTO、KMS/凭据恢复和生命周期策略 |
| OPS-TRUST | 数据库 superuser、KMS/HSM、WORM、legal hold、备份目标、Redis ACL/TLS 和对象存储策略属于运维信任边界 | 运维信任 | **不能由应用自证** | 应用 trigger、hash chain 和签名游标不能阻止数据库 owner 修改数据；反滥用 `key ID` authority 能检测节点漂移，但无法修复运营者丢失的 HMAC secret | 使用职责分离、非 owner runtime、独立审计日志/WORM 锚定、密钥双人控制、轮换和恢复演练。数据库与 secret 必须作为同一代恢复，epoch 不得回退或复用 |
| OPS-BACKUP-COMPAT | 生产备份已 fail-closed，仍保留显式 development legacy 与明文 rollback/人工硬崩溃处置 | 兼容性＋运维取舍 | **生产默认已关闭；剩余项可继续收紧** | base Compose 与脚本默认强制 Ed25519、age、sequence/restore floor 和 file-backed 分权 URL；legacy 只有单一 `development-legacy` 开关并警告。backup/restore 都在 Unix-socket-only 临时 PostgreSQL 验证 dump，不再用生产角色 createdb；restore 不 terminate peer，发现存量连接即要求先停服务，并在单个替换事务内复用 migrator-owned schema/ACL/default-privilege policy 后才重新开放连接。恢复前 rollback 目录仍可能是明文，SIGKILL/断电后的 journal 仍需人工判断；sequence/floor state 丢失仍会改变 lineage 或可信下限 | rollback 放在加密卷并完成密钥/状态离机副本与恢复演练；实现确定性 resume/compensate 后再关闭硬崩溃项。任何 `allow-generation-change` 都需独立审计；legacy 兼容期结束后删除显式开发入口 |
| EXT-CLUSTER | 集群、CLU-MUC、capacity ledger 和 shared storage 的当前 checkout 尚无完整运行证据 | 仅缺运行证据 | **执行后可关闭证据项** | 两节点 fixture 已定义但本轮只做静态/纯测试；尚未证明所有非对称分区、lease loss、SM race、旧新二进制、managed Redis failover、S3/MinIO crash/restore 和 provider lifecycle | 在固定 release commit 上执行全部隔离 PostgreSQL/Redis/MinIO fixture、网络分区和 kill-point，并保存配置、日志、版本、结果和 RPO/RTO。完成前多节点仍为 `Experimental` |
| EXT-CAPACITY | `1,000-session` 测试不是 1,000 名同时活跃用户的生产 SLA | 仅缺目标环境证据 | **目标硬件验收后可关闭证据项** | 现有脚本主要验证认证连接和调度，未完整模拟 initial presence、roster、MUC、OMEMO、MAM、upload、push 与 federation 混合负载 | 在目标 Linux 主机执行代表性账号/资源和业务混合、冷/热启动及 24–72 小时 soak，记录 CPU、RSS、FD、Tokio、PostgreSQL WAL/IOPS、网络和 p50/p95/p99；结论只适用于被测 commit/配置/硬件 |
| EXT-FEDERATION | 公网 DNSSEC/SRV/TLSA、IPv4/IPv6、DANE、PKIX/本地 CRL 轮换和多个独立 peer 尚未形成当前 release 证据 | 外部环境＋仅缺运行证据 | **执行后可关闭证据项** | 本地 resolver、TLS policy 和 CRL 测试不能证明公共 DNS、CA 路径或第三方服务器行为；在线撤销能力缺口另由 `PROFILE-REVOCATION` 记录，不能用互操作测试代替实现 | 在公网 staging 对 Prosody/ejabberd/Openfire 等独立实现记录完整矩阵、DNS chain、证书指纹、版本、CRL reload/drain 和故障结果 |
| EXT-COMPONENT | 真实第三方 external component/gateway 互操作证据不足 | 仅缺运行证据＋第三方差异 | **执行后可关闭证据项** | 2026-08-27 的 isolated strict mock peer 覆盖了本地 runtime 形状，但不能代替真实 XEP-0114 accept/connect 或 XEP-0225 component；标准缺少应用 ACK 的永久边界仍由 `STD-FINAL-ACK` 保留 | 使用固定版本的真实组件分别验证两种 XEP-0114 方向，以及 XEP-0225 STARTTLS、SASL、bind/unbind、重连、Northstar/component restart、背压、稳定 ID 重试和组件侧去重，并保存证据 |
| EXT-CLIENT | 网页、Gajim 和其他原生客户端互操作证据不足 | 仅缺运行证据＋客户端差异 | **执行后可关闭证据项** | 现有人工证据只有一次未记录 Gajim 版本的 localhost 加密 MUC；Northstar browser transfer 仍需真实双浏览器、崩溃边界和 PostgreSQL race 验证。Conversations、Dino、Monal 等只属于标准 XMPP/OMEMO wire 互操作范围，不承诺导入其私有密钥或 ratchet 数据库 | 使用最终 release binary、可信公网 TLS、固定客户端版本，执行登录、OMEMO 单聊/群聊、多设备、trust、MAM、Carbons、CSI/SM 和重连矩阵；browser-to-browser transfer 单独执行迁移/崩溃测试。若将来要导入第三方私有状态，必须另建产品与密码学设计项 |
| EXT-SECURITY | 尚无独立 RFC/XEP 审查、安全审计和渗透测试 | 外部资格 | **第三方完成后可关闭证据项** | 内部静态检查、单元测试和自审不能构成认证，也不能证明不存在未知漏洞 | 固定 release commit、binary digest、SBOM、部署拓扑和 threat model，委托独立方审查 XML/state machine、REST/WebSocket/BOSH/S2S/component、Redis/object store、浏览器密码学和权限模型。高风险公网部署前必须完成 |
| EXT-OPERATIONS | 真实告警接收、升级/静默/恢复、离机备份和灾难恢复尚缺目标部署演练 | 外部运维证据 | **演练后可关闭证据项** | 仓库有 metrics、Prometheus rules、Grafana 和 runbook，但阈值与通知链没有目标流量基线；代码不能证明值班人员或备份目的地有效 | 完成通知演练、恢复演练、容量阈值校准和定期 restore drill，记录负责人、时间、RTO/RPO 和失败处置 |

## 当前发布候选的证据状态

| 项目 | 结果 | 证据范围 |
| --- | --- | --- |
| `0126`–`0128`、SM、Caps 与 WebSocket 终止序列确定性回归 | 当前候选为 `1,184 total / 1,017 passed / 167 ignored / 0 failed` | 这是最终工作树的普通 Rust 测试结果；ignored 的隔离 PostgreSQL/Redis 项没有执行，不能视为通过。发布 CI 仍须把结果绑定到最终 commit |
| Rust 最终静态质量门禁 | `fmt`、all-target/all-feature `check`、Clippy `-D warnings` 全部通过 | 结果对应 2026-09-02 的最终暂存工作树；提交后 CI 必须重跑，不能由这条记录替代 |
| 架构静态门禁 | `AppState=9`；协议树 `0 db authority / 0 db domain-model / 0 state.pool / 0 sqlx:: / 0 PgPool` | MIX producer service gate、Caps queue/cache 非权威与 exact-owner teardown、SM event/recheck 静态不变量均通过；静态匹配仍不是权限或故障安全的运行证明 |
| 外发 XML 与文档/迁移门禁 | 通过：raw-XML 基线为零，127 个 migration，152 个 capability，ledger/checksum 和文档一致 | 迁移当前最大值为 `0128`；实际应用迁移、角色授权与回滚仍由隔离 CI/目标环境证明 |
| 运行时/外部证据 | 本轮未新增 | 没有执行 fuzz、畸形网络流量、故障注入、极限负载、公网联邦或客户端 GUI 验证；实现变化不能自动继承旧制品的运行证据 |

本轮明确未执行 fuzz、WebSocket/BOSH 畸形帧、Slowloris/churn、反滥用/密码学攻击式矩阵、SIGKILL/磁盘满/断电点、PostgreSQL/Redis/对象存储故障注入、千会话极限负载或公网联邦安全探测。详细手动验证方案见 [MANUAL_SECURITY_VALIDATION.md](MANUAL_SECURITY_VALIDATION.md)。

## 发布解释

- 当前没有记录为“已复现且尚未修复”的 P0/P1 代码漏洞；这不等于经过独立审计，也不等于生产资格已经完成。
- 单节点模式不受 Redis 集群架构债务直接阻断，但仍必须完成目标硬件、备份恢复、证书、公网互操作、客户端和安全审计门禁后，才能作高风险公网生产声明。
- 多节点模式只有在 `EXT-CLUSTER` 关闭后才可考虑从 `Experimental` 晋升；通过基本两节点用例不足以证明共识或任意分区安全。
- “标准限制”“刻意设计”和“平台限制”行不能因测试通过而删除，只能在产品不再支持对应协议/客户端形态，或底层标准和平台发生实质变化时重审。
- `Partial`、`Pass-through` 和 `Experimental` 的逐协议范围以 [XEP_MATRIX.md](../XEP_MATRIX.md) 为准；本表不重复宣称完整支持所有可选 XEP 行为。

## 维护规则

1. 可修项只有在实现、迁移、自动化回归、权限/隐私说明和运维文档全部完成后才能移除。
2. 仅缺运行证据的项目必须保存针对精确 commit、二进制、配置和环境的结果；脚本存在不等于脚本已执行。
3. 永久边界应保留稳定 ID 和准确措辞，不能为了发布宣传而删除。
4. 若已经解决的历史问题再次回归，应建立新的 Issue ID、最小复现和失败测试，而不是复制旧报告。
5. 当前实现映射见 [TRACEABILITY.md](TRACEABILITY.md)，生产操作见 [PRODUCTION_OPERATIONS.md](PRODUCTION_OPERATIONS.md)；已经完成或失效的旧解决计划仅保留在 [历史归档](archive/) 中。
