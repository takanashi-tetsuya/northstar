# Northstar 当前剩余妥协、设计边界与发布门禁

本文記錄 Northstar 的已知限制與驗收邊界。遷移鏈為 `0001`–`0152`，
共 151 項，保留刻意缺號 `0021`。已解決問題見 [changelog](../CHANGELOG.md)。

CI 验证隔离环境中的代码与运行行为；生产环境、公网互操作和独立安全审计
需要各自的验收记录。手动测试方法见 [MANUAL_SECURITY_VALIDATION.md](MANUAL_SECURITY_VALIDATION.md)。

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
| ARCH-SVC | 協議層已移除直接資料庫權限，部分工作器入口仍接收完整執行期狀態 | 架構債務 | **可逐步關閉** | 靜態門禁要求 `AppState=0 public fields`，協議樹的資料庫權限參照亦為零。HTTP 帳號撤銷、一般管理操作的 claim／effect、叢集 listener 及會話清理已使用窄能力；`SessionCleanupService` 只在建構時接收 `Arc<AppState>`。其他工作器與傳輸入口仍須檢查，零公開欄位也不等於資料庫角色已分權 | 收斂剩餘的寬權限入口並通過對應門禁後，才依領域拆分資料庫角色；保留協議樹的零權限基線 |
| ARCH-CLU | Redis 多节点控制面不是共识系统，活跃 socket/worker 仍属于单个进程 | 架构债务＋刻意范围 | **可显著改善，不能在现架构中证明为共识** | PostgreSQL 保存权威 fence、lease、outbox、key epoch 和 replay fence；Redis 只承担实时控制与唤醒。账号禁用、删除或改密在本节点立即撤销路由并同步撤销 durable SM；账号变更与逐进程撤销队列在同一 PostgreSQL 事务提交。节点由 NOTIFY 唤醒并以 1 秒轮询补漏，关闭旧路由后确认确切修订号；30 秒 generation sweep 仍保留为补充校验。撤销读取或确认超时（2 秒）会关闭本机路由，连续失败或 10 秒 watchdog 超时会触发关键 worker 停机。排队、调度及网络分区仍会增加延迟，不能保证毫秒级撤销。非对称分区、进程崩溃和短暂 authority cache 窗仍需要完整故障证明，因此多节点模式保持 `Experimental` | 若要晋升，需完成持久撤销队列的规模与故障验证，以及任意 Redis/PostgreSQL 分区、split-brain、滚动版本、schema expand/contract、SIGKILL、managed failover 和 RPO/RTO 验证；否则永久保留“实验性而非共识系统”，不得无条件声称跨节点“立即撤销” |
| ARCH-CLU-V13 | durable MIX cross-node hand-off 的 wire contract 升至 v13，旧节点不能滚动兼容 | 刻意 fail-closed 安全设计 | **协议扩展后可改善；当前必须保留** | v13 将一个精确 MIX recipient lease 随签名命令传送。目标节点先在 PostgreSQL 中将它旋转为 node/request fence，随后只能转交至 socket fence、XEP-0198 或 BOSH owner；只有该 typed hand-off 才会确认 source durable row。v12 及更旧节点不理解这一语义，因此混合节点会拒绝并保留重试行，绝不会把“写入远端内存队列”误报成已投递 | 部署时先停用/排空跨节点 MIX 交付，再将所有节点升级为同一 v13 release 后恢复；若要支持滚动升级，必须设计带版本协商、双写确认与旧节点安全拒绝的 expand/contract 过程，不能静默降级 hand-off 语义 |
| ARCH-CLU-VOLATILE | 部分跨节点事件仍是软状态 | 架构债务＋刻意设计 | **按事件类型决定** | 可存储的 `normal`/`chat` direct message、文档列明的特定邀请、PubSub/PEP mutation、MUC 管理操作和已进入 durable admission 的 S2S/component message 有 PostgreSQL 持久投影；普通 MUC groupchat 只有 archive 加 best-effort Redis 实时扇出，普通 presence、MUC presence/typing、Carbons 及部分 roster/presence 通知在故障时可能丢失或稍后收敛 | 对必须可靠的事件建立有界 recipient-snapshot outbox、稳定 ID 和 ACK；presence/typing 等瞬态状态是否持久化必须先做产品与隐私决策，不能笼统承诺“集群零丢失” |
| ARCH-CLU-MUC | 複合 MUC 管理 IQ 的原子處理 | 已解決的架構債務 | **已實作** | 合法的多筆 role、affiliation 及混合操作由同一 PostgreSQL 交易檢查權限、occupant generation、最終 owner 與受眾，再寫入單一事件及 outbox；任何一筆失敗都整批回滾 | 維持單節點、跨節點、聯邦及重試回歸測試；不把普通 MUC groupchat 的即時扇出說成可靠投遞 |
| ARCH-DB-ROLE | 除上傳生命週期外，多數可變業務表仍共用 runtime 角色 | 架构债务＋运维信任 | **`users`、XEP-0133 与 session authority 边界已关闭；其余子系统尚未逐服务分权** | migration 0108 已把注册、登录 verifier 升级、改密、管理员状态/提权、会话撤销、删除、roster version 与 recovery generation 迁到 typed capability。runtime 对 `users` 只有 SELECT，连列级 INSERT/UPDATE/REFERENCES 也被清除；runtime 与独立 `northstar_commands` 均无法读取/写入 command session/keyed authority 表。专用 command role 无任何 relation/sequence 权限，只能执行 canonical manifest 的 `command` 分区。上傳生命週期已由 `northstar_storage` 的獨立連線池與 ACL 管理。所有 definer 都必须以完整规范化签名进入独立 manifest、由 migrator 持有并 pin schema；grant reconciliation 和每次 runtime/command 启动都会按 ACL catalog 验证“owner＋唯一授权 workload”、无 grant option、无 PUBLIC/backup/未知/退役 grantee、无未登记 overload。session authority 还精确核对 trigger 的表、名字、function OID/signature、tgtype、启用状态、无 WHEN 和无额外项。伪 token、跨 command/target、过期、完成后 replay、旧 generation 和并发单赢家均有 DB 门禁 | 剩餘妥協是同一 runtime 角色仍對非 `users`、非上傳的多數可變業務表有廣泛 DML，且 command URL 与 runtime URL 仍位于同一 OS 进程（进程完全攻陷高于“任意 runtime SQL”威胁边界）。继续按认证、消息、MUC/PubSub、上传拆分应用服务/数据库能力；完整签名 manifest 的 exact allowlist 只能收窄、不能绕过或退回名字/数量门禁 |
| ARCH-MIGRATE-STORAGE | Local ↔ S3 上傳物件遷移 | 已解決的工具缺口 | **已實作** | 離線遷移器記錄每次複製嘗試，逐物件核對來源 SHA-256 和目的端精確版本，切換前重讀全部目的物件；任一不符便保留原權威與來源資料。新啟動節點會拒絕進行中的遷移 | 運維仍須先停止所有現有節點並保留來源及退役鍵；本地檔案系統不因此變成多節點共用儲存 |
| ARCH-RESTORE | 硬中斷後的還原判定 | 已解決的工具缺口＋運維前置條件 | **已實作；目標部署待驗** | 恢復命令以 fsync journal、資料庫 XID 與同交易結果標記判定前進或補償，並核對 S3 新鍵的精確版本；證據缺漏時保持連線 fence 關閉。2026-09-26 隔離 VM 的本地與 S3 三個 SIGKILL 中斷點、獨立金鑰解密回滾 dump 均通過，見 [本地 VM 驗收](LOCAL_VM_QUALIFICATION.md) | 還原前仍須停止所有 writer，保留受保護的備份與物件版本；在實際目標儲存與密鑰環境重演後才可宣稱部署級復原能力 |
| OPS-RESTORE-OFFLINE | rollback dump 的一致性依赖明确的 stopped-writer 恢复窗口 | 刻意离线恢复设计＋PostgreSQL 连接模型 | **当前必须由运维前置条件关闭** | rollback dump 在 `ALLOW_CONNECTIONS=false` 之前生成，因为当前最小权限 migrator 在数据库禁止连接后不能新建 `pg_dump` 会话。脚本在 cutover fence 后拒绝任何仍存在的 peer，但无法从数据库内证明 dump 与 fence 之间没有一个已经退出的短连接写入；违反“先停 Northstar 和全部数据库客户端”的前置条件，补偿快照可能落后于该写入 | 恢复前由 supervisor 停止并验证全部 writer，隔离数据库网络入口，仅保留恢复凭据，再执行 restore；在目标环境保存 `pg_stat_activity`/supervisor 证据。若要消除人工前置条件，需要新的数据库侧 quiescence/write-epoch authority 或可预建并在 fence 后使用的一致快照通道，且不得通过授予应用 superuser/CREATEDB 来绕过 |
| ARCH-OPTIONAL-XMPP | 若干低优先级可选协议形状没有实现 | 产品范围＋架构成本 | **可实现，但不阻塞当前 profile** | 不支持 BOSH multi-stream、通用 S2S multi-domain multiplex、additional-domain/target piggyback 和多条 pooled S2S stream；这些能力没有被广告 | 只有在出现明确互操作需求时逐项实现并建立第三方测试；在此之前必须继续写成“不支持”，不能用普通 stanza 转发冒充完整实现 |
| HIST-JID | 旧 JID 数据的 canonical collision 无法自动决定合并对象 | 历史数据＋刻意 fail-closed | **只能人工关闭每个实例** | `audit-identities --dry-run` 能只读检测格式问题和碰撞，但不能判断两个历史 principal 谁应保留；自动合并可能造成越权 | 在恢复副本上审计，由数据所有者逐项决定合并/重命名/删除，备份后停掉全部节点再迁移。工具不应自行猜测所有权 |
| HIST-MAM-DIRECTION | 旧 archive 行缺少权威消息方向 | 历史数据 | **新数据可修，旧数据不可无损回填** | REST MAM 对未知 `direction` 参数直接拒绝，而不是根据 JID 猜测后返回不完整结果 | 新 schema 从明确版本开始保存权威方向；API 对旧行返回 `unknown` 或提供版本化契约。不得伪造历史方向 |
| STD-FINAL-ACK | 任意 S2S、XEP-0114 和 XEP-0225 对端没有通用 application-stanza ACK | 标准限制 | **永久边界** | PostgreSQL outbox、严格顺序和稳定 XEP-0359 ID 把丢失风险降为 at-least-once；Northstar 入站 admission 会抑制精确重放，但无法强制任意第三方 peer 去重。已协商 XEP-0198 的 S2S 连接等待 peer ACK 后才完成 outbox；未协商 SM 的对端及组件仍在 socket write 后完成。S2S 支持最多 60 秒的同程序续传；重启、切换节点或租约失效时回到持久队列重试。ACK 丢失或数据库完成前崩溃仍可能重复，`Cross-domain PubSub` 最终跨域传输也继承该边界 | 只有双方采用额外 ACK/幂等扩展时才能进一步收窄；对任意标准 peer 必须永久声明“at-least-once，可能稳定 ID 重复”，不得声称 exactly-once |
| STD-C2S-ACK | 服务器无法证明客户端已经显示或处理消息 | 标准限制 | **永久边界** | XEP-0198 和 BOSH ACK 前允许按稳定 ID 重放；无 SM 的 TCP/WebSocket 在成功写 socket 后完成。客户端可能已经收到字节但尚未确认 | 推荐 SM、receipts 和 endpoint stable-ID 去重。服务器只能证明传输边界，不能证明 UI 展示或用户阅读 |
| STD-COMPONENT | XEP-0114 没有 TLS 协商或应用 stanza ACK；XEP-0225 仍为 Deferred | 标准限制 | **不能在保持原协议时根治** | XEP-0114 的 SHA-1 handshake 不是传输加密，默认只能位于 loopback、VPN、mTLS 隧道或等价隔离网络；组件重试仍可能重复稳定 ID | 可停用 XEP-0114、用安全隧道或受审计替代协议；兼容模式下必须限制网络范围、保护 secret，并要求组件幂等 |
| STD-REMOTE-MUC-SM | C2S XEP-0198 不恢复远端/federated MUC occupancy | 标准限制＋安全设计 | **需要跨服务器新协议才可改变** | 本地节点无法证明仍拥有远端房间中的 occupant，因而 fail-closed，不伪造无缝恢复 | 只有远端服务器共同实现可验证 ownership/resume 协议并通过互操作后才能改变；当前永久声明“需要重新加入，不能保证无缝恢复” |
| DESIGN-NOSTORE | `no-store`、signal-only、headline、Carbons、presence/typing 和部分 post-commit 通知是 `volatile`/best-effort | 刻意设计＋隐私语义 | **不应统一持久化** | `no-store` 不进入 MAM、spool 或 outbox；没有有界在线 route 时显式失败。瞬态状态可在背压、断线或集群故障中丢失，避免违反隐私承诺或形成无界积压 | 逐类定义可靠性；只有不违反 XEP-0334 和用户预期的类别才可增加持久 outbox。必须永久避免把 `no-store` 静默降级为存储 |
| DESIGN-PRIVACY | 匿名房间 MAM 的 sender filter 被拒绝 | 刻意隐私设计 | **不建议改变** | 对匿名历史按真实发送者过滤会成为身份 oracle；服务器宁可拒绝该查询形状 | 除非能证明不会泄露匿名身份并经过隐私审查，否则永久保留拒绝行为 |
| DESIGN-ENDPOINT | Jingle 媒体、ICE、TURN 数据面、call state、已读/反应渲染和 push 数据面不由核心服务器执行 | 刻意分层＋外部依赖 | **不是服务器缺陷** | Northstar 验证/路由 Jingle 与消息扩展，通过 XEP-0215 发现服务和签发 coturn 凭据；实际 STUN/TURN、媒体和 XEP-0357 push service 必须独立部署。Push 所依赖规范仍有 Deferred 范围 | 关闭的是部署门禁：配置真实服务并做端到端通话/推送测试；不能把核心服务器宣传为 TURN、媒体服务器或移动平台 push gateway |
| DESIGN-BOUNDS | 明确的持久容量、内存、并发、dead-letter、保留期与 fail-closed readiness 上限可能拒绝真正的新工作 | 刻意资源安全设计 | **不应取消；不得用它掩盖正确性缺陷** | MIX 在独立提交的完整 reconciliation 后才应用 `100,000` row/`256 MiB` 与 PAM `10,000` global/`64` per-account 硬上限；这些上限不决定 ACK、释放或锁所有权。Caps 的 observation 才是语义权威，cache 与有界 dispatcher 只保存可丢弃的复用数据/唤醒提示；提示饱和或 TTL 到期不删除 effect，federated resource 超限则在 presence 路由前显式返回 `resource-constraint`。其他持久队列同样在写入前执行明确 admission，避免磁盘、连接池、对象存储或恢复债务无界增长 | 用目标 SLO、告警、恢复与排空 runbook 验证参数。若必须增加上限、等待固定轮询/重试次数、依赖 cache 驻留或重复请求才能消除 false-full、丢 effect、错 owner，即属于待修架构缺陷而不是容量调优。保留上限的条件是拒绝可观测、语义完整、释放可线性化且恢复不依赖任意时间常数 |
| DESIGN-RETENTION | replay/idempotency tombstone、集群 operation journal 和审计在线窗口都有有限保留期 | 刻意资源与隐私设计 | **边界永久，期限可配置/审查** | 这些行支持在线重试而非永久 WORM 证据；到期后无法无限期识别旧 replay。legal hold 会阻止受保护内容删除 | 根据威胁模型和法规设置期限；需要永久证据时使用外部 WORM/签名锚定，不把在线 PostgreSQL 表宣传成永久取证系统 |
| DESIGN-UPLOAD-SCAN | 服务端无法对 OMEMO 加密附件做有意义的明文恶意内容扫描 | 密码学边界＋刻意 E2EE | **永久边界** | 服务器只能验证密文大小、类型声明、hash 和存储完整性；服务器端解密扫描会破坏 E2EE | 可在客户端加密前扫描，或对明确未加密上传接入扫描器；不得声称“密文已经完成恶意内容扫描” |
| DESIGN-OMEMO | OMEMO 私钥、信任决定和 fingerprint 验证属于端点；举报解密明文无法由服务器证明 | 标准/密码学边界 | **永久边界** | 服务端保存 PEP 公共材料和 archive ciphertext/digest，不托管私钥。举报中的解密文本必须标注为 `user-supplied/unverified`，所以 moderation 不是 zero knowledge | 保留人工指纹/QR 验证、设备撤销和密文证据链；服务器不得自动信任设备、伪造验证或宣称能证明用户解密结果 |
| DESIGN-TLS-RELOAD | TLS reload 不能原地替换现有连接已经协商的会话 | TLS 架构属性 | **只能缓解** | 新连接立即使用新证书、trust/CRL generation；旧连接继续使用原握手，只有明确证书撤销会触发精确 drain，普通续期不会无差别踢线 | 高风险轮换执行受控 connection drain；永久声明“reload 影响新握手，现有 TLS 会话需要重连或显式 drain” |
| PROFILE-REVOCATION | 本地 CRL、自有服務憑證的可選 OCSP stapling，以及可選的出站 S2S staple 驗證已實作；尚無線上取得回應 | 產品範圍＋網路安全取捨 | **部分實作，仍需環境驗證** | 自有憑證可載入操作者提供的 DER 回應；嚴格出站 PKIX 模式要求對端提供簽名有效、狀態為 `good` 且仍在有效期的 staple，缺失或錯誤時拒絕連線。DANE-EE 不套用 CA 撤銷。兩種模式均不從 AIA 抓取資料 | 在隔離 VM 以目標憑證和不同客戶端驗證輪換、失效及 TLS 1.2/1.3；若增加線上來源，先定義白名單、地址與重定向限制、快取、超時和失敗政策。完成前不宣稱線上 OCSP/CRL/AIA 支援 |
| PROFILE-XEP | `Partial`、`Pass-through`、`Experimental` 只表示明确实现的 profile，不是完整实现整个 XEP | 刻意产品范围＋规范成熟度 | **逐项可扩展** | XEP-0225、XEP-0357、XEP-0408、XEP-0487 等包含 Deferred/Experimental 边界；vCard4、现代媒体/信任扩展和 MIX/MUC coexistence 只实现矩阵声明的语义 | 以 [XEP_MATRIX.md](XEP_MATRIX.md) 为唯一逐协议范围。只有实现、自动化证据、第三方互操作和规范状态均允许时才能升级标签；端点职责不得伪装成服务器状态机 |
| WEB-ORIGIN | 网页服务器和静态资源发布链始终位于浏览器 OMEMO 的 E2EE 信任根 | Web 平台架构＋运维信任 | **网页形态下永久存在** | 控制服务器、TLS/CDN 或发布凭据的一方可以在用户下次加载时替换验证代码；同源 CSP、SRI、hash 和签名 manifest 能提高可见性，但验证器也由同源下发时不能消除该风险 | 高风险部署提供独立签名的桌面/移动/浏览器扩展客户端和可验证更新/透明日志。网页客户端必须永久声明其代码分发方属于信任根 |
| WEB-PLATFORM | 浏览器没有 TLS exporter 或可靠 secure-memory/erase 能力 | 浏览器平台限制 | **当前 Web API 下不可根治** | 网页端不能实现真实 SCRAM-SHA-256-PLUS，密码登录使用 SASL2 SCRAM-SHA-256；可选 Passkeys 通过 WebAuthn 验证 Origin、RP ID 和用户确认，再签发 FAST 凭据。两种方式均使用 FAST 和 SM；JavaScript 字符串无法保证清零，ArrayBuffer 擦除也只是 best-effort | Passkeys 改善防钓鱼能力，但不等同 TLS channel binding，仍依赖 HTTPS 和同源安全。缩短密码/密钥生命周期、Worker 隔离、立即清表单并优先 FAST。要获得 channel binding 和可证明安全内存，需浏览器标准新增能力或使用原生客户端 |
| WEB-TRANSFER | OMEMO 恢复包是一次性设备 **move**，不是 escrow 或通用备份 | 刻意密码学设计＋平台限制 | **可改善 UX，不应改名为 backup** | 同一 Double Ratchet 状态不能在源/目标并行使用；弱包口令可被离线猜测，服务器限流无效；已因前向保密删除的旧密钥不能恢复，服务器也不能证明离线副本已物理擦除 | 使用高熵口令/安全设备通道、冻结 source、永久 generation fence 和重新验证联系人。若需要可恢复备份，必须另行设计并审计多设备/备份协议 |
| SUPPLY-WASM | `libomemo.js 2.0.2` 與 `hash-wasm` 已固定來源、雜湊與 SBOM，但尚不能從原始碼逐位元組重建最終 WASM/JS | 上游供應鏈限制 | **可透過升級或重建工程關閉** | CI 已離線驗證兩個 npm 發佈包與部署位元組、registry 簽名，以及 `libomemo.js` 的簽署標籤。`hash-wasm` 使用的舊 registry 金鑰現已過期；兩者仍缺精確編譯器、可信建構來源及兩次獨立重建證據 | 使用固定 digest、簽署且無網路的建構容器，讓兩個隔離 builder 產生相同位元組，並離線核驗部署檔、SBOM、來源證明與工具鏈報告；完成前維持 `provenance-traced-not-reproducible` |
| PROVIDER-S3 | `object_store 0.14.1` 不能对 S3 noncurrent version 发出精确 version-qualified DELETE，晚完成 multipart 也受 provider lifecycle 影响 | 上游 API＋对象存储模型 | **应用侧不能完全关闭** | commit/scrub 阶段验证 version、size 和 SHA-256；delete 阶段只能先 HEAD 核对当前 version，再发出不带 version 的 DELETE，因此仍存在 provider 侧 HEAD→DELETE 边界，不能删除指定 noncurrent version。cleanup tombstone 处理晚出现的当前对象，但旧版本、delete marker 和未完成 multipart parts 仍可能占用存储 | 对选定 provider 审计并演练 version expiration、noncurrent/delete-marker lifecycle、abort multipart、Object Lock 和 legal hold；或升级到支持精确版本删除且经过测试的后端 API |
| OPS-S3-BACKUP | PostgreSQL 备份只保存对象 manifest，不包含 S3 对象字节 | 外部基础设施责任 | **通过部署验收关闭** | S3 部署必须结合 provider-native versioned snapshot/replication、KMS、Object Lock 和凭据备份；不能拿本地 tar 流程替代 | 在隔离 namespace 完整恢复数据库及对象，然后逐对象验证 version/size/SHA-256；记录 RPO/RTO、KMS/凭据恢复和生命周期策略 |
| OPS-TRUST | 数据库 superuser、KMS/HSM、WORM、legal hold、备份目标、Redis ACL/TLS 和对象存储策略属于运维信任边界 | 运维信任 | **不能由应用自证** | 应用 trigger、hash chain 和签名游标不能阻止数据库 owner 修改数据；反滥用 `key ID` authority 能检测节点漂移，但无法修复运营者丢失的 HMAC secret | 使用职责分离、非 owner runtime、独立审计日志/WORM 锚定、密钥双人控制、轮换和恢复演练。数据库与 secret 必须作为同一代恢复，epoch 不得回退或复用 |
| OPS-BACKUP-COMPAT | 回滾制品可能是明文，且保留 `development-legacy` 模式 | 維運取捨 | **仍需收緊** | 生產備份預設要求 Ed25519 簽名、age 加密及可信還原代際。還原使用停止寫入的窗口、私有 journal、資料庫 XID 與同交易標記。切換前註冊並核驗四個後端 PID：維護控制、目標協調、主替換與補償；封鎖新連線後，目標庫只允許後三個已登記 PID。`recover-restore.sh` 可在 `SIGKILL` 後核驗證據並繼續或補償。證據衝突、過舊而無法判定的 XID，或缺失的物件版本都會保留連線 fence。回滾目錄預設仍可能保存明文 dump 與物件 | 將回滾目錄放在加密儲存，離機保存密鑰與可信狀態，並在目標環境演練硬中斷復原；過舊 XID 的不確定情況仍須人工處理。相容期結束後移除 `development-legacy` |
| EXT-CLUSTER | 叢集、CLU-MUC、capacity ledger 和共用儲存尚缺完整環境驗收 | 僅缺運行證據 | **完整矩陣通過後才可關閉** | 隔離 VM 已完成兩節點簽名 Redis 控制面、版本化 MinIO、跨節點雙向直達訊息；短暫 Redis 分區拒絕不安全新綁定並恢復，B 的 PostgreSQL 分區令關鍵 worker 關閉程序、手動重啟後恢復，B 的 MinIO 分區在 30 秒讀取上限回 503、解除後按原雜湊讀回；B 硬中斷時租約阻擋立即重入；一個非空物件的 S3→Local→S3 離線往返保留 SHA-256。這是探索性結果，詳見 `LOCAL_VM_QUALIFICATION.md` | 在凍結版本上補齊長時間與組合分區、lease loss、SM race、混合版本、Redis failover、遷移硬中斷恢復、S3/MinIO 磁碟遺失與新主機還原、provider lifecycle，保存設定、原始日誌和 RPO/RTO。完成前多節點仍為 `Experimental` |
| EXT-CAPACITY | `1,000-session` 测试不是 1,000 名同时活跃用户的生产 SLA | 仅缺目标环境证据 | **目标硬件验收后可关闭证据项** | 现有脚本主要验证认证连接和调度，未完整模拟 initial presence、roster、MUC、OMEMO、MAM、upload、push 与 federation 混合负载 | 在目标 Linux 主机执行代表性账号/资源和业务混合、冷/热启动及 24–72 小时 soak，记录 CPU、RSS、FD、Tokio、PostgreSQL WAL/IOPS、网络和 p50/p95/p99；结论只适用于被测 commit/配置/硬件 |
| EXT-FEDERATION | 隔離 VM 的基本雙向訊息與對端停機恢復已通過，完整聯邦矩陣仍未完成 | 僅缺實驗證據 | **完整本地矩陣通過後才可關閉** | 2026-09-26 在無公網路由的 VM 網路中，Northstar 分別與固定版本 Prosody、ejabberd 雙向送達訊息，重建 Northstar 節點後再次通過；兩個對端各自停機時保留出站佇列，重啟後送達。結果屬未凍結候選版本的探索性驗證，詳見 `LOCAL_VM_QUALIFICATION.md`。在線撤銷缺口另見 `PROFILE-REVOCATION` | 在固定提交上補齊 DNSSEC/SRV/TLSA、DANE、IPv4/IPv6、憑證輪換、失敗分支與重連，保存版本、設定、DNS 鏈與原始日誌。公網部署邊界另見 `DEPLOY-PUBLIC` |
| DEPLOY-PUBLIC | 隔離 VM 實驗無法驗證公網部署 | 本輪刻意排除 | **不以本地實驗關閉** | 本地 DNSSEC、私有 CA 與虛擬網路不能證明公網 DNS 傳播、公共 CA 信任鏈、實際 IPv4/IPv6 路由或跨營運商故障行為 | 若日後需要宣稱公網生產資格，另行安排公網驗收；本輪只宣稱已測 VM 拓撲 |
| EXT-COMPONENT | 第三方組件互操作尚未覆蓋全部方向與版本 | 運行證據＋第三方差異 | **XEP-0114 accept 已局部驗證；完整矩陣未完成** | 2026-09-26 隔離 VM 以固定版本 Slixmpp 1.10.0 驗證 XEP-0114 accept 的鑑權、錯誤密碼拒絕、C2S 回音及 Northstar 重啟後重新鑑權與投遞；原始證據見 [本地 VM 驗收](LOCAL_VM_QUALIFICATION.md)。先前 strict mock peer 仍只算內部契約測試；組件缺乏通用應用 ACK 的限制見 `STD-FINAL-ACK` | 補齊獨立 XEP-0114 connect gateway 投遞、XEP-0225 第三方實作、斷線 outbox、背壓、穩定 ID 重試及去重；沒有獨立對端時保持相應項目開放 |
| EXT-CLIENT | 網頁、Gajim 和其他原生客戶端互操作證據不足 | 僅缺運行證據＋客戶端差異 | **逐客戶端記錄結果** | 現有人工證據只有一次未記錄 Gajim 版本的 localhost 加密 MUC；Northstar browser transfer 仍需雙瀏覽器、崩潰邊界和 PostgreSQL race 驗證。一般客戶端互通不包含匯入私有 ratchet 資料庫 | 使用最終候選 binary、受信任的實驗室 CA 與固定客戶端版本，在 VM 網路執行登入、OMEMO、多設備、trust、MAM、Carbons、CSI/SM 與重連矩陣；另測 browser transfer。Conversations 需 Android VM；Monal 若沒有可接入隔離網路的 Apple 裝置，須明記未測 |
| EXT-SECURITY | 尚无独立 RFC/XEP 审查、安全审计和渗透测试 | 外部资格 | **第三方完成后可关闭证据项** | 内部静态检查、单元测试和自审不能构成认证，也不能证明不存在未知漏洞 | 固定 release commit、binary digest、SBOM、部署拓扑和 threat model，委托独立方审查 XML/state machine、REST/WebSocket/BOSH/S2S/component、Redis/object store、浏览器密码学和权限模型。高风险公网部署前必须完成 |
| EXT-OPERATIONS | 真实告警接收、升级/静默/恢复、离机备份和灾难恢复尚缺目标部署演练 | 外部运维证据 | **演练后可关闭证据项** | 仓库有 metrics、Prometheus rules、Grafana 和 runbook，但阈值与通知链没有目标流量基线；代码不能证明值班人员或备份目的地有效 | 完成通知演练、恢复演练、容量阈值校准和定期 restore drill，记录负责人、时间、RTO/RPO 和失败处置 |

## 发布验证

候选版本的状态以对应提交的 [GitHub Actions](https://github.com/takanashi-tetsuya/northstar/actions)
结果为准。压力测试的故障分析、修复和制品校验记录见
[CI 验证记录](handoff/2026-09-12/CI-PERFORMANCE-FOLLOWUP.md)。
发布预演验证 Windows、Linux 与 Docker 构建；正式发布还会验证草稿中的
下载制品、来源证明和公开镜像，完成后由维护者手动发布。

定时 fuzz、production/cluster load envelope 和 scheduled stress 属于定时或
手动 CI；普通 push/PR 按策略跳过这些工作。最终发布还需要精确 `main` 提交的
可信 CI、签名标签及制品验证，流程见 [发布职责](governance/release-roles.md)。

## 发布解释

- 当前没有记录为“已复现且尚未修复”的 P0/P1 代码漏洞；这不等于经过独立审计，也不等于生产资格已经完成。
- 單節點模式不受 Redis 集群架構債務直接阻斷。隔離 VM 驗收只適用於被測拓撲；高風險公網生產聲明仍需另行驗證公網部署、離機備份、目標硬體、客戶端與獨立安全審查。
- 多节点模式只有在 `EXT-CLUSTER` 关闭后才可考虑从 `Experimental` 晋升；通过基本两节点用例不足以证明共识或任意分区安全。
- “标准限制”“刻意设计”和“平台限制”行不能因测试通过而删除，只能在产品不再支持对应协议/客户端形态，或底层标准和平台发生实质变化时重审。
- `Partial`、`Pass-through` 和 `Experimental` 的逐协议范围以 [XEP_MATRIX.md](XEP_MATRIX.md) 为准；本表不重复宣称完整支持所有可选 XEP 行为。

## 维护规则

1. 可修项只有在实现、迁移、自动化回归、权限/隐私说明和运维文档全部完成后才能移除。
2. 仅缺运行证据的项目必须保存针对精确 commit、二进制、配置和环境的结果；脚本存在不等于脚本已执行。
3. 永久边界应保留稳定 ID 和准确措辞，不能为了发布宣传而删除。
4. 若已经解决的历史问题再次回归，应建立新的 Issue ID、最小复现和失败测试，而不是复制旧报告。
5. 当前实现映射见 [TRACEABILITY.md](TRACEABILITY.md)，生产操作见 [PRODUCTION_OPERATIONS.md](PRODUCTION_OPERATIONS.md)；已经完成或失效的旧解决计划仅保留在 [历史归档](archive/) 中。
