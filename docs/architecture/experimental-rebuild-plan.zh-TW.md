# Northstar 實驗架構現況

更新：2026-10-06。Stage0／1與Stage2 reservation/finalization受控子退出已驗收。
來源版本與測試 hash 見下列結果索引。

## 階段與退出條件

| 階段 | 必須成立的責任與證據 | 現況 |
|---|---|---|
| 0 基線 | 固定來源；admission、commit、handoff、write、ACK、settlement各有明確權威；Unknown不當rollback | 已驗收 |
| 1 規格 | actor共用容量／TTL、初態與混合負載預檢；精確oracle；取消、中斷、缺證據與cleanup分判 | 限定synthetic／fixture scope已驗收 |
| 2 Shared admission | production與controlled共用transitions；真實outcome、完整effect/fence關聯；可保存、重播、縮減的正常／拒絕／replay／expiry／Unknown案例 | Reservation/finalization子退出已驗收 |
| 3 Direct lifecycle | 真mode-aware commit連接既有router、exact queue item、write及SM/BOSH owner；取消、partial write、replacement與stale ACK不丟失責任 | [有限受控退出已驗收](../evidence/experimental-rebuild/stage3-controlled-acceptance.json)：16／16 baseline、4／4 mutation／shrink、62項reader controls與責任矩陣完成；真實adapter／資源限制仍屬後續階段 |
| 4 高風險域 | MUC/MIX、auth publication（含write/exposure後failure/cancel）、worker claim/recovery皆有production共用受控案例及跨域組合 | [BOSH selected-control gate](../evidence/experimental-rebuild/stage4-bosh-auth-control-results.json)、[MUC discussion continuation](../evidence/experimental-rebuild/stage4-muc-discussion-results.json)、[MIX foreground](../evidence/experimental-rebuild/stage4-mix-foreground-results.json)、[MIX worker](../evidence/experimental-rebuild/stage4-mix-worker-results.json)、[auth returned-receipt continuation](../evidence/experimental-rebuild/stage4-auth-returned-receipt-results.json)、[auth pre-receipt observation](../evidence/experimental-rebuild/stage4-auth-pre-receipt-results.json)及[SM recovery retention](../evidence/experimental-rebuild/stage4-sm-retention-results.json)限定source／component範圍通過；完整階段仍未完成 |
| 5 Real adapters | PostgreSQL交易／鎖／fence／Unknown與模型相符；stock wire與獨立peer；確切版本及cleanup | 未完成 |
| 6 有限qualification | 有效負載、資源／事件／時間界限、backpressure／recovery觀測及獨立cleanup；缺terminal不能Pass | 未完成；72h soak已取消 |

另見[責任稽核](../handoff/2026-10-03/experimental-authority-audit.md)及
[領域缺口](../handoff/2026-10-03/experimental-domain-gap-audit.md)。

## Stage2：實際共用與驗證

[Coordinator](../../crates/northstar-abuse-policy/src/admission_execution.rs)與
[純交易決策](../../crates/northstar-abuse-policy/src/admission_transaction.rs)由正式
[service](../../src/services/message_admission.rs)及[SQL repository](../../src/db/message_admission_repository.rs)使用。
SQL原有交易、鎖、authority及fence檢查保留。準備中的prospective fence與已確認receipt分開；
completion不能替換獨立witness，取消可留下Waiting，多個Unknown不能偷用隱藏world消除不確定性。
Reconcile保留實際返回的effect與as-of，但尚無production runtime consumer。

- 固定82案record與82案saved-input replay各自完成；input、Rust stdout、evaluation相同，PID／耗時各自驗證
- 每次domain為36 Pass、5預期Safety違反、5 Cancelled、2 Inconclusive、34 InvalidScenario；FixtureMatched不等於全數Pass
- 3→2縮減保留同一cap反例與因果，精確一列移除的正對照為4096
- 24個actual v2 reader情境通過：前後完整正例，中間22個篡改依指定phase／reason拒絕；原證據及來源未改
- 113項pure/mock與51項具名Rust CI提供各自有限證據；數量不可相加，251項ignored不算DB驗證
- [Object-only parser修正](../evidence/experimental-rebuild/stage2-map-only-parser-results.json)另通過7項精確回歸；固定82案未涵蓋positional records／array-hidden UUID，不是一般strict-input證明

[接受範圍](../evidence/experimental-rebuild/stage2-acceptance.json)、
[record/replay索引](../evidence/experimental-rebuild/stage2-record-replay-results.json)、
[reader結果](../evidence/experimental-rebuild/stage2-v2-reader-results.json)、
[具名CI](../evidence/experimental-rebuild/stage2-named-rust-ci-matrix.md)保留來源、hash與限制。

## 等價性與未完成邊界

[前後比較](../evidence/experimental-rebuild/stage2-existing-rust-before-after.md)有5個相同test-body的既有Rust回歸。
另11個Stage1獨立模型案例與新Rust相容projection一致；這不是舊production SQL實測或全產品等價證明。
4097反例以前一個過期pending row仍存留為前提，尚未證明production caller可達性。
舊相容案例的首個failure在case8/op-1，native／shrink目標在op-2。

[Saved-case source readiness](../evidence/experimental-rebuild/stage3-profile-readiness-results.json)已完成；[首次record](../evidence/experimental-rebuild/stage3-baseline-first-stop.json)在C01因finalization-return觀測缺口停止（1/16），原始驗證資料私有保留。
[Callback觀測修正](../evidence/experimental-rebuild/stage3-finalization-boundary-results.json)後，重新綁定的[固定16案record與16案replay](../evidence/experimental-rebuild/stage3-baseline-record-replay-results.json)各自通過獨立審查；每次為8 Pass、5 planned Cancelled、3 InvalidScenario，完整DTO（含seq）與evaluation一致。舊C01停止及另一次零案例的prelaunch失敗仍保留，不能改稱通過。
[隔離no-flush反例及縮減](../evidence/experimental-rebuild/stage3-no-flush-record-replay-results.json)的4案record與4案replay已驗收：每次3個同目標Safety違反（qualified=false）及1個單byte寫入失敗的Pass正對照；完整DTO（含seq）、evaluation與shrink關係一致。
[Stage3有限受控驗收](../evidence/experimental-rebuild/stage3-controlled-acceptance.json)另完成62項reader檢查：4個完整正例、42個固定外部authority拒絕、15個明列測試manifest前提的內層拒絕及1個tuple縮減拒絕；未新增Rust案例啟動。責任矩陣已獨立審查，這不代表所有CI或全產品等價性通過。先前d288文件checkpoint的Caddy診斷收到完整synthetic429回應後仍等待TLS EOF逾時，原因未知；後續27053來源checkpoint的CI為32成功／1略過，不能據此視為解決，仍列入Stage5同一未解問題。
[BOSH auth-control修正](../evidence/experimental-rebuild/stage4-bosh-auth-control-results.json)把publication綁到實際被選入回應且被responder接受的control；失敗或pending後drop不能完成cache。24項精確Rust與295項Node檢查、compile／Clippy通過；舊predicate比較只是source-bound witness。完整credential／frame關聯、SQL publication及Stage4跨域證據仍待完成。工作區回退造成最初auth本地raw與binary遺失；相同27053來源另完成24項精確Rust、295項Node及compile／Clippy的新驗證並私有保存，不能稱原始檔已恢復。
[MUC discussion continuation](../evidence/experimental-rebuild/stage4-muc-discussion-results.json)已連接同一request／COMMIT receipt／returned result與一次性fanout，保留原SQL、room guard、Replay原ID及volatile語義；39項精確Rust（22新案、17控制）、329項Node及兩package compile／Clippy通過。這仍是pure／fake與source範圍；完整MUC保存組合尚未完成。
[MIX foreground](../evidence/experimental-rebuild/stage4-mix-foreground-results.json)已分開authenticated Replay read、fresh message COMMIT、實際return與一次性local wake，保留原SQL及獨立capacity prelude。31項精確Rust（17新案、14控制）、367項Node與三package compile／Clippy通過。首輪既有native ACK probe因新增COMMIT同名呼叫而匹配兩處，在Cargo前停止；精確限定原native呼叫後的新批次通過，原失敗保留。五項protocol模組測試使用真owner與supplied fake facts，未執行完整protocol→service→SQL；此checkpoint不涵蓋MIX worker；完整auth correlation與跨域保存組合仍待完成。
[MIX worker](../evidence/experimental-rebuild/stage4-mix-worker-results.json)已連接既有Delivery worker的claim、personal archive、typed transfer、renewal scope及一次性settlement owner；64項普通命令、53項精確Rust與467項Node檢查已通過獨立審查；Rust無failure／ignored，compile／Clippy及migration source gate皆通過。53項精確Rust含26新案（16 pure core、10有限runtime／protocol controls）及27既有控制。Claim區分空佇列read與實際mutating statement receipt；Stored／Replay保留各自真COMMIT與原ID，local／cluster typed handoff立即消耗舊worker settlement權限。Renewal仍只與route並行，helper的child銷毀後才可關閉scope並選擇ACK／defer／retry／dead-letter；false、LeaseLost與NotMoved不推論row已不存在。Child先drop再retire，保留receipt與panic知識，不新增Drop補償。原SQL、exact-token／active-lease條件、fair admission及PAM／drain／retry政策保留。CI source checker修正既有producer數18→19；兩個舊negative probe改綁真worker ACK及原BOSH函式，保留exactly-one與verifier；舊DTO僅在非test build採局部dead-code expectation。Local controls使用真in-memory queue／oneshot與supplied typed completion；cluster只分類supplied receipts，SQL仍是source correspondence，未執行live SQL／wire／saved workload。原cold compile達到既定時間上限後停止；僅重用已確認cleanup完成的隔離cache，另一次相同界限的完整批次通過，舊失敗不改稱成功。先前foreground checkpoint CI為29成功／3失敗／1略過，兩個direct jobs與aggregate的同一舊count問題保留；不預先推論新checkpoint CI。完整auth correlation、跨域保存組合及Stage4仍未完成。
[Auth returned-receipt continuation](../evidence/experimental-rebuild/stage4-auth-returned-receipt-results.json)從實際返回的credential receipt開始，以私有receipt-instance／frame／connection綁定最終control、native write／BOSH exposure、publication及captured effects。BOSH先驗完整selected set，再按FIFO消耗各自owner；U未綁定success被選中而B綁定success仍排隊時，僅U自己的NoSQL publication可執行。Restore／supersession保留同一holder；每個selected owner須有真實成功facts才能完成bookkeeping／cache，true callback或偽造Completed標記不足。Handler return與publication retirement分開，child先銷毀，Drop不做SQL／retry。64項普通命令、54項精確Rust（24新增、10修改、20既有控制）及504項Node實際通過，Rust無failure／ignored，compile／Clippy及source gates皆通過；此限定結果已通過獨立審查。首輪Caps source-anchor停止及次輪Clippy停止保留；最小修正維持by-value API，第三輪在相同界限內通過。這仍是有限in-process／fake及source證據，不涵蓋credential receipt返回前的FAST／bind／resume COMMIT／Unknown、live SQL／wire或跨域保存組合。Base62ed的兩次CI皆因required jobs取消而terminal failure，原因未知；未觀測到assertion failure，不能稱全CI通過。
[Auth pre-receipt observation](../evidence/experimental-rebuild/stage4-auth-pre-receipt-results.json)已把FAST／bind／resume的begin、generation query、refusal rollback、COMMIT、receipt construction及raw return接到同一私有attempt；保留原SQL、參數、stage ID及rollback錯誤傳遞政策。重複或retired借用在I/O前拒絕，first facts不被覆寫，prospective receipt在COMMIT入口凍結；只有獨立matching COMMIT witness與exact receipt instance可移交既有publication owner。矛盾的成功回傳走既有inline Close；真正repository Err／COMMIT Unknown仍保留原fallback，原frame同時保存先前attempt與後續成功，child先銷毀再retire。80項普通命令、70項精確Rust（16新增、2修改、52既有控制）與541項Node實際通過，Rust無failure／ignored，compile／Clippy及source gates通過；此有限普通結果已通過獨立審查。首輪generation query的whole-file count使78項Node失敗，收窄到原helper body後保留原verifier；次輪rollback表格測試的unnecessary_unwrap改為等義match，保留FastExpired忽略錯誤及其他路徑原錯誤。兩次失敗皆保留，第三輪完整通過不改寫舊結果。Rollback／Unknown-fallback案例使用supplied facts與真in-memory owners，實際SQL及SASL2 handler仍是source／gate證據；live SQL／wire、跨域保存組合、SM retention及完整Stage4尚未完成。Base298973的CI為32成功／1略過，先前取消原因與TLS EOF問題仍未解。
[SM recovery retention](../evidence/experimental-rebuild/stage4-sm-retention-results.json)已保留有效recovery所需的exact existing lease／allocation／shard／capacity charge；runtime與startup共用同一SQL分類，區分Resume與Teardown claim，保留claim跨原SM TTL，且不reacquire或renew過期live lease。Cleanup採Read Committed及鎖後fresh revalidation；startup先檢查受保護mapping與shared counters，再以實際doomed／orphan／backfill差額核對最終projection，避免repair掩蓋錯誤。Activation重查exact live target binding；purpose、grant、catalog與新0157 ledger一併更新，舊migration未修改。41項普通命令、28項精確Rust（5新增、3修改、20既有控制）及541項Node已完整通過獨立驗收，compile／Clippy與source gates通過。五項新增測試執行production的protected-projection比較，SQL eligibility／lock／MVCC／clock仍屬source對應；既有空live-lease audit的helper解析調整未當作retention SQL驗證。早期不完整attempt及cold compile時間上限停止皆保留，後續完整結果不改寫它們。LIMIT不保證physical scan工作量；stopped-writer／legacy-claim升級、真PostgreSQL、restart／resume／ACK及跨域保存組合仍未完成。
[SM cleanup forward correction](../evidence/experimental-rebuild/stage4-sm-cleanup-alias-correction.json)保留f154f4ce的實際CI失敗（17成功／13失敗／2略過）。PostgreSQL在cleanup首個claim刪除子查詢發現candidate同時是PL/pgSQL record與table alias；maintenance及auth-identity各有直接SQL錯誤，其他reaper／readiness失敗的同源判斷仍是跨job推論。新增0158只更名該alias與四個qualified references，0157及舊migration不改寫；grant、signature、origin與retention／lock政策保留。13項bounded static／pure命令完成，包括541項Node、兩個真documentation正例及四個精確缺link反例；四份操作文件與158／157-row ledger已對齊。這未執行新的Rust或手動SQL；修正後的真PostgreSQL／readiness結果須由下一checkpoint的CI確認，舊失敗不改稱通過。
Stage3須保留reservation、durable message commit、finalization各自的Unknown／receipt與外層取消owner。
Queue接受不等於write或peer ACK；可恢復storage不等於已排程retry。Guard-only沒有durable reservation receipt。
Stage5才驗真SQL／clock／crypto／wire fidelity；成功的有限supervision不證明所有OS資源或fault邊界。
時鐘控制範圍須明列，密碼學entropy維持CSPRNG；不引入全域executor或通用DSL。

既有capacity4096、accepted TTL6h、pending30m、lease60s，以及timeout／retry／delivery語義沿用。
SM retention來源修正及有限ordinary驗證已完成；真PostgreSQL、clock、rollout與restart驗證仍待完成。
只保留有效recovery的exact existing binding/allocation，同lease_id／shard／capacity charge；runtime與startup共用eligibility，
不reacquire或renew過期租約，owner／revocation維持fail-closed，保留claim跨TTL語義。
預設300s TTL＋30s claim約330s，比120s約增加210s，再加cleanup延遲；一般設定不是此硬上限。
BOSH exact-item與SM retention的刻意差異須另存前後案例。

操作介面及剩餘驗證見[controlled admission交接](controlled-admission-validation-handoff.zh-TW.md)。
