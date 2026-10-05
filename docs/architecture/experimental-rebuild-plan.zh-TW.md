# Northstar 實驗架構現況

更新：2026-10-05。Stage0／1與Stage2 reservation/finalization受控子退出已驗收。
來源版本與測試 hash 見下列結果索引。

## 階段與退出條件

| 階段 | 必須成立的責任與證據 | 現況 |
|---|---|---|
| 0 基線 | 固定來源；admission、commit、handoff、write、ACK、settlement各有明確權威；Unknown不當rollback | 已驗收 |
| 1 規格 | actor共用容量／TTL、初態與混合負載預檢；精確oracle；取消、中斷、缺證據與cleanup分判 | 限定synthetic／fixture scope已驗收 |
| 2 Shared admission | production與controlled共用transitions；真實outcome、完整effect/fence關聯；可保存、重播、縮減的正常／拒絕／replay／expiry／Unknown案例 | Reservation/finalization子退出已驗收 |
| 3 Direct lifecycle | 真mode-aware commit連接既有router、exact queue item、write及SM/BOSH owner；取消、partial write、replacement與stale ACK不丟失責任 | [有限受控退出已驗收](../evidence/experimental-rebuild/stage3-controlled-acceptance.json)：16／16 baseline、4／4 mutation／shrink、62項reader controls與責任矩陣完成；真實adapter／資源限制仍屬後續階段 |
| 4 高風險域 | MUC/MIX、auth publication（含write/exposure後failure/cancel）、worker claim/recovery皆有production共用受控案例及跨域組合 | [BOSH selected-control gate](../evidence/experimental-rebuild/stage4-bosh-auth-control-results.json)限定component範圍通過；完整階段仍未完成 |
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
[Stage3有限受控驗收](../evidence/experimental-rebuild/stage3-controlled-acceptance.json)另完成62項reader檢查：4個完整正例、42個固定外部authority拒絕、15個明列測試manifest前提的內層拒絕及1個tuple縮減拒絕；未新增Rust案例啟動。責任矩陣已獨立審查，這不代表所有CI或全產品等價性通過。當前文件checkpoint的Caddy診斷收到完整synthetic429回應後仍等待TLS EOF逾時，原因未知，列入Stage5同一未解問題。
[BOSH auth-control修正](../evidence/experimental-rebuild/stage4-bosh-auth-control-results.json)把publication綁到實際被選入回應且被responder接受的control；失敗或pending後drop不能完成cache。24項精確Rust與295項Node檢查、compile／Clippy通過；舊predicate比較只是source-bound witness。完整credential／frame關聯、SQL publication及Stage4跨域證據仍待完成。
Stage3須保留reservation、durable message commit、finalization各自的Unknown／receipt與外層取消owner。
Queue接受不等於write或peer ACK；可恢復storage不等於已排程retry。Guard-only沒有durable reservation receipt。
Stage5才驗真SQL／clock／crypto／wire fidelity；成功的有限supervision不證明所有OS資源或fault邊界。
時鐘控制範圍須明列，密碼學entropy維持CSPRNG；不引入全域executor或通用DSL。

既有capacity4096、accepted TTL6h、pending30m、lease60s，以及timeout／retry／delivery語義沿用。
SM retention修正仍待實作：只保留有效recovery的exact existing binding/allocation，同lease_id／shard／capacity charge，
runtime與startup採一致eligibility；不reacquire或renew過期租約，owner／revocation維持fail-closed，保留claim跨TTL語義。
預設300s TTL＋30s claim約330s，比120s約增加210s，再加cleanup延遲；一般設定不是此硬上限。
BOSH exact-item與SM retention的刻意差異須另存前後案例。

操作介面及剩餘驗證見[controlled admission交接](controlled-admission-validation-handoff.zh-TW.md)。
