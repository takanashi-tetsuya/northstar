# Stage 2 具名 Rust CI 證據矩陣

Commit：[1a9d7cbdfa6eaf90febec839f189282d2e1218fa](https://github.com/takanashi-tetsuya/northstar/commit/1a9d7cbdfa6eaf90febec839f189282d2e1218fa)，tree 6787043ec17b44ed1444d8ed25833f8d257e9c22。

既有 [Rust test job 111378407905](https://github.com/takanashi-tetsuya/northstar/actions/runs/37182739788/job/111378407905) 已成功，命令為 `cargo test --workspace --all-targets --all-features --locked`。本次只讀日誌與該 commit 的 test body，沒有重新執行或發布。

可直接對應的 **51 條具名 `... ok`** 分布為 shared coordinator/transaction 19、controlled harness 26、service/witness 6。這是 fixed 82 計畫以外可採用的精確來源執行證據，不是整體 Stage 2 驗收判定。JSON 保留所有測試原行、decoded log 行號、immutable source URL／行號與義務對應；下表列代表性 source links。

51是具名unit function數，並非51個與fixed82互斥的新scenario，不能把兩個數相加。

| 義務 | 代表測試 | test body 實際檢查 |
|---|---|---|
| 完整request/effect／prepared witness | [T05](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/crates/northstar-abuse-policy/src/admission_execution.rs#L578)、[T11](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/crates/northstar-abuse-policy/src/admission_execution.rs#L719) | 10個guard欄位、15個observation欄位及fence/receipt變造不消耗合法狀態 |
| 取消／Unknown／receipt | [T40](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/crates/northstar-test-harness/src/controlled_admission/mod.rs#L79)、[T51](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/src/services/message_admission/witness.rs#L109) | 區分precommit、Unknown與ReceiptPreserved；丟棄synthetic future仍保留已觀察事實 |
| 多個Unknown／proof歧義 | [T27](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/crates/northstar-test-harness/src/controlled_admission/mod.rs#L478)、[T28](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/crates/northstar-test-harness/src/controlled_admission/mod.rs#L566) | 四個world mask皆保留四狀態；proof缺失停ModelIncomplete，不由實際Allowed篩掉 |
| 證據／view預算及失敗保存 | [T33](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/crates/northstar-test-harness/src/controlled_admission/mod.rs#L625)、[T45](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/crates/northstar-test-harness/src/controlled_admission/mod.rs#L643) | 64-view後保留prefix/實際outcome再停；detail省略時仍記index0的active=4097失敗 |
| 實際coordinator投影 | [T34](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/crates/northstar-test-harness/src/controlled_admission/mod.rs#L179)、[T43](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/crates/northstar-test-harness/src/controlled_admission/mod.rs#L143) | 同輸入隨實際core狀態產生不同outcome；未delivered結果不由cut補造 |
| Reconcile as-of／effect身分 | [T12](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/crates/northstar-abuse-policy/src/admission_execution.rs#L1016)、[T22](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/crates/northstar-test-harness/src/controlled_admission/execution.rs#L1382) | 12種inner-effect變造拒絕；delivered實際時間支配投影/篩選/界限 |
| 輸入／saved delivery／純交易 | [T32](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/crates/northstar-test-harness/src/controlled_admission/mod.rs#L354)、[T25](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/crates/northstar-test-harness/src/controlled_admission/mod.rs#L54) | 未知/重複/缺explicit-null欄位拒絕；wrong→valid→duplicate保留Request/AlreadyCompleted |
| 服務橋接／redaction | [T47](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/src/services/message_admission.rs#L362)、[T48](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/src/services/message_admission.rs#L387) | Fake Repository modes檢查receipt必要性及Busy/Unknown保留，不洩漏sentinel payload |

## 不計入的證據與剩餘範圍

- 此 exact job 有 **251** 條 named ignored，不沿用歷史 252。包括 PostgreSQL admission capacity/cleanup、crash atomicity/fence/rotation、proof rollback，全部排除於 passed 證據。
- Service/witness 執行真實 Rust wrapper 搭配 fake Repository／synthetic future，沒有證明 production outer ownership 或真 SQL/wire；仍屬 Stage 3/5 後續義務。
- Reconcile 證明 typed sample/effect 傳遞與純函式邊界，不證明 PostgreSQL snapshot/statement 實際原子性。Budget 證明模型／證據大小，不證明 OS timeout、RAM/CPU或process-group監督。
- 七個 generic harness process/readiness/socket helpers與其他 namespaces 不計入51個；replay CLI target有0個tests，編譯binary不等於執行驗收。
- Rust job不包含Python oracle/shrinker/supervisor及另錄的113個pure/mock suite。Saved evidence-reader（包括v2）的tamper拒絕、fixed82 capture/replay及全部clock/resource情境另需精確證據。
- Cargo stdout/stderr Running headers交錯，crate attribution採exact source namespace，不用最近header猜測。

完整具名矩陣：[stage2-named-rust-ci-matrix.json](stage2-named-rust-ci-matrix.json)。只含公開test-status摘行與來源，不含完整raw log或重複33-job列表。
