# 既有 Rust 回歸：Stage1 → 當前重建

Before：[2bdfed95 / Rust job111237748170](https://github.com/takanashi-tetsuya/northstar/actions/runs/37135039680/job/111237748170)；after：[1a9d7cbd / Rust job111378407905](https://github.com/takanashi-tetsuya/northstar/actions/runs/37182739788/job/111378407905)。兩次job皆成功，本次僅讀既有log/source。

五個同名tests在兩次都有精確 `... ok`，各自test body SHA256完全相同：

| 既有test | before / after source | 真正assertion與限制 |
|---|---|---|
| admission::tests::snapshot_state_transitions_and_merging | [before](https://github.com/takanashi-tetsuya/northstar/blob/2bdfed95c4516ce34296c5fa57a3eb3be49d158d/crates/northstar-abuse-policy/src/admission.rs#L469) / [after](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/crates/northstar-abuse-policy/src/admission.rs#L469) | Snapshot starts sequence/penalty at zero; success advances sequence/events; failure advances sequence/penalty; rotating merge preserves sequence 2, penalty 1 and two events. In-memory actor-snapshot example only; no persistent transaction, multiple Unknown or concurrent merge. |
| admission::tests::message_admission_material_and_shard_distribution | [before](https://github.com/takanashi-tetsuya/northstar/blob/2bdfed95c4516ce34296c5fa57a3eb3be49d158d/crates/northstar-abuse-policy/src/admission.rs#L440) / [after](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/crates/northstar-abuse-policy/src/admission.rs#L440) | Admission key, payload MAC and identity digest have length 32; computed shard is in [0,64); lock ID is nonzero. One deterministic material example; despite the name this does not statistically prove shard distribution or exercise storage admission. |
| tests::property_replay_and_expiry_rejections | [before](https://github.com/takanashi-tetsuya/northstar/blob/2bdfed95c4516ce34296c5fa57a3eb3be49d158d/crates/northstar-abuse-policy/src/lib.rs#L358) / [after](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/crates/northstar-abuse-policy/src/lib.rs#L360) | Three finite proof cases reject missing/already-used challenge context, expired challenge and an unfinished hard cooldown. A finite pure evaluator test, not an exhaustive property sweep or database rollback/restart proof. |
| abuse::tests::prefetched_pow_is_accepted_once_and_replay_is_rejected | [before](https://github.com/takanashi-tetsuya/northstar/blob/2bdfed95c4516ce34296c5fa57a3eb3be49d158d/src/abuse_tests.rs#L598) / [after](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/src/abuse_tests.rs#L598) | A solved memory challenge verifies once; replay returns an error containing already used. In-memory one-use path only; no durability, multi-process race or new coordinator correctness. |
| abuse::tests::closed_persistent_backend_is_never_treated_as_an_allow | [before](https://github.com/takanashi-tetsuya/northstar/blob/2bdfed95c4516ce34296c5fa57a3eb3be49d158d/src/abuse_tests.rs#L911) / [after](https://github.com/takanashi-tetsuya/northstar/blob/1a9d7cbdfa6eaf90febec839f189282d2e1218fa/src/abuse_tests.rs#L911) | A lazily constructed pool is explicitly closed; verify_or_allow returns an error within a one-second Tokio timeout instead of allowing. No live database connection/SQL is exercised. This proves the closed-pool fail-closed regression, not real SQL failure/commit behavior. |

`admission.rs`與`abuse_tests.rs`是相同Gitblob；`lib.rs`只加兩個module宣告，所選test body不變。`src/abuse.rs`本身已有修改，所以不能由test source相同推導production全體相同。

目前51個coordinator/harness/service具名tests在Stage1 log中出現數為0，全部是after-only證據，不標成before passed。上面5個是保留既有行為的有限回歸樣本，不能作為51或82個scenario之外的加總驗收數。

另列且本brief不驗證：Stage1 model11→當前Rust的同輸入/預期比較；saved record→replay的byte/source binding及independent reader/tamper拒絕。真SQL/wire、production outer ownership仍須各自證據。

[精確CI原行、test-body SHA與來源](stage2-existing-rust-before-after.json)。無專案執行、重跑、source或remote修改。
