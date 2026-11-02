# Northstar 並行工作流計劃書

2026-11-02 · 線上版：https://claude.ai/artifact/FqrEDQc87PEzT9HJf1fscS

## 摘要

本計劃把主線以外的九項工作交給在雲端工作的第二個智能體（下稱執行者）。S28–S31 仍由本機的架構智能體（下稱主線）負責，兩邊透過 GitHub 的 dev 分支交接。

拆出的工作都有三個特徵：不等 `OutboundItem` 等待定設計、不碰主線正在改的路徑、可以用測試名與 gate 機械驗證。root crate 現有約 228,000 行，其中測試約 108,000 行；工作流 E 把測試遷出，對編譯速度的改善最大。

| 工作流 | WP 區段 | 內容 | 規模 | 前置 |
| --- | --- | --- | --- | --- |
| A1 | WP-400–404 | XEP-0084 檢查移入新 kernel crate | 小 | 無 |
| A2 | WP-405–409 | OfflineStore 型別併入 `northstar-message-core` | 小 | 無 |
| B1 | WP-410–414 | schema、identity 遷移離開 root | 4,533 行 | 無 |
| B2 | WP-415–419 | PIE 與資料工具離開 root | 約 5,400 行 | B1 |
| C1 | WP-420–423 | `RootAbuseEffects` 移入 workflows | 89 行 | 無 |
| C2 | WP-424–427 | roster、privacy、presence 儲存庫 | 1,107 行 | 無 |
| C3 | WP-428–429 | pep\_roster、profile、pubsub 儲存庫 | 約 4,300 行 | 無 |
| D | WP-430–439 | OMEMO 恢復移入 auth，收掉 `db/retention.rs` | 約 1,500 行以上 | 無 |
| E | WP-440–469 | 已完成上下文的 root DB 測試遷入所屬 crate | 最大 | 依批次，E1、E4 無 |

A、B1、C、D 之間可依任意順序進行，建議由 A1 開始熟悉流程。S29 的 SM、replay、cluster 與 transports 不在本計劃內，見最後一節。

```text
可立即開始：A1（建議起點）、A2、B1、C1、C2、C3、D、E1、E4
有前置關係：B1 → B2、C1 → E2、C3 → E3、D → E5
```

箭頭左邊完成後才能開始右邊。第一行的工作流彼此沒有先後要求。

## 主線回覆（第二輪）

A1–C3 已在 dev。D（`cloud/d-r2`，`ca46c694`）由主線連同 WP-329–333 一起落地。dev CI 41393345312 的 passkeys 失敗不是偶發。sqlx 0.8.6 的 BEGIN 若在完成前被取消，連線會帶著未結束的交易回到池裡，下一個借用者的 `SET TRANSACTION ISOLATION LEVEL` 就會失敗。WP-329 加了 `northstar_postgres::pool::options()`，在連線歸還時檢查交易狀態，正式程式的連線池都改用它。gate 禁止正式程式直接寫 `PgPoolOptions::new()`，測試檔不受限；放在 `test-support` feature 後面的共用程式碼不算測試檔，要用 `pool::options()`。

| 回報項目 | 決定 |
| --- | --- |
| E1 的 `authentication_tests` | 留在 root。主線在 S29 把它與 `db/authentication_effects.rs` 一起移，E1 只移其他三個檔 |
| E4 的 `api_operations_idle_tests` | 移出 E4。它由 `api_operations_tests` 以 `include!` 載入，後者用到 `crate::cluster::ClusterManager`；`northstar-cluster` 建好後由主線兩檔一起移 |
| `RootAccountRepository`、`RootAdminCommandRepository` | WP-332 已改名為 `northstar_workflows::account_repository::WorkflowAccountRepository` 與 `northstar_workflows::admin_command_repository::WorkflowAdminCommandRepository`，移測試時用新名稱 |
| root `db/mod.rs` 與 message-postgres 的過渡匯出 | 保留。主線移動 `src/s2s`、`src/cluster`、`db/sm*`、`db/replay*` 時一併刪除 |
| OMEMO 三張表的分類 | 接受。poll capability 與 `fast_tokens` 一樣，是會過期的 credential-secret |
| retention 驗收指令 | 已在工作流 D 更正為兩條 |
| PostgreSQL 16 | 本地用 16 除錯可以，結果以 CI 的 17 為準 |
| toolkit 的 node 測試 | `gates.sh` 已改為 `node --test --test-reporter=spec`，不必再設 `NODE_OPTIONS` |
| `docs/ARCHITECTURE.md` 的舊段落與 MixHost 條目 | 主線在 S29 的紀錄中處理 |
| 已被取代的 `cloud/*` 分支 | 保留，S31 之後由主線清理 |

下一步：E1（三個檔）、E2、E3、E4（四個檔）可以開始，E5 等 D 落地。開始前照「推送流程」第 3 步同步 dev 並重跑 `newbase.sh`。

## 開始之前

執行者在雲端環境工作，手上只有 GitHub repo `takanashi-tetsuya/northstar` 的 clone。主線機器上的檔案、腳本與編譯快取都拿不到，程式由執行者直接修改。工具包隨 repo 提供，在 `docs/handoff/2026-11-02/toolkit/`，下文以 `$TK` 代表。下列指令都從 repo 根目錄執行。

環境需要 Rust 1.97.1（由 `rust-toolchain.toml` 固定）、Node 22、Python 3 與 git。`gh` 用來查 CI 與讀 log。PostgreSQL 17 不是必要條件，DB 測試 CI 都會跑。

先讀這三份文件，路徑皆在 repo 內：

- `docs/architecture/target-architecture.zh-TW.md`：目標架構，重點是 §4.1 分層、§4.3 與 §4.5 持久化。
- `docs/architecture/engineering-structure.zh-TW.md`：第 5.23 節是 root 殘餘清單，文末有各階段教訓。
- `catalog/data-ownership.yaml`：每張資料表的歸屬。

每條工作流開一個分支，從 `origin/dev` 的最新提交開始，並在第一次修改前記錄基線：

```bash
git fetch origin dev
git switch -c cloud/a1 origin/dev
export TK=docs/handoff/2026-11-02/toolkit
bash $TK/newbase.sh
```

`newbase.sh` 要編譯所有測試目標，第一次會花比較久。分支名若由雲端平台指定，就用平台的名稱。按 WP 順序在分支上累積提交。

| 工具 | 用途 | 指令 |
| --- | --- | --- |
| `check.sh` | 提交前：格式化，更新 lock、catalog 與產生檔，對指定套件跑 clippy 與測試 | `LINT="..." ROOTF="..." bash $TK/check.sh <套件...>` |
| `verify.sh` | 落地前：測試名守恆、選擇器、產生檔、Stage 4、全部 gates | `bash $TK/verify.sh <工作流>` |
| `newbase.sh` | 重新記錄測試名與 gate 基線 | `bash $TK/newbase.sh [提交]` |
| `db.sh` | 在本地 PostgreSQL 跑 ignored 測試 | `PGURL=... PKG=... PREFIX=... bash $TK/db.sh` |
| `stage4bind.py` | 檢查並更新 Stage 4 公開回歸綁定的 15 個檔案 | `python3 $TK/stage4bind.py . --rebind` |

基線與日誌存在 `~/.cache/northstar/`，環境回收後會消失，用 `bash $TK/newbase.sh $(git merge-base HEAD origin/dev)` 重建。測試名映射在 `$TK/maps/`，隨分支提交，不會遺失。

## 必守規則

工作先推到自己的分支讓 CI 驗證，綠燈後再快轉到 dev。不開 PR，不做 merge commit，不 force push。需要新外部套件或新版本時停下來回報。

**權限與外部依賴**

- 不使用任何繞過權限的選項，也不修改 repo 的 CI 權限或分支保護。
- 不下載 CI artifacts。讀 CI log 用 `gh run view <id> --log-failed`。
- 把工作區內已有的 crate 或同版本外部依賴加進 manifest 不需詢問。`check.sh` 印出 `external package added:` 時必須停止並回報，新工作區 crate 不會出現在這一行。
- 清理時不對可能為空的變數執行 `rm`。檔案刪除用 `git rm`。

**不得修改的路徑**

這些路徑屬於主線的 S28–S30。如果工作必須碰到，先停下來回報原因。

| 路徑 | 原因 |
| --- | --- |
| `src/s2s/**`、`crates/contexts/federation/**` | S28 federation |
| `src/services/{federation_outbox,s2s_outbox_dispatch,s2s_sm_outbox}.rs` | S28 federation |
| `src/db/{federation_outbox,s2s_outbox_dispatch,s2s_sm_outbox}_repository.rs` | S28 federation |
| `src/cluster/**` | S29 cluster |
| `src/xmpp/{outbound,local_routes}/**` | S29 session routing |
| `src/services/sm*`、`src/db/sm*`、`src/db/authentication_effects.rs` | S29 session，依賴 `OutboundItem` 設計 |
| `src/db/room_effects.rs`、`src/db/muc_delivery_repository.rs` | 依賴 S28、S29；A2、C2 可做最小的 import 修改 |

`docs/architecture/**` 除 `generated/` 外也由主線維護。每個 WP 的提交內文要寫三項：做了什麼、root 減少多少行、待主線決定的事。主線會把它們寫進藍圖。若 gate 要求修改藍圖內的路徑字面值，可以只改那一行。

**修改 gate 的紀律**

`scripts/`、`catalog/` 內的路徑要跟著移動，但不能削弱審查。負向檢查移動後要仍能觸發，`scripts/test-*.mjs` 內的變異案例也要同步。每次移動後掃描舊路徑與 `db::名稱` 字面值：

```bash
grep -rnE 'db[\:?]+<名稱>' scripts/ catalog/
```

**提交格式**

主旨不超過 72 字元，形如 `[WP-400] Move the XEP-0084 checks to a kernel crate`。內文每行在 72 字元內折行，說明原因與上述三項，結尾是執行者自己的 `Co-Authored-By` 行。提交者身分用平台預設值。

**推送流程**

每完成一個 WP 就推到自己的分支，環境回收時才不會遺失工作。CI 對所有分支都會跑，一輪約 25 分鐘；同一分支的新推送只會取消該分支的舊 run，不影響 dev。整條工作流完成後照下列順序落地到 dev：

1. 跑 `bash $TK/verify.sh <工作流>`，逐行確認「驗證流程」的驗收項目。
2. 執行 `git push origin HEAD`，等這個提交在分支上的 CI 全部綠燈。失敗就修正後重推。
3. 執行 `git fetch origin dev`。dev 有前進就 rebase，`Cargo.lock`、`catalog/crates.yaml`、`docs/architecture/generated/` 的衝突用 `check.sh` 重新產生來解決，再跑 `bash $TK/newbase.sh origin/dev`，回到第 1 步。
4. 確認 dev 沒有進行中的 CI：`gh run list --branch dev --workflow ci.yml --status in_progress --json databaseId --jq length` 要印出 `0`，`--status queued` 也一樣。dev 的新推送會取消進行中的 run。
5. 執行 `git push origin HEAD:dev`。這必須是快轉，被拒絕就回到第 3 步。推送要在讀完前面的結果後另外執行，不要串在其他指令後面。
6. 確認 dev 上這個提交的 CI 綠燈。失敗就修正後重新走這個流程。

雲端平台不允許推 dev、只能推指定分支，或沒有 `gh` 權限時，停在第 2 步，回報分支與 SHA，由主線落地。

`gh` 要在 repo 目錄內執行。查 CI 用 `gh run list --commit <sha> --workflow ci.yml --json status,conclusion,databaseId`，間隔至少 5 分鐘。不要用 `gh run watch`，它會耗盡 5,000/hr 的共用配額。

## 分層與持久化規則

所有依賴方向由 `tools/architecture-validator/src/main.rs` 強制，層級從 crate 路徑與套件名後綴推導。dev-dependencies 不受檢查。

| 層級 | 路徑或名稱 | 可依賴 | 限制 |
| --- | --- | --- | --- |
| kernel | `crates/kernel/*` | 只有 kernel | 不可用 async runtime、SQL、網路套件 |
| platform | `crates/platform/*` | kernel、platform | 不可依賴任何 context |
| context core | 無特定後綴，含 `northstar-abuse-policy` | kernel、任何 core | 不可用 tokio、futures、sqlx、網路套件 |
| application | `-application`、`northstar-protocol-runtime` | 自己的 core、kernel、任何 core、platform | 不可用 SQL、網路套件；tokio 可用 |
| adapter | `-postgres`、`-xmpp`、`-http`、`-storage` | 自己的 application、任何 core、platform、kernel | 不可依賴其他 adapter 或別的 application |
| workflows | `crates/contexts/workflows/*` | kernel、platform、任何 core、application、`-postgres` | 不可依賴 `-xmpp`、`-http`、`-storage`、edges |
| edge | `crates/edges/*` | kernel、platform、core、application | 不可依賴 adapter |
| composition | repo root | 任何 crate | 最終只剩組裝，見 S31 |
| tooling | `tools/*` | 任何 crate | 非 tooling 的 crate 不可依賴它 |

持久化規則來自目標架構 §4.5：

- 每個 `-postgres` 只寫自己資料表的 SQL，可讀取並鎖定 `users`；寫入 `users` 屬於 auth。測試夾具可以直接插入。
- 跨上下文的同交易流程屬於 workflows，其 SQL 可以跟著一起移入 `northstar-workflows`。
- 命名 `sqlx::Transaction` 的 trait 放在 `-postgres` 或 workflows，絕不放在 application。

root 內的資料流要按這些形狀收斂：

- root 不留門面。消費者直接 import 擁有項目的 crate，變成沒人用的重新匯出要刪掉。
- `src/xmpp/protocol/*.rs` 不可以 `use crate::db::...`。host 實作放在 `src/state/<ctx>_host.rs`。
- 下游 crate 需要的測試項目標為 `#[cfg(any(test, feature = "test-support"))]`，由 root 的 `[dev-dependencies]` 啟用。測試需要之外的欄位不要加 cfg。
- `AppState` 欄位按 `src/state/<ctx>_module.rs` 的 `<Ctx>Module`、`<Ctx>ModuleParts<'a>` 組裝，範例是 `src/state/message_module.rs`。

## 驗證流程

每個 WP 都要通過小迴圈才提交，落地前要通過 `verify.sh` 與分支上的 CI。CI 涵蓋 fmt、clippy、全部測試、gates 與 DB 測試，但不查兩件事：測試有沒有遺失，以及 `--bin rust-xmpp-server` 的過濾器在測試搬走後還選不選得到測試。這兩件只有 `verify.sh` 會查。`2c62d1a6` 的基線是 3,125 個測試名與 254 個 ignored 測試名，移動後總數不變。

**每個 WP 的小迴圈**

1. 實作移動，同時更新 gate，並把測試名映射規則加進 `$TK/maps/<工作流>.sed`。
2. 跑檢查。引數列出的套件跑 clippy 與全部測試，`LINT` 列出只做 clippy 的套件，`ROOTF` 是 root 的測試篩選：

   ```bash
   LINT=rust-xmpp-server ROOTF="<root 的測試篩選>" bash $TK/check.sh <改動的套件>
   ```
3. 每一行 exit 都要是 0，也不能有 `external package added:`。
4. 提交。

工作區的 feature unification 會遮住缺漏的 feature，所以改過的 crate 都要用 `-p <crate>` 單獨測試。`check.sh` 就是這樣跑的。

**落地前的全驗證**

```bash
bash $TK/verify.sh a1
```

輸出要逐行符合下表，有任何一行不符就不推送。

| 輸出行 | 要求 |
| --- | --- |
| `fmt exit`、`production exit`、`fuzz exit` | 都是 0 |
| `tests: names match mapped base` | 總數與基線相同 |
| `ignored: names match mapped base` | 總數與基線相同 |
| `selectors:` | `0 match no test` |
| `layers exit`、`validator exit` | 都是 0 |
| `generated:` | `current` |
| `stage4 bindings:` | `15 files, 0 stale` |
| 最後一行 | `GATES == BASE` |

`fuzz/` 是獨立工作區，有自己的 lockfile。`check.sh` 不檢查它，只有 `verify.sh` 會檢查。全工作區的 clippy 與測試不在 `verify.sh` 內，由 CI 負責。

**測試名映射**

基線每行是 `<binary>:<測試路徑>`。測試移動後，在 `$TK/maps/<工作流>.sed` 加一條 BRE 規則並隨分支提交，較具體的規則放前面：

```bash
s/^rust_xmpp_server:services::extdisco::tests::/northstar_message_application:extdisco::tests::/
```

要等對應的移動真的發生才加規則，否則比對會出現不存在的測試名。

**DB 測試**

ignored 測試需要真實 PostgreSQL。CI 會全部跑，本地只是為了更快除錯：環境有 PostgreSQL 17 才用 `db.sh`，沒有就交給 CI，下文驗收項目裡的 `db.sh` 指令也改看 CI 結果。`db.sh` 為每個測試建一個新 schema。`PGURL` 要指向 locale 為 C 的空資料庫，URL 不帶 query string，角色要能建立 schema 與 role。

```bash
export PGURL=postgres://xmpp_test:xmpp-test-password@127.0.0.1:5432/xmpp_test
PKG=northstar-upload-postgres PREFIX=upload FILTER='^tests::' bash $TK/db.sh
PKG=northstar-upload-postgres PREFIX=upload_migrate FILTER='^migration::' bash $TK/db.sh
PKG=rust-xmpp-server PREFIX=authentication FILTER='^db::authentication_tests' bash $TK/db.sh
PKG=rust-xmpp-server PREFIX=api_operations OPS=1 FILTER='^db::api_operations' bash $TK/db.sh
```

有些測試會斷言自己的 schema 前綴，前綴不對時會在測試開頭 panic。看該測試開頭的 `strip_prefix`，用對應的 `PREFIX` 加 `FILTER` 單獨重跑；上面第二行就是這種情況。`northstar-abuse-postgres` 沒有 ignored 測試，`ran 0 tests` 屬正常。

| 測試類別 | 需要的設定 |
| --- | --- |
| `db::authentication_tests` | `PREFIX=authentication` |
| 呼叫 `operation_mutation_pool` 的測試 | `OPS=1` |
| `db::operation_journal_worker_repository_tests::claim_and_target_plan_commit_or_roll_back_together` | 用 `OPS=1` 並以 `FIRST=<完整測試名>` 讓它先跑 |
| MUC 測試 | 工具已設 `XMPP_TEST_CREATED_SCHEMA_LOG` |
| `cluster::muc_routing_tests` | 需要 Redis，本地通常沒有，交給 CI |

每個測試的日誌在 `~/.cache/northstar/runs/db/`。最後一行是 `ran N tests, fail=0`。找不到測試時會印出 `ran 0 tests`，這不算通過，要檢查 `FILTER`。

## 工作流 A：小型收斂

兩項都不改行為，只消除重複與繞道，適合用來練熟驗證流程。

### A1 XEP-0084 檢查（WP-400）

目標：頭像載荷檢查集中到一個新 kernel crate，MIX 不再透過 `MixHost` 繞回 root 取得它。

1. 建立 `crates/kernel/northstar-xmpp-avatar`，依賴 `base64 0.22`、`roxmltree 0.20`、`sha1 0.10`。
2. 不要命名為 `northstar-xep-0084`。`scripts/check-plugin-architecture.mjs` 要求該前綴的 crate 有 `DESCRIPTOR`、catalog 項目與組態開關，這會變成行為變更。
3. 從 `northstar-pubsub-xmpp/src/payload.rs` 移入 `valid_avatar_data`、`valid_avatar_metadata`、`decode_avatar_data`、`sha1_matches`，以及只有它們用的輔助函式。共用的輔助函式則在新 crate 設為 `pub`。
4. 從 `northstar-pubsub-application/src/profile.rs` 移入 `sha1_hex`、`detected_media_type`、`valid_png_image`，消費者直接 import 新 crate。
5. 新 crate 擁有 `AVATAR_DATA`、`AVATAR_METADATA`。`payload.rs:15`、`pep.rs:134`、`vcard.rs:42`、`profile.rs:9` 的重複定義改為引用；`mix.rs:64`、`mix_service.rs:69` 的 `NODE_AVATAR_*` 改為由它們賦值。
6. 刪除 `MixHost` 的 `valid_avatar_data`、`valid_avatar_metadata`（`northstar-mix-xmpp/src/ports.rs:243-244`）與 root 實作（`src/xmpp/protocol/mix.rs:212-217`）。`channel_pubsub.rs:266-268` 改為直接呼叫新 crate。
7. 刪除 `northstar-pubsub-xmpp/src/pep.rs:60` 與 `src/xmpp/protocol/pep.rs:10` 的重新匯出。

驗收：

- `MixHost` 內不再有 avatar 相關方法，`AVATAR_DATA` 只有一個字面值定義。
- 移動的測試都在 `$TK/maps/a1.sed` 有規則。
- `bash $TK/check.sh northstar-xmpp-avatar northstar-pubsub-xmpp northstar-pubsub-application northstar-mix-xmpp northstar-room-postgres northstar-room-application` 全部通過。

### A2 OfflineStore 型別（WP-405）

目標：`OfflineStoreOutcome` 與 `OfflineStorePolicy` 只在 `northstar-message-core` 定義一次。

1. 把兩個型別放進 `northstar-message-core`。derive 取聯集 `Clone, Copy, Debug, Eq, PartialEq`，保留 `mam_backed` 的說明註解。
2. 刪除 `northstar-room-core/src/lib.rs:226,234` 與 `northstar-message-postgres/src/offline.rs:15,23` 的定義。
3. `northstar-room-core` 加上 `northstar-message-core` 依賴，core 互相依賴是允許的。
4. 刪除 `src/db/room_effects.rs:115-134` 兩個型別之間的轉換，這是該保留檔案允許的最小修改。
5. 消費者改為直接 import `northstar_message_core`，包括 workflows 的 `message_repository`、`retraction_repository` 與 root 測試。

驗收：

- 整個工作區只剩一處 `enum OfflineStoreOutcome`。
- `bash $TK/check.sh northstar-message-core northstar-message-postgres northstar-room-core northstar-room-postgres northstar-room-application northstar-muc-xmpp northstar-workflows` 全部通過。
- `PKG=rust-xmpp-server PREFIX=room FILTER='^db::(archive::offline_queue|muc_tests)' bash $TK/db.sh` 全部通過。

## 工作流 B：schema、identity 與資料工具

這條工作流讓 root 不再擁有遷移邏輯：schema 驗證下沉到 platform，跨上下文的 identity 正規化進 workflows。

### B1 schema 與 identity 遷移（WP-410–412）

| 項目 | 目的地 | 原因 |
| --- | --- | --- |
| `db/schema.rs`、`db/migration_preflight.rs` | `northstar-postgres` 的 `schema`、`migration_preflight` 模組 | 與 `MIGRATOR` 同層，不依賴任何 context crate |
| `db/{identity_migration,jid_identity,authorization_identity,push_identity,profile_identity,remaining_identity,session_identity}.rs` | `northstar_workflows::identity_migration` 子模組 | 在同一個交易內改寫多個 context 的資料表 |
| `db/mod.rs` 的 `migrate_for_domain` | 同上 | 它包住 identity 正規化 |
| `db/migration_upgrade_test.rs` | 同上 | 測試對象是 `migrate_for_domain` |
| `db/mod.rs` 的 `#[cfg(test)] migrate` | 留在 root，改為轉呼叫 `migrate_for_tests` | 還有 66 個檔案在用，E 會逐步減少 |

1. **WP-410**：移動 schema 與 preflight。`super::MIGRATOR` 改為 crate 內部引用，刪除 `pub use schema::*`。消費者是 `src/main.rs:310`、`src/runtime/subservers.rs:239`、`src/state/construction.rs:540`。
2. **WP-411**：移動 identity 模組到 workflows，加上 `northstar-pubsub-core`、`northstar-session-core` 依賴。`session_identity.rs:235` 的 `super::sm::SmMucMembership` 改為 `northstar_session_core::SmMucMembership`。
3. **WP-412**：移動 `migrate_for_domain`，更新 `scripts/check-database-role-boundaries.sh:499,503` 的字面值。那個 advisory lock 的鏖定與解鎖要原樣保留。

各模組以 `pool` 為參數的版本目前是 `#[cfg(test)]`，移動後改成 `#[cfg(any(test, feature = "test-support"))]`。在 workflows 加 `migrate_for_tests`，內容照搬 `db::migrate`，並由 root 的 dev-dependency 啟用該 feature。

要改的測試路線：`scripts/{authorization-jid-identity,jid-identity,push-jid-identity,rfc7622-identity,session-jid-identity}-db-wsl.sh`、`scripts/n08-db01-wsl.sh`、`scripts/database-role-boundary-db-ci.sh`。它們若有 `--bin rust-xmpp-server` 要改成 `-p northstar-workflows`，原因見「已知陷阱」。

驗收：

- 這 9 個檔案與 `db/migration_upgrade_test.rs` 都離開 `src/db/`，`src/db/mod.rs` 內沒有 `migrate_for_domain`。
- `PKG=northstar-workflows PREFIX=identity FILTER='identity_migration' bash $TK/db.sh` 全部通過。測試若檢查 schema 前綴，按錯誤訊息調整 `PREFIX`。
- `scripts/check-database-role-boundaries.sh` 通過。

### B2 PIE 與資料工具（WP-415–416）

目標：PIE 與 identity 稽核工具移入新 crate `crates/contexts/workflows/northstar-data-tools`。路徑使它自動得到 workflows 層級。獨立成 crate 是為了避免 `northstar-workflows` 增大約 5,000 行。

1. **WP-415**：移動 `src/tools/pie.rs`、`src/tools/pie/`、`src/db/pie.rs`、`src/db/pie/`。更新 `scripts/check-database-role-boundaries.sh:25,109,520,760` 的路徑。`src/main.rs:268` 改為呼叫新 crate。
2. **WP-416**：移動 `src/tools/identity_audit.rs` 與 `src/tools/identity_audit/`。`src/main.rs:213-216` 改為呼叫新 crate。
3. 測試內的 `crate::db::migrate` 改為 `northstar_workflows::identity_migration::migrate_for_tests`。

`src/tools/storage_migration.rs` 留在 root。它需要 `northstar-upload-storage`，而 workflows 層級不能依賴 `-storage`。它實際上是組裝層的 CLI，由 S31 處理。

驗收：

- `src/tools/` 只剩 `storage_migration.rs`，`src/db/pie*` 已消失。
- `PKG=northstar-data-tools PREFIX=pie bash $TK/db.sh` 全部通過。

## 工作流 C：收掉 src/db 的跨上下文儲存庫

這些模組同時碰兩個以上 context 的資料表，按 §4.5 全部進 `northstar-workflows`。它們在 root 幾乎沒有依賴，是最清楚的機械移動。

共同做法：

- root 的 `pub use northstar_*::*` glob 不要帶過去，每個 `db::名稱` 都改成擁有它的 crate。
- 消費者直接 import `northstar_workflows::...`，`src/db/mod.rs` 不留轉發。
- 測試跟著模組移動。需要 SM 或其他 root 項目的測試留在 root，只改 import。
- 主要消費者在 `src/state.rs:298`、`src/state/{auth_module,roster_module,service_accessors,account_deletion_recovery,session_cleanup_presence,pubsub_notification_delivery}.rs`、`src/api/contexts/http_registration_endpoint.rs`。

### C1 RootAbuseEffects（WP-420）

把 `src/db/abuse_effects.rs` 移成 `northstar_workflows::abuse_effects`，型別改名 `WorkflowAbuseEffects`，`persistent_guard` 一起移動。`scripts/check-architecture-boundaries.mjs:2960,3135` 讀的是這個檔案，其 key-retirement 檢查要跟著改路徑。

驗收：`src/db/abuse_effects.rs` 不存在，gate 會在新路徑觸發。

### C2 roster、privacy、presence（WP-424–426）

1. **WP-424**：`src/db/roster.rs` 移成 `northstar_workflows::roster`。`RootRosterEffects` 改名 `WorkflowRosterEffects`。`PostgresRosterRepository`、`RootAccountRepository`、`RootAdminCommandRepository` 別名與 `roster.rs:116-441` 的綁定函式一併移動。`transition_local_presence_subscription_authorized_test_hook` 與 `RosterRemovalRoute` 改為 `test-support`。
2. **WP-425**：`privacy_denies_for_sm_session` 移成 `northstar_workflows::privacy`，它讀 session 的 SQL 函式，不能進 roster 的 adapter。`src/db/muc_delivery_repository.rs:43` 只改 import。同檔的 `postgres_privacy_lists_are_bounded_ordered_cascading_and_enforced` 要建 SM 會話，留在 root。
3. **WP-426**：`src/db/presence_repository.rs` 移成 `northstar_workflows::presence_repository`。

驗收：

- `src/db/roster.rs`、`src/db/presence_repository.rs` 已消失，`src/db/privacy.rs` 只剩測試或已刪除。
- `PKG=northstar-workflows PREFIX=roster FILTER='^roster|^presence' bash $TK/db.sh` 全部通過。
- `scripts/privacy-db-wsl.sh`、`scripts/roster-service-db-wsl.sh` 的套件與篩選器已更新。

### C3 pep\_roster、profile、pubsub（WP-428–429）

這些模組需要 roster 或 blocking 查詢，所以不能進 `northstar-pubsub-postgres`。workflows 要加上 `northstar-pubsub-application`、`northstar-pubsub-core`、`northstar-pubsub-postgres` 依賴。

1. **WP-428**：`src/db/pep_roster.rs`、`src/db/profile.rs`、`src/db/profile/tests.rs` 移入 workflows。`crate::xmpp::xml_builder` 改為 `northstar_xml_builder`。
2. **WP-429**：`src/db/pubsub_repository.rs` 與子模組 `pep_ports`、`pubsub_outbox`、`pubsub_ports`、`service_tests`、`tests` 移入 workflows。`test_pubsub_service` 改為 `test-support`。

驗收：

- 上述檔案離開 `src/db/`。
- `PKG=northstar-workflows PREFIX=pubsub FILTER='^(pep_roster|profile|pubsub_repository)' bash $TK/db.sh` 全部通過。
- `scripts/profile-jid-identity-db-wsl.sh`、`scripts/pubsub-db-wsl.sh`、`scripts/test-source-structure.mjs` 已更新。

## 工作流 D：OMEMO 恢復與 retention 收尾

OMEMO 恢復歸屬 auth 上下文，移動後 `src/db/retention.rs` 就能整個退場。HTTP 層（`src/api/omemo_recovery.rs`、`src/api/contexts/{omemo_poll,omemo_recovery_http}.rs`）留在 root 等 S30，只改 import。

1. **WP-430**：`src/services/omemo_recovery.rs`（211 行）移入 `northstar-auth-application`。
2. **WP-431**：`src/db/omemo_recovery.rs`（1,071 行）與 `src/db/omemo_recovery_repository.rs`（235 行）移入 `northstar-auth-postgres`。刪除 `src/db/mod.rs:111` 的 glob 匯出。
3. **WP-432**：在 `catalog/data-ownership.yaml` 的 `identity` 段加入 `omemo_recovery_counters`、`omemo_recovery_transfers`、`omemo_recovery_poll_capabilities`，欄位格式照 `users`。這三張表來自 migration 0093，目前漏列。如果 `db-bootstrap` 有生成產物，一併更新。
4. **WP-433**：`omemo_recovery_service`、`omemo_recovery_poll_context` 收進 `src/state/auth_module.rs` 的 `AuthModule`，`src/state/omemo_poll_admission.rs` 退場。獨立連線池的建立留在 `src/state/construction.rs`，因為 `scripts/check-database-role-boundaries.sh:518` 要求字面值在那裡；建好的 repository 由 `AuthModuleParts` 傳入。
5. **WP-434**：`PostgresMaintenanceRepository` 移成 `northstar_workflows::maintenance_repository`，刪除 `src/db/retention.rs`。它內部的 `crate::db::cleanup_omemo_recovery_transfers`、`crate::db::cleanup_expired_subscriptions` 改為直接呼叫擁有它們的 crate。消費者是 `src/runtime/subscription_cleanup.rs:390`、`src/runtime/subservers.rs:257,281`、`src/state/runtime_contexts.rs:35-63`。

需要跟著改的 gate：`scripts/check-database-role-boundaries.sh:34,112,758`、`scripts/check-omemo.mjs`、`scripts/check-architecture-boundaries.mjs`、`catalog/runtime-experiments.json:936`、`docs/TRACEABILITY.md`。

驗收：

- `src/services/omemo_recovery.rs`、`src/db/omemo_recovery*.rs`、`src/db/retention.rs` 都已消失。
- `AppState` 不再有這兩個直接欄位。
- `PKG=northstar-auth-postgres PREFIX=omemo FILTER='omemo_recovery' bash $TK/db.sh` 全部通過。
- `PKG=rust-xmpp-server PREFIX=retention FILTER='^db::retention_tests' bash $TK/db.sh` 的 3 個測試全部通過。
- `PKG=rust-xmpp-server PREFIX=retention OPS=1 FILTER='^db::retention_policy_repository_tests' bash $TK/db.sh` 的 2 個測試全部通過。

## 工作流 E：DB 測試遷出 root

`src/db` 有 71 個測試檔、約 48,800 行，其中 53 個檔（約 31,800 行）除了 `db` 之外不引用其他 root 模組。下表五批遷出後，root 測試二進位會明顯變小。

| 批次 | WP | 測試檔（`src/db/` 下） | 目的地 | 前置 |
| --- | --- | --- | --- | --- |
| E1 帳號與 auth | WP-440–444 | `users_tests`、`fast_tests`、`account_repository_registration_guard_tests`（`authentication_tests` 由主線移） | `northstar-auth-postgres`，涉及 workflows 的進 workflows | 無 |
| E2 abuse | WP-445–449 | `abuse_guard_tests`、`abuse_keys_tests` | `northstar-workflows` | C1 |
| E3 pubsub | WP-450–454 | `pubsub_integration_tests/*` | `northstar-workflows` | C3 |
| E4 operations | WP-455–459 | `api_control_tests`、`api_pages_tests`、`admin_commands_boundary_tests`、`admin_command_sessions_tests` | `northstar-workflows` | 無 |
| E5 治理與保存 | WP-460–469 | `reports_tests`、`data_lifecycle_tests`、`retention_policy_repository_tests`、`upload_admin_tests` | `northstar-workflows` | D |

不要移動這些：`authentication_tests`、`api_operations_tests` 與它 `include!` 的 `api_operations_idle_tests`、`sm_tests`、`replay_tests`、`s2s_tests`、`capacity/tests`、`cluster_keys/tests`、MUC 與 MIX 相關測試。它們依賴主線正在改的模組。

**移動規則**

- 測試跟著被測函式所在的 crate。測試夾具可以直接插入別的上下文的資料表。
- `-postgres` crate 內的 `db::migrate` 改為 `northstar_postgres::MIGRATOR.run(&pool)`，先例在 `northstar-pubsub-postgres/src/outbox.rs:693`。空 schema 上的 identity 正規化沒有資料可改，若測試仍依賴它就放在 workflows 並用 `migrate_for_tests`。
- `db/test_support.rs` 的 `operation_mutation_pool` 移成 `northstar_postgres::test_support`，放在 `test-support` feature 後面。`tools/northstar-test-harness` 沒有 sqlx 依賴，不要放那裡。
- `-postgres` crate 的單元測試不要拿 `northstar-workflows` 當 dev-dependency，循環會產生互不相容的同名型別。需要 workflows 的測試就放在 workflows。
- 引用 `crate::xmpp`、`crate::cluster`、`crate::api` 的測試，如果只是純函式就改成擁有它的 crate；需要 `AppState` 或 root 場景的測試留在 root。

**每移一個測試檔都要做**

1. 在 `$TK/maps/<工作流>.sed` 加上映射。
2. 找出引用該模組的路線：`grep -ln '<模組名>' scripts/* .github/workflows/*`。
3. 把路線內的 `--bin rust-xmpp-server` 改成 `-p <crate>`，測試路徑改成新的模組路徑。路線若有測試數目斷言，數字也要同步。
4. 用 `db.sh` 在新位置跑完整個檔，確認 `ran N tests` 的 N 與基線 `ws.ignored` 內該模組的數目相同。沒有 PostgreSQL 時，到 CI log 確認同一批測試有執行。

驗收：每批測試名總數不變，`selectors` 仍是 `0 match no test`，CI 的 DB 工作有實際跑到這些測試。

## 已知陷阱

以下都是 S16–S27 實際出過的問題。

| 症狀 | 原因 | 處理 |
| --- | --- | --- |
| 測試移走後路線仍然綠燈 | `--bin rust-xmpp-server` 篩選跑 0 個測試並以 exit 0 結束 | 每次移測試都搜尋路線並改成 `-p <crate>`。`selectors` 只抓得到同一條命令內的過濾器，抓不到寫在變數裡的 |
| 全區測試通過，單獨測 crate 失敗 | feature unification 遮住缺漏的依賴或 feature | 用 `check.sh` 單獨測試每個改過的 crate |
| gate 全綠但實際不再檢查 | 路徑或公開性改變後，負向 regex 變成永遠不匹配 | 移動後故意測試該 gate 會觸發 |
| gate 字面值找不到 | rustfmt 會拆行；`pub(crate)` 移到 crate 後變 `pub`；自由函式比方法少 4 格縮排 | 先用 `check.sh` 格式化，再改 gate |
| `E0446` 私有型別洩漏 | root 型別出現在公開的關聯型別 | 標示為名義上的 `pub` |
| `E0117` 孤兒規則 | root 對外部型別實作外部 trait | 用 root 本地 wrapper 或 newtype |
| 別名無法當建構子 | tuple struct 建構子不能透過 `pub type` 呼叫 | 改用原型別，`.0` 存取不受影響 |
| 公開 trait 出現 `async_fn_in_trait` | 公開 trait 不能直接寫 `async fn` | 改用 `fn ... -> impl Future<Output = T> + Send`，root 實作可以寫 `async fn` |
| `&Arc<H>` 無法傳給 `&impl Trait` | 沒有 deref coercion | 用 `.as_ref()` |
| 刪 `use` 後編譯怪異 | `#[cfg]` 留在下一個項目上 | 刪除時連屬性一起刪；`src/db/privacy.rs` 已有重複的 `#[cfg(test)]` |
| clippy `result_unit_err`、`result_large_err` | 公開函式回傳 `Result<_, ()>` 或過大的外部 enum | 定義具名錯誤，或用帶 reason 的 `#[expect]` |
| CI 失敗但本地 gates 通過 | CI 還跑 `scripts/test-room-db-experiments.py`，`gates.sh` 不含它 | 推送前手動跑，預期 31 個測試 |
| 測試名全對但 catalog 報錯 | 掃描原始碼的產生器要先跑 | 在 `git mv` 前跑完產生器，或改完後用 `check.sh` |

其他需要知道的 gate 行為：

- `check-outbound-xml-construction` 的 BASELINE 鍵必須存在，seam 與 crate handler 都要列出。
- `catalog/source-layers.json` 的基線項目在檔案不再引用該層時要刪除。
- `check-source-structure` 有每檔大小基線，`src/cluster/listener.rs` 已在 1,500 行上限。
- `check-abuse.mjs` 的 `abuseSources` 是按位置解構，調整清單時要保持順序。
- `catalog/runtime-experiments.json` 的 owner 要跟著 crate 變更。
- `docs/*.md` 的本地連結會被檢查，`docs/handoff`、`docs/evidence` 是歷史檔案，不要改。
- 基線本身有 3 個非零項目：`check-ci-required`、`check-move-only`、`test-caddy-http2`。這是既有狀態，`GATES == BASE` 只比對有沒有變化。

CI 偶發失敗：DR drill 報 `restore refused: 1 other target database session(s) remain after the connection fence`，或 runner 中途死亡。這兩種情況用 `gh run rerun <id> --failed`，其他失敗都要修。

## 不在範圍內的工作

主線繼續負責 S28 federation、S29 session 與 cluster、S30 transports、S31 composition root。下列項目都有設計依賴，執行者不要動手：

- SM 持久化（`services/sm*`、`db/sm*`，約 8,000 行）與 `db/authentication_effects.rs`：依賴 `OutboundItem` 設計。
- replay：依賴 `OutboundSender`、`BoshResponseOwnership`。
- `db/room_effects.rs`、`db/muc_delivery_repository.rs`：依賴 federation 與 session 的遷移。
- `xmpp/direct_delivery.rs`、`db/direct_commit_cluster.rs`、`db/node_message_projection_repository.rs`。
- `src/xmpp/protocol/*` 的 seam 與其測試，S30、S31 才會退場。

**回報方式**

每條工作流落地後，回報最後提交的 SHA、CI run id、root 減少的行數。遇到以下情況就停下來回報，不要自行繞過：

- 需要修改不得修改的路徑。
- `check.sh` 印出 `external package added:`。
- gate 只能靠削弱檢查才能通過。
- 移動會改變行為或 SQL。
- 本計劃的目的地在分層規則下行不通。
