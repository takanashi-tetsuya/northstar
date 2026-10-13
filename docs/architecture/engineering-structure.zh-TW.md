# Northstar 工程結構藍圖

更新：2026-10-11。基線提交：`10d598234c74fefcdc7b7856026e2dd654fe1e1c`。

本文是**結構工作**（程式碼放在哪裡、由誰擁有、如何機械驗證）的唯一權威。
它不改變任何協議、交易、migration 或安全語義。領域邏輯收斂仍依
[模組化執行計劃](../MODULARIZATION_EXECUTION_PLAN.md)，實驗架構重建仍依
[重建帳本](experimental-rebuild-plan.zh-TW.md)，產品限制仍依
[已知問題](../KNOWN_ISSUES.md)。三者與本文分工見第 7 節。

## 1. 「結構明確」的可驗收定義

1. **一處一責**：每個原始碼檔案屬於唯一的層與擁有模組，能從路徑判斷。
2. **檔案可讀**：生產檔案有行數預算；超出的既有檔案只能縮小（ratchet）。
3. **測試歸位**：測試與受測模組放在一起，`src/` 根目錄不放測試檔。
4. **門禁不綁版面**：靜態門禁以「模組」而非「單一檔案＋函式相鄰順序」定位原始碼，
   拆檔不會讓門禁失效或被迫放寬。
5. **狀態單一來源**：每類狀態只有一份權威文件，其他文件只連結。
6. **變更可追溯**：每個結構變更屬於一個工作包（WP），提交訊息帶 WP 編號，`dev` 不收 WIP 提交。

## 2. 基線量測（`10d5982`）

| 指標 | 數值 | 問題 |
| --- | ---: | --- |
| 根 crate `rust-xmpp-server` Rust 行數 | 393,655（503 檔） | 佔全部 Rust 的 81%；`crates/` 只有 82,698 行 |
| 超過 3,000 行的檔案 | 23 | 最大 `src/db/mix.rs` 8,619 行、`src/cluster.rs` 8,553 行、`src/state.rs` 7,744 行 |
| 超過 1,500 行的檔案 | 87 | 審閱與合併衝突成本高 |
| `src/` 根目錄平放的 `.rs` | 41 檔／68,077 行 | 執行期、安全、傳輸、工具、測試混在同一層 |
| `src/` 根目錄測試檔 | 7（6 個 `*_tests.rs`＋`test_activation.rs`） | 測試沒有與受測模組放在一起 |
| `scripts/` 項目 | 330 | 門禁、fixture、VM 工具、一次性證據工具平放 |
| `check-architecture-boundaries.mjs` | 4,051 行、238 次讀檔 | 以固定路徑讀檔 |
| shell 門禁的相鄰範圍擷取 | 例：`sed -n '/^async fn A(/,/^fn B(/p' src/db/mix.rs` | 搬動或拆分函式即失效 |

第 4 項是後續一切拆檔的前置障礙：先讓門禁對版面不敏感，才能低風險地拆檔。

## 3. 目標分層

`catalog/crates.yaml` 已定義 crate 層級（foundation／domain／xep／application／adapter／service／tooling）。
根 crate 內部對應同一方向，依賴只能由上往下：

```text
L4 組合與執行期   main.rs、subservers、state（AppState 組裝）、workers、operation_runtime、維護 worker
L3 應用服務       src/services/**  （呼叫 crates/*-application 與注入的 port）
L2 介面卡         持久化 src/db/**；協議／傳輸 src/xmpp/** src/bosh/** src/s2s/** components；
                  HTTP src/api/**；物件儲存 src/storage/**；叢集控制面 src/cluster/**
L1 平台橫切       config、error、logging、metrics、tls／crl／ocsp、password_work
L0 函式庫         crates/*（domain／xep／application／foundation），不得依賴根 crate
測試專用          只在 #[cfg(test)]；受控重播與 Stage 4 實驗程式只在既有 cfg(test) 模組
```

### 3.1 根 crate 目標目錄（S4 階段才搬動）

| 目標目錄 | 現有來源 | 說明 |
| --- | --- | --- |
| `src/runtime/` | `workers.rs`、`operation_runtime.rs`、`capacity_maintenance.rs`、`upload_worker.rs`、`retention.rs`、`subscription_cleanup.rs`、`connection_actors.rs`、`subservers*` | 組合根以外的監督、worker 與程序角色 |
| `src/security/` | `tls.rs`、`crl.rs`、`ocsp.rs`、`password_work.rs`、`abuse.rs`、`account_recovery.rs` | 憑證、密碼工作量、反濫用 |
| `src/cluster/` | `cluster.rs`、`cluster_security.rs`（併入） | 叢集控制面 |
| `src/xmpp/`、`src/s2s/` | `components.rs`、`outbound.rs`、`transport_parsing.rs`、`mam_pubsub_parsing.rs` | 依實際呼叫方歸入傳輸或聯邦 |
| `src/platform/` | `config.rs`、`error.rs`、`logging.rs`、`metrics.rs` | 平台橫切 |
| `src/tools/` | `pie.rs`、`identity_audit.rs` | 離線運維工具 |
| 受測模組內 | 7 個根目錄測試檔 | 改為 `<模組>/tests*.rs` |

`auth.rs`、`jid.rs`、`mam_pubsub_parsing.rs` 等相容 facade 在呼叫方遷完後移除。
搬動以「新路徑＋舊路徑暫時 `pub(crate) use` 轉出」進行，最後一個 WP 刪除轉出。

## 4. 結構規則（由門禁執行）

| 規則 | 內容 | 執行方式 |
| --- | --- | --- |
| R1 行數預算 | 生產 `.rs` 檔 ≤ 1,500 行；測試檔 ≤ 3,000 行。既有超標檔記錄在基線，只能縮小；新檔不得超標 | `scripts/check-source-structure.mjs`＋`catalog/source-structure-baseline.json` |
| R2 根目錄收斂 | `src/` 根目錄 `.rs` 數只能減少；不得新增根目錄測試檔 | 同上 |
| R3 模組拆分方式 | 大檔拆成「`foo.rs`＋`foo/子模組.rs`」，保持原有模組路徑；拆分 WP 只移動程式碼，不改邏輯。可見性的不變式：搬移後每個名稱的可見範圍只能維持或縮小，不得擴大。維持原範圍的寫法是「私有→`pub(super)`、`pub(super)`→`pub(in <父模組的上層>)`（如 `pub(in crate::xmpp::protocol)`、`pub(in crate::db)`）、`pub(crate)`／`pub` 不動」，適用於搬入子檔的頂層項目、結構欄位與固有 impl 成員；不需跨檔使用者也可維持私有（範圍縮小）。WP-24 起一律採維持原範圍的寫法，由只移動檢查的 `VISIBILITY:` 行逐項核對，免去依編譯錯誤反覆補可見性。協議模組的父檔以明確的 `use self::子模組::{…};` 列出兄弟子檔與測試使用的名稱（只供測試者加 `#[cfg(test)]`），模組外使用者以原可見性轉出（`pub(super) use`／`pub(crate) use`）；已由 `db/mod.rs` 以 `pub use x::*` 整體轉出的 db 模組，父檔改以 `pub use self::子模組::*;` 轉出（bin crate 中未被使用的明確轉出是 unused import，`-D warnings` 下失敗） | 「只移動」差異檢查（第 6 節，`scripts/check-move-only.mjs`） |
| R4 門禁定位 | 門禁以模組讀原始碼（`foo.rs` 與 `foo/**.rs` 視為同一模組），以括號配對擷取指定項目；禁止新增依函式相鄰順序的擷取。Rust 單元測試以 `include_str!` 讀自身模組原始碼者，拆分時改讀父檔的 `#[cfg(test)] const MODULE_SOURCE`（父檔＋各正式子檔），並以守衛測試確認清單與非測試的 `mod` 宣告一致。子檔依拆分前在單檔中的先後順序列出：有些契約以出現不只一次的標記切割原始碼，依字母排列會取錯片段（WP-25 的 `let exact_replay =`） | `scripts/lib/source-module.mjs`；Rust 測試見 `src/db/cluster_muc.rs`、`src/db/archive.rs` |
| R5 證據不可改寫 | `scripts/fixtures/**/historical*`、`docs/evidence/**` 與已記錄的 Stage 證據不得因結構工作修改 | 審閱 |
| R6 測試專用碼 | 受控重播與實驗程式只能存在於 `#[cfg(test)]` 模組 | 既有門禁＋審閱 |
| R7 提交 | 一個 WP 一至數個提交，訊息首行以 `[WP-xx]` 開頭；不推 WIP | 審閱 |

## 5. 工作包順序

| 階段 | WP | 內容 | 退出條件 |
| --- | --- | --- | --- |
| S0 護欄 | WP-01 | `scripts/lib/source-module.mjs`：模組檔案解析、模組全文讀取、Rust 項目括號配對擷取（略過字串、字元、註解）；提供 CLI 給 shell／Python 門禁；附單元測試 | 新測試通過；不改任何既有門禁 |
| | WP-02 | `scripts/check-source-structure.mjs`＋基線 JSON（R1／R2 ratchet）；接入 CI `web-static` | 在基線提交上通過；人為加長檔案時失敗 |
| S1 門禁解耦 | WP-1x | 依拆檔目標，逐一把引用該檔的門禁改為模組讀取（R4）。盤點以檔案路徑全文搜尋 `scripts/`（含 shell／WSL 套件與 Python 實驗程式）、`catalog/`、`.github/` 與 `CODEOWNERS`，並搜尋 `src/`、`crates/` 中的 `include_str!("*.rs")`，不只看 `ci.yml` 中的 node 門禁。禁止型斷言（「原始碼不得含 X」）只讀單一檔案時，拆分後不會失敗而是靜默失效，因此盤點不能只靠「拆完後測試仍通過」（WP-31 時 `runtime-experiments.json` 的測試 anchor 隨測試搬家；`muc-cluster-wsl.sh` 綁定 `db/cluster_muc.rs`，由 WP-13 先行解耦）。盤點結果見 5.1 | 改寫前後門禁在同一提交都通過；以故意刪除被檢片段的反例確認仍會失敗（shell 門禁同樣需要反例，WP-13 即由反例抓到傳入絕對路徑而全部失敗的錯誤） |
| | WP-11 | `check-outbound-xml-construction.mjs` 的基線項目加上 `module`／`file` 範圍：`module` 以 `productionModuleFiles` 展開（拆出的子檔自動繼承預算）；子樹內已有既存發現的 `protocol.rs`、`services/mix.rs` 維持 `file` | 展開後的檔案集合包含原清單；在 `federated_muc/` 下放入原始 XML 字面值時失敗 |
| | WP-12 | `check-architecture-boundaries.mjs` 對 `federated_muc.rs` 改用 `readProductionModule`；修正 2148／2259／2262 行在 template literal 中被吞掉的 `\b`、`\s`、`\.` 跳脫 | 修正後的禁止規則對注入的 `db::` 呼叫會失敗；現行原始碼仍通過 |
| S2 拆大檔 | WP-2x | 一次拆一個大檔（順序：`federated_muc.rs` → `db/pubsub.rs`、`db/cluster_muc.rs`（後者先做 WP-13）→ `xmpp/protocol/muc.rs` → `db/archive.rs` → `xmpp/protocol/mix.rs` → `db/mix.rs` → `state.rs` → `cluster.rs` → `config.rs`） | 只移動差異檢查通過；fmt、受影響套件 check／clippy `-D warnings`、單元測試與相關門禁通過；基線下修 |
| S3 測試歸位 | WP-3x | 7 個根目錄測試檔移入受測模組（WP-32 搬 cluster 四個與 abuse 一個；`shutdown_notification_tests.rs` 測的是 `main.rs` 的關機監督，`test_activation.rs` 是只因檔名被歸為測試的正式模組，兩者改在 S4 隨 `main.rs` 的程式碼搬入 `src/runtime/` 時歸位） | 測試數量與名稱集合不變 |
| S4 根目錄分層 | WP-4x | 依 3.1 分組搬動，最後移除舊路徑轉出（分組、規則與綁定見 5.2） | `src/` 根目錄只剩 `main.rs` 與各層目錄宣告；5.2 列出的保留檔除外 |
| S5 領域收斂 | — | 依模組化執行計劃 C1／C2／D1 把邏輯移入 crates | 依該計劃 |
| S6 文件收斂 | WP-6x | 修正 KNOWN_ISSUES 的 migration 數、README 的發佈敘述、HANDOFF 現況；`docs/README.md` 建立狀態地圖 | 文件一致性門禁通過 |

獨立於結構工作的已知缺陷另以 `BUG-xx` 工作包處理。BUG-01（`operation_runtime::run_one`
取消時 lease heartbeat 未停止）已修正；修正會讓檔案超過行數預算，因此先以 WP-31 把該檔測試
移出，再套用修正，而不是放寬基線。

### 5.1 S1 盤點：剩餘 S2 目標的路徑綁定（`1d524b9`）

拆檔前，下表每個綁定都要確認在拆分後仍成立：已以模組讀取者不需動；以單一檔案讀取且被檢內容
可能搬進子檔者，先開 WP-1x 改為模組讀取（R4）。

| 目標 | 以檔案路徑綁定的門禁與資料 |
| --- | --- |
| `xmpp/protocol/muc.rs` | `check-architecture-boundaries.mjs`、`check-execution-boundaries.mjs`（兩者 WP-14 起以模組讀取）、`check-outbound-xml-construction.mjs`（WP-11 起以模組讀取）、`check-database-role-boundaries.sh`（只要求父檔保留 `#[path = "muc_tests.rs"]`） |
| `db/archive.rs` | `check-architecture-boundaries.mjs`、`check-execution-boundaries.mjs`（兩者 WP-15 起以模組讀取）、自身測試的 `include_str!("archive.rs")`（WP-25 起改讀 `MODULE_SOURCE`） |
| `xmpp/protocol/mix.rs` | `check-architecture-boundaries.mjs`、`check-execution-boundaries.mjs`、`test-mix-outbox-boundaries.mjs`（三者 WP-16 起以模組讀取）、`check-outbound-xml-construction.mjs`（WP-11 起以模組讀取）、`check-migration-versions.sh`（WP-17 起以模組讀取）、`test-source-module.mjs`（只要求子檔含 `worker.rs`、不含 `stage4_saved`）、架構門禁的工作者註冊表與 `catalog/runtime-experiments.json` 的 `owner`（`mix-iq-relay-expiry`、`mix-presence-recovery` 綁定註冊所在的檔案，註冊搬進子檔時兩處同步修改，否則門禁直接失敗；WP-26 把兩個註冊留在父檔）。執行門禁逐字比對 `deliver_channel_stanza_inner` 的簽名與 `MixOutboxDeliveryPort` 的結構本體，兩者依 R3 改為 `pub(super)` 後，門禁的期望與自測的變異原文在 WP-26 同步更新 |
| `db/mix.rs` | `check-architecture-boundaries.mjs`、`check-execution-boundaries.mjs`、`check-migration-versions.sh`、`check-database-role-boundaries.sh`（四者 WP-17 起以模組讀取：遷移檢查的必要片段讀正式檔、禁止片段讀含測試子檔的全模組，四段 `sed` 相鄰範圍改為依宣告讀取項目；架構門禁的三項全 src 呼叫者掃描豁免模組的每個檔案）、`check-outbound-xml-construction.mjs`（WP-11 起以模組讀取）。就地套用 R3 可見性（92 行）後，五個門禁與執行、MIX outbox 兩組自測都照常通過，沒有逐字比對可見性的期望；WP-27 拆分時門禁與自測都不需修改 |
| `state.rs` | `check-architecture-boundaries.mjs`、`check-execution-boundaries.mjs`、`check-session-lifecycle-boundary.mjs`、`check-subserver-boundaries.mjs`、`check-omemo.mjs`、`check-migration-versions.sh`、`check-database-role-boundaries.sh`（七者 WP-18 起以模組讀取：架構門禁的項目擷取要求宣告唯一，AppState 服務存取器只從各 `impl AppState` 區塊收集）、`.github/CODEOWNERS`（WP-18 起另列 `src/state/**`）、架構門禁的工作者註冊表與 `catalog/runtime-experiments.json` 的 `owner`（綁定 `.supervise(`／`.register_observer(` 註冊所在的檔案：WP-28 拆分時兩個 `.supervise(` 註冊 `start_locked_muc_expiry`、`start_runtime_control_refresh` 留在父檔，session-cleanup observer 的註冊隨 `AppState::new` 搬入 `construction.rs`，其 `owner` 同步改為 `src/state/construction.rs`）。`AppState` 結構也留在父檔：架構門禁要求其欄位全為私有，搬出後 R3 會改為 `pub(super)`。除該結構外就地套用 R3 可見性（159 行）後，七個門禁與執行、子伺服器、MIX outbox 三組自測都照常通過；WP-28 拆分時門禁與自測都不需修改 |
| `cluster.rs` | `check-architecture-boundaries.mjs`、`check-migration-versions.sh`（兩者 WP-19 起以模組讀取：架構門禁的 13 處擷取要求宣告唯一）、`check-outbound-xml-construction.mjs`（WP-11 起以模組讀取）、`muc-cluster-wsl.sh`（WP-13 起以模組讀取）、`cluster-wsl.py`（以 `^const NODE_PROTOCOL_VERSION` 讀父檔，CI 的 `test-cluster-*.py` 在匯入時即讀取；套用 R3 後會直接失敗，因此該常數留在父檔）、架構門禁的工作者註冊表與 `catalog/runtime-experiments.json` 的 `owner`（`cluster-muc-outbox` 綁定 `start_muc_outbox_delivery` 中的註冊，拆分時留在父檔）。就地套用 R3 可見性（490 行）後，架構、對外 XML、遷移門禁與 MUC 叢集靜態契約都照常通過；WP-29 拆分時兩者都留在父檔，門禁、自測與目錄都不需修改 |
| `config.rs` | `check-architecture-boundaries.mjs`、`check-abuse.mjs`（兩者 WP-20 起以模組讀取：架構門禁的 3 處擷取要求宣告唯一）。正式模組只排除測試子檔，檔案內嵌的 `#[cfg(test)] mod tests` 仍在讀取範圍內，必要片段只出現在測試中時仍會通過；拆分時把該模組移為獨立測試檔即可補上。`listener-readiness-stress-wsl.sh` 只在註解中提到該檔，實際讀取執行檔 `--runtime-connection-budget` 的輸出；`config/environment.rs` 的 `include_str!` 以自身位置為基準。就地套用 R3 可見性（189 行）後，兩個門禁照常通過；WP-30 把內嵌測試模組移為 `config/tests.rs`，上述缺口隨之補上（必要片段只出現在測試檔時改為失敗），門禁與自測都不需修改 |

### 5.2 S4 盤點：根目錄檔案的路徑綁定（`1761f49`）

盤點範圍同 5.1：`scripts/`、`catalog/`、`.github/`、`fuzz/`，以及 `src/`、`crates/` 中的 `include_str!`、
`#[path]` 與以字串組出的原始碼路徑。`recovery/*.json` 是歷史快照的雜湊清單、`scripts/fixtures/**`
與 `docs/evidence/**` 屬 R5 證據，都沒有程式拿來比對現行原始碼，不隨搬移修改。
`check-documentation-consistency.mjs` 要求 `README.md`、`docs/**` 等文件中的本地 Markdown 連結都存在，
因此指向被搬檔案的連結（`docs/TRACEABILITY.md` 18 處、`docs/architecture/resource-bounds.zh-TW.md`
6 處）也是路徑綁定，在同一 WP 改寫。這項綁定在 WP-41 的完整 CI 才發現，之後改以掃描全部連結的
腳本盤點，結果列入下表。只在內文提到的舊路徑（`docs/` 與 `crates/*/MIGRATION.md`），以及
`resource-bounds` 連結上已過時的行號錨點，留到 S6 一併修正。tracing 事件的預設 target 是模組路徑，
搬移後會改變（例如 `rust_xmpp_server::tools::pie`）；`RUST_LOG` 設定、WSL 腳本與文件只篩選不搬移
的模組（`cluster`、`s2s::inbound`、`xmpp::…`），因此不受影響。

模組路徑本身也是綁定，搬移後測試名稱會多一層前綴（例如 `tools::pie::tests::…`）。WP-43 的單元
測試發現第一類：測試以 `current_exe()` 重新執行測試執行檔並指定 `--exact` 測試路徑
（`config/environment.rs`、`logging.rs`），選不到測試時子程序的結果會讓父測試失敗。接著以字串
搜尋盤點出第二類：WSL 測試腳本以 `cargo test <路徑> -- --exact` 選取測試。不加 `--exact` 的選取
是子字串比對（`abuse::tests::…`、`tls::tests::generated_`、`catalog/runtime-experiments.json` 的
命令），搬移後仍然選得到；加了 `--exact` 的選取會選不到測試，而 cargo 選不到任何測試時仍然成功
結束。`pie-db-wsl.sh`、`identity-audit-db-wsl.sh` 檢查「1 passed」，會明確失敗；
`runtime-tls-test-wsl.sh` 的 CRL 案例沒有檢查，在 CI 中靜默通過但沒有執行任何測試。這三處由
WP-41c 修正，WP-44 的 `retention-db-wsl.sh` 列入下表。第三類是門禁比對呼叫端程式碼中的舊模組
路徑（`config::load_dotenv()?;`、`identity_audit::maybe_run(`、`retention::serve_context(`、
`subscription_cleanup::serve_context(`、`subservers::run_maintenance()`、
`logging::report_result(run().await)`、`password_work::reserve()`），搬移 WP 不改呼叫端，因此
只影響 WP-48。

搬移規則：

1. 架構負責人以 `git mv` 整棵搬移（`x.rs` 連同 `x/`）；分層目錄以 `mod.rs` 宣告，與既有的
   `api`、`db`、`s2s`、`services`、`xmpp` 一致。`main.rs` 改為 `mod <層>;`，並以私有的
   `use <層>::<模組>;` 暫時保留舊路徑，因此搬移 WP 不改任何呼叫端；WP-48 改寫呼叫端並刪除轉出。
2. 子樹內的 `super::` 與 `pub(super)` 都相對於子樹，搬移後不變。被搬模組頂層檔案中的
   `pub(super)` 原本是全 crate 可見，依 R3 改為 `pub(crate)`；頂層檔案的 `super::` 原指 crate
   根，改為 `crate::`。
3. 超標檔隨 `git mv` 改名時，基線條目同步改名、行數不變，並以 `git diff -M` 證明是同一檔案；這不
   放寬 R1，內容一有變更就照常適用。
4. 門禁、目錄、fuzz、`include_str!`、文件連結與 `--exact` 測試選取綁定的路徑在同一 WP 改寫，
   並以反例確認新路徑仍受檢查；`--exact` 選取要以 `cargo test <路徑> -- --exact --list` 確認
   恰好選到一個測試。

| WP | 目標 | 搬入的檔案 | 以檔案路徑綁定的門禁與資料 |
| --- | --- | --- | --- |
| WP-41 | `src/tools/` | `pie.rs`（2,779 行，超標）、`identity_audit.rs`（2,168 行，超標） | `check-database-role-boundaries.sh` 的 `pie_source`；`db/upload_tests.rs` 的 `include_str!("../pie.rs")`；`TRACEABILITY.md` 連結 1 處 |
| WP-42 | `src/security/` | `tls.rs`（2,190 行，超標）、`crl.rs`、`ocsp.rs`、`password_work.rs`、`abuse.rs`（2,622 行，超標）連同 `abuse/`、`account_recovery.rs` | `check-abuse.mjs` 與架構門禁讀 `abuse.rs`、`account_recovery.rs`，架構門禁另讀 `tls.rs`；`abuse/tests.rs` 的 migration `include_str!` 多一層 `../`；`TRACEABILITY.md` 連結 6 處（abuse、crl、ocsp、tls） |
| WP-43 | `src/platform/` | `config.rs` 連同 `config/`、`error.rs`、`logging.rs`、`metrics.rs` | `check-abuse.mjs`（`config`、`error`）、架構門禁（`config` 以模組讀取）、`check-omemo.mjs`（`metrics`）；`config/environment.rs` 的 `.env.development.example` `include_str!` 多一層 `../`；連結 7 處（`TRACEABILITY.md` 的 config 3、metrics 2，`resource-bounds` 的 config 2）；`config/environment.rs`、`logging.rs` 以 `--exact` 重新執行自身測試的路徑字串 |
| WP-44 | `src/runtime/` | `workers.rs`（1,717 行，超標）、`operation_runtime.rs` 連同目錄、`capacity_maintenance.rs`、`upload_worker.rs`（1,990 行，超標）、`retention.rs`、`subscription_cleanup.rs`、`connection_actors.rs`、`subservers.rs` 連同目錄、`test_activation.rs` | `catalog/runtime-experiments.json` 的 `owner`（workers、operation_runtime、upload_worker、subservers）與架構門禁的工作者註冊表、`check-subserver-boundaries.mjs`（retention、subscription_cleanup、subservers）、`test-source-module.mjs`（以 operation_runtime 為夾具）、`db/upload_tests.rs` 的 `include_str!("../upload_worker.rs")`；連結 6 處（`TRACEABILITY.md` 的 operation_runtime、retention、upload_worker，`resource-bounds` 的 connection_actors 1、workers 2）；`retention-db-wsl.sh` 以 `--exact` 選取的 `subscription_cleanup::tests::…` |
| WP-45 | `src/runtime/` | `main.rs` 的服務任務監督與關機通知（`ServiceTaskExit`、`await_shutdown_notifications`、`drain_service_tasks` 等）連同 `shutdown_notification_tests.rs` | 只移動拆分，依 R3 與只移動檢查；先盤點門禁對 `main.rs` 的讀取 |
| WP-46 | `src/cluster/` | `cluster_security.rs` 併為 `cluster/security.rs` | `catalog/runtime-experiments.json` 兩處；`TRACEABILITY.md` 連結 1 處 |
| WP-47 | `src/xmpp/`、`src/s2s/` | `components.rs`（2,638 行，超標）、`outbound.rs`、`transport_parsing.rs`、`mam_pubsub_parsing.rs`，依實際呼叫方歸入 | 架構、對外 XML 與執行門禁；`fuzz/fuzz_targets/bosh_ws_framing.rs` 的 `#[path = "../../src/transport_parsing.rs"]`、`check-parser-fuzz-coverage.mjs`、`test-parser-fuzz-coverage.mjs`、`fuzz/Cargo.toml`；連結 3 處（`TRACEABILITY.md` 的 components、outbound，`resource-bounds` 的 outbound） |
| WP-48 | — | 改寫呼叫端（`crate::<模組>` 改為 `crate::<層>::<模組>`）並刪除 `main.rs` 的暫時轉出，可依層再分。較長的路徑使 rustfmt 折行，十個超標檔會變長（R1），因此 WP-48a 先把其中八個的內嵌測試模組移為子檔，再改寫這十個檔案並一次調降基線 | 只改路徑，不改語義；門禁比對呼叫端舊模組路徑的片段（`check-subserver-boundaries.mjs` 與其自測、`check-abuse.mjs` 的 `password_work::reserve()`、架構門禁的 `logging::report_result`）同步改寫 |

S4 後根目錄保留的檔案：`main.rs`；同名目錄的模組檔 `state.rs`、`cluster.rs`、`bosh.rs`、`storage.rs`
（`bosh/response_owner.rs` 由 CI 的 Stage 4 綁定測試與 `stage4_build_record.py` 以路徑讀取）；只在
`#[cfg(test)]` 編譯的 `stage4_replay.rs`（`controlled_admission_supervision.py` 綁定它與
`stage4_replay/compact.rs`）與 `direct_replay.rs`；相容 facade `auth.rs`、`jid.rs`（分別有 38、170 個
使用檔），在 S5 呼叫方改用 crate 後移除。

## 6. 委派與驗收協議

角色：**架構負責人**撰寫 WP 規格、執行全部驗證並審閱差異；**程式修改**由 Antigravity CLI（`agy`）執行。

1. 由 `dev` HEAD 建立獨立 git worktree（只含受追蹤檔案，不含 `.env` 等本機秘密）。
2. 以 `agy -p --mode accept-edits` 交付 WP 規格。agy 只能改檔，不執行 shell；不授予
   `--dangerously-skip-permissions`。規格須明寫「不得執行任何 shell 指令，只用檔案檢視與編輯
   工具」，否則新對話會先嘗試指令、被 headless 模式拒絕後不做任何修改。規格若留有詮釋空間，
   agy 會反覆推敲並改讀 `.git`、`package.json` 等檔案，越出 worktree 的讀取被拒後同樣不做修改
   （WP-15 初版只寫「在讀取上方加註解」即如此）；小範圍修改一律給逐字的原文與新文。
3. 架構負責人執行驗證：`cargo fmt --check`、受影響套件的 `cargo check`／`clippy -D warnings`
   （all-targets）、相關單元測試、CI 離線步驟，以及 R3 的只移動檢查。
   CI 離線步驟由 `node scripts/run-ci-offline.mjs` 執行：`ci.yml` 中不需外部服務的全部步驟
   （`web-static`、`rust-quality` 的驗證步驟、fuzz 目標前置檢查）逐字照 workflow 執行，只跳過需要
   root 的套件安裝與 `sudo` 測試並逐行列出；另加 `muc-cluster-wsl.sh` 在啟動 Redis 前的靜態契約。
   workflow 出現它不支援的寫法（`if`、`shell`、`${{ }}`、`|` 以外的區塊字串）時直接失敗，不會
   略過。這組步驟先在乾淨基準提交上全數通過，之後任何失敗都歸因於該 WP。
   只移動檢查由 `node scripts/check-move-only.mjs [--allow-doc] <base-rev> <module.rs>` 執行
   （`--after-rev <rev>` 可事後稽核已提交的拆分），以「項目」為單位：拆分前後的頂層項目多重集合
   必須相同。固有 impl 區塊（`impl 型別 { ... }`）展開為各成員，以「正規化後的 impl 標頭＋成員」
   為鍵，因此同一型別的方法可分散到不同子檔各自的 `impl` 區塊，標頭（含屬性與 where 子句）不同
   則判為不同；trait impl 無法拆開，維持整體比對。impl 標頭上的註解，以及檔尾、區塊尾只含註解的
   部分，也各自作為項目比較（WP-04）。比較時忽略 `use`、無本體的 `mod x;`、可見性修飾、字面值以外的空白與 rustfmt 重排
   產生的尾逗號。開頭的 `super::` 依實際模組深度換算（WP-05）：子目錄外深度 0、子目錄內深度 1，
   每層內嵌 `mod x { ... }` 再加 1；連續 k 個 `super::` 換算為「深度 − k」層，在被拆模組之上仍寫
   `super::`，等於被拆模組時寫 `self::`。因此子檔中的 `super::super::` 等同原本的 `super::`，單一的
   `super::` 等同原本的 `self::`；整個內嵌模組（如 `#[cfg(test)] mod tests { ... }`）搬成獨立檔案時
   模組深度不變，路徑原樣保留即判為相同。字串與字元字面值逐位元組比較，因此縮排變動不能改到多行
   字串內容；唯一的例外是非原始字串中行尾 `\` 續行後下一行開頭的空白，rustc 不把它算入字串值，
   比較前先刪去，續行隨搬移少一層縮排仍判為相同（WP-48a）。`include_str!` 路徑相對於所在檔案，檔案搬進子目錄時須改寫，會列為差異逐項審閱。被忽略的可見性
   修飾另以 `VISIBILITY:` 行列出供審閱，不影響結果。拆檔時 agy 逐字複製、不重排；`cargo fmt`
   由架構負責人執行（確定性格式化，不屬撰寫程式）。內嵌測試模組搬成獨立檔案、少一層縮排後，
   `cargo fmt` 可能改變寫法（WP-26 把 match 分支的 `=> { X }` 改成 `=> X,`），只移動檢查不正規化
   這類差異而判為不同；此時以 rustfmt 格式化逐字複製的原模組本體，與新檔逐位元組比對，相同即證明
   差異只來自格式化。
   內容不變的整檔搬移由架構負責人以 `git mv` 執行（檔案系統操作，與 `cargo fmt` 同樣不屬撰寫
   程式；agy 不執行 shell，重新輸出數千行檔案只會增加逐字複製的風險）；檔內須隨之修改的部分
   （`#[path]` 屬性、`include_str!` 相對路徑）仍交由 agy，再以 `git diff -M` 確認其餘內容不變（WP-32）。
4. agy 的檔案工具不受 worktree 限制（曾把修改寫進主 checkout）。規格一律寫明 worktree 的絕對
   路徑；每次 agy 執行前後，架構負責人以 `bash scripts/checkout-fingerprint.sh --exclude <該 worktree>`
   比對 `git worktree list` 列出的其他每個 checkout 的內容指紋（相對 HEAD 的 diff 與未追蹤檔內容
   雜湊），把越界修改移回 worktree 並還原原處。
5. 多步驟的拆檔，每一步開新的 agy 對話並給完整、獨立的規格，刪除範圍寫明行號。同一對話持續
   累積上下文時，單步可達 35 分鐘、170 萬 tokens，且會嘗試以 shell 刪除大段程式；新對話同樣
   規模的一步約 6 分鐘、25 萬 tokens（WP-22／23 的 15 步每步 1–4 分鐘、4–16 萬 tokens）。
   可見性清單需包含出現在 `pub(super)` 項目簽名中的型別與測試直接讀取的欄位（WP-21 漏列
   `FederatedRoomConfig`，由編譯錯誤回饋一輪修正）。規格中交給 `source-module.mjs` 的路徑必須是
   相對於 repository 的路徑（它拒絕絕對路徑；WP-13 初版因此每項檢查都失敗，由反例抓到）。
   agy 逐字複製時會在多行 SQL 字串的續行多加一格空白（WP-22 一次、WP-25 兩次），都由逐位元組的
   字面值比較抓到；規格須明寫字串內的行首空白一律照原樣，即使數目是奇數或看似沒對齊。
   agy 也會順手做語義相同的「改善」（WP-26 把 `stanza.clone()` 改成 `&stanza`），由只移動檢查
   抓到；規格須明寫不得做任何改善，即使原寫法看似多餘。agy 也會漏抄片段（WP-30 搬移測試模組時
   漏掉一個斷言中的 `.is_err()`），同樣由只移動檢查抓到並以一輪回饋修正。
   門禁中逐字比對簽名或結構本體的期望，會因 R3 的可見性改寫而失敗（WP-26 的執行門禁兩處）。
   S1 盤點以反例模擬搬移時，須依 R3 加上可見性，才能事先找出這類期望，列入拆分 WP 的規格，連同
   自測中以原文作變異錨點的測試一起更新。
6. 失敗輸出回饋到同一個 agy 對話（`--conversation`）修正，最多三輪；仍失敗則縮小 WP 範圍。
7. 審閱通過後以 `[WP-xx]` 提交到 `dev`；推送後以該提交的完整 CI 為準，不沿用舊綠燈。

WP 規格固定包含：目標、允許修改的檔案、不得改變的語義（SQL、migration、鎖、交易、wire、
錯誤訊息、門禁強度）、不得觸碰的證據檔、退出檢查。

## 7. 與其他計劃的分工

| 文件 | 權威範圍 |
| --- | --- |
| 本文 | 檔案位置、模組邊界、行數預算、門禁定位方式、結構 WP 狀態 |
| [模組化執行計劃](../MODULARIZATION_EXECUTION_PLAN.md) | 領域邏輯由根 crate 收斂到 crates 的順序與退出證據 |
| [重建帳本](experimental-rebuild-plan.zh-TW.md) | Stage 0–6 受控驗證；結構 WP 不改寫其證據，未來 record 須用新來源契約 |
| [已知問題](../KNOWN_ISSUES.md) | 產品限制與發布門禁 |

結構搬動會使綁定舊路徑與雜湊的受控 record 合約失效；這只影響之後的新 record，已保存的
Stage 證據仍綁定其原提交。

## 8. WP 狀態

| WP | 狀態 | 提交 |
| --- | --- | --- |
| WP-01 | 完成（三輪回饋，測試夾具另以縮小範圍的 WP-01c 修正） | 見 `git log --grep '\[WP-01\]'` |
| WP-02 | 完成（三輪回饋） | 見 `git log --grep '\[WP-02\]'` |
| WP-11 | 完成（覆蓋由 40 檔增為 42 檔，無遺漏） | 見 `git log --grep '\[WP-11\]'` |
| WP-12 | 完成（三個失效的禁止／要求規則恢復作用） | 見 `git log --grep '\[WP-12\]'` |
| WP-21 | 完成：`federated_muc.rs` 7,326 行拆為 presence／message／iq／owner／admin／moderate／tests，父檔 843 行；74 個項目不變，可見性一輪回饋 | 見 `git log --grep '\[WP-21\]'` |
| WP-31 | 完成：`operation_runtime.rs` 測試移至 `operation_runtime/tests.rs`（47 個項目不變），catalog anchor 同步 | 見 `git log --grep '\[WP-31\]'` |
| BUG-01 | 完成：spawned heartbeat 以 drop guard 停止；移除 guard 時新測試失敗 | 見 `git log --grep '\[BUG-01\]'` |
| WP-13 | 完成：`muc-cluster-wsl.sh` 的 `db/cluster_muc.rs`、`cluster.rs` 靜態契約改以模組讀取；7 個反例全部如預期失敗 | 見 `git log --grep '\[WP-13\]'` |
| WP-22 | 完成：`db/pubsub.rs` 4,565 行拆為 node／subscription／affiliation／item／collection／disco／digest，父檔 1,161 行；109 個項目不變，以 `pub use self::子模組::*;` 轉出、可見性不動；agy 在 SQL 字面值內多加一個空白，由逐位元組字面值比較抓到並一輪修正 | 見 `git log --grep '\[WP-22\]'` |
| WP-23 | 完成：`db/cluster_muc.rs` 5,964 行拆為 query／session_route／outbox／room／moderation／admin_batch／affiliation／occupancy，父檔 1,090 行；121 個項目不變，唯一可見性變更為 `grant_cluster_muc_invitation_in_tx` 由 `pub(super)` 改為等價的 `pub(in crate::db)`。兩個 `include_str!` 自讀測試改讀 `MODULE_SOURCE`（其中一個禁止型斷言原本已靜默失效），並以反例確認 | 見 `git log --grep '\[WP-23\]'` |
| WP-03 | 完成：`scripts/check-move-only.mjs`、`scripts/run-ci-offline.mjs`、`scripts/checkout-fingerprint.sh`，兩組測試接入 CI `web-static`。新規則把子檔的單一 `super::` 視為原本的 `self::`，補上舊工具的盲點；以 `--after-rev` 重驗 WP-21／22／23／31，結果與當時一致。四輪回饋修正了路徑打錯時仍判通過、測試檔語法錯誤與 workflow 不支援寫法未直接失敗等問題 | 見 `git log --grep '\[WP-03\]'` |
| WP-14 | 完成：架構與執行門禁對 `xmpp/protocol/muc.rs` 改以模組讀取（遙測檢查讀含測試子檔的全模組）。反例顯示舊的單檔讀取漏看既有子檔 `muc/presence.rs` 中的 `state.cluster`；`saved_stage4.rs` 的 `state.metrics` 與 `muc/message.rs` 的重複 `muc_message` 本體均如預期失敗 | 見 `git log --grep '\[WP-14\]'` |
| WP-04 | 完成：只移動檢查把固有 impl 區塊展開為成員比對，trait impl 維持整體；impl 標頭註解與只含註解的結尾也納入比較。12 個新測試；以 `--after-rev` 重驗 WP-21／22／23 結果不變；兩輪回饋修正重構時被加倍的反斜線跳脫 | 見 `git log --grep '\[WP-04\]'` |
| WP-24 | 完成：`xmpp/protocol/muc.rs` 6,165 行拆為 admin／admin_batch／discussion／owner／moderate／register／groupchat／join，父檔 973 行，最大子檔 `join.rs` 1,438 行；兩個 `impl ProtocolSession` 區塊的方法分到各子檔自己的 impl 區塊，182 個項目不變、0 輪回饋。32 項可見性變更全部是維持原範圍的寫法；2,186 個測試名稱不變；6 個反例（`state.cluster`、`state.metrics`、`state.pool`、移除 MUC 階段、改動討論封套、原始 XML 字面值）放入新子檔均被門禁抓到。後續：`muc_presence`（1,384 行）、`muc_admin_set`（998 行）、`muc_owner_set`（645 行）、`muc_message`（614 行）是單一函式過長，屬邏輯重構，不在只移動範圍 | 見 `git log --grep '\[WP-24\]'` |
| WP-15 | 完成：架構與執行門禁對 `db/archive.rs` 改以模組讀取（`payload_value` 禁止檢查與個人 admission insert 計數讀含測試子檔的全模組）。5 個反例：測試子檔中的 `payload_value`、搬入子檔後改壞的 `impl Drop for FederatedMamRoomGuard`、搬入測試子檔的 `commit_mix_archive` 均以對應規則失敗；原樣搬入正式子檔的兩者仍通過。初版規格措辭含糊致 agy 未做修改，改為逐字原文／新文後一次完成 | 見 `git log --grep '\[WP-15\]'` |
| WP-05 | 完成：只移動檢查依實際模組深度（子目錄＋內嵌模組層數）換算開頭的 `super::`，整個內嵌模組搬成獨立檔案時不再誤判；深度 0 與 1 的結果與舊規則相同。6 個新測試；以 `--after-rev` 重驗 WP-21／22／23／24／31 結果不變；以 `db/archive.rs` 的 `history_identity_pg_tests` 試搬，新規則判為相同、舊規則判為不同 | 見 `git log --grep '\[WP-05\]'` |
| WP-25 | 完成：`db/archive.rs` 5,256 行拆為 personal_history／mix_archive／mam_query／mam_room／offline，三個內嵌測試模組改為獨立檔案（模組路徑與深度不變，依 WP-05 規則比對），父檔 306 行，最大正式子檔 `personal_history.rs` 843 行、測試檔 `history_identity_pg_tests.rs` 1,925 行。101 個項目不變；唯一的非搬移修改是自讀測試改讀 `MODULE_SOURCE`、migration 路徑多一層 `../`，另加守衛測試。35 項可見性變更全部是維持原範圍的寫法；測試名稱除新增守衛測試外不變。兩輪回饋修正 agy 在 SQL 字串內多加的空白；`MODULE_SOURCE` 依字母排列使順序相依的契約取錯片段，改為原檔順序。5 個反例（測試檔中的 `payload_value`、改壞房間鎖的釋放、改壞 MIX 封存提交、改壞精確重播比對、自清單移除子檔）均被抓到 | 見 `git log --grep '\[WP-25\]'` |
| WP-16 | 完成：架構門禁、執行門禁與 `test-mix-outbox-boundaries.mjs` 對 `xmpp/protocol/mix.rs` 改以模組讀取；執行門禁原本在第一個測試模組處截斷原始碼，模組讀取後子檔接在父檔之後會被一併截掉，改為逐一移除 `#[cfg(test)]` 模組。盤點時發現架構門禁對協議層 `state.pool`／`sqlx::`／`PgPool`／db 依賴的計數只讀 `src/xmpp/protocol/` 頂層檔案，`mix/`、`federated_muc/` 等子目錄的正式程式碼不在內（`muc/` 另有 WP-14 的模組檢查）；改為逐一讀取各頂層模組。門禁輸出與測試數不變。反例：`mix/forms.rs`、`federated_muc/owner.rs` 加入 `sqlx::` 修改前通過、修改後失敗；三個受檢函式搬入新子檔後通過，在子檔中改壞則失敗；宣告為 `#[cfg(test)]` 的子檔不算正式程式碼；子檔內的測試模組被移除 | 見 `git log --grep '\[WP-16\]'` |
| WP-26 | 完成：`xmpp/protocol/mix.rs` 7,647 行拆為 session／message／presence／channel_iq／channel_pubsub／channel_mam／iq_parse／payloads／federation／relay／local_delivery／channel_delivery／claimed，內嵌測試模組 `shared_claimed_delivery_policy_tests` 改為獨立檔案；父檔 296 行，保留命名空間常數、共用的網域輔助函式與兩個工作者註冊（`catalog/runtime-experiments.json` 的 `owner` 不變），最大子檔 `federation.rs` 997 行。361 個項目不變，118 項可見性變更全部是私有改為 `pub(super)`；2,187 個測試名稱不變。一輪回饋撤回 agy 把 `stanza.clone()` 改成 `&stanza` 的「改善」；`cargo fmt` 對搬出的測試檔重排 match 分支，以 rustfmt 格式化原模組本體逐位元組相同證明。執行門禁兩處逐字期望與兩個自測依 R3 可見性更新。6 個反例（`channel_delivery.rs` 的認領路由形狀、`message.rs` 的前景槽與 `sqlx::`、`presence.rs` 的路由 fence、`claimed.rs` 的認領 admission、`federation.rs` 的原始 XML）均被抓到。後續：只移動檢查正規化 rustfmt 的 match 分支寫法；`session.rs` 中 `push_mix_roster_update` 上方的文件註解描述的是投遞工作者（原檔即如此，屬內容修正） | 見 `git log --grep '\[WP-26\]'` |
| WP-17 | 完成：遷移、資料庫角色、架構與執行門禁對 `db/mix.rs` 改以模組讀取（遷移檢查對已在 WP-26 拆分的 `xmpp/protocol/mix.rs` 也改讀正式模組）。遷移檢查的四段 `sed` 相鄰範圍（ACK、admission fence 的四個函式、重試及其服務端）改為依宣告讀取項目，`migration-upgrade-wsl.sh` 因此要求 node。門禁輸出與自測數不變。盤點找到四個靜默缺口，修改前通過、修改後失敗：搬出的 ACK 函式中的禁止片段、搬出的 fence 函式中的 `pg_try_advisory_xact_lock`、測試子檔中的 `mix-pam-operation-capacity-v1`、子檔中未列入清單的 fenced producer。檢查要求的函式原樣搬入子檔後由失敗改為通過，在子檔中改壞或搬入測試子檔則失敗；子檔中的 repository 呼叫者與父檔同樣豁免，`mix/forms.rs` 中的仍會失敗 | 見 `git log --grep '\[WP-17\]'` |
| WP-18 | 完成：架構、執行、OMEMO、session 生命週期、子伺服器、遷移與資料庫角色門禁對 `state.rs` 改以模組讀取；`state.rs` 已有約九十個子檔，門禁原本只讀父檔。架構門禁的 14 處取第一次出現的擷取改為要求宣告唯一（擷取結果逐字元相同）；AppState 服務存取器若從全模組收集，會把子檔中 context 型別的同名存取器也算進來，改為只從 `impl AppState` 區塊收集。執行門禁的憑證轉發檢查改為逐一移除測試模組，不再在第一個測試模組處截斷。門禁輸出與自測數不變。盤點找到四個靜默缺口，修改前通過、修改後失敗：子檔中的 AppState 服務存取器、子檔中被禁止的 runtime control refresh 工作者、子檔中 OMEMO 輪詢視窗重複計數、子檔中第二個 MUC outbox 啟動。檢查要求的函式（含 `AppState::new`）原樣搬入子檔後由失敗改為通過，在子檔中改壞或搬入測試子檔則失敗；工作者註冊搬入子檔前後都失敗 | 見 `git log --grep '\[WP-18\]'` |
| WP-27 | 完成：`db/mix.rs` 8,619 行拆為 delivery_capacity／delivery_queue／delivery_transfer／delivery_settlement／intent／channel／membership／participant／publish／mam／projection／admin／nick_preference／jid_map_retract／pam_join／pam_completion，父檔 281 行，最大子檔 `admin.rs` 781 行。226 個項目不變；71 項可見性變更全部是維持原範圍的寫法（70 項私有改為 `pub(super)`，1 項 `pub(super)` 改為 `pub(in crate::db)`）；2,191 個測試名稱不變。兩輪回饋：agy 在 `delivery_queue.rs` 的 SQL 字串內多加的空白由驅動程式的自動回饋修正；`projection.rs` 沒有 `pub` 項目，其 glob 轉出依編譯器要求改為私有 `use`。途中 agy 用量額度耗盡，中斷的一步以只移動檢查確認已完成後才續接，驅動程式此後在 agy 回報錯誤時直接停止。8 個反例（`delivery_queue.rs` ACK 中的禁止片段、`delivery_capacity.rs` 的 fail-fast 鎖與 SKIP LOCKED 不變式、`delivery_settlement.rs` 的終端重試上限、`membership.rs` 直接寫 users、`publish.rs` 中未列入清單的 fenced producer、`delivery_queue.rs` 的認領 read-empty 區分、`channel.rs` 的原始 XML）均被抓到 | 見 `git log --grep '\[WP-27\]'` |
| WP-19 | 完成：架構與遷移門禁對 `cluster.rs` 改以模組讀取（含既有子檔 `listener.rs`、`pool.rs`）。架構門禁的 13 處取第一次出現的擷取改為要求宣告唯一（擷取結果逐字元相同），遷移檢查的 MIX 叢集所有權片段改讀正式模組。門禁輸出與自測數不變。盤點找到兩個靜默缺口，修改前通過、修改後失敗：`listener.rs` 中的 `state.pool`、子檔中第二個 `maintenance_once`。檢查要求的函式（叢集維護、Redis 維護權限、MUC outbox、失敗監督、帳號撤銷、pubsub listener、訊息契約解析）原樣搬入子檔後由失敗改為通過，在子檔中改壞或搬入測試子檔則失敗；遷移檢查要求的 `NodeDeliveryContract::DurableMix` 只出現在子檔時由失敗改為通過，只出現在測試子檔時仍失敗 | 見 `git log --grep '\[WP-19\]'` |
| WP-20 | 完成：架構門禁與 `check-abuse.mjs` 對 `config.rs` 改以模組讀取（含既有子檔 `environment.rs`）；架構門禁的 3 處取第一次出現的擷取改為要求宣告唯一（擷取結果逐字元相同）。門禁輸出與自測數不變。盤點找到兩個靜默缺口，修改前通過、修改後失敗：搬入子檔並加上 `Clone` 的 `Config`、`environment.rs` 中加上 `Clone` 的 `RawConfig`。檢查要求的項目（命令池模式、執行期連線預算、預設訊息突發量）原樣搬入子檔後由失敗改為通過，在子檔中改壞或搬入測試子檔則失敗。必要片段只出現在內嵌測試模組時修改前後都通過，留待 WP-30 把測試模組移為獨立檔案 | 見 `git log --grep '\[WP-20\]'` |
| WP-28 | 完成：`state.rs` 7,744 行拆出 runtime_control／omemo_poll_admission／upload_runtime／suspended_muc／muc_resume／local_muc／federation_policy／local_session／runtime_config／telemetry_accessors／runtime_contexts／service_accessors／construction／admission_guards／jid_text 十五個子模組，兩個內嵌測試模組 muc_membership_snapshot_tests、route_helper_tests 移為獨立測試檔；父檔 656 行（保留 `AppState` 結構與兩個 `.supervise(` 註冊），最大正式子檔 `construction.rs` 1,363 行。1,262 個項目不變；106 處可見性變更全部維持原範圍（1 項 `pub(super)` 改為 `pub(crate)`，其餘是私有項目、欄位或方法改為 `pub(super)`）；2,191 個測試名稱不變。session-cleanup observer 的註冊隨 `AppState::new` 搬入 `construction.rs`，`catalog/runtime-experiments.json` 的 `owner` 同步修改，門禁與自測不需修改。拆分後一輪回饋：`jid_text.rs` 未用到的 `use super::*;` 刪除，`construction` 的 glob 只有測試使用而改加 `#[cfg(test)]`。途中兩次中斷：agy 用量額度耗盡使 `local_muc` 一步只複製未移除，還原後重跑；驅動程式的旁寫檢查在 worktree 目錄為空時誤報，改用 `nullglob` 並以只移動檢查確認該步後續接。13 個反例均被抓到：`runtime_control.rs` 的控制健康錯誤保留與新增的 runtime control refresh 工作者、`local_session.rs` 的 SM resume Pending 路由精確擁有權與憑證轉發、`construction.rs` 的 XEP-0133 命令池角色驗證、OMEMO 恢復輪詢專用池與未登記的工作者、`omemo_poll_admission.rs` 的准入上限與輪詢視窗重複計數、`suspended_muc.rs` 的 MUC SM 關聯快照、`service_accessors.rs` 新增的 AppState 服務存取器、`local_muc.rs` 的第二個 MUC outbox 啟動、目錄中過期的 observer `owner` | 見 `git log --grep '\[WP-28\]'` |
| WP-29 | 完成：`cluster.rs` 8,553 行拆出 delivery_contract／node_delivery／health／publisher／authority／worker_capabilities／teardown／maintenance_redis／recovery_replay／routing／muc_occupancy／muc_fanout／workers／muc_outbox 十四個子模組，既有子檔 listener、pool 與四個測試檔不動；父檔 571 行（保留常數含 `NODE_PROTOCOL_VERSION`、`ClusterManager` 結構、建構與能力存取器、`start_muc_outbox_delivery`），最大新子檔 `muc_outbox.rs` 787 行。431 個項目不變；219 處可見性變更全部是私有項目、欄位或方法改為 `pub(super)`；2,191 個測試名稱不變。routing、muc_fanout 只含 `impl ClusterManager` 區塊，不設 glob。拆分後 clippy 一次通過，門禁、自測與 `catalog/runtime-experiments.json` 都不需修改。authority 一步的方法範圍在 `ClusterMaintenanceRedis` 也有同名方法，提示產生器改以所屬 impl 區塊篩選，事後確認只搬走 `ClusterManager` 的方法。途中兩次中斷：以 SIGSTOP 暫停驅動程式使背景包裝視為結束而終止進行中的 agy，以只移動檢查確認 node_delivery 一步未留下改動；重開機清掉暫存區與第一個 worktree，工具由對話記錄重建，worktree 改放 `/home/liu/XMPP-worktrees/` 後自 dev 重跑全部 14 步。13 個反例均被抓到：`delivery_contract.rs` 的入站訊息契約驗證埠、`muc_outbox.rs` 的 outbox 窄清理介面、MUC 事件與受眾的獨立讀取、收件人快照邊界與離線從屬投影、`workers.rs` 的 Redis 租約維護權限、MUC 佔用協調窄埠與未登記的工作者、`maintenance_redis.rs` 的 Redis 維護配接器與釋放權杖、`worker_capabilities.rs` 的 pubsub listener 傳輸能力新增簽章者、`delivery_contract.rs` 與 `node_delivery.rs` 中改名的 `NodeDeliveryContract::DurableMix`、`routing.rs` 新增的原始對外 XML | 見 `git log --grep '\[WP-29\]'` |
| WP-30 | 完成：`config.rs` 4,279 行拆出 raw／defaults／runtime_validation／domain_policy／components／web_origin／listeners／loading／parsing／secret_files 十個子模組，內嵌測試模組移為 `config/tests.rs`，既有子檔 environment 不動；父檔 292 行（保留連線預算常數與清單、命令池與儲存池模式解析、`Config` 結構、註冊／聯邦／外部路由／元件存取器與 `Deref`），最大正式子檔 `loading.rs`（`Config::from_env`）1,151 行。257 個項目不變；166 處可見性變更全部是私有項目、欄位或方法改為 `pub(super)`；2,191 個測試名稱不變。loading 只含 `impl Config` 區塊，不設 glob；`RawConfig` 的 serde `default = "…"` 經 `raw.rs` 的 `use super::*;` 與父檔私有的 defaults glob 解析。拆分後 clippy 一次通過，門禁與自測都不需修改。一輪回饋：搬移測試模組時 agy 漏掉 `host_meta_v2_advertises_only_bounded_public_literal_addresses` 一行斷言中的 `.is_err()`，由只移動檢查抓到，修正後測試主體與原檔逐位元組相同。7 個反例均被抓到：`raw.rs` 的 `RawConfig` 加上 `Clone`、`loading.rs` 刪去執行期連線預算檢查（含只在測試檔留下該呼叫）、`runtime_validation.rs` 放寬主連線池下限、`defaults.rs` 改動預設訊息突發量（含只在測試檔留下原值）、`loading.rs` 放寬訊息突發量的驗證範圍；兩個「只在測試檔」反例在 WP-20 時不會失敗，本 WP 補上。S2 的拆檔順序至此完成 | 見 `git log --grep '\[WP-30\]'` |
| WP-32 | 完成：`cluster_listener_continuation_tests.rs`、`cluster_muc_routing_tests.rs`、`cluster_tests.rs`、`cluster_direct_admission_tests.rs` 移入 `src/cluster/`（去掉 `cluster_` 前綴，與 `mod` 名稱一致），`abuse_tests.rs` 移為 `src/abuse/tests.rs`；架構負責人以 `git mv` 搬檔，agy 刪去五行 `#[path]`，並把 `abuse/tests.rs` 中離線去重 migration 的 `include_str!` 路徑多加一層 `../`。cluster 四檔為純改名，模組路徑不變，2,191 個測試名稱不變。門禁以正式模組讀取 `cluster.rs`，依 `#[cfg(test)] mod` 排除這些子檔，門禁與自測都不需修改；基線移除五個根目錄測試檔。4 個反例均被抓到：必要片段只留在 `cluster/tests.rs`（入站訊息契約驗證埠，架構門禁）、`cluster/direct_admission_tests.rs`（`NodeDeliveryContract::DurableMix`，遷移檢查）、`cluster/muc_routing_tests.rs`（離線從屬投影，MUC 叢集靜態契約），以及在 `src/` 重新放入測試檔（結構門禁） | 見 `git log --grep '\[WP-32\]'` |
| WP-41 | 完成：S4 第一包。`pie.rs`、`identity_audit.rs` 以 `git mv` 移入新的 `src/tools/`（純改名），`tools/mod.rs` 以 `pub(crate) mod` 宣告；`main.rs` 改為 `mod tools;`，以私有的 `use tools::{identity_audit, pie};` 保留舊路徑，呼叫端不變。agy 改寫資料庫角色門禁的 `pie_source`、`db/upload_tests.rs` 的 `include_str!`、基線的兩個超標條目（行數不變）與根目錄清單。2,191 個測試名稱只有 18 個 PIE／身分稽核測試多了 `tools::` 前綴。完整 CI 抓到盤點遺漏的文件連結（`TRACEABILITY.md` 指向舊的 `identity_audit.rs`），一輪回饋修正後，5.2 改以掃描全部連結補盤點其餘 S4 WP。4 個反例均被抓到：`tools/pie.rs` 改掉 migrator 連線字串的防護訊息、移除 PIE 連線池的 schema 固定（資料庫角色門禁）、在 `tools/pie.rs` 加一行（改名後的超標條目照常限制）、在 `src/` 放回 `pie.rs`（結構門禁） | 見 `git log --grep '\[WP-41\]'` |
| WP-42 | 完成：`abuse.rs` 連同 `abuse/`、`account_recovery.rs`、`crl.rs`、`ocsp.rs`、`password_work.rs`、`tls.rs` 以 `git mv` 移入新的 `src/security/`，`security/mod.rs` 以 `pub(crate) mod` 宣告，`main.rs` 的暫時轉出加上 `use security::{…};`。七個檔案中只有 `abuse/tests.rs` 有改動：migration 的 `include_str!` 多加一層 `../`，其餘都是純改名。agy 改寫 `check-abuse.mjs` 的兩處讀取、架構門禁的三處讀取、基線的兩個超標條目（行數不變）與六個根目錄條目，以及 `TRACEABILITY.md` 的 6 個連結。2,191 個測試名稱只有 55 個多了 `security::` 前綴。8 個反例都在新路徑被抓到：`abuse.rs` 接受資料庫交易、帳號刪除回復改名租約釋放（`check-abuse.mjs`）；`abuse.rs` 公開訊息准入、帳號刪除回復讀取 metrics、`tls.rs` 取得 `AppState`（架構門禁）；`tls.rs` 加一行、放回 `src/crl.rs`（結構門禁）；`TRACEABILITY.md` 的 TLS 連結改回舊路徑（文件一致性門禁） | 見 `git log --grep '\[WP-42\]'` |
| WP-43 | 完成：`config.rs` 連同 `config/`、`error.rs`、`logging.rs`、`metrics.rs` 以 `git mv` 移入新的 `src/platform/`，`platform/mod.rs` 以 `pub(crate) mod` 宣告，`main.rs` 的暫時轉出加上 `use platform::{…};`，`use config::Config;` 等呼叫端不變。agy 改寫 `check-abuse.mjs`（config、error）、架構門禁（config 以模組讀取）、`check-omemo.mjs`（metrics）與 `listener-readiness-stress-wsl.sh` 註解中的路徑、`config/environment.rs` 的 `.env.development.example` `include_str!`（多一層 `../`）、基線的四個根目錄條目，以及 7 個文件連結。2,191 個測試名稱只有 72 個多了 `platform::` 前綴。兩輪回饋：platform 單元測試失敗，查出 `config/environment.rs` 與 `logging.rs` 以 `--exact` 重新執行自身測試，路徑字串仍是舊模組，改為 `platform::…` 後 72 個測試全部通過；據此盤點出 WSL 腳本的 `--exact` 選取（見 5.2，WP-41c 修正）。第一次 agy 呼叫因 OAuth 網路錯誤沒有執行，重試後完成。8 個反例都在新路徑被抓到：`RawConfig`、`Config` 加上 `Clone`（架構門禁）；預設訊息突發量改為 61、`IdempotencyBusy` 改名（`check-abuse.mjs`）；OMEMO 輪詢指標改名（`check-omemo.mjs`）；放回 `src/error.rs`（結構門禁）；`TRACEABILITY.md` 與 `resource-bounds` 的 config 連結改回舊路徑（文件一致性門禁） | 見 `git log --grep '\[WP-43\]'` |
| WP-41c | 完成：修正 WP-41、WP-42 遺漏的 `--exact` 測試選取（盤點見 5.2）。`pie-db-wsl.sh`、`identity-audit-db-wsl.sh` 改選 `tools::…`；`runtime-tls-test-wsl.sh` 的 CRL 案例改選 `security::crl::tests::…`，並與前兩者一樣要求輸出「1 passed」。修正前 CRL 的 8 個案例在 CI 中都選不到測試卻通過，修正後 8 個案例都實際執行並通過。以 `cargo test <路徑> -- --ignored --exact --list` 確認三個選取各選到一個測試、舊路徑選到 0 個；把 CRL 選取改回舊路徑時腳本以「expected exactly one CRL fixture test」失敗。以變數組出模組路徑的選取經搜尋為 0 | 見 `git log --grep '\[WP-41c\]'` |
| WP-44 | 完成：`capacity_maintenance.rs`、`connection_actors.rs`、`operation_runtime.rs` 連同目錄、`retention.rs`、`subscription_cleanup.rs`、`subservers.rs` 連同目錄、`test_activation.rs`、`upload_worker.rs`、`workers.rs` 以 `git mv` 移入新的 `src/runtime/`，`runtime/mod.rs` 以 `pub(crate) mod` 宣告，`main.rs` 的暫時轉出加上 `use runtime::{…};`。agy 改寫架構門禁的 9 處路徑（含 `roleIdentity` 對 `subservers.rs` 的比對，它決定維護工作者的身分前綴）、`check-subserver-boundaries.mjs` 的 3 個檔案、`test-source-module.mjs` 的夾具路徑 3 處、`runtime-experiments.json` 的 path／owner 9 處、`db/upload_tests.rs` 的 `include_str!`、基線（兩個超標條目改名、行數不變，刪除 9 個根目錄條目）、6 個文件連結與 `retention-db-wsl.sh` 的 `--exact` 選取，一輪完成。2,191 個測試名稱只有 79 個多了 `runtime::` 前綴；新選取以 `--list` 確認選到 1 個測試。`test_activation.rs` 不再是根目錄檔，檔名造成的測試分類只影響行數上限。12 個反例都在新路徑被抓到：retention、upload_worker、capacity_maintenance 取得 `AppState`，operation_runtime 把 `execute_after_commit` 改為 `execute_before_commit`（架構門禁）；`roleIdentity` 改回舊路徑（工作者清單不符）；subservers 匯入 `AppState`、`RetentionContext` 多一個欄位（子伺服器門禁）；`WorkerRegistry` 改名（執行實驗目錄）；`run_one` 改名（source-module 自測）；`workers.rs` 加一行、放回 `src/retention.rs`（結構門禁）；retention 連結改回舊路徑（文件一致性門禁） | 見 `git log --grep '\[WP-44\]'` |
| WP-45 | 完成：`main.rs` 的服務任務監督移到新的 `src/runtime/service_tasks.rs`：`ServiceTaskExit`、`ServiceTaskDrainReport`、`spawn_service_task`、`unexpected_service_task_exit`、`await_shutdown_notifications`、`drain_service_tasks`、`panic_payload` 與兩個收束逾時常數，改為 `pub(crate)`（`panic_payload` 維持私有），常數改用匯入的 `Duration`；`run()` 中的 `spawn_service_task(` 呼叫點留在 `main.rs`，架構門禁的服務任務清單照舊讀取。`shutdown_notification_tests.rs` 以 `git mv` 移到 `runtime/service_tasks/`（純改名），原本的 `#[path]` 宣告改為一般子模組；`main.rs` 測試模組中測監督程式的 5 個測試與只供測試的 `unexpected_task_exit` 移到 `service_tasks.rs` 的 `tests` 模組。`main.rs` 由 1,413 行減為 1,175 行。架構師先以腳本從 `main.rs` 產生預期的 `service_tasks.rs` 與 `main.rs` 並以 rustfmt 確認，agy 一輪完成且兩檔與預期逐字相同。綁定只有 `runtime-experiments.json` 啟動族的預算來源（路徑與 anchor）與基線的一個根目錄條目。2,191 個測試名稱中 15 個換了路徑（10 個 `runtime::service_tasks::shutdown_notification_tests::…`、5 個 `runtime::service_tasks::tests::…`），全部通過。3 個反例都被抓到：收束逾時改為 16 秒（執行實驗目錄的 anchor）；放回根目錄測試檔（結構門禁）；`run()` 中一個服務任務改名（架構門禁的服務任務清單） | 見 `git log --grep '\[WP-45\]'` |
| WP-46 | 完成：`cluster_security.rs` 以 `git mv` 移為 `src/cluster/security.rs`（純改名，1,259 行），`cluster.rs` 以 `pub(crate) mod security;` 宣告；其餘子模組維持私有，這個模組另有 `platform/config` 與 `db/cluster_keys.rs` 使用，因此對 crate 可見。`main.rs` 的暫時轉出加上 `use cluster::security as cluster_security;`，呼叫端（大多在 `cluster/` 內）不變。檔案頂層沒有 `pub(super)`，`super::` 只出現在內嵌測試模組。agy 改寫 `runtime-experiments.json` cluster 族的 owner 與預算來源路徑、基線的根目錄條目與 `TRACEABILITY.md` 連結 1 處，一輪完成。2,191 個測試名稱中 5 個改為 `cluster::security::tests::…`，全部通過。4 個反例都被抓到：owner anchor 的模組說明改字、信封有效期改為 11 秒（執行實驗目錄）；放回根目錄檔（結構門禁）；連結改回舊路徑（文件一致性門禁） | 見 `git log --grep '\[WP-46\]'` |
| WP-47 | 完成：`components.rs`（2,638 行，超標）以 `git mv` 移為 `src/s2s/components.rs`，`outbound.rs`（806 行）、`transport_parsing.rs`、`mam_pubsub_parsing.rs` 移入 `src/xmpp/`，都是純改名；`s2s/mod.rs` 與 `xmpp/mod.rs` 以 `pub(crate) mod` 宣告，`main.rs` 的暫時轉出加上 `use s2s::components;` 與 `use xmpp::{mam_pubsub_parsing, outbound, transport_parsing};`。四個檔案頂層都沒有 `pub(super)`，`super::` 只出現在內嵌測試模組。agy 改寫架構門禁 2 處、對外 XML 門禁 1 處、執行門禁的 `outbound` 檔案路徑、parser fuzz 門禁與其自測各 1 處、`bosh_ws_framing.rs` 的 `#[path]`、基線（超標條目改名、行數不變，刪除 4 個根目錄條目）與 3 個文件連結；上表列的 `fuzz/Cargo.toml` 只指向 `fuzz_targets/`，不必改。三行模組宣告使超標的 `xmpp/mod.rs` 由 1,607 行增為 1,610 行，違反 R1；依 WP-30 的作法，把它的內嵌測試模組（15 個測試）移到 `xmpp/tests.rs`，`mod.rs` 減為 1,338 行、低於上限，基線刪除該條目。架構師先以腳本產生預期的兩個檔案並以 rustfmt 確認，agy 的後續修正與預期逐字相同；`xmpp::tests::…` 的測試名稱不變。2,191 個測試名稱中 33 個加上新前綴（`s2s::components::` 22、`xmpp::outbound::` 6、`xmpp::transport_parsing::` 3、`xmpp::mam_pubsub_parsing::` 2），全部通過。離線環境沒有 `libfuzzer-sys`，無法建置 fuzz 目標，`#[path]` 由 parser fuzz 門禁與其自測確認。8 個反例都被抓到：元件路由與 S2S 的託管網域判斷參數對調、元件遙測改名（架構門禁）；元件模組加入字串拼接的 XML（對外 XML 門禁）；`bosh_auth_control` 改為 `false`（執行門禁）；fuzz `#[path]` 改回舊路徑（parser fuzz 門禁）；`components.rs` 加一行、放回 `src/outbound.rs`（結構門禁）；連結改回舊路徑（文件一致性門禁） | 見 `git log --grep '\[WP-47\]'` |
| WP-48a | 第一個提交完成：WP-48 的路徑改寫會使十個超標檔變長（見 5.2），先把其中八個檔案的內嵌測試模組移為子檔，作法同 WP-30、WP-47：`bosh.rs`、`db/reports.rs`、`security/tls.rs`、`services/sm.rs`、`xmpp/protocol/messaging.rs`、`xmpp/protocol/sm.rs` 的 `tests`，`xmpp/protocol.rs` 的 `legacy_sasl_wire_tests`，`xmpp/protocol/misc.rs` 的 `legacy_tests`。父檔保留 `#[cfg(test)] mod <名稱>;`，本體少一層縮排，但 `services/sm` 測試中多行 SQL 字串的續行保留原縮排，字串內容不變；rustfmt 另把 42 個敘述合併成較少行。架構師以腳本與 rustfmt 產生預期檔，agy 產出的 16 個檔案逐位元組相同；`services/sm/tests.rs` 第一次留下 350 行未去縮排，經兩次定點修正。綁定兩處：`check-session-lifecycle-boundary.mjs` 改從 `legacy_sasl_wire_tests.rs` 讀取回歸測試 `drop_requires_local_quiesce(false, 1)`，`runtime-experiments.json` 的 session-regression 測試路徑改為 `services/sm/tests.rs`。只移動檢查把 `security/tls.rs` 的一個測試判為不同：行尾 `\` 續行的字串少一層縮排，但值不變。因此先以單獨提交讓檢查器比較前刪去續行開頭的空白（見 5.2），並補自測。2,191 個測試名稱不變。基線在本提交不調降，第二個提交改寫路徑後一次調降。途中 agy 1.3.3 不再提供原本的模型，改用 Gemini 3.8 Flash。6 個反例均被抓到：回歸測試改弱（session lifecycle 門禁）；錨點測試改名（執行實驗目錄）；以下四個由只移動檢查抓到：搬移後的斷言反轉、續行字串的內容改動、SQL 續行少一層縮排、刪掉一個搬移的測試 | 見 `git log --grep '\[WP-48a\]'` |
