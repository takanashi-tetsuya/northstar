# Northstar 工程結構藍圖

更新：2026-10-21。基線提交：`10d598234c74fefcdc7b7856026e2dd654fe1e1c`。

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

S16 起 workspace 的 crate 結構以[目標架構](target-architecture.zh-TW.md)為準：crate 依目錄分為 kernel、platform、contexts、edges 與 tools，由 R10 執行。
根 crate 內部以頂層模組分層，依賴只能由上往下，同層可互相使用。分層的權威清單是
`catalog/source-layers.json`，由 R9 執行：

```text
4 組合          main.rs、runtime（程序角色、operation runtime、維護 worker）、state（AppState 組裝）、tools
3 介面卡        持久化 db；協議／傳輸 xmpp、bosh、s2s；HTTP api；物件儲存 storage；叢集控制面 cluster
2 應用服務      services（呼叫 crates/*-application 與注入的 port）
函式庫          crates/{kernel,platform,contexts/*}/*，不得依賴根 crate
測試專用        只在 #[cfg(test)]；受控重播與 Stage 4 實驗程式只在既有 cfg(test) 模組
```

介面卡呼叫應用服務，應用服務經 port 使用持久化與傳輸，因此介面卡在應用服務之上。S10 之前本節把兩者
的順序寫反，平台層也沒有列出 worker 監督；S10 依呼叫方向修正，並量測現有的違規（5.6）。S17 把平台層與相容
facade 移出根 crate（5.13），根 crate 只剩上面三層。

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
| R1 行數預算 | 生產 `.rs` 檔 ≤ 1,500 行；測試檔 ≤ 3,000 行。既有超標檔記錄在基線，只能縮小；新檔不得超標。超標的生產檔不得保留頂層內嵌測試模組（`#[cfg(test)] mod x { … }`），測試移為子檔（S7） | `scripts/check-source-structure.mjs`＋`catalog/source-structure-baseline.json` |
| R2 根目錄收斂 | `src/` 根目錄 `.rs` 數只能減少；不得新增根目錄測試檔 | 同上 |
| R3 模組拆分方式 | 大檔拆成「`foo.rs`＋`foo/子模組.rs`」，保持原有模組路徑；拆分 WP 只移動程式碼，不改邏輯。可見性的不變式：搬移後每個名稱的可見範圍只能維持或縮小，不得擴大。維持原範圍的寫法是「私有→`pub(super)`、`pub(super)`→`pub(in <父模組的上層>)`（如 `pub(in crate::xmpp::protocol)`、`pub(in crate::db)`）、`pub(crate)`／`pub` 不動」，適用於搬入子檔的頂層項目、結構欄位與固有 impl 成員；不需跨檔使用者也可維持私有（範圍縮小）。WP-24 起一律採維持原範圍的寫法，由只移動檢查的 `VISIBILITY:` 行逐項核對，免去依編譯錯誤反覆補可見性。協議模組的父檔以明確的 `use self::子模組::{…};` 列出兄弟子檔與測試使用的名稱（只供測試者加 `#[cfg(test)]`），模組外使用者以原可見性轉出（`pub(super) use`／`pub(crate) use`）；已由 `db/mod.rs` 以 `pub use x::*` 整體轉出的 db 模組，父檔改以 `pub use self::子模組::*;` 轉出（bin crate 中未被使用的明確轉出是 unused import，`-D warnings` 下失敗） | 「只移動」差異檢查（第 6 節，`scripts/check-move-only.mjs`） |
| R4 門禁定位 | 門禁以模組讀原始碼（`foo.rs` 與 `foo/**.rs` 視為同一模組），以括號配對擷取指定項目；禁止新增依函式相鄰順序的擷取。Rust 單元測試以 `include_str!` 讀自身模組原始碼者，拆分時改讀父檔的 `#[cfg(test)] const MODULE_SOURCE`（父檔＋各正式子檔），並以守衛測試確認清單與非測試的 `mod` 宣告一致。子檔依拆分前在單檔中的先後順序列出：有些契約以出現不只一次的標記切割原始碼，依字母排列會取錯片段（WP-25 的 `let exact_replay =`）。模組目錄另有獨立擁有模組的 `xmpp/protocol.rs`、`api/mod.rs`、`bosh.rs` 不以模組讀取（會納入無關模組），門禁改讀「父檔＋`catalog/source-role-splits.json` 所列角色子檔」（`roleSplitFiles`／`readRoleSplitFile`，CLI `--role-split`）；結構門禁驗證該清單（鍵依序排列、子檔為葉檔、父檔有非測試的 `mod` 宣告且清單依宣告順序），這些檔案的守衛測試改比對該清單（WP-82g） | `scripts/lib/source-module.mjs`、`catalog/source-role-splits.json`；Rust 測試見 `src/db/cluster_muc.rs`、`src/db/archive.rs` |
| R5 證據不可改寫 | `scripts/fixtures/**/historical*`、`docs/evidence/**` 與已記錄的 Stage 證據不得因結構工作修改；Stage 4 純測試 lane 以 SHA-256 綁定的腳本逐位元組不變，搬移與路徑改寫都略過它們（讀現行樹的 `test-experiment-contract.py` 隨路徑改寫並重新綁定，見 5.12）。S16（WP-164）起 `src/` 不再被釘住：已保存的 Stage 4 證據綁定其原提交，historical75 lane 改用 `scripts/fixtures/stage4-profile-binding-v1/historical` 中 `bosh/response_owner.rs` 的凍結副本 | 審閱；各 lane 自行比對綁定的大小與雜湊。`catalog/source-structure-baseline.json` 若再出現 `pinned` 即視為無效 |
| R6 測試專用碼 | 受控重播與實驗程式只能存在於 `#[cfg(test)]` 模組 | 既有門禁＋審閱 |
| R7 提交 | 一個 WP 一至數個提交，訊息首行以 `[WP-xx]` 開頭；不推 WIP | 審閱 |
| R8 文件不留舊路徑 | 現行文件與 `crates/*/MIGRATION.md` 不得寫 S4 已移走的根目錄模組路徑（含 `../src/` 與目錄形式）；有日期的紀錄（`docs/` 下的 `evidence`、`archive`、`handoff`、`changelog`、`releases` 與 `CHANGELOG.md`）、本文與固定提交的連結保留當時的路徑 | `scripts/check-documentation-consistency.mjs` |
| R10 crate 層級 | workspace crate 依所在目錄屬於 kernel、platform、context（core／application／adapter）、edge、composition 或 tooling 層（[目標架構](target-architecture.zh-TW.md) 4.1）；只能依 [crate 政策](crate-policy.md) 的規則依賴其他 workspace crate 與外部 crate，dev-dependency 不檢查 | `tools/architecture-validator`＋`catalog/crates.yaml`（由 `scripts/generate-crate-catalog.mjs` 產生） |
| R9 層級方向 | 根 crate 的每個頂層模組屬於 `catalog/source-layers.json` 的一層（第 3 節）；一層只能使用同層與 `may_use` 所列的層，`may_use` 不得列出 rank 較高的層。檢查範圍是從 `src/main.rs` 沿 `mod` 宣告走到的生產碼：測試專用 cfg 下宣告的模組連同整個子樹不算，檔內測試專用的項目、欄位、分支與陳述式也不算。既有違規以「檔案→目標頂層模組」記錄在同一檔案的 `baseline`，只能減少：新的違規、不再需要的基線項目與不屬任何層的目標都失敗。搬移 WP 以 `--write` 重寫基線，審閱時確認只刪不增 | `scripts/check-layer-dependencies.mjs`＋`catalog/source-layers.json` |

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
| S6 文件收斂 | WP-61–63 | 修正 KNOWN_ISSUES 的遷移鏈敘述與 README 的發佈敘述（WP-61）；HANDOFF 改為只記錄其他文件沒有的現況，`docs/README.md` 建立狀態地圖（WP-62）；現行文件與 `crates/*/MIGRATION.md` 改用分層路徑，`resource-bounds` 的原始碼連結固定到審閱提交（WP-63） | 文件一致性門禁通過，並檢查遷移鏈敘述、狀態地圖與舊路徑（R8）。已完成 |
| S7 R1 收斂 | WP-71a–c | 超標生產檔的頂層內嵌測試模組移為子檔，只移動、不改測試；最後由結構門禁拒絕超標生產檔保留內嵌測試模組（R1）。盤點見 5.3 | 測試名稱集合不變；全部門禁與完整 CI 通過；基線刪除降到上限內的條目並下修其餘條目。已完成 |
| S8 角色拆分 | WP-81a–f、WP-82a–i、WP-83a–z、WP-84a–c | 其餘 35 個超標生產檔依角色拆為「`foo.rs`＋`foo/子模組.rs`」（R3）；以單檔讀取原始碼的門禁先改讀正式模組（R4），模組目錄另有獨立模組的三檔改讀角色拆分清單（WP-82g）。盤點見 5.4 | 只移動檢查通過；全部門禁與完整 CI 通過；基線刪除降到上限內的條目。已完成：基線只剩被釘住的 3 個生產檔（R5）與 2 個超過測試上限的測試檔（`db/pubsub_integration_tests.rs` 6,108 行、`db/upload_tests.rs` 3,429 行），由 S9 拆分 |
| S9 測試檔拆分 | WP-91、WP-92a–b、WP-93 | 超過測試上限的兩個測試檔拆為「`x_tests.rs`＋`x_tests/角色_tests.rs`」，子檔是原測試模組的子模組；只移動檢查先改為依所在檔案解析 `include_str!`／`include_bytes!` 的路徑（WP-91）。盤點見 5.5 | 只移動檢查通過；去掉子模組一段後測試名稱與 ignored 測試集合不變；WSL 腳本的每個選擇器恰好對應一個測試；全部門禁與完整 CI 通過。已完成：基線只剩被釘住的 3 個生產檔（R5） |
| S10 層級方向 | WP-101–104 | 依頂層模組定義五層並以門禁執行（R9，WP-101）；被下層使用、本身不依賴上層的程式往下搬：worker 與連線 actor 監督（WP-102）、JID 文字工具（WP-103）移到 `platform`，MUC 占用者紀錄移到 `services::muc`（WP-104）。盤點見 5.6 | 搬移只改路徑；測試名稱依路徑對應後不變；基線只刪不增；全部門禁與完整 CI 通過。已完成：基線由 139 條降到 104 條，其餘見 5.6、5.7 |
| S11 層級搬移第二批 | WP-110–118 | 逐條核對 5.6 剩下的 104 條，不需新 port 的 33 條以搬移定義或改寫路徑處理：`services` 經轉出引用的 crate 型別改為直接引用 crate（WP-111）；retention repository port 移到 `services`、PIE 匯入紀錄移到 `db`（WP-112、113）；DANE 與 lab DNSSEC、XEP 擴充註冊表、`SmIpPolicy` 與遞送佇列計數器、叢集匯流排簽章與金鑰紀錄移到平台層（WP-114–117）；被下層使用的純資料紀錄移到使用它的那一層（WP-118）。盤點見 5.7 | 搬移只改路徑；測試名稱依路徑對應後不變；基線只刪不增；全部門禁與完整 CI 通過。已完成：基線由 104 條降到 71 條（68 檔），其中 20 條由 S12 處理（見 5.8） |
| S12 層級搬移第三批 | WP-120–128 | 核對 5.7 剩下的 71 條，20 條只需搬到使用者所在的層，或加一個只委派既有方法的小 port：abuse guard、帳號刪除復原與 standalone MUC 維護 worker 移到使用它們的層（WP-121、122、126）；XML 工具與 stanza 驗證移到 `services`（WP-123）；`services` 對 `cluster`、`s2s` 各一處的呼叫改經自己擁有的 port（WP-124、125）；REST 處理器的 context 與服務綁定移到 `api::contexts`，即時 session 與 MUC 占用者經 port 讀取（WP-127）；叢集監聽器的訊息政策移到 `cluster`（WP-128）。盤點見 5.8 | 搬移只改路徑，新 port 只委派原有方法；測試名稱依路徑對應後不變；基線只刪不增；全部門禁與完整 CI 通過。已完成：基線由 71 條降到 51 條（50 檔），平台層不再向上引用，其中 20 條由 S13 處理（見 5.9） |
| S13 層級搬移第四批 | WP-130–136 | 核對 5.8 剩下的 51 條，20 條只需把 context 的定義與組合層的建構分開，或加一個只委派既有方法的小 port：REST 端點與上傳 context 移到 `api::contexts`，建構子留在 `state`（WP-131）；帳號拆除、MUC 占用計數、SM 指標與帳號管理快取改經 port 讀取（WP-132–134）；本節點的 session 與 MUC 占用者紀錄移到 `xmpp::local_routes`，即時路由表與其操作留在 `state`（WP-135）；session 清理流程移到它依賴的 `state`（WP-136）。盤點見 5.9 | 搬移只改路徑，新 port 只委派原有方法；測試名稱依路徑對應後不變；基線只刪不增；全部門禁與完整 CI 通過。已完成：基線由 51 條降到 31 條（31 檔），`services` 只剩對 `xmpp` 對外佇列的 2 條，其餘依 5.9 交給模組化執行計劃 |
| S14 叢集介面卡解耦 | WP-140–144 | 核對 5.9 中 `cluster` 的 4 條：它們不持有組合根做事，只是 worker 與監聽器的 context 定義在 `state`，或 worker 啟動時以 `AppState` 建構 context。先把 S13 留在 `state`、不碰 `AppState` 的即時路由表操作移到 `xmpp::local_routes`（WP-141），再依 S13 的做法把 context 的定義移到 `cluster`／`xmpp`、建構子留在 `state`：MUC 遞送與 outbox worker（WP-142）、叢集維護（WP-143）、監聽器與故障監督（WP-144）；`cluster` 的 worker 改收組合根建好的 context。盤點見 5.10 | 搬移只改路徑；測試名稱依路徑對應後不變；基線只刪不增；全部門禁與完整 CI 通過。已完成：基線由 31 條降到 27 條，`cluster` 不再引用組合層 |
| S15 介面卡參數收窄 | WP-150–154 | 核對 5.10 剩下的 27 條中只讀少數設定或句柄的介面卡函式：不再收整個組合根，改收實際用到的值，或收介面卡定義、`state` 建構的小 context。S2S 的 TLS 函式改收 `&TlsContext`，DNS 函式改收 `FederationDnsContext`（WP-151）；dialback 的 stream features 改收 `S2sFeaturePolicy`，向權威伺服器驗證金鑰的 `verify_remote` 移到 `s2s::outbound`（WP-152）；S2S 直送路由的 port 介面卡移到 `state`（WP-153）；MIX／MUC 鏡像連結改收 MIX 服務（WP-154）。盤點見 5.11 | 函式行為不變，複製的只有固定設定，共享狀態仍以借用在原處讀取；測試名稱不變；基線只刪不增；全部門禁與完整 CI 通過。已完成：基線由 27 條降到 22 條，`s2s` 只剩持有組合根的 4 個檔案 |
| S16 地基 | WP-160–165 | 依[目標架構](target-architecture.zh-TW.md)開始整體重構（WP-160）。刪除未整合的 `services/*` 微服務原型與只為它存在的 crate、工具、契約、目錄、部署檔與 CI 步驟，ADR 0002–0007 標為 superseded（WP-161）；56 個 crate 以 `git mv` 移入 `crates/{kernel,platform,contexts/<context>}` 與 `tools/`，套件名稱不變（WP-162）；crate 依賴圖依層級檢查（R10，WP-163）；解除 Stage 4 對 `src/` 的釘選與 S4 的 `crate::outbound` shim（WP-164）；記錄建置時間基準（WP-165）。盤點見 5.12 | 測試名稱不變；根 crate 行數不變；全部門禁與完整 CI 通過。已完成 |
| S17 平台 | WP-171–178 | 根 crate 的平台橫切移為 crate：`jid`、`auth` 相容 facade 退役，呼叫端直接引用 `northstar-xmpp-types`、`northstar-auth-core`（WP-171）；worker 監督與連線 actor 移入 `northstar-runtime`，日誌、指標登錄、遞送計數器與 PubSub 准入計量移入 `northstar-telemetry`（WP-172）；`src/security` 的安全機制與受保護的秘密檔讀取移入 `northstar-security`（WP-173）；XEP 擴充目錄成為 kernel 的 `northstar-xep-catalog`，JID 與 XML 文字工具併入 `northstar-xmpp-types`、`northstar-xml-builder`，`AppError` 移到 `api::error`（WP-174）；設定模組不再引用 auth core（WP-175），原始碼讀取器支援 crate 根 `lib.rs`（WP-176），設定移入 `northstar-config`（WP-177）；記錄階段與建置時間（WP-178）。`src/storage` 只服務上傳，改隨 S19 進 upload 上下文。盤點見 5.13 | 搬移只改路徑與可見性；測試名稱依路徑對應後不變；R9 基線不增；全部門禁與完整 CI 通過。已完成：`src/platform`、`src/security` 與兩個 facade 不再存在 |
| S18 會話核心介面 | WP-181–185 | 新的 edge crate `northstar-stream` 提供 IQ 路由表：`IqRoute`（酬載元素、命名空間、get／set）、`IqRouter`（排序後以借用的鍵二分搜尋）與 `IqHandler`（WP-181）；訊息遞送經 session 應用層的 `RemoteRoutePort` 送往遠端網域，協定處理器不再引用 `crate::s2s`（WP-182）；`ProtocolSession::iq` 的 match 改為 48 條各註冊一次的路由，路由的閘門決定請求交給處理器、回 `service-unavailable`，或與沒有路由一樣回 `feature-not-implemented`（WP-183、184）；記錄階段（WP-185）。盤點見 5.14 | 測試名稱只增加；全部門禁、模糊測試編譯與完整 CI 通過。已完成：client IQ 只經路由表分派；協定處理器的生產程式碼不再引用 `bosh`、`s2s` |

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
`resource-bounds` 連結上已過時的行號錨點，由 S6 的 WP-63 修正。tracing 事件的預設 target 是模組路徑，
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
| WP-48 | — | 改寫呼叫端（`crate::<模組>` 改為 `crate::<層>::<模組>`）並刪除 `main.rs` 的暫時轉出，可依層再分。較長的路徑使 rustfmt 折行，十個超標檔會變長（R1），因此 WP-48a 先把其中八個的內嵌測試模組移為子檔，再改寫這十個檔案並一次調降基線 | 只改路徑，不改語義；門禁比對呼叫端舊模組路徑的片段同步改寫。盤點時列出 `check-subserver-boundaries.mjs` 與其自測、`check-abuse.mjs`、架構門禁的 `logging::report_result`；各子 WP 先在暫存副本跑全部門禁，另找到執行門禁的 `crate::outbound::…` 片段與其自測、`check-federated-route-boundaries.mjs` 與其自測、架構門禁的工作者監督參數、兩條以可選前綴比對 `Metrics` 的排除規則（新路徑可以繞過，WP-48g 收緊），以及 `fuzz/fuzz_targets/rest_extractors.rs` 為 `#[path]` 引入的 `api/extract.rs` 提供的 `error` 替身（WP-48e）。`bosh/response_owner.rs` 與 `stage4_replay.rs` 的內容被 Stage 4 證據釘住，不改寫；`main.rs` 為它們保留 `outbound` 轉出，結構門禁拒絕其他檔案使用 `crate::outbound`（WP-48d、WP-48g） |

S4 後根目錄保留的檔案：`main.rs`；同名目錄的模組檔 `state.rs`、`cluster.rs`、`bosh.rs`、`storage.rs`
（`bosh/response_owner.rs` 由 CI 的 Stage 4 綁定測試與 `stage4_build_record.py` 以路徑讀取）；只在
`#[cfg(test)]` 編譯的 `stage4_replay.rs`（`controlled_admission_supervision.py` 綁定它與
`stage4_replay/compact.rs`）與 `direct_replay.rs`；相容 facade `auth.rs`、`jid.rs`（分別有 38、170 個
使用檔），在 S5 呼叫方改用 crate 後移除。

`bosh/response_owner.rs` 與 `stage4_replay.rs` 的綁定不只是路徑。`test-stage4-saved-profile-historical.py`
與 `stage4_build_record.py` 釘住 `response_owner.rs` 的大小、SHA-256 與變異位移，`controlled_admission_supervision.py`
釘住 `stage4_replay.rs`、`stage4_replay/compact.rs` 的 SHA-256，`stage4_case.py` 釘住 16 個存檔夾具。上表的盤點只找路徑綁定，
因此 WP-48b 改了 `stage4_replay.rs` 的一行匯入；這項比對只在驗證組合實驗契約時執行，離線 CI 沒有抓到。WP-48d 的完整 CI
因 `response_owner.rs` 的歷史綁定測試失敗才發現。WP-48d 先恢復 `stage4_replay.rs`，並把這 19 個檔案的 SHA-256 記錄為結構基線的
`pinned`，由結構門禁比對（R5）。這兩個檔案只用到 `crate::outbound` 一個舊路徑，WP-48 不改寫它們，`main.rs` 的
`outbound` 轉出保留給它們。

### 5.3 S7 盤點：超標生產檔的內嵌測試模組（`657a660`）

S4 完成時有 60 個超標生產檔，共 144,606 行，其中 47 個含 54 個頂層內嵌測試模組。測試留在超標檔中有兩個問題。
第一，之後依角色拆分時，正式碼和測試要一起搬。第二，以模組讀取的門禁讀正式模組時只排除測試子檔，
內嵌模組仍在讀取範圍內，必要片段只出現在測試中時門禁也會通過（見 5.1 的 `config.rs`）。

S7 依 WP-30、WP-48a 的作法處理 45 個檔案的 52 個模組：`foo.rs` 的模組移到 `foo/<模組>.rs`，
`mod.rs` 的模組移到同一目錄，原處只留 `#[cfg(test)] mod <模組>;`。`bosh/response_owner.rs` 與
`stage4_replay.rs` 的內容被 Stage 4 證據釘住（R5），保留內嵌測試。

| WP | 範圍 | 檔案／模組 | 降到上限內 |
| --- | --- | --- | --- |
| WP-71a | `src/xmpp/`：`frame_execution.rs`、`auth_publication.rs` 與 `protocol/` 下 11 個檔案 | 13／14 | 6 |
| WP-71b | `src/db/` | 14／16 | 6 |
| WP-71c | `src/api/`、`src/runtime/`、`src/s2s/`、`src/services/`、`src/storage*`、`src/tools/`、`direct_replay.rs`；結構門禁新增 R1 的內嵌測試規則 | 18／22 | 10 |

子檔多一層目錄，相對路徑的 `include_str!`／`include!` 要多一個 `../`。`api/mod.rs` 的子檔在同一目錄，
路徑不變。`catalog/runtime-experiments.json` 有兩個測試錨點：`frame_execution.rs` 的 `mod tests {`
改為 `mod tests;`；workers 測試的檔案路徑改為 `src/runtime/workers/tests.rs`。全部移完後，在暫存副本上
2,191 個測試名稱不變，全部門禁結果與 dev 相同，fmt、clippy 與單元測試都通過。

S7 結束時剩 38 個超標生產檔，共 91,605 行。除了 3 個被釘住的檔案（R5），其餘 35 個要依角色拆分
（S2 的作法），見 5.4。

### 5.4 S8 盤點：依角色拆分其餘超標檔（`bf66ccc`）

這 35 個檔案各拆為「`foo.rs`＋`foo/子模組.rs`」（R3），依門禁綁定分三組：

| 組 | WP | 檔案 | 前置條件 |
| --- | --- | --- | --- |
| 無單檔綁定 | WP-81a–f | `db/pubsub_repository.rs`、`db/api_operations.rs`、`db/upload.rs`、`tools/identity_audit.rs`、`xmpp/protocol/messaging/saved_case.rs`、`direct_replay.rs` | 無：只有結構基線與 R5 夾具提到路徑 |
| 門禁以單檔讀取 | WP-82a–e 解耦（WP-82f、82h 為拆分後的跟進），WP-83a–z 拆分 | 其餘 26 檔（如 `s2s/inbound.rs`、`services/mix.rs`、`db/users.rs`、`xmpp/protocol/sasl2.rs`） | 14 個門禁腳本改為讀正式模組（R4），以模擬拆分的反例確認仍會失敗 |
| 模組目錄另有獨立模組 | WP-82g 讀取範圍，WP-84a–c 拆分 | `xmpp/protocol.rs`（63 個正式子模組）、`api/mod.rs`（18 個）、`bosh.rs`（3 個，含被釘住的 `response_owner.rs`） | 門禁刻意以單檔讀取，改為讀整個模組會納入無關模組；WP-82g 改讀「父檔＋`catalog/source-role-splits.json` 所列角色子檔」，清單為空時門禁輸出逐字不變（R4） |

拆分沿用 S2 的規則：只移動整個項目，`use` 不移動；R3 的可見性改寫由只移動檢查的 `VISIBILITY:` 行逐項核對；
`db/mod.rs` 以 `pub use x::*` 整體轉出的模組，父檔以 `pub use self::子模組::*;` 轉出，其他模組由父檔明確匯入
並以原可見性轉出；子模組只含 trait impl 時父檔只宣告模組。

每個檔案先由唯讀提案取得設計：依角色分組的行號範圍，以及路徑與項目名稱的綁定盤點（門禁、catalog、
`include_str!`、測試選取）。第一輪提案把公開入口與整個 `impl` 留在父檔，`security/abuse.rs`、
`xmpp/protocol/messaging.rs`、`presence.rs`、`pep.rs` 因單一 `impl` 就超過 1,500 行而無解，另有九個檔案的
父檔接近上限。第二輪改用 WP-24 已採用的作法：固有 impl 的成員可分到子檔中標頭相同的 `impl` 區塊（只移動
檢查以「impl 標頭＋成員」為鍵）；公開入口不必留在父檔，函式與型別的路徑由父檔轉出保留，方法在哪個子檔
定義都可呼叫。留在父檔的是：`use`、模組文件、測試模組宣告與 `#[cfg(test)]` 輔助項目、被門禁或測試連同
可見性逐字比對的項目、工作者註冊（`.supervise(`／`.register_observer(`）與 catalog 錨點。單一函式與 trait
impl 不能以搬移分割（`cluster/listener.rs` 的 `listen_once` 1,453 行、`xmpp/protocol/messaging.rs` 的
`message` 方法 1,436 行、`db/mix_repository.rs` 的 `impl MixRepository` 1,444 行），只能整體留在父檔或移入自己的子檔。

拆分時須保留的綁定（WP-82 與提案盤點）：

- 以 `include_str!` 讀原始碼的 Rust 測試改讀 `MODULE_SOURCE`（R4）：`s2s/inbound_tests.rs`、`xmpp/protocol/pep/tests.rs`、
  `db/cluster_muc_tests.rs`（讀 `db/muc.rs`）、`db/upload_tests.rs`（讀 `db/users.rs` 與 `tools/pie.rs`）、
  `db/replay/bosh_ack_bound_schema_tests.rs`、`api/tests.rs` 與 `api/system/tests.rs`（讀 `api/mod.rs`）。
  讀者在模組外時，`MODULE_SOURCE` 與 `module_source()` 用可達的最窄可見性
  （`pub(super)`、`pub(crate)`）；`db/mod.rs` 的 glob 轉出會把它們帶進 `db`，同名不衝突，未使用時也不產生警告。
  `upload_tests.rs` 已超過測試檔上限，不得變長，守衛測試一律放在新的測試子檔 `module_source_tests.rs`（WP-81c）。
- 依相鄰順序切割的測試：`upload_tests.rs` 取 `async fn delete_user_with_roster_inner(` 到
  `pub(super) async fn delete_user_with_roster_locked_in_transaction(` 之間（含可見性，兩者留在 `db/users.rs` 父檔）；
  `pep/tests.rs` 取 `pep_subscribe`、`pep_unsubscribe`、`pep_target_owner` 之間（三者須在同一檔案且依序）。
- 逐字比對：執行門禁比對 `services/mix.rs` 三個 ACK 函式與 `db/muc.rs` 的 `admit_muc_discussion_observed` 的正規化本體；
  架構門禁的 DB MIX 生產者方法以呼叫者允許清單綁定 `db/mix_repository.rs`；`catalog/runtime-experiments.json`
  以 `pub(crate) struct PubSubService<R> {` 綁定 `services/pubsub.rs`，以 `API_BODY_LIMIT_BYTES` 綁定 `api/mod.rs`；
  `xmpp/protocol/pubsub.rs` 的兩個工作者註冊由架構門禁與 catalog 綁定該檔。

### 5.5 S9 盤點：超過上限的測試檔（`f1b63cc`）

`db/upload_tests.rs`（3,429 行，模組 `db::upload::tests`）與 `db/pubsub_integration_tests.rs`（6,108 行，模組
`db::pubsub::integration_tests`）都只以 `#[cfg(test)] #[path]` 從父檔載入，沒有門禁讀它們的原始碼，綁定在測試路徑
與檔案位置：

- 測試路徑：CI 的 PubSub 資料庫分片執行 `scripts/pubsub-db-wsl.sh`，以 `--exact` 逐一選取其中 27 個測試，
  拆分後選擇器須加上子模組；HTTP Upload 分片的 `scripts/upload-db-wsl.sh` 以子字串 `db::upload::tests` 選取。
  子檔若改成父檔的兄弟模組（`db/mix.rs` 的 `*_integration_tests` 寫法），upload 測試會落出這個篩選而靜默不跑，
  因此子檔一律是原測試模組的子模組，測試路徑變為「原模組::子模組::名稱」。
- 子檔位置：以 `#[path]` 載入的檔案被當作 `mod.rs`，其中的 `mod x;` 會找 `src/db/x.rs`，子檔須以
  `#[path = "x_tests/角色_tests.rs"]` 明確宣告。子檔名以 `_tests.rs` 結尾：結構門禁的 `classify` 與架構門禁的
  工作者註冊掃描都依檔名辨識測試檔，`x_tests/` 目錄名不算。子檔不放進生產模組目錄（如 `db/upload/`），
  否則會被模組讀取（R4）當成正式子檔。
- 相對路徑：upload 測試有 12 個 `include_str!`（migration、`pie.rs`、`users.rs`、`runtime/upload_worker.rs`）
  與 3 個 `super::module_source()`，pubsub 測試有 4 個 `super::super::` 路徑，搬入子檔後各多一層。
  只移動檢查原本逐位元組比對字串，WP-91 改為依所在檔案解析 include 路徑後比對。
- 不受影響：`docs/evidence/tasks/M00-03.yaml` 只以函式名提到兩個測試（R5，不改）。
- 既有缺口：`pubsub-db-wsl.sh` 原本沒有列出 `collection_edges_require_child_ownership_and_legacy_edges_do_not_disclose`
  與 `collection_edge_insert_linearizes_after_child_owner_revocation`，CI 從未執行這兩個資料庫測試；WP-93 補上。

### 5.6 S10 盤點：層級依賴（`bc1e493`）

依第 3 節的分層，WP-101 的門禁在 `bc1e493` 走到 624 個生產檔，其中 110 檔有 139 條違反方向的引用（同一檔案對
同一目標頂層模組算一條）：

| 方向 | 條數 | 組成 |
| --- | ---: | --- |
| 介面卡 → 組合 | 90 | 對 `state` 73（`xmpp` 35、`api` 15、`cluster` 13、`s2s` 8、`bosh`、`db` 各 1）、對 `runtime` 16（`xmpp` 5、`cluster` 4、`s2s` 3、`db` 2、`api`、`bosh` 各 1）、`db` 對 `tools` 1 |
| 應用 → 介面卡、組合 | 32 | `services` 對 `xmpp` 15、`cluster` 8、`db` 4、`s2s` 1、`runtime` 2、`state` 2 |
| 平台 → 上層 | 17 | `platform` 對 `s2s` 3、`cluster`、`xmpp`、`db` 各 2、`services` 1；`security` 對 `db` 3、`services`、`runtime`、`state`、`xmpp` 各 1 |

S10 只搬「被下層使用、本身不依賴上層」的程式，搬移只改路徑：

- `runtime/workers.rs`（含測試）與 `runtime/connection_actors.rs` 不使用 crate 內其他模組，搬到 `platform`（WP-102，
  減少 18 條：各介面卡、`services` 與 `security` 對 `runtime` 的引用）。
- `state/jid_text.rs` 的五個字串工具沒有 crate 依賴，搬到 `platform`（WP-103，減少 6 條）。
- `SerializableMucOccupant`、`LocalMucOccupantIdentity` 與兩者間的轉換是純資料，搬到 `services::muc::occupancy`
  （WP-104，減少 11 條）。`MucOccupant` 的 endpoint 持有 session handle，連同兩個 `From<&MucOccupant>` 留在 `state`。

S10 後剩 104 條，分布在 90 個檔案。S10 當時判斷這些都要先有 port 或窄化的 context；S11 逐條核對後，其中 33 條
只是定義放錯層或經轉出引用，以搬移處理（5.7）。S10 後的組成：

- 介面卡經組合層取得狀態（58）：`xmpp` 24、`api` 15、`cluster` 8、`s2s` 8、`bosh` 1 引用 `AppState` 與 `state` 中
  定義的窄化 context（如 `ApiQueryContext`、`ClusterMaintenanceContext`），context 型別由 `state` 組裝也定義在
  `state`；`db/retention.rs` 實作的 retention 與訂閱清理 repository trait 定義在 `runtime`，`db/pie.rs` 使用的
  PIE 匯入型別定義在 `tools::pie`，這兩組 port 要先移到應用層。
- 應用服務直接使用介面卡（30）：`services` 使用 `xmpp` 的對外佇列與 XML 工具（15）、`cluster` 的就緒與路由查詢
  （8）、`db` 的列型別（4）、`s2s` 的元件註冊表（1），以及 `state` 的 session 清理 context 與 `MucOccupant`（2）。
- 平台層向上（16）：`platform::config` 持有 `s2s` 的 `DaneMode`、`xmpp` 的 `ExtensionRuntime`、`cluster` 的
  `ClusterSecurityConfig` 與 `db` 的 `SmIpPolicy`；`platform::metrics` 讀 `db` 與 `services` 的計數器；
  `security::abuse` 使用 `db` 的 abuse repository 與 `services` 的訊息准入，`security::account_recovery` 使用
  `state` 與 `xmpp`。

### 5.7 S11 盤點：第二批層級搬移（`d5d18b0`）

S11 逐條檢查 5.6 剩下的 104 條引用指向什麼：被引用的若是型別定義或轉出路徑，而不是需要注入的行為，搬移定義或
改寫路徑就能消除，不需要新 port。這類共 33 條，分為 8 個 WP，由 codex 平行執行（減少數以依序整合時的基線重寫為準）：

| WP | 減少 | 內容 |
| --- | ---: | --- |
| WP-111 | 12 | `services` 與 `xmpp/protocol/sm_owner.rs` 經 `xmpp::outbound`、`cluster`、`db`、`state` 引用的型別其實定義在 workspace crate（`northstar_delivery_core`、`northstar_xml_builder`、`northstar_message_core`、`northstar_xep_0016`、`northstar_session_core`），改為直接引用 crate |
| WP-112 | 1 | `db/retention.rs` 實作的 retention 與訂閱清理 repository trait 由 `runtime` 移到 `services::maintenance_repositories` |
| WP-113 | 1 | `db/pie.rs` 寫入的 PIE 匯入紀錄由 `tools::pie` 移到 `db::pie::model` |
| WP-114 | 3 | `platform::config` 持有的 DANE 模式與 lab DNSSEC 錨點，連同兩者共用的公開 IP 判斷，由 `s2s` 移到 `security`（`dane`、`lab_dnssec`、`address_scope`） |
| WP-115 | 2 | XEP 擴充註冊表由 `xmpp` 移到 `platform::extensions` |
| WP-116 | 3 | `SmIpPolicy` 由 `services::sm` 移到 `platform::config`；PubSub、MIX、S2S 遞送佇列的 10 個計數器由 `db` 移到 `platform::delivery_counters`；指標登錄直接讀 `northstar_pubsub_application` 的 PubSub 准入計數 |
| WP-117 | 6 | 叢集匯流排簽章由 `cluster::security` 移到 `security::cluster_bus`；叢集金鑰紀錄與就緒探測身分由 `db`、`cluster` 移到 `security::cluster_keys` |
| WP-118 | 5 | 管理者 session 清理紀錄移到 `services::admin_session_cleanup_worker`；abuse guard 與 repository 交換的紀錄移到 `security::abuse::records`；叢集指標快照移到 `services::metrics_snapshot` |

S11 後剩 71 條，分布在 68 個檔案。S11 判斷它們都要先有 port 或窄化的 context；S12 逐條核對後，其中 20 條只需搬移
或一個委派既有方法的小 port（見 5.8）。S11 結束時的分布：

- 介面卡經組合層取得狀態（55）：`xmpp` 23、`api` 15、`cluster` 8、`s2s` 8、`bosh` 1 引用 `AppState` 與 `state` 中
  定義的窄化 context。
- 應用服務直接使用介面卡或組合層（12）：`xmpp` 7（對外佇列的 `OutboundItem`、`RouteSendError` 與 `xml_util` 的
  stanza 工具）、`cluster` 2（`ClusterMixRouteLookup`、`ClusterMucDeparture` 等叢集能力）、`state` 2（session 清理
  使用的 `AppState`、`MucOccupant` 與 standalone MUC 維護 context）、`s2s` 1（元件註冊表）。
- 平台層向上（4）：`security::abuse` 使用 `services` 的訊息准入見證，`security::abuse::key_management` 建立 `db` 的
  abuse persistence，`security::account_recovery` 使用 `state` 與 `xmpp`。

### 5.8 S12 盤點：第三批層級搬移（`366f507`）

S12 逐條核對 5.7 的 71 條引用。依賴上層、也只有上層在用的程式往上搬（WP-121、122、126）；只依賴下層、被下層使用的
程式往下搬（WP-123、127、128）；下層若只呼叫上層物件的一個方法，就由下層定義只含該方法的 port，上層實作時委派原有
方法，呼叫端不變（WP-124、125，WP-121、127 也各用一個）。這類共 20 條，分為 8 個 WP，由 codex 平行執行（減少數以
依序整合時的基線重寫為準）：

| WP | 減少 | 內容 |
| --- | ---: | --- |
| WP-121 | 2 | abuse guard 由 `security::abuse` 移到 `services::abuse`：平台層沒有使用者，guard 本身依賴訊息准入服務。guard 改收既有的 `AbusePersistence` port，PostgreSQL 實作由組合層建立 |
| WP-122 | 2 | 帳號刪除復原由 `security::account_recovery` 移到 `state::account_recovery`，它完全依賴 `AppState` 與 `AccountDeletionRecoveryContext` |
| WP-123 | 5 | XML 工具（含三個子模組與三個測試檔）、client stanza 驗證與 Jingle 驗證由 `xmpp` 移到 `services`；三者只依賴 `jid`、`platform`、`security`、`services` 與 workspace crate |
| WP-124 | 1 | `services::mix` 定義 `MixClusterRouteLookup` port，叢集介面卡實作時委派原有的 `lookup_nodes` |
| WP-125 | 1 | `ComponentRoute` 移到 `services::federation_outbox`，該模組新增 `ComponentWake` port，由 s2s 元件註冊表實作 |
| WP-126 | 1 | standalone MUC 占用維護 worker 由 `services` 移到 `state`，與它的 context 以及叢集版 worker 放在一起 |
| WP-127 | 6 | REST 的查詢、治理、保留、檢舉與 HTTP 入口 context，以及 10 個服務綁定別名，由 `state` 移到 `api::contexts`；查詢 context 經 `LocalPresenceDirectory` port 讀取本節點的 session 與 MUC 占用者，由 `state::api_query_presence` 實作；`FromRef` 實作留在 `state.rs` |
| WP-128 | 2 | 叢集監聽器的訊息政策與兩個命令結果 enum 由 `state` 移到 `cluster::listener_policy`；`privacy_allows_session` 改收 session 的三個值，不再收 `OnlineSession` |

S12 後剩 51 條，分布在 50 個檔案，平台層已沒有向上引用。S12 判斷它們都要先有 session／傳輸 port，或把 context 從
組合層拆出；S13 逐條核對後，其中 20 條只需把 context 的定義與建構分開，或一個委派既有方法的小 port（見 5.9）。
S12 結束時的分布：

- 介面卡經組合層取得狀態（47）：`xmpp` 23、`api` 9、`s2s` 8、`cluster` 6、`bosh` 1 引用 `AppState` 與 `state` 中
  需要 `AppState` 的 context（例如帳號管理的 `RegistrationAdminContext`、`SessionAdminContext`）。
- 應用服務直接使用介面卡或組合層（4）：`services::messaging` 與 `services::messaging::direct_workflow` 使用 `xmpp`
  對外佇列的 `OutboundItem`、`RouteEnqueue` 與 `RouteSendError`；`services::session_cleanup` 使用 `state` 的
  `AppState`、`MucOccupant`、`SuspendedMucEndpoint`，以及 `cluster` 的 `ClusterMucDeparture`、
  `ClusterSessionRouteRelease`。

### 5.9 S13 盤點：第四批層級搬移（`3f32a6d`）

S13 逐條核對 5.8 的 51 條引用。介面卡經 `state` 取得的不全是 `AppState` 本身，有一部分是定義在 `state` 的 context
或紀錄：這些 context 的欄位只有服務、政策與計數器，只因 `FromRef` 建構子讀 `AppState` 才放在組合層。做法是把定義移到
使用者所在的層，建構子與 `FromRef` 留在 `state`；context 若要呼叫組合層的物件，就由介面卡定義只含該方法的 port，
`state` 實作時委派原有方法。這類共 20 條，分為 6 個 WP，由 codex 平行執行（減少數以依序整合時的基線重寫為準）：

| WP | 減少 | 內容 |
| --- | ---: | --- |
| WP-131 | 2 | 12 個 REST 端點與上傳 context（登入、註冊、挑戰、登出、密碼變更、passkey、OMEMO 復原與輪詢、上傳讀寫刪）移到 `api::contexts`；`FromRef` 建構子集中到 `state::rest_endpoint_contexts`；OMEMO 輪詢的准入上限與上傳准入守衛隨 context 搬移 |
| WP-132 | 3 | `api::contexts::account_teardown` 定義 `AccountSessionTeardown`、`AccountGenerationTeardown` 兩個 port 與可複製的 handle；`state` 的兩個拆除流程實作時委派原有方法，程式本身不變 |
| WP-133 | 1 | readiness 與 metrics context 移到 `api::contexts`；MUC 占用數經 `OccupancyCount` port、SM 指標經 `SmRecoveryGauges` port 讀取，SM 探針與建構留在 `state::metrics_context` |
| WP-134 | 2 | `RegistrationAdminContext`、`SessionAdminContext` 移到 `api::contexts`，以 `Arc<dyn RegistrationCache>`、`Arc<dyn AdminSessionLookup>` 綁定 `services::account_admin` 既有的 port |
| WP-135 | 10 | `OnlineSession`、MUC 占用者、暫停中的 SM 端點等紀錄與只操作單一紀錄的方法移到 `xmpp::local_routes::{session, muc}`；即時路由表與其全部操作留在 `state`，以私有匯入使用 |
| WP-136 | 2 | `services::session_cleanup` 移到 `state::session_cleanup`：它以 `Arc<AppState>` 建構，使用十個組合層 context，只有 `state` 與 XMPP 協議 actor 使用 |

S13 後剩 31 條，分布在 31 個檔案。R9 的門禁只計算具名路徑：`api/route_composition.rs` 經 `api/mod.rs` 的匯入仍收
`Arc<AppState>`，這條依賴記在 `api/mod.rs`。剩下的都持有或傳遞組合根本身，要先有 session／傳輸 port，交給
[模組化執行計劃](../MODULARIZATION_EXECUTION_PLAN.md)（Phase D 的 session／傳輸 port、Phase E 的基礎設施 port 與
8.1 的 D1）；之後每減少一條，都由 R9 的基線 ratchet 記錄：

- 介面卡經組合層取得狀態（29）：`xmpp` 15（`xmpp/mod.rs`、協議 actor `protocol.rs` 與 13 個協議子模組，actor 持有
  `Arc<AppState>`）、`s2s` 8（元件、dialback、DNS、TLS、入站、出站與 SM）、`cluster` 4（`cluster.rs`、MUC outbox、
  復原重播與 worker）、`api` 1（`api/mod.rs` 的 listener 與路由組裝）、`bosh` 1。
- 應用服務直接使用介面卡（2）：`services::messaging` 與 `services::messaging::direct_workflow` 使用 `xmpp` 對外佇列的
  `OutboundItem`、`RouteEnqueue` 與 `RouteSendError`，這些型別另有 `crate::outbound::…` 路徑的使用者，要等對外佇列
  有 port 後一起處理。

### 5.10 S14 盤點：叢集介面卡解耦（`4d63ba7`）

S14 核對 5.9 中 `cluster` 的 4 條（`cluster.rs`、`cluster/muc_outbox.rs`、`cluster/recovery_replay.rs`、
`cluster/workers.rs`）。這幾個檔案不持有 `AppState` 做事：`cluster.rs` 與 `workers.rs` 只在 worker 啟動時以
`AppState` 建構 context，其餘是 context 型別定義在 `state`。這些 context 的邏輯呼叫 S13 留在 `state` 的即時路由表
操作（`session_entries_for_in`、`fence_local_session_in` 等），所以先把這些只接 `&DashMap`、不碰 `AppState` 的自由
函式移到介面卡層，再依 S13 的做法把 context 的定義與建構分開。WP-142、143 平行執行，WP-144 要用 WP-142 搬出的
型別，在兩者整合後才開始（減少數以依序整合時的基線重寫為準）：

| WP | 減少 | 內容 |
| --- | ---: | --- |
| WP-141 | 0 | `state/local_session.rs`、`local_muc.rs`、`suspended_muc.rs` 中只操作即時路由表的自由函式與快照紀錄移到 `xmpp::local_routes::{session_table, muc_table, suspended_muc}`；`AppState` 仍擁有路由表與全部方法 |
| WP-142 | 2 | `MucDeliveryContext` 移到 `xmpp::muc_delivery`，`ClusterMucDeliveryEndpoints`、`ClusterMucOutboxWorkerContext` 移到 `cluster`；`start_muc_outbox_delivery` 改收 worker registry 與建好的 context |
| WP-143 | 1 | 復原重播喚醒、直送 spool 喚醒、維護用的本地投影與 `ClusterMaintenanceContext` 移到 `cluster` |
| WP-144 | 1 | 監聽器的 dispatch、MIX caps、封鎖出席、SM MUC 拆除與故障監督 context 移到 `cluster`，`SmTeardownLocalEffects` 移到 `xmpp::local_routes::sm_teardown`；`ClusterListenerRuntime` 由 `state` 建構，`run_pubsub_listener` 改收 runtime |

S14 後剩 27 條，分布在 27 個檔案：介面卡經組合層取得狀態 25 條（`xmpp` 15、`s2s` 8、`api` 1、`bosh` 1），應用服務
直接使用 `xmpp` 對外佇列 2 條，都持有或傳遞組合根本身，依 5.9 交給模組化執行計劃。

### 5.11 S15 盤點：介面卡參數收窄（`5c16fed`）

S15 核對 5.10 剩下的 27 條，找出只向 `AppState` 讀幾個設定值或句柄、不持有組合根做事的檔案。`s2s` 的 8 條中，
`tls.rs`、`dns.rs` 只讀聯邦 TLS 素材、一個 OCSP 旗標、解析器、DNS 覆寫與兩個位址政策；`dialback.rs` 讀三個旗標，
另有一個向權威伺服器開連線的函式；`inbound/direct_route.rs` 是包住 `&AppState` 實作傳訊服務 port 的組合接線。
`xmpp` 的 15 條中只有 `protocol/mix_muc.rs` 屬於這一類。四個 WP 平行執行、依序整合：

| WP | 減少 | 內容 |
| --- | ---: | --- |
| WP-151 | 2 | TLS 函式改收 `&TlsContext`，`s2s_client_config` 另收 OCSP 旗標；DNS 函式改收 `s2s::dns` 定義、`state` 建構的 `FederationDnsContext`（`Copy`，解析器、覆寫與 TLS 素材以借用傳入）；`AppState::s2s_dns_override` 移為 context 的方法 |
| WP-152 | 1 | `features` 改收 `S2sFeaturePolicy`；`verify_remote` 逐位元組移到 `s2s/outbound/dialback_verify.rs`，由 `s2s::outbound` 轉出 |
| WP-153 | 1 | `S2sDirectRoutePort` 以 `git mv` 移到 `state/s2s_direct_route.rs`；`check-federated-route-boundaries` 改讀新路徑，並要求 `state.rs` 註冊該模組 |
| WP-154 | 1 | `maybe_link_local_mirror` 改收鏡像旗標、本地網域與 `&MixService<R>`，對 `MixRepository` 泛型，不點名 `db` 型別；架構門禁改為要求這個參數與其上的 `link_local_muc_mirror` 呼叫 |

S15 後剩 22 條，分布在 22 個檔案：介面卡經組合層取得狀態 20 條（`xmpp` 14、`s2s` 4、`api` 1、`bosh` 1），應用服務
直接使用 `xmpp` 對外佇列 2 條。`s2s` 剩下的 `components.rs`、`inbound.rs`、`outbound.rs`、`sm.rs` 以及 `xmpp` 的
協定處理器都持有或傳遞組合根本身，依 5.9 交給模組化執行計劃。

### 5.12 S16 盤點：原型刪除、crate 搬移與層級門禁（`f6d3517`）

刪除前逐項確認使用者：只被 `services/*` 使用的 crate、工具與資料刪除，仍有使用者的保留。

| 處置 | 項目 |
| --- | --- |
| 刪除 | `services/*`（15 個 crate）；`foundation-contracts`、`-service-runtime`、`-telemetry`、`-security`；`tools/data-split-migrator`、`tools/catalog-validator`；Buf 契約（`contracts/`、`buf*.yaml`、`tests/contracts`、`docs/contracts`）與其相容性腳本、CI 工作；Program 6 收斂稽核；服務、路由、XEP 擁有權、資料分類、保存期限與叢集目錄；`deploy/compose`、`deploy/kubernetes`；切換、workload identity 與語意慣例文件 |
| 保留 | `restore-verifier`、`db-bootstrap`、Kafka 政策產生器與 `catalog/topics.yaml`、`rpc-authorization.yaml`、`key-classes.yaml`、`deploy/spire`、`deploy/otel-collector`、`foundation-postgres`、`-db-test`、`-eventing`、`-eventing-postgres`、`-kms`、`architecture-validator`（移除路由目錄與執行期圖） |
| 標為 superseded | ADR 0002–0007 |

crate 的去處：`northstar-xmpp-types`、`-xml-builder`、`-xml-framing`、`-xep-core` 與 24 個 `northstar-xep-*` 進
`crates/kernel`；`northstar-web-surface` 與 5 個 `foundation-*` 進 `crates/platform`；其餘 21 個依目標架構 4.2 的上下文進
`crates/contexts/<context>`；`northstar-test-harness` 進 `tools/`。搬移腳本依固定的對應表 `git mv`，再改寫 manifest 的
`path`、workspace members、`fuzz/Cargo.toml` 與現行文件、腳本中的 `crates/<name>` 一律改為新路徑；有日期的紀錄、
固定提交的連結與 Stage 4 凍結腳本不改。以 `crates/` 目錄列舉或組路徑的三個門禁（文件一致性、parser fuzz 覆蓋、
XEP 外掛）改由 `scripts/lib/workspace-members.mjs` 讀 workspace members。

Stage 4 純測試 lane 綁定 22 個檔案，它們只在隔離目錄執行、描述的是證據當時的原始碼，維持不變，例外有二：
`src/bosh/response_owner.rs` 改由 `scripts/fixtures/stage4-profile-binding-v1/historical` 的凍結副本提供；
`scripts/test-experiment-contract.py` 另在一般 CI 讀現行樹的 abuse-policy 模型計算來源雜湊，因此路徑跟著 crate 改，
public100 lane 重新綁定它的大小與雜湊。`src/` 的釘選解除後，`response_owner.rs` 由 2,884 行降到 814 行而離開超標清單，
`stage4_replay.rs` 由 7,270 行降到 4,521 行（內嵌測試移到子檔）。

層級門禁上線時現有依賴圖沒有違規：S1–S15 已把 crate 之間的方向整理好，S16 只把它固定下來。

建置時間基準（`f6d3517`，16 核、rustc 1.97.1，獨立 target 目錄、debug、`--workspace --all-targets`）：

| 量測 | 時間 |
| --- | --- |
| 乾淨建置 | 203.7 秒 |
| 改動根 crate（`src/main.rs`）後重建 | 25.4 秒 |
| 改動 `northstar-xmpp-types` 後重建 | 35.5 秒 |
| 無變更 | 1.1 秒 |

根 crate 單一編譯單元的時間（`--timings`）：測試版 binary 151.8 秒、正式 binary 87.7 秒，兩者都在第 51.9 秒（依賴編完）才開始，是乾淨建置的關鍵路徑。之後每個階段以同樣方式量測並比較。

### 5.13 S17 盤點：平台橫切移為 crate（`a0ebe279`）

| 原位置 | 去處 | 層 |
| --- | --- | --- |
| `src/jid.rs`、`src/auth.rs`（只轉出型別） | 刪除，呼叫端直接引用 `northstar_xmpp_types::jid`、`northstar_auth_core` | — |
| `src/platform/workers.rs`、`connection_actors.rs` | `northstar-runtime` | platform |
| `src/platform/{logging,metrics,delivery_counters}.rs`；`northstar-pubsub-application` 的准入計量 | `northstar-telemetry` | platform |
| `src/security/*`、`src/platform/config/secret_files.rs` | `northstar-security` | platform |
| `src/platform/extensions.rs` | `northstar-xep-catalog` | kernel |
| `src/platform/jid_text.rs` | `northstar_xmpp_types::jid_text`（JID 切分）、`northstar_xml_builder::escape`（XML 跳脫） | kernel |
| `src/platform/error.rs` | `src/api/error.rs` | 根 crate（介面卡） |
| `src/platform/config.rs` 與 `config/` | `northstar-config` | platform |

搬移由腳本完成：`git mv`、`pub(crate)` 改為 `pub`、把 `crate::<舊路徑>` 改寫為新 crate 的路徑（`use crate::{...}`
群組中搬走的項目拆成自己的 `use`），基底變了就在新基底上重跑腳本，而不是解衝突。依層級規則需要調整的有三處：
PubSub 准入計量原本在上下文 crate、由指標登錄讀取，platform 不能依賴上下文，因此計量移到 `northstar-telemetry`、由
PubSub 更新（WP-172）；設定比對秘密改用 `subtle::ConstantTimeEq`，SCRAM 迭代次數的上下限成為設定常數，由驗證服務的
測試確認與 auth core 一致（WP-175）；根 crate 測試使用的建構子與探測改放在 `test-support` feature 後面，只由根 crate
的 dev-dependencies 開啟，執行期 binary 不含它們（WP-172、173）。

讀原始碼的門禁跟著路徑改：執行期實驗可以指名 workspace 套件（`cargo test --locked -p <套件> <選擇器>`，WP-172）；
`readProductionModule` 把 crate 根 `lib.rs` 當作 `mod.rs`，子模組是同目錄的檔案，同目錄的 `main.rs` 與 `bin/` 是另一個
crate 根而略過（WP-176）；R9 的層級清單刪除平台層與 facade 層，基線維持 22 條。

根 crate 由 834 檔 396,498 行降到 797 檔 381,964 行；五個新 crate 共 14,716 行（config 4,447、security 5,759、
runtime 2,203、telemetry 1,862、xep-catalog 445）。`src/storage`（物件儲存、S3、備份、遷移）只有上傳使用，屬於
upload 上下文的介面卡，S19 隨上傳一起移出；目標架構因此不再列 `northstar-object-store`。

建置時間（`a0ebe279`，量法同 5.12）。這次量測時機器同時執行其他工作（負載約 6），因此在同樣條件下重測了 S16，
兩個階段以同一次重測比較：

| 量測 | S16（5.12，閒置） | S16（同負載重測） | S17 |
| --- | --- | --- | --- |
| 乾淨建置 | 203.7 秒 | 240.7 秒 | 243.6 秒 |
| 改動根 crate（`src/main.rs`）後重建 | 25.4 秒 | 43.8 秒 | 34.8 秒 |
| 改動 `northstar-xmpp-types` 後重建 | 35.5 秒 | 37.3 秒 | 44.6 秒 |
| 無變更 | 1.1 秒 | 0.6 秒 | 2.0 秒 |

同負載下乾淨建置持平；改動根 crate 後的重建由 43.8 秒降到 34.8 秒，平台程式碼不再隨根 crate 重新編譯；改動
`northstar-xmpp-types` 後的重建由 37.3 秒增為 44.6 秒，新的平台 crate 也依賴它而要重新編譯。負載下的單次量測有誤差，
之後的階段在機器閒置時量測。

### 5.14 S18 盤點：會話核心介面（`7fc57a4`）

| 項目 | 位置 | 說明 |
| --- | --- | --- |
| IQ 路由表 | `crates/edges/northstar-stream`（457 行） | `IqRoute`、`IqRouter`、`IqHandler`；處理器對會話與回應型別泛型，型別留在根 crate 直到會話搬入 |
| 路由註冊 | `src/xmpp/protocol/dispatch/iq_routes.rs` | 48 條路由；閘門 `Always`、`RouteEnabled`、`RouteEnabledOrUnavailable`、`HttpUpload` |
| 分派 | `ProtocolSession::iq`（`src/xmpp/protocol/dispatch.rs`） | 查表後依 `Admission` 處理；原本的 match 刪除 |
| 遠端路由 port | session 應用層的 `RemoteRoutePort`；`src/state/remote_route.rs` 由 `AppState` 實作 | XEP-0334 no-store 訊息改經 port 送往遠端網域 |

與目標架構 S18 列的差異：只有 IQ 依鍵分派，因此本階段只建立 IQ 路由表；訊息、出席與串流層 nonza 在 `handle` 中
依元素名稱各有一個入口，屬於串流狀態邏輯，是否需要 `StanzaHandler` 留到 S30 拆解 `ProtocolSession` 時決定。
`SessionContext` 不做成單一 trait：各上下文把處理器搬進自己的 `-xmpp` crate 時，定義該處理器需要的會話能力
（已驗證的使用者、網域、服務），由 `ProtocolSession` 實作，與 S15 收窄介面卡參數的做法相同。路由的處理器目前是
`ProtocolSession` 的函式，註冊在靜態路由表中；處理器搬出時只換註冊的函式，路由表不必改。

`src/xmpp/protocol` 中仍有 4 處引用 `crate::bosh`，都在 `#[cfg(test)]` 的 saved-case 夾具
（`messaging/saved_case*`、`sm_owner/tests.rs`）；依 4.6，它們隨測試支援 crate 移出，不屬於協定處理器的依賴。

根 crate 由 797 檔 381,964 行變為 799 檔 382,566 行：match 分支改寫為具名的處理器函式，並新增路由註冊與 port 實作。
S17 推上 dev 後 CI 的模糊測試編譯失敗：`rest_extractors` 以 `#[path]` 讀 `src/api/extract.rs`，它的 `AppError` 替身
模組仍叫 `platform`；本地驗證沒有編譯模糊測試。WP-179 修正替身並刪除 WP-171 留下的未使用匯入，驗證腳本也加入
`cargo check --manifest-path fuzz/Cargo.toml --bins`。刪掉的匯入卻是 `check-parser-fuzz-coverage` 要求的：被納入的
驗證器原本以 `crate::jid` 引用 JID crate，門禁因此要求模糊測試匯入它；WP-171 後驗證器以完整路徑引用，匯入成為未使用。
WP-179 只跑了模糊測試編譯、沒有重跑門禁，dev 的 CI 仍失敗；WP-186 讓 crate 需求可以指定由被納入的正式模組引用。

## 6. 委派與驗收協議

角色：**架構負責人**撰寫 WP 規格、執行全部驗證並審閱差異；**程式修改**由 Antigravity CLI（`agy`）執行，S8–S13 改由 Codex CLI 執行（第 8 點），S14 起回到 agy（第 9 點）。

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
   `cargo fmt` 可能改變寫法（WP-26 把 match 分支的 `=> { X }` 改成 `=> X,`）。WP-49 起只移動檢查
   把只含一個運算式的 match 分支區塊視同去掉區塊的寫法（區塊內有頂層 `;`、註解或開頭屬性，以及空
   區塊，照原樣比較），WP-26 以 `--after-rev` 重新稽核即為相同。其他格式化差異仍以 rustfmt 格式化
   逐字複製的原模組本體，與新檔逐位元組比對，相同即證明差異只來自格式化。
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
   字面值比較抓到；規格須明寫字串內的行首空白一律照原樣，即使數目是奇數或看似沒對齊。要原樣保留的
   續行要寫明前導空白的格數，例如「`line N (13 leading spaces): VALUES(…)`」；寫成「`line N: <原文>`」時，
   agy 會把冒號後的分隔空白算進縮排（WP-71b 一個子檔的 35 行都多一格）。
   agy 也會順手做語義相同的「改善」（WP-26 把 `stanza.clone()` 改成 `&stanza`），由只移動檢查
   抓到；規格須明寫不得做任何改善，即使原寫法看似多餘。agy 也會漏抄片段（WP-30 搬移測試模組時
   漏掉一個斷言中的 `.is_err()`），同樣由只移動檢查抓到並以一輪回饋修正。
   門禁中逐字比對簽名或結構本體的期望，會因 R3 的可見性改寫而失敗（WP-26 的執行門禁兩處）。
   S1 盤點以反例模擬搬移時，須依 R3 加上可見性，才能事先找出這類期望，列入拆分 WP 的規格，連同
   自測中以原文作變異錨點的測試一起更新。
6. 失敗輸出回饋到同一個 agy 對話（`--conversation`）修正，最多三輪；仍失敗則縮小 WP 範圍。
7. 審閱通過後以 `[WP-xx]` 提交到 `dev`；推送後以該提交的完整 CI 為準，不沿用舊綠燈。
8. Codex（S8 起，2026-10-15）：程式修改改由 Codex CLI 執行，agy 暫停；第 1、3、4、7 點照舊，
   以下取代第 2、5、6 點中 agy 專屬的部分。
   - 呼叫：`codex exec --ignore-user-config -m gpt-6.1-sol -c approval_policy="never"
     -c sandbox_mode="workspace-write"`（唯讀提案用 `read-only`），並把
     `sandbox_workspace_write.exclude_slash_tmp`、`exclude_tmpdir_env_var` 設為 true、`network_access` 設為
     false。寫入只限該 worktree，不載入使用者設定中的 MCP 與外掛，沙箱擋下的指令直接失敗、不要求提權；
     不使用 `--dangerously-bypass-approvals-and-sandbox`。回饋以 `codex exec resume <session>` 在同一對話進行。
   - 平行：每個 WP 一個 worktree，最多 16 個同時執行。規格禁止執行 cargo（共用的 target 目錄會互相阻塞）；
     格式化、建置、測試與完整 CI 由架構負責人在整合分支依序執行，同一時間只跑一個完整 CI。執行前後的
     checkout 指紋比對（第 4 點）排除平行執行中的 worktree。
   - 拆分：設計先由唯讀提案取得（見 5.4），架構負責人審閱後寫成設計 JSON，再產生規格。規格要求 codex
     寫一支切割腳本，從 `git show <rev>:<file>` 依行號切出子檔與父檔，不手抄程式碼；之後只做三種修改
     （`super::` 多一層、R3 可見性、`include_str!` 多一個 `../`）與模組接線，並自行執行只移動檢查直到通過。
     規格附上每個範圍首末行的原文，codex 可據以核對行號。
   - 門禁解耦（WP-82）：codex 改寫讀取方式，並以暫時的 `zz_probe.rs` 子檔做反例：放入禁止片段時門禁須
     失敗，原樣搬入受檢項目時須通過，結束後還原。架構負責人在整合後抽樣重做反例。
   - 沙箱中 Node 的 `execFileSync('git')` 會因 stdin 而 EPERM；只移動檢查的 git 子行程在沙箱內失敗時，
     codex 改在記憶體中比較，結果仍由架構負責人在沙箱外重跑確認。
   - 盤點 `include_str!` 讀者時不得截斷搜尋輸出：WP-81c 的盤點以 `head` 截斷而漏看 `db/upload.rs` 的三個
     讀者，由單元測試抓到。
   - 整合後除了門禁本身，也要跑門禁的自測：WP-83t、83w 拆分後執行門禁仍通過，但自測的變異輔助已失效
     （WP-82h）；以檔案與行號綁定的豁免（對外 XML 門禁的 allowlist）隨拆分移動，列入拆分 WP 的規格。
   - 角色拆分（WP-84）：新子檔加入 `catalog/source-role-splits.json`。平行拆分各自修改同一份清單，整合時
     不套用 codex 對清單的修改，改由整合腳本依設計寫入該檔的條目。
   - 測試檔拆分（WP-92）：規格逐項列出各子檔的項目，子檔以 `use super::*;` 取得父測試模組的共用 helper 與
     匯入。完全不用父模組名稱的子檔不要這一行（`-D warnings` 下是 unused import，WP-92a 的
     `source_contract_tests.rs`）；只經子檔 glob 使用的父檔匯入不算未使用。`cargo fmt` 會把相鄰的 `mod`
     宣告依字母排序。
   - 層級搬移（S10）：codex 的沙箱中 `.git` 唯讀，整檔搬移由架構負責人在交付前以 `git mv` 執行，規格只要求改寫
     路徑。層級檢查必須沿模組樹判斷測試碼：原型只依檔名分類，把 `#[cfg(test)] mod saved_case;` 等宣告下的 4 個
     檔案算成生產碼（143 條對門禁的 139 條）。平行的搬移各自修改同一個父模組（WP-102、103 都改
     `platform/mod.rs`），整合時手動合併；每個 WP 整合後以 `--write` 重寫基線，確認只刪不增後併入該 WP 的提交。
   - 層級搬移（S11）：型別搬離以 glob 轉出的模組（`db/mod.rs` 的 `pub use x::*`、`cluster.rs` 的
     `worker_capabilities::*`）後，原檔改以私有 `use` 匯入，私有匯入不經 glob 轉出，所以 `crate::db::X` 形式的
     使用者都要改路徑；經 glob 匯入取得型別的檔案也要列入搜尋（WP-116 漏了兩個經 `services::sm::*` 取得
     `SmIpPolicy` 的檔案，由 clippy 抓到）。門禁以正規化原始碼字串比對的片段會綁定型別路徑：WP-111 改寫
     `TransportOwnershipSource` 的路徑後，`check-execution-boundaries.mjs` 的原生 MIX ACK 期望字串隨之更新並重跑
     門禁自測，因此改寫路徑的規格要求先搜尋 `scripts/` 中的舊路徑。多個 WP 修改同一組匯入時（`security/mod.rs`、
     readiness 的兩個檔案）依序 cherry-pick 並手動合併；有些條目要相關 WP 都整合後才消失（`services/readiness.rs`
     對 `db` 的引用在 WP-117、118 都整合後才去掉）。
   - 層級搬移（S12）：小 port 只定義下層實際呼叫的方法；trait 方法與 inherent 方法同名時，實作以
     `Type::method(self, …)` 委派，避免遞迴（WP-124、125）。繞過一個轉出點後，要檢查它是否還有使用者：WP-123 讓
     `xml_util` 直接引用 `northstar_xml_builder`，`xmpp::xml_builder` 對 `ValidatedXmlFragment` 的轉出因此沒有使用者，
     在 clippy `-D warnings` 下失敗，由架構負責人移除。兩個大範圍路徑改名（WP-121 的 `security::abuse`、WP-123 的
     `xmpp::xml_util`）修改同一批匯入行，整合時取一邊再套用另一邊的改名；`check-abuse.mjs` 的同一行被三個 WP 修改。
     測試名稱的路徑對應要涵蓋每個搬移的模組（WP-126 的 4 個測試漏列，由人工比對確認）。
   - 層級搬移（S13）：context 的定義與建構分開放：定義跟著使用者，`FromRef` 與建構子留在組合層，欄位改為
     `pub(crate)`。泛型服務要改持 trait object 時，在 port 擁有者加上 `impl<T: Port + ?Sized> Port for Arc<T>`，
     服務本身不必改（WP-134）。單一 WP 的減少數不一定等於整合後的減少數：基線以「檔案→層」計，檔案要等它所有具名的
     上層路徑都消失才離開基線，WP-132 單獨驗證時減少 0 條，接在 WP-131 之後減少 3 條；WP-135 單獨驗證時
     `services/session_cleanup.rs` 多出一條對 `xmpp` 的引用，WP-136 先整合把該檔移到 `state` 後消失，git 的改名偵測
     把 WP-135 對舊路徑的修改套到新路徑。所以「基線只刪不增」以依序整合的每一步為準，整合順序要讓搬檔的 WP 在前。
     驗證會先跑 `cargo fmt`，rustfmt 會把相鄰的 `mod` 宣告排序，平行的 WP 在 `state.rs`、`api/contexts.rs` 增刪
     `mod` 與匯入行時幾乎都會衝突，整合時取兩邊的聯集再格式化。WP-135 單獨驗證時通過 clippy，整合後 `state.rs` 的三個
     glob 轉出已沒有 `pub` 項目，`muc_resume` 的 glob 與兩個 workspace crate 型別的轉出失去最後的使用者，在 clippy
     `-D warnings` 下失敗；由架構負責人把 glob 改為 `pub(crate)`、刪除無人使用的轉出，`state` 的測試改為直接引用 crate。

9. agy（S14 起，2026-10-21）：程式修改回到 Antigravity CLI，預設模型 `gemini-3.8-flash-high`，小任務可用
   `claude-opus-5-5-high`；第 1–7 點照舊，第 8 點中與工具無關的經驗仍適用。
   - 機械搬移由架構負責人先做並提交：整檔以 `git mv` 移到新位置，`impl AppState` 建構子再以腳本依行號逐位元組
     切回 `state` 中原名的檔案；agy 只補匯入、可見性、路徑與門禁，不重新輸出搬移的程式碼。規格以 worktree 中的
     確切檔名與匯入清單交付，平行執行時各自一個 worktree，cargo 由架構負責人依序執行。
   - 層級搬移（S14）：S13 把即時路由表的操作留在 `state`（WP-135），S14 推翻這個決定：介面卡的 context 要呼叫它們，
     留在組合層會讓 context 也離不開組合層。這些函式只接路由表，移到 `xmpp::local_routes` 後 `state.rs` 以私有 glob
     匯入，`state` 的子模組經 `use super::*;` 照舊使用。worker 不再收 `Arc<AppState>`：組合根在 supervisor 的
     closure 內建構 context 或 runtime，重啟時每次重建，與原本在 worker 內建構相同。
   - agy 會補上規格漏列的匯入（WP-141 的 `anyhow::Context`），但搬移後失去使用者的匯入與 glob 轉出由 clippy 抓到：
     有的只在 bin 目標下未使用、在測試目標下仍被使用，所以兩個目標都要檢查，測試模組經 `super::` 取用的名稱
     （`state/session_key_tests.rs`）改為直接引用新路徑。父模組刪除 `use crate::state::AppState;` 後，經
     `use super::*;` 取得它的子模組（`cluster/workers.rs`）會失去該名稱：WP-142 先在子模組補上匯入，WP-144 再刪除。
   - 參數收窄（S15）：介面卡只讀少數設定或句柄時，改收那些值或一個介面卡定義、`state` 建構的小 context，
     比搬移定義更直接；`Copy` 的 context 只複製固定設定，解析器、TLS 素材等共享狀態仍以借用在原處讀取。規格除了
     列出呼叫端，也要搜尋門禁中被收窄函式原本使用的 accessor 名稱：WP-154 讓 `mix_muc.rs` 不再呼叫
     `.mix_service()`，架構門禁因此失敗，匯入它的三個門禁也一併失敗；由架構負責人把規則改為要求新的參數與呼叫，
     並以變異確認仍會拒絕。
   - crate 搬移（S17）：以 `current_exe()` 與 `--exact <模組路徑>` 重新執行自己的測試，模組搬走後選擇器要跟著改
     （WP-172 的 logging、WP-177 的 environment），否則子程序找不到測試而以成功結束；workspace 測試因此以
     `--no-fail-fast` 執行，避免第一個失敗的測試 binary 讓其餘 binary 不跑。多個 WP 同時進行：各自一個 worktree，
     搬移腳本與 agy 平行，cargo 工作經 flock 佇列依序執行；鏈上的 WP 以搬移後的測試名稱對應表串接比對。
   - 以 `#[path]` 讀根 crate 原始碼的程式（模糊測試、部分門禁）不在 workspace 的編譯範圍內，搬移改了它們引用的
     路徑時，workspace 全綠也看不出來；每個階段的驗證因此也編譯 `fuzz/` 的全部 target（S18）。

WP 規格固定包含：目標、允許修改的檔案、不得改變的語義（SQL、migration、鎖、交易、wire、
錯誤訊息、門禁強度）、不得觸碰的證據檔、退出檢查。

## 7. 與其他計劃的分工

| 文件 | 權威範圍 |
| --- | --- |
| 本文 | 檔案位置、模組邊界、行數預算、門禁定位方式、結構 WP 狀態 |
| [目標架構](target-architecture.zh-TW.md) | S16 起的目標 workspace 架構、層級與上下文邊界、全面重構的階段順序 |
| [模組化執行計劃](../MODULARIZATION_EXECUTION_PLAN.md) | 領域邏輯由根 crate 收斂到 crates 的順序與退出證據 |
| [重建帳本](experimental-rebuild-plan.zh-TW.md) | Stage 0–6 受控驗證；結構 WP 不改寫其證據，未來 record 須用新來源契約 |
| [已知問題](../KNOWN_ISSUES.md) | 產品限制與發布門禁 |

版本、資料庫遷移、XEP 支援、需求追溯與交接等其他狀態的權威文件，列在 `docs/README.md` 的
[狀態地圖](../README.md#status-map)。

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
| WP-48a | 完成，三個提交：WP-48 的路徑改寫會使十個超標檔變長（見 5.2），先把其中八個檔案的內嵌測試模組移為子檔，作法同 WP-30、WP-47：`bosh.rs`、`db/reports.rs`、`security/tls.rs`、`services/sm.rs`、`xmpp/protocol/messaging.rs`、`xmpp/protocol/sm.rs` 的 `tests`，`xmpp/protocol.rs` 的 `legacy_sasl_wire_tests`，`xmpp/protocol/misc.rs` 的 `legacy_tests`。父檔保留 `#[cfg(test)] mod <名稱>;`，本體少一層縮排，但 `services/sm` 測試中多行 SQL 字串的續行保留原縮排，字串內容不變；rustfmt 另把 42 個敘述合併成較少行。架構師以腳本與 rustfmt 產生預期檔，agy 產出的 16 個檔案逐位元組相同；`services/sm/tests.rs` 第一次留下 350 行未去縮排，經兩次定點修正。綁定兩處：`check-session-lifecycle-boundary.mjs` 改從 `legacy_sasl_wire_tests.rs` 讀取回歸測試 `drop_requires_local_quiesce(false, 1)`，`runtime-experiments.json` 的 session-regression 測試路徑改為 `services/sm/tests.rs`。只移動檢查把 `security/tls.rs` 的一個測試判為不同：行尾 `\` 續行的字串少一層縮排，但值不變。因此先以單獨提交讓檢查器比較前刪去續行開頭的空白（見 5.2），並補自測。2,191 個測試名稱不變。接著改寫這十個檔案與搬出的測試檔中 199 處舊路徑（`outbound` 157、`crl` 14、`abuse` 11 等），檔案中不再有舊路徑；`db/sm.rs`（48 處）與 `cluster/listener.rs` 以 `use crate::xmpp::outbound;` 匯入一次再寫 `outbound::X`，否則仍會變長，其餘檔案寫完整路徑。架構師以 WP-48 的 codemod 與 rustfmt 算出結果，寫成五份共 182 處的精確替換，agy 的結果逐位元組相同。基線只在最後一次調降，與 WP-48a 之前比較：仍超標的 `bosh.rs` 3,229→2,122、`security/tls.rs` 2,190→1,570、`xmpp/protocol.rs` 2,781→2,330、`xmpp/protocol/messaging.rs` 2,926→2,601、`db/sm.rs` 2,031→2,030、`cluster/listener.rs` 1,637→1,634；`db/reports.rs`、`services/sm.rs`、`xmpp/protocol/misc.rs`、`xmpp/protocol/sm.rs` 降到上限內，移出基線；結果與 `--update` 相同。途中 agy 1.3.3 不再提供原本的模型，改用 Gemini 3.8 Flash。9 個反例均被抓到：回歸測試改弱（session lifecycle 門禁）；錨點測試改名（執行實驗目錄）；以下四個由只移動檢查抓到：搬移後的斷言反轉、續行字串的內容改動、SQL 續行少一層縮排、刪掉一個搬移的測試；`bosh.rs`、`cluster/listener.rs` 各加一行，`services/sm.rs` 加到 1,501 行（結構門禁） | 見 `git log --grep '\[WP-48a\]'` |
| WP-48b | 完成：`src/db/` 36 個檔案與 `storage.rs`、`storage/s3.rs`、`stage4_replay.rs` 改用分層路徑，共 216 處（`crate::outbound` 126、`abuse` 44、`password_work` 14、`config` 8、`workers` 4 等，另有 `use crate::{…}` 群組中的項目），這些檔案中不再有舊路徑；超標檔都沒有變長，基線不變。架構師先在暫存副本以 WP-48 的 codemod 與 rustfmt 算出結果並跑過全部門禁，找出綁定 db 程式碼的門禁片段三處，在同一 WP 改寫：`check-abuse.mjs` 的註冊交易 CPU 許可參數型別、`check-execution-boundaries.mjs` 的 MIX 認領投影與 BOSH bind 擁有權，以及其自測中的 MIX 投影變異。agy 依 193 處精確替換產出，結果逐位元組相同。途中一份含 8 個 abuse／帳號儲存庫檔案的規格被 Gemini 的內容政策過濾拒收（秒退、未改任何檔案），改為逐檔送出後全部接受，之後的規格避免把這類檔案集中在同一份。2,191 個測試名稱不變。4 個反例均被抓到：註冊交易的 CPU 許可改為 `Option`（`check-abuse.mjs`）；MIX 認領投影的租約權杖換成常數、BOSH bind 不再複製成員收據、BOSH bind 改回舊路徑（執行門禁） | 見 `git log --grep '\[WP-48b\]'` |
| WP-48c | 完成：`src/state.rs` 與 `src/state/` 58 個檔案改用分層路徑，共 161 處（`crate::outbound` 34、`config` 18、`metrics` 15、`workers` 11、`operation_runtime` 10 等，另有 `use crate::{…}` 群組中的項目），這些檔案中不再有舊路徑；超標檔都沒有變長，基線不變。綁定 state 程式碼的門禁片段只有一處，在同一 WP 改寫：`check-architecture-boundaries.mjs` 要求執行期控制刷新工作者以 `crate::runtime::workers::WorkerCriticality::Critical` 與 `WorkerMode::Continuous` 受監督。agy 依 153 處精確替換產出，結果逐位元組相同。2,191 個測試名稱不變。3 個反例均被架構門禁抓到：刷新工作者改為 `Restartable`、看門狗改為固定 30 秒、改回舊路徑 | 見 `git log --grep '\[WP-48c\]'` |
| WP-48d | 完成：`src/xmpp/` 39 個檔案與 `src/bosh/` 6 個檔案改用分層路徑（`bosh.rs` 本身已在 WP-48a 處理），共 196 處（`crate::outbound` 129、`abuse` 22、`workers` 18、`password_work` 6 等，另有 `use crate::{…}` 群組中的項目），這些檔案中不再有舊路徑。`bosh/response_owner.rs` 的內容被 Stage 4 證據釘住（見 5.2），保留四處 `crate::outbound`；同一 WP 的第一個提交先恢復 WP-48b 改到的 `stage4_replay.rs`，並把 19 個被釘住檔案的 SHA-256 記錄為結構基線的 `pinned`，結構門禁比對內容，`--update` 保留這些項目，自測增加 4 個。超標檔都沒有變長，基線不變。`transport_parsing`、`mam_pubsub_parsing` 在此失去最後的呼叫端，未使用的 import 會讓 clippy 失敗，因此一併刪除 `main.rs` 中這兩個轉出；之後每個子 WP 刪除自己清空的轉出，其餘留給 WP-48g。綁定這些程式碼的門禁片段在同一 WP 改寫：架構門禁的 MIX 外送工作者監督參數（`crate::runtime::workers`），以及執行門禁的三處 `crate::xmpp::outbound` 片段（BOSH 啟用的第一個 `OutboundItem`、MIX 本地型別化移交的三個 `MixTransportCompletion` 分支、SM 記錄的 `DurableDeliverySuperseded` 判斷）與其自測中的對應變異。agy 依 196 處精確替換產出，結果逐位元組相同；完整 CI 因 `response_owner.rs` 的 Stage 4 歷史綁定測試失敗，架構師恢復該檔與執行門禁中它的來源欄位片段。第一個提交的 17 處替換由 agy 產出，自測檔結尾多一個空行，經一次定點修正後相同。2,191 個測試名稱不變。12 個反例均被抓到：MIX 外送工作者改為 `Critical` 或改回舊路徑（架構門禁）；三處片段各改回舊路徑、SM 記錄在任何檢查點錯誤後都還原（執行門禁）；`stage4_replay.rs` 改用分層路徑、`response_owner.rs` 改用分層路徑、`compact.rs` 與存檔夾具被改（結構門禁）；門禁不再比對雜湊、`--update` 丟掉 `pinned`（結構自測） | 見 `git log --grep '\[WP-48d\]'` |
| WP-48e | 完成：`src/services/` 26 個檔案與 `src/api/` 17 個檔案改用分層路徑，另加 `crate::abuse` 的最後一個呼叫端，共 171 處（`crate::outbound` 71、`abuse` 52、`error` 10、`config` 9、`workers` 8 等，另有 `use crate::{…}` 群組中的項目），這些檔案中不再有舊路徑；超標檔都沒有變長，基線不變；`error`、`password_work`、`abuse` 的轉出失去最後的呼叫端而刪除：services 與 api 改完後，`crate::abuse` 只剩 `s2s/inbound_tests.rs` 的一個測試使用，它只在 `cfg(test)` 編譯，`abuse` 轉出在二進位建置中成為未使用的 import，clippy 失敗；因此這一行提前在此改寫（原屬 WP-48f），並刪除 `abuse` 轉出，由架構師直接修改。舊的預期鏈只在 48d 與 48g 跑過 clippy，48e 的這個問題到 worktree 驗證才發現。執行門禁的原生 MIX 確認片段改為 `crate::xmpp::outbound`。`fuzz/fuzz_targets/rest_extractors.rs` 以 `#[path]` 引入 `src/api/extract.rs` 並提供 `AppError` 替身，`extract.rs` 改用 `crate::platform::error` 後，替身由 `mod error` 移入 `mod platform { pub mod error }`。fuzz crate 無法離線建置（缺 `libfuzzer-sys`），架構師以暫存 crate 搭配 `libfuzzer-sys` 的本地替身編譯同一檔案：新舊兩檔一致時通過，新 `extract.rs` 配舊替身時失敗。agy 依 153 處精確替換產出，結果逐位元組相同；規格依敏感詞數分組（每份約 24 個以內）以避開 Gemini 內容過濾。2,191 個測試名稱不變。3 個反例均被抓到：原生 MIX 確認改回舊路徑或不轉交請求（執行門禁）、fuzz 替身留在 `mod error`（fuzz 檢查） | 見 `git log --grep '\[WP-48e\]'` |
| WP-48f | 完成：其餘呼叫端改用分層路徑：`src/cluster.rs` 與 `src/cluster/` 12 個、`src/runtime/` 9 個、`src/s2s/` 8 個、`src/platform/` 與 `src/tools/` 各 2 個檔案，以及 `src/security/account_recovery.rs`，共 163 處（`crate::cluster_security` 55、`outbound` 40、`workers` 16、`config` 10 等，另有 `use crate::{…}` 群組中的項目）；除 `main.rs` 與兩個被 Stage 4 證據釘住的檔案（WP-48d）外，整個 crate 不再有舊路徑。超標檔都沒有變長，基線不變；`cluster_security`、`metrics`、`connection_actors`、`crl`、`ocsp`、`tls` 的轉出失去最後的呼叫端而刪除；`outbound` 的轉出留給那兩個檔案，其餘轉出只有 `main.rs` 自己使用。綁定這些程式碼的門禁片段在同一 WP 改寫：聯邦路由門禁的 S2S 直接路由 adapter 簽名（`crate::xmpp::outbound`）與其自測，以及子伺服器門禁的維護訂閱清理看門狗（樣式由可選的 `crate::` 改為可選的 `crate::runtime::`）與其自測。agy 依 154 處精確替換產出，結果逐位元組相同。2,191 個測試名稱不變。4 個反例均被抓到：adapter 改回舊路徑或改為借用 enqueue（聯邦路由門禁）；清理看門狗改回舊路徑或改為固定 5 秒（子伺服器門禁） | 見 `git log --grep '\[WP-48f\]'` |
| WP-48g | 完成：刪除 `main.rs` 剩下的 14 個舊路徑轉出（只有 `main.rs` 自己使用），`main.rs` 自身 43 處改用分層路徑（`platform::config::Config`、`runtime::subservers::run_maintenance`、`tools::pie::run` 等），此後舊路徑只剩 `crate::outbound` 仍可編譯：Stage 4 證據釘住內容的 `bosh/response_owner.rs` 與 `stage4_replay.rs` 還使用它（見 5.2），`main.rs` 保留 `use xmpp::outbound;` 並註明原因。結構門禁改為拒絕其他檔案使用 `crate::outbound`（直接寫或作為 `use crate::{…}` 群組的項目，註解除外），自測增加 2 個、擴充 1 個。讀取 `main.rs` 的門禁片段同步改寫：架構門禁的 `platform::logging::report_result(run().await)` 與工作者註冊表中的清理看門狗，以及子伺服器門禁的維護分派。架構門禁有兩條排除規則（caps 效果分派不得接收 `&Metrics`、帳號刪除復原不得持有 `Arc<Metrics>`）原本只接受可選的 `crate::metrics::` 前綴，自 WP-43 起有效的 `crate::platform::metrics::Metrics` 可以繞過，反例證實舊樣式抓不到；改為接受 `crate::`、`platform::`、`metrics::` 任意組合的前綴。agy 依 54 處精確替換產出，結果逐位元組相同。2,191 個測試名稱不變。8 個反例均被抓到：`main` 的結果回報改回舊路徑、清理看門狗改為固定 5 秒、caps 接收 `&crate::platform::metrics::Metrics`、復原持有 `Arc<crate::platform::metrics::Metrics>`（架構門禁）；維護分派改回舊路徑（子伺服器門禁）；其他檔案直接寫 `crate::outbound` 或在群組中寫 `outbound::…`（結構門禁）、門禁不再檢查群組項目（結構自測） | 見 `git log --grep '\[WP-48g\]'` |
| WP-49 | 完成，兩個提交，處理 S2–S4 留下的三個後續項目。`check-subserver-boundaries.mjs` 盤點結構欄位的正規表示式只接受 `pub` 與 `pub(crate)`，宣告為 `pub(super)` 或 `pub(in …)` 的欄位不列入盤點，新增欄位可繞過能力清單；改為接受任何 `pub(…)`，現有四個結構沒有這類欄位，結果不變，自測增加 2 個。`xmpp/protocol/mix/session.rs` 中 `push_mix_roster_update` 上方的註解描述的是 MIX 投遞工作者（從拆分前的 `mix.rs` 帶來），改為描述函式本身。`check-move-only.mjs` 把只含一個運算式的 match 分支區塊視同去掉區塊的寫法（rustfmt 隨縮排在兩者間切換，見第 6 節），有頂層 `;`、註解或開頭屬性的區塊與空區塊照原樣比較；WP-26 以 `--after-rev` 重新稽核由不同（1／1）變為相同，其他拆分 WP 的稽核結果不變，自測增加 1 個。agy 依 8 處精確替換產出，結果逐位元組相同；架構負責人審閱探針後在自測補 3 行守衛斷言（合法 Rust 的比較無法區分有無 `;` 守衛）。9 個反例都失敗：兩個受限可見性的新欄位（門禁）、舊正規表示式（自測）、不展開區塊（自測與 WP-26 稽核）、拿掉 `;`／註解／屬性／空區塊守衛（自測） | 見 `git log --grep '\[WP-49\]'` |
| WP-61 | 完成：`KNOWN_ISSUES.md` 開頭的遷移鏈敘述由 `0001`–`0156`／155 項改為 `0001`–`0158`／157 項。這句話在 9/29 的審計中已漂移過一次，因此文件一致性門禁改由 `migrations/` 推導範圍、數量與刻意缺號（現為 `0021`），忽略空白後逐字比對；新增 migration 或出現新缺號而沒有同步這句話時失敗。`README.md` 與 `docs/README.zh-TW.md` 的發行套件段落原寫「維護者發佈後提供」，改為已發佈（`v0.2.0` 於 2026-09-20 發佈），保留 tag workflow 先建草稿、審閱後才發佈的說明；發佈狀態無法離線驗證，不加門禁。agy 依 5 處精確替換產出，結果逐位元組相同；5 個反例（舊範圍、舊數量、缺少缺號、新增 migration 並同步四份操作文件的連結、移走一個 migration）都由新檢查抓到 | 見 `git log --grep '\[WP-61\]'` |
| WP-62 | 完成：`docs/HANDOFF.md` 停在 2026-09-29（等待是否重跑浸泡），以 `git mv` 移為 `docs/handoff/2026-09-29/HANDOFF.md`，開頭註明為歷史快照並連到現行交接，8 個相對連結多兩層 `../`。新的 `docs/HANDOFF.md` 只記錄不屬於其他權威文件的現況（分支與推送、本機 VM 實驗室、接手步驟），其餘只連結；VM 狀態（六台 shut off、沒有 `northstar*` user unit、私有證據沒有 9/29 之後的浸泡紀錄）於 2026-10-13 核對。`docs/README.md` 新增狀態地圖，列出九類狀態各自的權威文件（第 1 節第 5 項），`src/` 一列連到本文。文件一致性門禁要求狀態地圖存在並連結這九個權威來源，且現行交接連結狀態地圖。agy 依 10 處精確替換與 1 個新檔產出，結果逐位元組相同；6 個反例（缺少地圖標題、地圖缺交接或本文、migrations 連結移出地圖、交接不連結地圖、移動後的交接保留舊相對連結）都失敗 | 見 `git log --grep '\[WP-62\]'` |
| WP-63 | 完成：WP-48 留下只在內文提到的舊路徑（見 5.2）。15 份文件（`docs/` 6 份與 9 份 `crates/*/MIGRATION.md`）中 48 處根目錄模組路徑改為分層路徑（`cluster_security` 改為 `src/cluster/security.rs`）。`docs/architecture/resource-bounds.zh-TW.md` 的 23 個原始碼連結帶著審閱時的行號，搬移後已不對應；改為固定到審閱提交 `f1e4f83` 的 GitHub 永久連結（四個已搬移的檔案用該提交的舊路徑），並註明行號屬於該提交。文件一致性門禁新增第 4 節 R8：現行文件與 MIGRATION.md 寫出 26 個已移走模組的根目錄路徑（含 `../src/` 與目錄形式）時失敗；有日期的紀錄、`CHANGELOG.md`、本文與 `http(s)` 連結略過，摘要行加上通過的文件數。agy 依 5 份規格共 41 處精確替換產出（內容過濾器限制每份規格的敏感詞數，`northstar-abuse-policy` 另拆兩份）；`northstar-xep-0059/MIGRATION.md` 少了檔首 BOM，由架構負責人補回，其餘逐位元組相同（預期檔原本漏了該檔的 7 個 CR，以 agy 保留的原始位元組為準）。8 個探針：現行文件、MIGRATION.md、未連結的 `../src/` 形式與目錄形式的舊路徑都失敗；固定提交的連結、crate 內部路徑、有日期的交接與 `CHANGELOG.md` 都通過 | 見 `git log --grep '\[WP-63\]'` |
| WP-71a | 完成：`src/xmpp/` 13 個超標檔的 14 個頂層內嵌測試模組（195 個測試）移為子檔，例如 `frame_execution.rs` 移為 `frame_execution/tests.rs`；`saved_case.rs` 的兩個模組分別移為 `saved_case/route_observation_tests.rs` 與 `saved_case/replacement_gate_tests.rs`。原處只留 `#[cfg(test)] mod <模組>;`。13 個父檔由 31,375 行減為 21,654 行；子檔共 9,639 行，最大的 2,045 行，在測試上限內。基線刪除 6 個降到上限內的條目（`frame_execution.rs`、`auth_publication.rs`、`caps.rs`、`dispatch.rs`、`saved_stage4.rs`、`sm_owner.rs`），下修 7 個（如 `pep.rs` 由 3,884 減為 3,308）。`pep/tests.rs` 的 `include_str!` 改讀 `../pep.rs`；`catalog/runtime-experiments.json` 中 frame_execution 測試的錨點由 `mod tests {` 改為 `mod tests;`。架構負責人以腳本產生預期檔（去縮排、`cargo fmt`、修正相對路徑與錨點、基線 `--update`），每個模組一份規格，列出去縮排後被 rustfmt 重排的行。agy 依 15 份規格產出，`presence/tests.rs` 有兩處 `assert_eq!` 少了 `!`，由架構負責人補回，其餘逐位元組相同。2,191 個測試名稱不變。3 個反例都失敗：錨點改回 `mod tests {`（執行實驗門禁）、`presence.rs` 多一行（結構門禁）、`include_str!` 改回原路徑（無法編譯） | 見 `git log --grep '\[WP-71a\]'` |
| WP-71b | 完成：`src/db/` 14 個超標檔的 16 個頂層內嵌測試模組（95 個測試）移為子檔，例如 `roster.rs` 的 `blocking_match_tests` 移為 `roster/blocking_match_tests.rs`；`capacity.rs` 與 `cluster_keys.rs` 各有兩個模組。14 個父檔由 32,418 行減為 23,726 行；子檔共 8,626 行，最大的 1,439 行。基線刪除 6 個降到上限內的條目（`capacity.rs`、`cluster_keys.rs`、`data_lifecycle.rs`、`messaging.rs`、`profile.rs`、`s2s.rs`），下修 8 個（如 `roster.rs` 由 3,927 減為 2,480）。相對路徑多一個 `../` 的有 `api_operations/tests.rs` 的 `include!`，以及 `capacity`、`cluster_keys`、`data_lifecycle`、`replay` 子檔讀 migration、部署 grants SQL 與父檔的 8 個 `include_str!`（`replay.rs` 改讀 `../replay.rs`）。agy 依 17 份規格產出，3 個子檔有縮排差異，由架構負責人改回，其餘逐位元組相同。`api_operations/tests.rs` 的 35 行 SQL 續行都多一格：規格把要原樣保留的續行列成「`line N: 原文`」，agy 把冒號後的分隔空白算進縮排；m4 起改列為「`line N (K leading spaces): 去掉前導空白的文字`」，之後的 88 行續行都正確（第 6 節第 5 項）。`messaging/tests.rs` 與 `admin_commands/boundary_tests.rs` 各有 2 行多去掉 4 格。2,191 個測試名稱不變。3 個反例都失敗：`roster.rs` 多一行、刪除條目的 `cluster_keys.rs` 增為 1,505 行（結構門禁）、`include!` 改回原路徑（無法編譯） | 見 `git log --grep '\[WP-71b\]'` |
| WP-71c | 完成：其餘 18 個超標檔的 22 個頂層內嵌測試模組（241 個測試）移為子檔，分布在 `src/api/`、`src/runtime/`、`src/s2s/`、`src/services/`、`src/storage*`、`src/tools/` 與 `direct_replay.rs`。`services/muc.rs` 有四個模組，`direct_workflow.rs` 有兩個；`api/mod.rs` 的子檔是同一目錄的 `api/tests.rs`。18 個父檔由 38,553 行減為 27,011 行；子檔共 11,451 行，最大的 1,333 行。基線刪除 10 個降到上限內的條目，下修 8 個（如 `services/mix.rs` 由 3,616 減為 3,289）。`api/system/tests.rs` 的 8 個 `include_str!`／`include_bytes!` 路徑多一個 `../`；`catalog/runtime-experiments.json` 中 workers 測試錨點的路徑改為 `src/runtime/workers/tests.rs`。結構門禁新增 R1 的內嵌測試規則：`countInlineTestModules` 計算沒有縮排、屬性含 `#[cfg(test)]` 或 `#[cfg(all(test, …))]` 的 `mod 名稱 {`；基線中的超標生產檔含這類模組時失敗，釘住的檔案除外（`stage4_replay.rs` 與 `bosh/response_owner.rs` 各保留一個）。自測增加 2 個、擴充 1 個。agy 依 24 份規格產出，結果逐位元組相同。兩次網路中斷（m3、m9）由驅動程式停下後重跑；此後只有在 agy 沒有改動任何檔案時，驅動程式才自動重試。2,191 個測試名稱不變。6 個反例中 5 個失敗：workers 錨點改回原路徑（執行實驗門禁）；`services/mix.rs` 放回內嵌測試模組（基線同步調高，以排除行數規則），以及 `tools/pie.rs` 加入 `#[cfg(all(test, unix))] pub(crate) mod`（結構門禁）；計數改為不累加（自測）；`api/system/tests.rs` 的 `include_str!` 改回原路徑（無法編譯）。測試檔內的內嵌模組依設計不受限，該反例照常通過 | 見 `git log --grep '\[WP-71c\]'` |
| WP-81a | 完成：`db/pubsub_repository.rs` 3,513 行拆為 conversions／outbox_rendering／pubsub_ports／pubsub_outbox／pep_ports，父檔 655 行，最大子檔 `pep_ports.rs` 1,090 行；子檔只含 trait impl，父檔只宣告模組。69 個項目不變，沒有可見性變更 | 見 `git log --grep '\[WP-81a\]'` |
| WP-81b | 完成：`db/api_operations.rs` 2,106 行拆為 operation_queue／operation_leases／target_leases／reconciliation，父檔 381 行；以 `pub use self::子模組::*;` 轉出。74 個項目不變，9 項可見性變更 | 見 `git log --grep '\[WP-81b\]'` |
| WP-81c | 完成：`db/upload.rs` 1,657 行拆為 slots／lifecycle／capacity_audit／storage_jobs／deletion，父檔 212 行；59 個項目不變，7 項可見性變更。`upload_tests.rs` 三個以 `include_str!("upload.rs")` 切割函式的測試在拆分後失敗（盤點漏看，見第 6 節第 8 點），改讀 `MODULE_SOURCE`；`upload_tests.rs` 已超過測試檔上限，完整 CI 的結構門禁拒絕它變長，守衛測試因此放在新的 `upload/module_source_tests.rs` | 見 `git log --grep '\[WP-81c\]'` |
| WP-81d | 完成：`tools/identity_audit.rs` 1,932 行拆為 identity_findings／schema／semantic_findings／invariants，父檔 566 行；64 個項目不變，27 項可見性變更 | 見 `git log --grep '\[WP-81d\]'` |
| WP-81e | 完成：`xmpp/protocol/messaging/saved_case.rs` 1,980 行拆為 ports／native／runs，父檔 510 行；87 個項目不變，29 項可見性變更 | 見 `git log --grep '\[WP-81e\]'` |
| WP-81f | 完成：`direct_replay.rs` 1,726 行拆為 case／evidence／delivery_evidence，父檔 493 行；157 個項目不變，1 項可見性變更。WP-81a–f 由 codex 平行執行，各自通過只移動檢查；整合後 fmt、clippy、單元測試與完整 CI（15 項通過、2 項本機略過）通過，基線刪除 6 個條目 | 見 `git log --grep '\[WP-81f\]'` |
| WP-82a | 完成：架構門禁對 27 個拆分目標改讀正式模組；協議目錄的清點只對 6 個目標讀模組、其餘維持單檔；`listen_once` 改以 `rustItemBody` 擷取，abuse 的 admission 檢查改為遮蔽測試模組而非在第一個測試模組截斷，MIX permit 的錯誤訊息指出子檔與行號。codex 執行 168 次反例，全部如預期 | 見 `git log --grep '\[WP-82a\]'` |
| WP-82b | 完成：對外 XML 門禁的 `services/mix.rs` 由只讀單檔改為讀正式模組並排除既有子樹 `foreground`、`outbox`（仍有原始 XML），拆出的新子檔受零預算約束；新增自測 `test-outbound-xml-construction.mjs`（14 個案例）接入 CI | 見 `git log --grep '\[WP-82b\]'` |
| WP-82c | 完成：執行、admission、子伺服器、聯邦路由與 session 生命週期門禁對 14 處讀取改讀正式模組；SASL2 計時器檢查改以 `findRustItem` 擷取入口函式，執行門禁的認證檢查逐一移除測試模組（自測增加 3 個） | 見 `git log --grep '\[WP-82c\]'` |
| WP-82d | 完成：遷移版本、資料庫角色、MUC 叢集與能力清單門禁對 6 個目標改讀正式模組；能力清單的 SQL 安全掃描逐一檢查 `db/role_attestation` 的每個正式檔案並報出子檔路徑與行號，儲存與命令角色的認證改以宣告擷取，不再以標頭之間切割 | 見 `git log --grep '\[WP-82d\]'` |
| WP-82e | 完成：`check-abuse.mjs` 對 `security/abuse`、`protocol/messaging`、`db/users`、`xml_util` 改讀正式模組；users 的交易檢查改以宣告擷取。WP-82a–e 由 codex 平行執行；整合後架構負責人在 4 個目標放入反例子檔，門禁均失敗；全部門禁、自測與完整 CI 通過 | 見 `git log --grep '\[WP-82e\]'` |
| WP-82f | 完成：架構門禁的三個直接呼叫 db:: MIX 掃描，原只豁免 `db/mix_repository.rs` 單檔，改為豁免該模組的正式檔案（測試檔照舊受檢）；執行門禁的 `MucService<R>` 檢查改選含 `fn new` 的那個同標頭 impl 區塊（`bodyContaining`），沒有或多於一個都失敗。自測增加 3 個 | 見 `git log --grep '\[WP-82f\]'` |
| WP-82g | 完成：`catalog/source-role-splits.json` 列出 `xmpp/protocol.rs`、`api/mod.rs`、`bosh.rs` 拆出的角色子檔；`source-module.mjs` 新增 `roleSplitFiles`／`readRoleSplitFile`／`validateRoleSplits` 與 `--role-split`，結構門禁驗證清單（排序、子檔存在且為葉檔、父檔有非測試的 `mod` 宣告且依宣告順序）。架構、abuse、web-auth、OMEMO、對外 XML、執行、session 生命週期、遷移版本與 runtime experiments 門禁對這三檔的單檔讀取改讀「父檔＋所列子檔」。清單為空時十個門禁輸出逐字相同；把 `bosh/action.rs` 列為子檔並放入 `protocol.state` 時架構門禁失敗，清單損毀時遷移與結構門禁失敗 | 見 `git log --grep '\[WP-82g\]'` |
| WP-82h | 完成：WP-83t、83w 拆分後執行門禁本身仍通過，但兩個自測失敗：sasl2 的 `impl ProtocolSession` 在每個檔案各出現一次而無法唯一擷取，改取含 `payload.replace_envelope(` 的區塊；BOSH、SM 與 BOSH 回應的變異輔助在第一個 `#[cfg(test)] mod tests` 截斷，模組讀取時會把附在父檔 `mod tests;` 宣告之後的子檔一併截掉，改為只以行內 `mod tests { ... }` 為界（同時讓 WP-84c 後的 BOSH 變異仍有效）。拆分前後 609 個自測都通過 | 見 `git log --grep '\[WP-82h\]'` |
| WP-82i | 完成：只移動檢查以去掉 `.rs` 推導子目錄，`api/mod.rs` 因此在 `api/mod/` 找子檔、只比較父檔；改為讀 `mod.rs` 所在的目錄，工作樹走訪也不再重複列出父檔。新增的 CLI 測試 h2 把 `mod.rs` 父檔拆出同目錄子檔，不修正時失敗。由 WP-84b 的拆分發現 | 見 `git log --grep '\[WP-82i\]'` |
| WP-83a | 完成：`s2s/inbound.rs` 3,822 行拆為 negotiation／session／dispatch／presence／iq，父檔 948 行，最大子檔 `negotiation.rs` 724 行；77 個項目不變，48 項可見性變更。`s2s/inbound_tests.rs` 的原始碼讀取改讀 `MODULE_SOURCE`（R4） | 見 `git log --grep '\[WP-83a\]'` |
| WP-83b | 完成：`xmpp/protocol/pep.rs` 3,308 行拆為 publishing／notifications／node_management／payload_validation，父檔 814 行，最大子檔 `publishing.rs` 731 行；92 個項目不變，35 項可見性變更。模組內的 `pep/tests.rs` 改讀 `MODULE_SOURCE`，在只移動檢查中顯示為一個只改讀取行的項目 | 見 `git log --grep '\[WP-83b\]'` |
| WP-83c | 完成：`services/mix.rs` 3,289 行拆為 contracts／operations／payloads／wake，父檔 1,001 行，最大子檔 `contracts.rs` 968 行；268 個項目不變，13 項可見性變更 | 見 `git log --grep '\[WP-83c\]'` |
| WP-83d | 完成：`xmpp/protocol/pubsub.rs` 3,220 行拆為 entity／owner／forms，父檔 1,221 行，最大子檔 `entity.rs` 987 行；115 個項目不變，17 項可見性變更 | 見 `git log --grep '\[WP-83d\]'` |
| WP-83e | 完成：`db/muc.rs` 3,149 行拆為 membership／history／admin，父檔 1,121 行，最大子檔 `membership.rs` 781 行；89 個項目不變，14 項可見性變更。`db/cluster_muc_tests.rs` 的原始碼讀取改讀 `MODULE_SOURCE` | 見 `git log --grep '\[WP-83e\]'` |
| WP-83f | 完成：`db/users.rs` 2,828 行拆為 registration／authentication／api_sessions，父檔 1,265 行，最大子檔 `authentication.rs` 862 行；93 個項目不變，10 項可見性變更。`db/upload_tests.rs` 讀 `db/users.rs` 的測試改讀 `MODULE_SOURCE` | 見 `git log --grep '\[WP-83f\]'` |
| WP-83g | 完成：`xmpp/xml_util.rs` 2,697 行拆為 muc／message_validation／stanza_rewrite，父檔 1,216 行，最大子檔 `message_validation.rs` 847 行；117 個項目不變，32 項可見性變更 | 見 `git log --grep '\[WP-83g\]'` |
| WP-83h | 完成：`security/abuse.rs` 2,622 行拆為 key_management／persistence／challenges，父檔 916 行，最大子檔 `challenges.rs` 701 行；201 個項目不變，49 項可見性變更 | 見 `git log --grep '\[WP-83h\]'` |
| WP-83i | 完成：`db/roster.rs` 2,480 行拆為 persistence／presence／blocking，父檔 717 行，最大子檔 `presence.rs` 933 行；80 個項目不變，21 項可見性變更 | 見 `git log --grep '\[WP-83i\]'` |
| WP-83j | 完成：`db/replay.rs` 2,396 行拆為 presence_policy／offline_delivery／bosh_transport，父檔 717 行，最大子檔 `offline_delivery.rs` 872 行；56 個項目不變，17 項可見性變更。模組內的 `replay/bosh_ack_bound_schema_tests.rs` 改讀 `MODULE_SOURCE`，在只移動檢查中顯示為一個只改讀取行的項目 | 見 `git log --grep '\[WP-83j\]'` |
| WP-83k | 完成：`tools/pie.rs` 2,219 行拆為 export_data／import_loading／import_payloads，父檔 745 行，最大子檔 `import_payloads.rs` 606 行；124 個項目不變，35 項可見性變更。`db/upload_tests.rs` 讀 `tools/pie.rs` 的測試改讀 `MODULE_SOURCE` | 見 `git log --grep '\[WP-83k\]'` |
| WP-83l | 完成：`services/pubsub.rs` 2,214 行拆為 repository_access／outbox，父檔 1,226 行，最大子檔 `outbox.rs` 520 行；130 個項目不變，3 項可見性變更 | 見 `git log --grep '\[WP-83l\]'` |
| WP-83m | 完成：`s2s/components.rs` 2,049 行拆為 connections／session／wire，父檔 523 行，最大子檔 `session.rs` 601 行；107 個項目不變，41 項可見性變更 | 見 `git log --grep '\[WP-83m\]'` |
| WP-83n | 完成：`db/admin_commands.rs` 2,037 行拆為 accounts／command_sessions／runtime_control，父檔 910 行，最大子檔 `runtime_control.rs` 453 行；73 個項目不變，4 項可見性變更 | 見 `git log --grep '\[WP-83n\]'` |
| WP-83o | 完成：`xmpp/protocol/messaging.rs` 2,036 行拆為 message_delivery，父檔 601 行，子檔 1,445 行；144 個項目不變，沒有可見性變更 | 見 `git log --grep '\[WP-83o\]'` |
| WP-83p | 完成：`db/sm.rs` 2,030 行拆為 lifecycle／persistence，父檔 972 行，最大子檔 `persistence.rs` 716 行；60 個項目不變，15 項可見性變更 | 見 `git log --grep '\[WP-83p\]'` |
| WP-83q | 完成：`services/muc.rs` 1,846 行拆為 room_operations／cluster_operations，父檔 968 行，最大子檔 `room_operations.rs` 543 行；155 個項目不變，沒有可見性變更 | 見 `git log --grep '\[WP-83q\]'` |
| WP-83r | 完成：`xmpp/protocol/commands.rs` 1,754 行拆為 execution／forms，父檔 687 行，最大子檔 `execution.rs` 691 行；82 個項目不變，21 項可見性變更 | 見 `git log --grep '\[WP-83r\]'` |
| WP-83s | 完成：`s2s/outbound.rs` 1,731 行拆為 connection／transport，父檔 816 行，最大子檔 `connection.rs` 483 行；69 個項目不變，19 項可見性變更 | 見 `git log --grep '\[WP-83s\]'` |
| WP-83t | 完成：`db/mix_repository.rs` 1,727 行拆為 repository_impl，父檔 285 行，子檔 1,448 行；33 個項目不變，沒有可見性變更 | 見 `git log --grep '\[WP-83t\]'` |
| WP-83u | 完成：`xmpp/protocol/presence.rs` 1,705 行拆為 subscriptions／availability，父檔 860 行，最大子檔 `availability.rs` 533 行；39 個項目不變，22 項可見性變更 | 見 `git log --grep '\[WP-83u\]'` |
| WP-83v | 完成：`cluster/listener.rs` 1,634 行拆為 responses，父檔 1,473 行，子檔 173 行；14 個項目不變，12 項可見性變更；`listen_once` 是單一函式，整體留在父檔 | 見 `git log --grep '\[WP-83v\]'` |
| WP-83w | 完成：`xmpp/protocol/sasl2.rs` 1,609 行拆為 parsing／authentication，父檔 826 行，最大子檔 `parsing.rs` 481 行；64 個項目不變，18 項可見性變更。對外 XML 門禁以檔案、行號與值豁免的 `</stream:stream>` 字面值由第 627 行移到第 136 行，allowlist、門禁內的自檢與 `test-outbound-xml-construction.mjs` 一併更新 | 見 `git log --grep '\[WP-83w\]'` |
| WP-83x | 完成：`db/role_attestation.rs` 1,573 行拆為 manifests／catalog，父檔 592 行，最大子檔 `manifests.rs` 549 行；34 個項目不變，9 項可見性變更。搬移的項目都是私有，父檔以私有的 `use self::子模組::*;` 匯入、不轉出（`db/mod.rs` 只轉出公開項目） | 見 `git log --grep '\[WP-83x\]'` |
| WP-83y | 完成：`db/room.rs` 1,570 行拆為 occupancy／conversions，父檔 903 行，最大子檔 `conversions.rs` 535 行；51 個項目不變，8 項可見性變更 | 見 `git log --grep '\[WP-83y\]'` |
| WP-83z | 完成：`security/tls.rs` 1,570 行拆為 certificates／material，父檔 871 行，最大子檔 `certificates.rs` 451 行；102 個項目不變，30 項可見性變更。WP-83a–z 由 codex 分兩批平行執行（每批最多 16 個），各自通過只移動檢查；整合後 fmt、clippy、單元測試、全部門禁與完整 CI（15 項通過、2 項本機略過）通過，基線刪除 26 個條目 | 見 `git log --grep '\[WP-83z\]'` |
| WP-84a | 完成：`xmpp/protocol.rs` 2,330 行拆為 legacy_auth／session_transport／session_sm，父檔 1,034 行，最大子檔 `legacy_auth.rs` 629 行；整個 protocol 模組 1,936 個項目不變，32 項可見性變更。三個子檔列入 `catalog/source-role-splits.json`，以單檔讀取 `protocol.rs` 的門禁隨之讀到搬走的程式碼 | 見 `git log --grep '\[WP-84a\]'` |
| WP-84b | 完成：`api/mod.rs` 1,539 行拆出 route_composition（572 行），父檔 1,009 行；整個 api 模組 534 個項目不變，21 項可見性變更。`api/tests.rs` 與 `api/system/tests.rs` 改讀 `MODULE_SOURCE`，守衛測試 `module_source_lists_every_role_split_child` 比對角色拆分清單 | 見 `git log --grep '\[WP-84b\]'` |
| WP-84c | 完成：`bosh.rs` 2,122 行拆為 response_output／request_policy，父檔 1,409 行，最大子檔 `request_policy.rs` 442 行；380 個項目不變，36 項可見性變更，被釘住的 `bosh/response_owner.rs` 不動。WP-84a–c 由 codex 平行執行，清單條目由整合腳本寫入；整合後 fmt、clippy、單元測試、全部門禁與完整 CI 通過，基線刪除 3 個條目 | 見 `git log --grep '\[WP-84c\]'` |
| WP-91 | 完成：`check-move-only.mjs` 的 `normalizeItems` 接收檔案路徑，`include_str!`／`include_bytes!` 的第一個一般字串參數依所在檔案解析為儲存庫路徑後比對；raw／byte 字串、含跳脫的字串、`include!` 與其他字面值仍逐位元組比對。自測 32 項通過；CLI 測試要呼叫 git，codex 沙箱中無法執行，由架構負責人執行 | 見 `git log --grep '\[WP-91\]'` |
| WP-92a | 完成：`db/upload_tests.rs` 3,429 行拆為 capacity_authority／storage_jobs／capacity_admission／source_contracts 四個子測試模組（`db/upload_tests/*_tests.rs`，最大 1,146 行），父檔留匯入與共用的 `insert_user`（42 行）；23 個項目不變。12 個 `include_str!` 多一個 `../`、3 個 `super::module_source()` 多一層，由只移動檢查確認 | 見 `git log --grep '\[WP-92a\]'` |
| WP-92b | 完成：`db/pubsub_integration_tests.rs` 6,108 行拆為 8 個子測試模組（`db/pubsub_integration_tests/*_tests.rs`，最大 1,099 行），父檔留匯入與共用 helper（380 行）；48 個項目不變，`pubsub-db-wsl.sh` 的 27 個選擇器加上子模組。WP-91、92a、92b 整合後 fmt、clippy、單元測試、全部門禁與完整 CI 通過；去掉子模組一段後 2,199 個測試名稱與 254 個 ignored 測試不變；基線刪除 2 個條目，只剩被釘住的 3 個生產檔 | 見 `git log --grep '\[WP-92b\]'` |
| WP-93 | 完成：`pubsub-db-wsl.sh` 補上 collection_graph 的兩個資料庫測試（子節點擁有權與舊邊不外洩、子節點擁有者撤銷後的邊插入線性化），從此由 CI 的 PubSub 資料庫分片執行；腳本 40 個選擇器各恰好對應一個 ignored 測試 | 見 `git log --grep '\[WP-93\]'` |
| WP-101 | 完成：`catalog/source-layers.json` 以頂層模組定義五層（組合 4、介面卡 3、應用 2、平台 1、facade 0）與各層的 `may_use`，別名 `outbound`→`xmpp`；`scripts/check-layer-dependencies.mjs` 從 `src/main.rs` 沿 `mod` 宣告建立生產模組樹（測試專用 cfg 下的宣告連同子樹排除），去掉檔內測試碼後收集 `crate::` 路徑、use 群組、到達根的 `super::` 與 `pub(in crate::x)` 指向的頂層模組。基線 139 條（110 檔）；新違規、過期的基線項目、不在任何層的目標，以及 `may_use` 列出較高 rank 的 catalog 都失敗。門禁與 33 個自測接入 `web-static` | 見 `git log --grep '\[WP-101\]'` |
| WP-102 | 完成：`runtime/workers.rs`（含測試）與 `runtime/connection_actors.rs` 以 `git mv` 原樣移到 `platform/`；43 個檔案的 92 處路徑、架構門禁的 4 個樣式、`catalog/runtime-experiments.json` 的 3 個錨點與 `docs/PROGRAM_RESPONSIBILITIES.md` 的 2 處路徑隨之改寫；24 個測試的路徑由 `runtime::` 改為 `platform::`，其餘名稱不變。基線減少 18 條 | 見 `git log --grep '\[WP-102\]'` |
| WP-103 | 完成：`state/jid_text.rs` 以 `git mv` 原樣移到 `platform/jid_text.rs`；`state.rs` 改為私有匯入，`state/` 下的模組照舊經 `use super::*;` 取用；api、db、direct_replay、runtime 與 xmpp 的呼叫方改用 `crate::platform::jid_text`。基線減少 6 條 | 見 `git log --grep '\[WP-103\]'` |
| WP-104 | 完成：`SerializableMucOccupant`、`LocalMucOccupantIdentity` 與兩者間的轉換逐字移到 `services::muc::occupancy`，由 `services::muc` 轉出；`MucOccupant` 與兩個 `From<&MucOccupant>` 留在 `state/local_muc.rs`，29 個檔案改用 `crate::services::muc`。基線減少 11 條。WP-101–104 由 codex 平行執行，依序整合，每步以 `--write` 重寫基線且只刪不增；整合後 fmt、clippy、單元測試、全部門禁與完整 CI 通過，基線由 139 條降到 104 條（90 檔） | 見 `git log --grep '\[WP-104\]'` |
| WP-111 | 完成：`services` 的 19 個檔案與 `xmpp/protocol/sm_owner.rs` 共 73 處路徑改為直接引用 workspace crate 中的定義（`northstar_delivery_core` 的遞送型別與 `BoshResponseOwnership`、`northstar_xml_builder::XmlElement`、`northstar_message_core` 的直送模式、`northstar_xep_0016::PrivacyStanzaKind`、`northstar_session_core::JoinedMucMembership`）；`check-execution-boundaries.mjs` 的原生 MIX ACK 期望字串隨路徑更新。基線減少 12 條 | 見 `git log --grep '\[WP-111\]'` |
| WP-112 | 完成：`RetentionStore`、`RetentionRepository` 與 `SubscriptionCleanupRepository` 逐字由 `runtime` 移到新的 `services::maintenance_repositories`，`db` 照舊轉出 `RetentionStore`。基線減少 1 條 | 見 `git log --grep '\[WP-112\]'` |
| WP-113 | 完成：`ConflictPolicy`、`PieUser`、`PreparedUser` 與其下的名冊、離線訊息、私有 XML、出席、PEP、封存紀錄逐字由 `tools/pie.rs` 移到 `db/pie/model.rs`；`PieUser` 的兩個私有欄位改為 `pub(crate)`，工具的 `MODULE_SOURCE` 不變。基線減少 1 條 | 見 `git log --grep '\[WP-113\]'` |
| WP-114 | 完成：`s2s/dane.rs` 原樣、`s2s/lab_dnssec.rs` 只改匯入行，以 `git mv` 移到 `security/`；兩者共用的公開 IP 判斷移到新的 `security::address_scope`；11 個測試的路徑由 `s2s::` 改為 `security::`。基線減少 3 條 | 見 `git log --grep '\[WP-114\]'` |
| WP-115 | 完成：`xmpp/extensions.rs` 以 `git mv` 原樣移到 `platform/extensions.rs`，13 處路徑與 `docs/LIBRARY_SPLIT_LEDGER.md` 隨之改寫；3 個測試的路徑由 `xmpp::extensions` 改為 `platform::extensions`。基線減少 2 條 | 見 `git log --grep '\[WP-115\]'` |
| WP-116 | 完成：`SmIpPolicy` 逐字移到 `platform::config`，`db` 照舊轉出；10 個遞送佇列計數器與其讀取函式移到新的 `platform::delivery_counters`（PubSub 與 S2S 的 static 加上佇列前綴，MIX 的名稱與遞增敘述逐字不變）；`services::pubsub` 的三個准入計數 wrapper 刪除，指標登錄改呼叫 `northstar_pubsub_application`。基線減少 3 條 | 見 `git log --grep '\[WP-116\]'` |
| WP-117 | 完成：`cluster/security.rs` 以 `git mv` 移到 `security/cluster_bus.rs`，檔內只改兩處 `ExpectedClusterPeerKey` 路徑；四個叢集金鑰紀錄與 `ClusterReadinessAuthority` 逐字移到新的 `security::cluster_keys`；12 個檔案的 59 處 `cluster::security` 路徑、`catalog/runtime-experiments.json` 的 2 個路徑與 3 份文件隨之改寫；5 個測試的路徑由 `cluster::security` 改為 `security::cluster_bus`。基線減少 6 條 | 見 `git log --grep '\[WP-117\]'` |
| WP-118 | 完成：三個管理者 session 清理紀錄由 `db::admin_commands` 移到 `services::admin_session_cleanup_worker`，六個 abuse 紀錄移到新的 `security::abuse::records`，`ClusterMetricsSnapshot` 由 `cluster::health` 移到 `services::metrics_snapshot`，全部逐字搬移。基線減少 5 條。WP-111–118 由 codex 平行執行，依序整合，每步以 `--write` 重寫基線且只刪不增；整合後 fmt、clippy、單元測試、全部門禁與完整 CI 通過，基線由 104 條降到 71 條（68 檔） | 見 `git log --grep '\[WP-118\]'` |
| WP-121 | 完成：`security/abuse.rs` 與 4 個子模組以 `git mv` 移到 `services/`；77 個 Rust 檔中 166 行的路徑、兩個門禁與 3 份文件隨之改寫；`new_persistent_for_deployment` 改收 `Arc<dyn AbusePersistence>`，PostgreSQL 實作由 `state/construction.rs` 建立；架構門禁掃描 `src/services` 時略過 abuse 模組自己的檔案。32 個測試的路徑由 `security::abuse` 改為 `services::abuse`。基線減少 2 條 | 見 `git log --grep '\[WP-121\]'` |
| WP-122 | 完成：`security/account_recovery.rs` 以 `git mv` 原樣移到 `state/`；`main.rs`、XEP-0077 帳號刪除路徑、刪除復原 context 與兩個門禁改用新路徑。基線減少 2 條 | 見 `git log --grep '\[WP-122\]'` |
| WP-123 | 完成：`xmpp/xml_util.rs`（含 3 個子模組與 3 個測試檔）、`xmpp/stanza_validation.rs` 與 `xmpp/protocol/jingle.rs` 以 `git mv` 移到 `services/`；92 個 Rust 檔、語意 stanza fuzz target 與 5 個門禁改用新路徑，對外 XML 門禁的基線鍵改名、預算不變；`xmpp::xml_builder` 只再轉出 `XmlElement`。74 個測試的路徑由 `xmpp::` 改為 `services::`。基線減少 5 條 | 見 `git log --grep '\[WP-123\]'` |
| WP-124 | 完成：`services::mix` 新增 `MixClusterRouteLookup`，`outbox_lookup_cluster_nodes` 改收 `&impl MixClusterRouteLookup`，`ClusterMixRouteLookup` 實作時委派原有方法。基線減少 1 條 | 見 `git log --grep '\[WP-124\]'` |
| WP-125 | 完成：`ComponentRoute` 逐字移到 `services::federation_outbox`，新增 `ComponentWake`；`FederationOutboxService` 持有 `Arc<dyn ComponentWake>`，`ComponentRegistry` 實作時委派原有的 `wake_route`。基線減少 1 條 | 見 `git log --grep '\[WP-125\]'` |
| WP-126 | 完成：`services/standalone_muc_maintenance.rs` 以 `git mv` 原樣移到 `state/`；4 個測試的路徑由 `services::` 改為 `state::`。基線減少 1 條 | 見 `git log --grep '\[WP-126\]'` |
| WP-127 | 完成：6 個 context 模組由 `state/` 移到新的 `api/contexts/`，10 個服務綁定別名與 HTTP 政策的轉出移到 `api::contexts`，`state` 建構的欄位與建構子改為 `pub(crate)`；`ApiQueryContext` 經 `LocalPresenceDirectory` 讀取 session 與 MUC 占用者，`state::api_query_presence` 以原本的程式碼實作；`FromRef` 留在 `state.rs`，處理器與架構門禁改寫為 `crate::api::contexts`。4 個測試的路徑由 `state::http_policy` 改為 `api::contexts::http_policy`。基線減少 6 條 | 見 `git log --grep '\[WP-127\]'` |
| WP-128 | 完成：`ClusterListenerMessagePolicy`、`SessionTerminationEffect` 與 `ClusterMixCapability` 移到新的 `cluster::listener_policy`，政策的 `AppState` 建構子逐字留在 `state`；`privacy_allows_session` 改收 user id、connection id 與選定的隱私清單，監聽器先由 session 的鎖複製清單再呼叫。基線減少 2 條。WP-121–128 由 codex 平行執行，依序整合，每步以 `--write` 重寫基線且只刪不增；整合後 fmt、clippy、單元測試、全部門禁與完整 CI 通過，基線由 71 條降到 51 條（50 檔） | 見 `git log --grep '\[WP-128\]'` |
| WP-131 | 完成：12 個 context 模組由 `state/` 以 `git mv` 移到 `api/contexts/`，連同 `OmemoRecoveryPollContext`、`PasskeyService`、`UploadService` 別名；建構子與 `FromRef` 移到新的 `state/rest_endpoint_contexts.rs`，`state` 建構的欄位改為 `pub(crate)`；OMEMO 輪詢的准入常數與視窗函式移到 `api::contexts::omemo_poll`，`UploadAdmission` 與上傳守衛移到新的 `api::contexts::upload_admission`；架構與 OMEMO 門禁改讀新路徑。3 個測試的路徑由 `state::` 改為 `api::contexts::`。基線減少 2 條 | 見 `git log --grep '\[WP-131\]'` |
| WP-132 | 完成：新的 `api/contexts/account_teardown.rs` 定義兩個拆除 port 與 `AccountTeardownContext`、`AccountGenerationTeardownContext`；`AccountTeardownRuntime`、`AccountGenerationTeardownSequence` 實作 port 時以 `Type::method(self, …)` 委派，`FromRef` 改為建構 handle；三個處理器與路由組裝改收 handle，架構門禁要求 port 檔不提 `AppState` 與 `crate::state`。基線減少 3 條 | 見 `git log --grep '\[WP-132\]'` |
| WP-133 | 完成：`ReadinessContext` 逐字移到新的 `api/contexts/readiness.rs`；`state/metrics_context.rs` 以 `git mv` 移到 `api/contexts/metrics.rs`，MUC 占用探針改收 `Arc<dyn OccupancyCount>`，SM 指標改經 `SmRecoveryGauges`；新的 `state/metrics_context.rs` 保留 SM 探針與原 `from_state` 的建構。2 個測試的路徑由 `state::metrics_context` 改為 `api::contexts::metrics`。基線減少 1 條 | 見 `git log --grep '\[WP-133\]'` |
| WP-134 | 完成：`services::account_admin` 為 `RegistrationCache`、`AdminSessionLookup` 加上 `Arc<T>` 實作；兩個管理 context 別名移到 `api::contexts`，`state/construction.rs` 以 trait object 傳入本機快取與 session 查詢，`FromRef` 留在 `state.rs`。基線減少 2 條 | 見 `git log --grep '\[WP-134\]'` |
| WP-135 | 完成：新的 `xmpp/local_routes/{session,muc}.rs` 收下由 `state/local_session.rs`、`local_muc.rs`、`suspended_muc.rs`、`muc_resume.rs` 逐字剪出的紀錄型別與方法，`pub(super)` 改為 `pub(crate)`；`state.rs` 以一行私有匯入使用；其他 27 個檔案改用新路徑，經 `state` 轉出取得的 workspace crate 型別改為直接引用 crate；整合後由架構負責人收斂 `state.rs` 失去使用者的轉出。基線減少 10 條 | 見 `git log --grep '\[WP-135\]'` |
| WP-136 | 完成：`services/session_cleanup.rs` 與其測試以 `git mv` 移到 `state/`，`sm_suspension` 改以 `crate::services` 匯入；協議 actor 以 workspace crate 引用 `SessionCleanupAccount`；架構門禁與 runtime 實驗目錄改讀新路徑。6 個測試的路徑由 `services::session_cleanup` 改為 `state::session_cleanup`。基線減少 2 條。WP-131–136 由 codex 平行執行，依 131、132、133、134、136、135 的順序整合，每步以 `--write` 重寫基線且只刪不增；整合後 fmt、clippy、單元測試、全部門禁與完整 CI 通過，基線由 51 條降到 31 條（31 檔） | 見 `git log --grep '\[WP-136\]'` |
| WP-141 | 完成：新的 `xmpp/local_routes/{session_table,muc_table,suspended_muc}.rs` 逐位元組收下 `state/local_session.rs`、`local_muc.rs`、`suspended_muc.rs` 中只操作即時路由表的函式與快照紀錄，以及 `state/cluster_muc_projection.rs` 的 `local_cluster_muc_projection_snapshot_in`；`pub(super)` 改為 `pub(crate)`，`state.rs` 以私有 glob 匯入；`check-execution-boundaries.mjs` 改從 `session_table.rs` 讀兩個路由輔助函式，23 個變異自測隨之改指 `sessionTable`。基線不變 | 見 `git log --grep '\[WP-141\]'` |
| WP-142 | 完成：`state/muc_delivery.rs` 以 `git mv` 移到 `xmpp/muc_delivery.rs`，`state/cluster_muc_delivery_endpoints.rs`、`cluster_muc_outbox_worker.rs` 移到 `cluster/`，三個建構子切回 `state` 中原名的檔案；`start_muc_outbox_delivery` 改收 worker registry 與 context，`cluster.rs` 不再匯入 `AppState`；架構門禁改讀新檔。基線減少 2 條 | 見 `git log --grep '\[WP-142\]'` |
| WP-143 | 完成：`state/cluster_recovery_replay.rs`、`direct_spool_wake.rs`、`cluster_maintenance.rs` 連同內嵌測試以 `git mv` 移到 `cluster/{recovery_replay_wake,direct_spool_wake,maintenance_locals}.rs`，`ClusterMaintenanceContext` 移到 `cluster/maintenance_context.rs`，建構子留在 `state`；11 個測試的路徑由 `state::` 改為 `cluster::`。基線減少 1 條 | 見 `git log --grep '\[WP-143\]'` |
| WP-144 | 完成：四個監聽器 context 以 `git mv` 移到 `cluster/listener_{dispatch,mix_caps,blocking,sm_muc_teardown}.rs`，故障監督 context 移到 `cluster/failure_supervisor_context.rs`，`SmTeardownLocalEffects` 移到 `xmpp/local_routes/sm_teardown.rs`，建構子留在 `state`；`ClusterListenerRuntime::from_state` 改為 `state` 的 `cluster_listener_runtime()`，`run_pubsub_listener` 改收 runtime；架構門禁分別讀 dispatch 的邏輯與建構子。基線減少 1 條。WP-141–144 依序整合，每步以 `--write` 重寫基線且只刪不增；整合後 fmt、clippy、單元測試、全部門禁與完整 CI 通過，基線由 31 條降到 27 條（27 檔） | 見 `git log --grep '\[WP-144\]'` |
| WP-150 | 完成：記錄 S15 的階段、盤點（5.11）、委派經驗與 WP 狀態 | 見 `git log --grep '\[WP-150\]'` |
| WP-151 | 完成：`s2s/tls.rs` 的五個函式改收 `&TlsContext`，`s2s_client_config` 另收 `ocsp_staple_required`；`s2s/dns.rs` 新增 `FederationDnsContext`，八個函式改收它，`state/federation_dns.rs` 的 `federation_dns_context()` 建構；`s2s_dns_override` 移為 context 的私有方法。基線減少 2 條 | 見 `git log --grep '\[WP-151\]'` |
| WP-152 | 完成：`features` 改收 `S2sFeaturePolicy`，由 `state` 的 `s2s_feature_policy()` 建構；`verify_remote` 由架構負責人逐位元組移到 `s2s/outbound/dialback_verify.rs`，`parse_verify_response` 改為 `pub(crate)`，inbound 的呼叫不變。基線減少 1 條 | 見 `git log --grep '\[WP-152\]'` |
| WP-153 | 完成：`s2s/inbound/direct_route.rs` 以 `git mv` 移到 `state/s2s_direct_route.rs`，型別與欄位改為 `pub(crate)`；inbound 改由新路徑匯入並自 `MODULE_SOURCE` 移除；`check-federated-route-boundaries` 改讀新檔、要求 `state.rs` 註冊模組，兩個變異自測改指新行；`message-execution.md` 改用新路徑。基線減少 1 條 | 見 `git log --grep '\[WP-153\]'` |
| WP-154 | 完成：`maybe_link_local_mirror` 改收鏡像旗標、`&MixService<R>` 與本地網域，三個呼叫端傳入同樣的 `AppState` accessor；架構門禁對 `mix_muc.rs` 改為要求該參數與 `link_local_muc_mirror` 呼叫，仍拒絕 `db::link_mix_muc_by_localpart`。基線減少 1 條。WP-151–154 依序整合，每步以 `--write` 重寫基線且只刪不增；整合後 fmt、clippy、單元測試、全部門禁與完整 CI 通過，基線由 27 條降到 22 條（22 檔） | 見 `git log --grep '\[WP-154\]'` |
| WP-160 | 完成：新增[目標架構](target-architecture.zh-TW.md)，定義層級、上下文、目錄與 S16–S31 的階段 | 見 `git log --grep '\[WP-160\]'` |
| WP-161 | 完成：刪除 `services/*` 原型與只為它存在的 crate、工具、契約、目錄、部署檔、文件與 CI 步驟（清單見 5.12）；`architecture-validator` 移除路由目錄與執行期圖；ADR 0002–0007 標為 superseded | 見 `git log --grep '\[WP-161\]'` |
| WP-162 | 完成：56 個 crate 以 `git mv` 移入層級目錄，manifest、members、fuzz 與現行路徑隨之改寫；三個門禁改讀 workspace members；`test-experiment-contract.py` 的來源路徑跟著改並重新綁定 | 見 `git log --grep '\[WP-162\]'` |
| WP-163 | 完成：`catalog/crates.yaml` 3.0.0 記錄目錄推得的層級、上下文與角色；`architecture-validator` 拒絕違反 R10 的依賴與外部 crate，新增 7 個測試；`crate-policy.md` 改寫 | 見 `git log --grep '\[WP-163\]'` |
| WP-164 | 完成：基線移除 `pinned`，門禁移除釘選與 `crate::outbound` 規則；`main.rs` 移除 S4 shim；`response_owner.rs`、`stage4_replay.rs` 改用 `crate::xmpp::outbound`，內嵌測試移為子檔；historical75 lane 改用凍結副本 | 見 `git log --grep '\[WP-164\]'` |
| WP-165 | 完成：記錄 S16 的階段、盤點（5.12）、R10 與建置時間基準。WP-161–164 依序整合；整合後 fmt、clippy、workspace 測試（2,863 個）、全部門禁與完整 CI 通過 | 見 `git log --grep '\[WP-165\]'` |
| WP-166 | 完成：行程群組測試等到 PID 檔可解析才讀取（shell 先建立檔案再寫入 PID，慢的 runner 會讀到空字串） | 見 `git log --grep '\[WP-166\]'` |
| WP-167 | 完成：tokio 鎖定版本升到 1.53.3（RUSTSEC-2026-0386），只改 `Cargo.lock` 的 tokio 項目 | 見 `git log --grep '\[WP-167\]'` |
| WP-171 | 完成：刪除 `src/jid.rs`、`src/auth.rs`，呼叫端以腳本改為直接引用 crate；層級清單刪除 facade 層與過時的 `outbound` 別名 | 見 `git log --grep '\[WP-171\]'` |
| WP-172 | 完成：`northstar-runtime`（workers、connection_actors）與 `northstar-telemetry`（logging、metrics、delivery_counters、准入計量）；`test-support` feature；執行期實驗可指名套件 | 見 `git log --grep '\[WP-172\]'` |
| WP-173 | 完成：`northstar-security` 收下 `src/security` 的九個模組與設定的 `secret_files`；cluster bus 的測試金鑰放在 `test-support` 後面 | 見 `git log --grep '\[WP-173\]'` |
| WP-174 | 完成：`northstar-xep-catalog`；`jid_text` 拆入 `northstar-xmpp-types` 與 `northstar-xml-builder`；`AppError` 移到 `api::error` | 見 `git log --grep '\[WP-174\]'` |
| WP-175 | 完成：設定以 `subtle` 比對秘密，SCRAM 迭代次數上下限成為設定常數，驗證服務測試確認與 auth core 一致 | 見 `git log --grep '\[WP-175\]'` |
| WP-176 | 完成：`source-module.mjs` 讀 crate 根 `lib.rs` 與同目錄子模組，略過 `main.rs` 與 `bin/`；新增 1 個測試 | 見 `git log --grep '\[WP-176\]'` |
| WP-177 | 完成：`northstar-config` 收下設定模組；`src/platform/` 刪除；R9 刪除平台層；兩個門禁改讀 crate 根 | 見 `git log --grep '\[WP-177\]'` |
| WP-178 | 完成：記錄 S17 的階段、盤點（5.13）與建置時間；目標架構刪除 `northstar-object-store`、加入 `northstar-xep-catalog`。WP-171–177 依序整合；每步 fmt、clippy、workspace 測試、層級與全部門禁通過 | 見 `git log --grep '\[WP-178\]'` |
| WP-179 | 完成：模糊測試 `rest_extractors` 的 `AppError` 替身模組改名為 `api`，刪除 `semantic_stanza` 未使用的 `jid` 匯入；該匯入是門禁要求的，CI 改為門禁失敗（WP-186） | 見 `git log --grep '\[WP-179\]'` |
| WP-181 | 完成：edge crate `northstar-stream`：`IqRoute`、`IqRouter`、`IqHandler`；7 個測試 | 見 `git log --grep '\[WP-181\]'` |
| WP-182 | 完成：session 應用層的 `RemoteRoutePort`，`AppState` 以已驗證的 S2S 路由實作；訊息遞送不再呼叫 `crate::s2s` | 見 `git log --grep '\[WP-182\]'` |
| WP-183 | 完成：只依鍵或自身 XEP 路由開關的 41 個 IQ 分支改為路由；`iq_routes.rs` | 見 `git log --grep '\[WP-183\]'` |
| WP-184 | 完成：註冊、MUC unique、HTTP upload、PubSub owner 改為路由；閘門決定未准入請求的回應；match 刪除，共 48 條路由 | 見 `git log --grep '\[WP-184\]'` |
| WP-185 | 完成：記錄 S18 的階段與盤點（5.14）；S17 的 CI 失敗與驗證腳本加入模糊測試編譯。WP-181–184 依序接到 S17 之上；fmt、clippy、workspace 測試、層級、模糊測試與全部門禁通過 | 見 `git log --grep '\[WP-185\]'` |
| WP-186 | 完成：模糊測試覆蓋門禁的 crate 需求可以指定被納入的正式模組，`semantic_stanza` 改為要求 `stanza_validation.rs` 以 `northstar_xmpp_types::jid::` 引用 JID crate；新增 1 個變異測試；dev 的 CI 恢復通過 | 見 `git log --grep '\[WP-186\]'` |
