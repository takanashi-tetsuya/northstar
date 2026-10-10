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
| R3 模組拆分方式 | 大檔拆成「`foo.rs`＋`foo/子模組.rs`」，以 `pub(crate) use` 保持原有模組路徑；拆分 WP 只移動程式碼，不改邏輯 | 「只移動」差異檢查（第 6 節） |
| R4 門禁定位 | 門禁以模組讀原始碼（`foo.rs` 與 `foo/**.rs` 視為同一模組），以括號配對擷取指定項目；禁止新增依函式相鄰順序的擷取 | `scripts/lib/source-module.mjs` |
| R5 證據不可改寫 | `scripts/fixtures/**/historical*`、`docs/evidence/**` 與已記錄的 Stage 證據不得因結構工作修改 | 審閱 |
| R6 測試專用碼 | 受控重播與實驗程式只能存在於 `#[cfg(test)]` 模組 | 既有門禁＋審閱 |
| R7 提交 | 一個 WP 一至數個提交，訊息首行以 `[WP-xx]` 開頭；不推 WIP | 審閱 |

## 5. 工作包順序

| 階段 | WP | 內容 | 退出條件 |
| --- | --- | --- | --- |
| S0 護欄 | WP-01 | `scripts/lib/source-module.mjs`：模組檔案解析、模組全文讀取、Rust 項目括號配對擷取（略過字串、字元、註解）；提供 CLI 給 shell／Python 門禁；附單元測試 | 新測試通過；不改任何既有門禁 |
| | WP-02 | `scripts/check-source-structure.mjs`＋基線 JSON（R1／R2 ratchet）；接入 CI `web-static` | 在基線提交上通過；人為加長檔案時失敗 |
| S1 門禁解耦 | WP-1x | 依拆檔目標，逐一把引用該檔的門禁改為模組讀取（R4）。盤點範圍包含 `scripts/` 與 `catalog/` 中以路徑＋anchor 指向原始碼的項目（WP-31 時 `runtime-experiments.json` 的測試 anchor 隨測試搬家） | 改寫前後門禁在同一提交都通過；以故意刪除被檢片段的反例確認仍會失敗 |
| | WP-11 | `check-outbound-xml-construction.mjs` 的基線項目加上 `module`／`file` 範圍：`module` 以 `productionModuleFiles` 展開（拆出的子檔自動繼承預算）；子樹內已有既存發現的 `protocol.rs`、`services/mix.rs` 維持 `file` | 展開後的檔案集合包含原清單；在 `federated_muc/` 下放入原始 XML 字面值時失敗 |
| | WP-12 | `check-architecture-boundaries.mjs` 對 `federated_muc.rs` 改用 `readProductionModule`；修正 2148／2259／2262 行在 template literal 中被吞掉的 `\b`、`\s`、`\.` 跳脫 | 修正後的禁止規則對注入的 `db::` 呼叫會失敗；現行原始碼仍通過 |
| S2 拆大檔 | WP-2x | 一次拆一個大檔（順序：`federated_muc.rs` → `db/pubsub.rs`、`db/cluster_muc.rs`（無門禁路徑綁定，不需 S1）→ `xmpp/protocol/muc.rs` → `db/archive.rs` → `xmpp/protocol/mix.rs` → `db/mix.rs` → `state.rs` → `cluster.rs` → `config.rs`） | 只移動差異檢查通過；fmt、受影響套件 check／clippy `-D warnings`、單元測試與相關門禁通過；基線下修 |
| S3 測試歸位 | WP-3x | 7 個根目錄測試檔移入受測模組 | 測試數量與名稱集合不變 |
| S4 根目錄分層 | WP-4x | 依 3.1 分組搬動，最後移除舊路徑轉出 | `src/` 根目錄只剩 `main.rs` 與各層目錄宣告 |
| S5 領域收斂 | — | 依模組化執行計劃 C1／C2／D1 把邏輯移入 crates | 依該計劃 |
| S6 文件收斂 | WP-6x | 修正 KNOWN_ISSUES 的 migration 數、README 的發佈敘述、HANDOFF 現況；`docs/README.md` 建立狀態地圖 | 文件一致性門禁通過 |

獨立於結構工作的已知缺陷另以 `BUG-xx` 工作包處理。BUG-01（`operation_runtime::run_one`
取消時 lease heartbeat 未停止）已修正；修正會讓檔案超過行數預算，因此先以 WP-31 把該檔測試
移出，再套用修正，而不是放寬基線。

## 6. 委派與驗收協議

角色：**架構負責人**撰寫 WP 規格、執行全部驗證並審閱差異；**程式修改**由 Antigravity CLI（`agy`）執行。

1. 由 `dev` HEAD 建立獨立 git worktree（只含受追蹤檔案，不含 `.env` 等本機秘密）。
2. 以 `agy -p --mode accept-edits` 交付 WP 規格。agy 只能改檔，不執行 shell；不授予
   `--dangerously-skip-permissions`。規格須明寫「不得執行任何 shell 指令，只用檔案檢視與編輯
   工具」，否則新對話會先嘗試指令、被 headless 模式拒絕後不做任何修改。
3. 架構負責人執行驗證：`cargo fmt --check`、受影響套件的 `cargo check`／`clippy -D warnings`
   （all-targets）、相關單元測試、`ci.yml` 中全部原始碼／catalog 門禁（43 項，先在乾淨基準提交上
   全數通過，之後任何失敗都歸因於該 WP），以及 R3 的只移動檢查。只移動檢查以「項目」為單位：
   拆分前後的頂層項目多重集合必須相同；比較時忽略 `use`、無本體的 `mod x;`、可見性修飾、
   字面值以外的空白與 rustfmt 重排產生的尾逗號，並把子檔中的 `super::super::` 視為原本的
   `super::`；字串與字元字面值逐位元組比較，因此縮排變動不能改到多行字串內容。拆檔時 agy
   逐字複製、不重排；`cargo fmt` 由架構負責人執行（確定性格式化，不屬撰寫程式）。
4. agy 的檔案工具不受 worktree 限制（曾把修改寫進主 checkout）。規格一律寫明 worktree 的絕對
   路徑；每次 agy 執行前後，架構負責人比對主 checkout 與其他 worktree 的內容指紋（相對 HEAD 的
   diff 與未追蹤檔內容雜湊），把越界修改移回 worktree 並還原原處。
5. 多步驟的拆檔，每一步開新的 agy 對話並給完整、獨立的規格，刪除範圍寫明行號。同一對話持續
   累積上下文時，單步可達 35 分鐘、170 萬 tokens，且會嘗試以 shell 刪除大段程式；新對話同樣
   規模的一步約 6 分鐘、25 萬 tokens。可見性清單需包含出現在 `pub(super)` 項目簽名中的型別
   與測試直接讀取的欄位（WP-21 漏列 `FederatedRoomConfig`，由編譯錯誤回饋一輪修正）。
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
| WP-03 | 待辦：把架構負責人的驗證工具（項目級只移動檢查、43 項門禁執行器、越界寫入指紋）收進 `scripts/`，附測試並接入 CI | — |
