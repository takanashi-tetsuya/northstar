# 後續拆分與重構路線圖（S46 起）

本文件是 S45 之後的工作計劃：接下來要做什麼、依什麼順序、每項要注意什麼，以及如何驗收。目的只有一個：讓程式的架構
良好、易於維護。已完成工作的逐項紀錄仍在[工程結構藍圖](engineering-structure.zh-TW.md)第 5 節與第 8 節；各項的現況以
[已知問題](../KNOWN_ISSUES.md)、[執行計劃](../MODULARIZATION_EXECUTION_PLAN.md)與[目標架構](target-architecture.zh-TW.md)
為準。本文件只寫計劃，不重複現況；某項完成後，在本文件把該項標為完成並連到工程結構藍圖的盤點小節。

閱讀順序：先讀第 1 節（目標）與第 4 節（總表），開始某一階段前再讀該項的詳細說明（第 5 節）、工作流程（第 7 節）、
驗證（第 8 節）與注意事項（第 9 節）。

## 1. 目標：什麼叫「架構良好、易於維護」

結構面的定義在[工程結構藍圖](engineering-structure.zh-TW.md)第 1 節（一處一責、檔案可讀、測試歸位、門禁不綁版面、
狀態單一來源、變更可追溯），S16–S43 已經做到，之後只需維持。S44 起的工作是語義面，驗收條件如下：

1. **一個操作，一個交易擁有者。** 使用者可見的一個操作（admission、穩定身分、封存／離線／outbox 投影、復原 fence）
   在一個 PostgreSQL 交易內提交，不拆成各自提交的偽服務（執行計劃的邊界規則 5）。
2. **多事實查詢讀同一個快照。** 回答需要多個事實的查詢（授權＋資料列＋計數）使用一個
   `REPEATABLE READ READ ONLY` 交易；需要寫入回覆的聯邦查詢用 READ COMMITTED 加上與寫入者一致的列鎖 fence。
3. **決定寫入內容的政策在寫入交易內判斷。** 渲染與投影所依據的政策事實（可見性、偏好、logging、選項）由鎖定的列判斷，
   不使用交易前讀到的值；交易前的讀取只能當快速路徑，交易內必須重新驗證。
4. **帶身分的寫入檢查帳號權威。** 在既有鎖順序內檢查 id、username、auth generation 與啟用狀態，不符時回滾。
5. **查詢與變更分型。** 查詢命令不進入變更的 post-commit planner；查詢不帶副作用（例如隱私租約刷新必須是明確的、
   有名字的變更操作）。
6. **權威用強型別傳遞。** port 之間傳 `CanonicalJid`、明確的 bare／full 投影與型別化的節點 ID，字串只在 XML 與 DB 邊界
   出現（邊界規則 7）。
7. **純邏輯不取時間與亂數。** 時鐘與產生的 ID 由應用層注入；資料庫權威用資料庫時鐘（邊界規則 2）。
8. **關閉的功能沒有任何附屬介面。** 路由、探索、HTTP 附屬端點與 worker 都消失，而不是在 handler 內拒絕（邊界規則 4）。
9. **每個語義修正都有證據。** 單元測試證明純決策；資料庫測試以暫停點在讀取或寫入中途提交競爭的變更，證明快照與 fence；
   在唯讀連線上執行查詢，證明查詢不寫入。穩定狀態下的 XML、錯誤條件、順序與 RSM 游標不變，除非該變更是記錄在案的決定。

## 2. S50 後的現況

- 工作區 95 個 package（94 個 member 加根 crate）：`kernel`（XEP 線格式、XML、時間型別）、`platform`（設定、PostgreSQL、runtime、安全、遙測、web
  surface）、`contexts`（abuse、archive、auth、federation、message、operations、pubsub、room、roster、session、upload，
  以及跨上下文交易的 `workflows`）、`edges`（bosh、c2s、cluster、http、s2s、stream）、`tools`（架構驗證器、`northstar-db-it`、
  `northstar-test-harness`）與根 crate `northstar-server`（組合根與程序監督）。層級依賴由 `architecture-validator` 與
  `catalog/crates.yaml` 執行。
- 結構工作完成：行數基線為空（生產檔 ≤ 1,500 行、測試檔 ≤ 3,000 行），根目錄沒有測試檔，靜態門禁中能改為測試的
  已改寫（S35、S36），門禁再審計完成（S42）。S46 再拆分 9 個接近上限的檔案（WP-663–671），S47 拆分 MIX repository
  port 與治理資料生命週期模組（WP-685、WP-686），S49 把 MIX 協定與儲存的大檔拆成葉模組（WP-705），S50 把訊息處理與 session table 的大檔拆成葉模組（WP-722）；
  目前最大的生產檔是 `northstar-message-core` 的 `jingle.rs`（1,376 行）。
- 語義退出：C1（PubSub/PEP）16 項發現全部關閉（S44 的 8 項、S46 的 8 項），C2（Archive/MAM）15 項
  全部關閉：S45 修正 10 項、C2-12（良性競態）以測試固定並維持現狀，S47 依使用者的產品決策實作其餘 4 項（C2-08、09、10、
  13）。聯邦 MUC MAM 統一格式的對端互通證據留在 K 的 `EXT-FEDERATION`。D 從 room 開始：S48 審計 C3（MUC）與 C4
  （MIX）各 19 項，C3 在 S48、C4 在 S49 全部關閉（工程結構藍圖 5.44、5.45），room 完成。S50 審計 message（C5，21 項）
  並全部關閉（5.46），message 完成。其他上下文尚未做語義退出審計，下一個是 roster／presence／privacy。
- workspace 測試 3,937 個（S50 的 `f94a3dc6`），其中 518 個是 ignored 測試，需要 PostgreSQL、Redis 或其他專用環境，
  由 CI 的專用腳本執行（其中 392 個在 `northstar-db-it`，包括 6 個不在 CI 執行的按需量測情境）。
- Cargo.lock 485 個套件；migration 到 `0164`；`cargo audit` 忽略 RUSTSEC-2026-0459（SQLx 的 `libsqlite3-sys` 升到 ≥ 0.39
  前保留）、RUSTSEC-2026-0543 與 RUSTSEC-2026-0542（`object_store` 經 chrono／humantime 引入，`cargo deny` 有相同例外）。

## 3. 已完成的任務（S0–S50）

細節見工程結構藍圖第 5 節的階段表與各盤點小節。

| 階段 | 內容 |
| --- | --- |
| S0–S9 | 護欄、門禁解耦（門禁以模組讀原始碼）、拆大檔、測試歸位、根目錄分層、文件收斂、行數預算收斂、依角色拆分超標檔、測試檔拆分 |
| S10–S15 | 層級方向與四批層級搬移、叢集介面卡解耦、介面卡參數收窄 |
| S16–S18 | 原型刪除與層級門禁、平台橫切移為 crate、會話核心介面 |
| S19–S28 | 依序把 upload、archive、pubsub、roster、abuse、auth、operations（與 `northstar-workflows`）、room、message、federation 移為上下文 crate |
| S29–S31 | 會話與叢集 edge、傳輸與 `ProtocolSession`、組合根；其間升級 SQLx 0.9 |
| S32–S36 | 門禁退役、組合根收斂、組合根狀態、靜態門禁改寫為測試 |
| S37–S43 | 時間型別遷移、會話核心收窄、依賴圖衛生、微服務時代殘留清除、根 crate 測試碼遷出、門禁再審計、執行計劃與超標檔 |
| S44 | C1、C2 唯讀審計；C1 的多事實查詢改為單一快照、自動建立的發布改為一個交易、PEP 建立與 Private XML 寫入檢查帳號 generation |
| S45 | C2：MUC／MIX MAM 的讀取授權與路由、寫入時的政策取樣、MAM 關閉時隱藏附屬介面、以測試固定刪除與 legal hold 下的行為 |
| S46 | C1 第二批：重播快照、訂閱命令、寫入前提、PEP 表單政策、頭像快取、型別化權威與注入的時鐘和 ID；預先拆分 9 個接近行數上限的檔案 |
| S47 | C2 的 4 項產品決策：MIX 個人副本收斂到頻道撤回、legal hold 下撤回成功（顯示覆蓋層與 V3 匯出）、outbox 配額的 generation 列、本地與聯邦 MUC MAM 統一投影；先拆分 MIX repository port 與治理資料生命週期模組 |
| S48 | D 的 room C3（MUC）：唯讀審計 room 上下文，修正 C3 的 19 項：確切的 occupant 路由與第 2 版叢集信封、提交時的受眾、房間退役的確切效果、延遲事件的渲染事實、唯讀快照、加入與 SM 連續性、定址投遞與邀請、注入的時鐘與 ID、型別化權威；runtime 執行緒保留 8 MiB stack（WP-715） |
| S49 | D 的 room C4（MIX）：先只移動地拆分 MIX 大檔並加入型別化的 MIX 位址，再修正 C4 的 19 項：PAM 投影與名冊 delta 同交易提交、反射流量的 PAM 快照、presence 復原依資料庫時鐘分頁清完、管理表單的稀疏 patch、託管探索的單一快照與鏡像連結的 fence、relay 回程的確切路由與單一消費者、投遞綁定收件者帳號（migration 0163）、聯邦邀請結果原子提交；叢集測試改等維護掃除（WP-716） |
| S50 | D 的 message C5：先只移動地拆分訊息處理的大檔並落地行動者 fence 與事件來源，再修正 C5 的 21 項：叢集訊息契約第 14 版的確切路由交接與全叢集優先權排序、提交交易內的單一政策快照與唯讀隱私查詢、重播重驗與 Bind2 的 MAM 證明、撤回綁定寄件者帳號並取消未被持有的原文（migration 0164）、Push 的 claim 快照、C2S／S2S／元件共用處理政策、ExtDisco 型別化、Carbons 的確切受眾 |

## 4. 待辦總表

優先序：P0 是下一階段，P1 接在其後，P2 可與 P0／P1 並行（檔案不重疊時），P3 需要外部環境或產品決策才能開始。
狀態欄只寫「未開始」「持續進行」「進行中（階段）」或「完成（階段，工程結構藍圖 5.x）」，細節留在工程結構藍圖。

| ID | 項目 | 類型 | 優先 | 前置 | 詳細 | 狀態 |
| --- | --- | --- | --- | --- | --- | --- |
| A | C1 語義退出第二批（C1-05、07、08、09、12、14、15、16） | 程式 | P0 | 無；A0 先做 | 5.1 | 完成（S46，工程結構藍圖 5.42） |
| B | C2 的 4 項產品決策與實作（C2-08、09、10、13） | 決策＋程式 | P1 | 使用者決定 | 5.2 | 完成（S47，工程結構藍圖 5.43） |
| C | 接近行數上限的檔案預先拆分 | 結構 | P0（隨 A 一起） | 無 | 5.3 | 完成（S46，工程結構藍圖 5.42） |
| D | 其他上下文的語義退出審計與修正 | 審計＋程式 | P1 | A 的做法定型 | 5.4 | 進行中：room 完成（S48 的 C3 MUC、S49 的 C4 MIX，工程結構藍圖 5.44、5.45），message 完成（S50 的 C5，5.46），下一個是 roster／presence／privacy |
| E | `northstar-workflows` 的範圍審查 | 結構 | P2 | D 的審計結果 | 5.5 | 未開始；前提（room、message 的審計）已在 S50 完成 |
| F | 服務能力收斂（`ARCH-SVC`） | 程式 | P2 | 無 | 5.6 | 未開始 |
| G | 資料庫角色分權（`ARCH-DB-ROLE`） | 程式＋migration | P2 | F | 5.7 | 未開始 |
| H | 叢集與投影的故障證據（`ARCH-CLU*`） | 測試＋環境 | P3 | 隔離 VM | 5.8 | 未開始 |
| I | XML 構造的審計範圍（`ARCH-XML`） | 測試 | P2 | 無 | 5.9 | 未開始 |
| J | 依賴、供應鏈與安全例外 | 維護 | 持續 | 上游版本 | 5.10 | 持續進行 |
| K | 發佈資格（8.2 的 7 個 gate、R1–R3） | 環境證據 | P3 | 凍結候選版本 | 5.11 | 未開始 |
| L | 可選產品範圍（XEP-0357、0447/0448、0487） | 產品 | P3 | K | 5.12 | 未開始 |

建議的階段編號（實際編號以開工時為準）：S46 = A＋C（已完成）；S47 = B（已完成）；S48 = D 的 room C3（已完成）；S49 = room C4（MIX，已完成）；S50 = message C5（已完成）；S51 起依 5.4 的順序每個上下文一個階段；
E、F、G、I 在 D 的空檔或之後插入。WP 編號接續 WP-662（本文件）。

## 5. 各項詳細說明

### 5.1 A：C1 語義退出第二批

**已完成**（S46，見[工程結構藍圖](engineering-structure.zh-TW.md) 5.42）：WP-672–683，16 項全部關閉。以下保留為當時的計劃。

來源：S44 的 C1 審計（WP-643）。S44 已關閉 C1-01、02、03、04、06、10、11、13。剩下 8 項全部在
`crates/contexts/pubsub/*` 與 `northstar-workflows` 的 `pubsub_repository`、`profile`，以及 `northstar-roster-xmpp` 的 presence。

| 發現 | 問題 | 要改成 |
| --- | --- | --- |
| C1-05 presence 重播 | 重播時訂閱候選、設定／ACL、最新項目分開取樣；一般 digest 用取樣的 show／digest 選項；PEP 自動重播用較早的明確清單 | 應用層的重播查詢回傳有界的已授權候選，每個候選（或每頁）一個快照，含確切的訂閱身分／選項、節點投遞政策與最新項目；digest 入列消費已接受的快照，或鎖定後重新驗證同一身分、選項與項目 |
| C1-07 訂閱選項與快速路徑 | 選項表單是修補，adapter 卻展開成完整舊映像；其他訂閱命令在交易前決定快速路徑結果與身分 | 型別化的選擇性欄位修補，與鎖定的列合併；pending／active 快速路徑、到期／SubID 與一般狀態判斷移進同一交易；使用者送來的 SubID 回聲保留為獨立欄位 |
| C1-08 PEP 發布與擁有者表單 | adapter 依節點預設推導發布選項、比較儲存的設定、依狀態執行 max-items 與特殊節點規則 | XML 解碼成型別化修補與已驗證的 payload 事實；預設與特殊節點政策集中一處；儲存設定的相等比較與 max-items 對鎖定的狀態判斷 |
| C1-09 一般寫入前提 | 一般發布把觀察到的節點而不是明確要求的前提傳給 SQL port；擁有者預檢與變更的目標查詢分開讀 UUID／名稱 | 明確的發布選項與 payload 事實進入鎖定後的授權與政策檢查；寫入目標綁定一次節點查詢，或採有文件的、完全在鎖下評估的名稱操作 |
| C1-12 事件受眾與頭像快取 | 頭像 presence 刷新是另一個本地快取寫入，沒有修訂號條件 | 保留事件重播的授權語義並明確測試；頭像快取依提交順序 fence，或在讀取／渲染時推導 |
| C1-14 port 中的權威型別 | 權威字串跨越 service 與 repository、再次正規化，並與 UUID／名稱字串一起組成 admission 鍵 | 新 port 使用 `CanonicalJid`、明確 bare／addressing 投影、型別化 NodeID／名稱；型別化的 admission 鍵，以相容映射保持現有雜湊輸入 |
| C1-15 presence 政策混合查詢與變更 | presence 政策閘在回傳布林前可能另外更新隱私租約，即使之後隱私拒絕 | 隱私刷新成為 roster 擁有的明確操作或有名字的 effectful admission port；重播政策在 C1-05 的快照內評估；新的唯讀使用者只拿讀取能力 |
| C1-16 時鐘與 ID | adapter 的到期檢查與修補 clamp、應用層的訂閱／退訂／選項到期、PEP 訂閱意圖時間戳直接呼叫 `Utc::now` | 時間與 ID 經應用層依賴注入；持久查詢權威用一個資料庫讀取時刻；寫入權威用鎖後的 E；PEP 事件工廠接收準備好的事件上下文 |

建議的 WP 切分（檔案所有權不重疊，才能並行）：

| WP | 內容 | 主要檔案 | 備註 |
| --- | --- | --- | --- |
| A0 契約 | 先定共用宣告：型別化權威（C1-14 的型別與相容映射）、注入的時鐘與 ID 介面（C1-16 的介面）、重播查詢與選項修補的 port 簽名 | `northstar-pubsub-core/src/lib.rs`（1,041 行，先拆出 `authority.rs`／`time.rs` 之類的子模組）、`northstar-pubsub-application/src/repository.rs` | 其他 WP 都依賴它；只加型別與簽名，不改行為 |
| A1 重播快照 | C1-05（一般與 PEP）與 C1-15 | `pubsub-xmpp/src/delivery.rs`、`pep/notifications.rs`、`pep_last_items.rs`、workflows `pubsub_repository/pubsub_outbox.rs`、roster `privacy.rs` | 設計決定：每頁一個快照，或先以候選索引掃描再每候選一個快照；保留 show 值、send-last 模式、去重與事件位元組 |
| A2 訂閱命令 | C1-07 | `pubsub-xmpp/src/pubsub/forms.rs`、`pubsub/entity.rs`（985 行）、`pubsub-application/src/service.rs` 的訂閱段、`pubsub-postgres/src/pubsub/subscription.rs`（1,013 行） | 決定：沒有送 SubID 但已有替換列時的行為、租約 clamp 的時鐘起點 |
| A3 一般寫入前提 | C1-09 | `pubsub-application/src/service.rs` 的發布段、`publish_policy.rs`、`pubsub-postgres/src/pubsub.rs`（1,164 行）、`pubsub-xmpp/src/pubsub/owner.rs` | 與 A2 同改 `service.rs`：先把 `service.rs`（1,166 行）依命令拆成子檔（只移動），再並行 |
| A4 PEP 政策層 | C1-08 | `pubsub-xmpp/src/pep/publishing.rs`、`pep/node_management.rs`、`pubsub-postgres/src/pep.rs`、新的 `pubsub-core/src/pep_policy.rs` | 保留選項不符與格式錯誤／超大 payload 的先後順序；保留 `bookmarks2_outbox_uses_locked_item_diff_after_lock_wait` |
| A5 頭像 fence | C1-12 | `pubsub-xmpp/src/vcard.rs`、workflows `profile.rs`、roster-xmpp `presence.rs` | 先查是否有可用的持久修訂號；沒有則優先讀取時代換；若選修訂號，需要 migration，先量測 |
| A6 收尾 | C1-14、C1-16 在 A1–A5 未涵蓋的呼叫點改用 A0 的型別與注入介面 | 散在各檔 | 最後做，避免與 A1–A5 衝突 |

量測先行：A1、A2、A3 會改變 SQL 形狀與鎖時間。動工前依執行計劃量測項目與圖操作的鎖等待、交易時間、讀取列數／位元組，
以及自動建立的競爭；變更後再量一次，數字寫進該 WP 的提交訊息與盤點。

測試：每項的「Tests」欄在審計報告中已列出（owner 單元測試、XMPP 回覆對應、DB-IT 交錯）。新增的 DB 測試登記在
`scripts/pubsub-db-wsl.sh` 或 `scripts/pubsub-outbox-db-wsl.sh`，否則 CI 不會執行。

完成條件：C1 的 16 項都關閉，或以已知問題記錄決定保留的行為；執行計劃的 C1 列移到「Done」。

### 5.2 B：C2 的 4 項產品決策

**已完成**（S47，見[工程結構藍圖](engineering-structure.zh-TW.md) 5.43）：使用者選擇 C2-08 收斂、C2-09 讓撤回成功（顯示
覆蓋層，匯出保留原文並附撤回紀錄）、C2-10 交易內 generation 列、C2-13 統一投影；WP-687–690 實作，WP-685、WP-686 先拆分。
已知問題的 4 列改為已解決，執行計劃的 C2 列移到「Done」。以下保留為當時的計劃。

這 4 項會改變線上格式、保存語義或需要 migration，必須先由使用者決定，修正 WP 不得自行決定。每項的現況與選項在已知
問題的對應列。開工時以一次提問列出全部 4 項，每項附建議選項。

| 已知問題 | 發現 | 選項 | 建議 | 實作範圍 |
| --- | --- | --- | --- | --- |
| `ARCH-MIX-TOMBSTONE` | C2-08 MIX 頻道撤回不收斂到個人 MAM 副本 | 甲：個人副本獨立保存，寫成契約；乙：收斂到頻道 tombstone | 乙較符合使用者預期，但需要持久的來源撤回 fence（可能要 migration），並擋下延遲到達的原文；遠端副本只在經驗證的反射後收斂 | MIX XMPP `message.rs`、`channel_delivery.rs`，room PG `mix/{publish,jid_map_retract}.rs`，workflows `mix_archive.rs`；DB-IT 在 `room/mix_sequence_retention.rs` |
| `ARCH-LEGAL-HOLD-DISPLAY` | C2-09 legal hold 保留的原文在撤回後仍出現在線上歷史 | 甲：「保全優先」為正式行為；乙：顯示覆蓋層，線上分頁隱藏原文、保留受治理證據 | 甲成本最低，S45 WP-659 已固定目前行為；若選乙需要新 migration，並同時改 MAM 分頁、撤回 repository、MUC 歷史與治理匯出 | 乙：archive-postgres `mam_query.rs`、workflows `retraction_repository.rs`、room PG `muc/history.rs`、operations-postgres `data_lifecycle.rs` |
| `ARCH-OUTBOX-QUOTA` | C2-10 聯邦 MUC 封存入列的配額以舊快照判斷 | 甲：交易內的 generation 或容量列，讓舊快照在提交時衝突並整批重試或拒絕；乙：在封存快照之前取得全域鎖 | 甲（鎖時間不變；可能要 migration）；乙會延長鎖時間 | federation PG `src/lib.rs` 與它的 DB 測試；列數、位元組、網域上限與 TTL 一致處理 |
| `ARCH-MUC-MAM-PROJECTION` | C2-13 聯邦與本地 MUC 的 MAM 投影不同 | 甲：統一成一種投影；乙：兩種格式分別寫成契約 | 甲，但聯邦格式變更必須以對端互通測試驗證（與 K 的 `EXT-FEDERATION` 相關） | archive-xmpp `protocol_session.rs`、room core `stanza.rs`、MUC XMPP 的聯邦 MAM 路徑 |

決策後：每項一個 WP，加上一個記錄 WP；已知問題的對應列改為已解決或改寫成契約，執行計劃的 C2 列移到「Done」。

### 5.3 C：接近行數上限的檔案

**已完成**（S46，見[工程結構藍圖](engineering-structure.zh-TW.md) 5.42）：表中除 `repository_impl.rs` 之外的 9 個檔案已拆分（WP-663–671）；`repository_impl.rs` 在 S47 的 WP-685 依角色拆分（降為 967 行）。以下保留為當時的計劃。

R1 的上限是生產檔 1,500 行、測試檔 3,000 行，由 `node scripts/check-source-structure.mjs` 執行（基線為空），新檔不得
超標，既有檔只能縮小。下列檔案在 1,400 行以上，下一次語義修改
很可能超標；在修改它們的 WP 之前，先做一個只移動的角色拆分 WP（R3：`foo.rs`＋`foo/子模組.rs`，保持模組路徑與可見範圍，
以 `node scripts/check-move-only.mjs` 驗證）。

| 檔案 | 行數 | 可能的修改來源 |
| --- | --- | --- |
| `crates/edges/northstar-cluster/src/listener.rs` | 1,492 | H、F |
| `crates/contexts/room/northstar-muc-xmpp/src/muc/join.rs` | 1,469 | D（room） |
| `crates/contexts/message/northstar-message-application/src/direct_lifecycle.rs` | 1,465 | D（message） |
| `crates/edges/northstar-stream/src/protocol/sm.rs` | 1,461 | D（session／傳輸） |
| `crates/contexts/room/northstar-muc-xmpp/src/federated_muc/message.rs` | 1,459 | B（C2-13）、D（room） |
| `crates/contexts/room/northstar-room-postgres/src/mix_repository/repository_impl.rs` | 1,425 | B（C2-08）、D（room） |
| `crates/edges/northstar-bosh/src/lib.rs` | 1,418 | D（傳輸） |
| `crates/contexts/session/northstar-session-core/src/publication.rs` | 1,417 | D（session） |
| `crates/contexts/pubsub/northstar-pubsub-application/src/service.rs` | 1,166 | A2、A3 同時修改，先拆 |
| `crates/contexts/pubsub/northstar-pubsub-postgres/src/pubsub.rs` | 1,164 | A3 |

測試檔中最大的是 `tools/northstar-test-harness/tests/saved_replay/stage4_replay/tests.rs`（2,742 行）、`stage4_replay/compact.rs`
（2,459 行）與 `stage4_replay.rs`（2,420 行）。它們屬於凍結的 Stage 4 重播工具，平常不改；若必須加測試，放在新檔。

做法：拆分規則見工程結構藍圖 R3 與第 6 節第 8 點的「拆分」。拆分 WP 只移動，不與語義修改放在同一個提交。

### 5.4 D：其他上下文的語義退出審計

**進度**：room 已審計（S48，C3 MUC 19 項、C4 MIX 19 項；審計報告不入庫）。C3 在 S48、C4 在 S49 全部關閉（見[工程結構藍圖](engineering-structure.zh-TW.md) 5.44、5.45），room 完成。message 在 S50 審計（C5，21 項）並全部關閉（5.46），message 完成；下一個是 roster／presence／privacy。

S19–S30 把各上下文搬成 crate 時，SQL 與交易邊界逐字搬移，沒有逐條檢查快照與競態。C1、C2 的審計都找到 15 項左右的發現，
其他上下文很可能有同類問題。每個上下文照 C1／C2 的方式做：先唯讀審計（一個 WP，報告不入庫），再依發現切修正 WP。

建議順序（依使用者可見性與風險）：

| 順序 | 上下文 | 重點 |
| --- | --- | --- |
| 1 | room（MUC／MIX 的非 MAM 部分） | 加入／離開與 occupancy、角色與從屬變更、房間設定、MIX 成員與 PAM、邀請；`muc/join.rs` 先拆 |
| 2 | message | 直訊 admission、離線 spool 與重播、回條、撤回、Carbons；`direct_lifecycle.rs` 先拆 |
| 3 | roster／presence／privacy | 訂閱狀態機、名冊版本、封鎖與隱私清單、presence 廣播；與 C1-15 的隱私租約一致 |
| 4 | auth | 註冊、登入、SASL2／FAST、改密、帳號停用與刪除對會話的撤銷；`users` 已有 typed capability（migration 0108） |
| 5 | session／傳輸（D1） | 資源綁定、SM 恢復與清理、CSI、BOSH；`sm.rs`、`bosh/lib.rs`、`publication.rs` 先拆 |
| 6 | federation | S2S outbox、dialback 與驗證、聯邦路由；與 B 的 `ARCH-OUTBOX-QUOTA` 一起看 |
| 7 | upload | slot 配額、物件生命週期、清理；已有獨立的 `northstar_storage` 角色 |
| 8 | abuse、operations | 舉報與審核、管理命令、資料生命週期與 legal hold、保留政策 |

審計報告的格式（沿用 C1／C2）：

1. 操作清單：每個查詢與變更的入口、port、SQL 與交易。
2. 快照與競態分析：每條路徑讀了哪些事實、在哪些交易、以什麼隔離等級；列出會回傳混合狀態或以撤銷身分寫入的交錯。
3. 交易與鎖順序：列鎖、advisory 鎖的順序與既有的鎖順序測試。
4. 命令／查詢分離：查詢是否有副作用，變更是否在交易外決定結果。
5. 發現：編號、類別（RACE-VISIBLE、RACE-BENIGN、LAYER、TYPE、TIME、TOMBSTONE、OTHER）、事實（檔案與行號）、現有測試、
   要改成什麼、單一請求的行為是否改變、測試計劃。
6. 工作包：依價值排序，檔案所有權不重疊，標出需要產品決策的項目。

審計規格要求：唯讀、不執行 cargo、引用要有檔案與行號、區分「程式碼事實」與「推測」、不得提出改變線上格式而不標為決策。

### 5.5 E：`northstar-workflows` 的範圍審查

`northstar-workflows` 依目標架構是跨上下文交易的唯一位置，目前 54 個頂層模組、約 33,000 行（不含測試檔約 25,000 行），是工作區最大的
crate。
問題是它可能累積只屬於單一上下文的程式，變成無人擁有的大雜燴，也拉長增量編譯。

1. 盤點每個模組：它在一個交易內碰了哪些上下文的資料表。只碰一個上下文的，移回該上下文的 `-postgres` crate。
2. 真正跨上下文的，依業務群組考慮拆成數個 workflow crate（例如帳號生命週期、訊息與封存、room、pubsub／profile、
   會話與 SM），每個只依賴它需要的上下文。拆分前量測增量編譯時間與依賴扇入，拆分後再量，沒有改善就不拆。
3. 目標架構的跨上下文交易清單隨之更新；架構驗證器的層級規則不變。

這項依賴 D 的審計結果（審計會順便指出哪些 workflow 其實只屬於一個上下文），排在 D 的前兩個上下文之後；room 與 message
已在 S48–S50 完成，可以開始。

### 5.6 F：服務能力收斂（`ARCH-SVC`）

現況：協議樹沒有資料庫權限參照，`ServerNode` 沒有公開欄位；HTTP 帳號撤銷、管理操作、叢集 listener 與會話清理已使用
窄能力。仍要檢查其他 worker 與傳輸入口是否接收過寬的狀態（例如完整的執行期狀態或 `Arc<ServerNode>`）。

做法：列出組合根中每個 worker 與傳輸入口的建構參數；每個入口只接收它呼叫的 port（小 port 只定義實際呼叫的方法）；
以架構門禁或 owner 測試鎖住新的窄介面。完成後已知問題的 `ARCH-SVC` 才能關閉，並作為 G 的前置。

### 5.7 G：資料庫角色分權（`ARCH-DB-ROLE`）

現況：`users`、XEP-0133 命令與 session authority 已分權（migration 0108），上傳生命週期有獨立的 `northstar_storage` 角色；
同一 runtime 角色仍對多數可變業務表有廣泛 DML。

做法：依認證、訊息、MUC／PubSub、上傳的順序，每個領域：

1. 列出該領域的資料表與實際使用的 SQL（D 的審計可直接提供）。
2. 新角色或 typed capability（definer 函式進入 canonical manifest，由 migrator 持有並 pin schema）。
3. migration 收回 runtime 的對應權限；grant reconciliation 與啟動檢查涵蓋新角色。
4. DB 門禁：偽 token、跨 target、過期、replay、舊 generation、並發單贏家。

注意：manifest 的 exact allowlist 只能收窄，不能退回名字或數量門禁；每個 migration 的版本檢查見
`scripts/check-migration-versions.sh`；目標部署的升級與還原驗收屬於 K。

### 5.8 H：叢集與投影（`ARCH-CLU`、`ARCH-CLU-DEGRADE`、`ARCH-CLU-VOLATILE`）

多節點模式維持 `Experimental`。程式面還能做的：

- 對必須可靠的事件建立有界的收件人快照 outbox、穩定 ID 與 ACK；presence、typing 等瞬態狀態是否持久化要先做產品與隱私
  決策，不能承諾「叢集零丟失」。
- 跨節點故障競態（取消中的 COMMIT／rollback、背壓、不可用路由）的單機可重現測試，放在 DB-IT 或 test harness。
- 其餘需要隔離 VM 的故障矩陣（非對稱分區、split-brain、滾動升級、SIGKILL、managed failover、RPO／RTO）屬於 K 的
  `EXT-CLUSTER`。

### 5.9 I：XML 構造（`ARCH-XML`）

執行期的外發 XML 都經結構化構造邊界，`check-outbound-xml-construction.mjs` 的基線為零，但它是靜態啟發式。下一步：
新的生成點一律納入門禁；對離線管理工具 `pie.rs` 等專用序列化器建立 fragment／QName／跳脫不變式與惡意輸入回歸測試。
不得把「靜態基線為零」寫成形式化安全證明。

### 5.10 J：依賴、供應鏈與安全例外

- RUSTSEC-2026-0459：SQLx 改用 `libsqlite3-sys` ≥ 0.39 後移除 `.cargo/audit.toml` 的忽略項。
- RUSTSEC-2026-0543、0542：`object_store` 不再經 chrono／humantime 引入，或上游有替代時，移除 `deny.toml` 與
  `.cargo/audit.toml` 的例外。
- 新的外部套件或版本一律先經使用者同意；升級以 `cargo update --precise` 精確指定，`fuzz/` 工作區的 Cargo.lock 一併對齊。
- `SUPPLY-WASM`（R3）：兩個隔離、固定版本的原始碼建置要重現部署位元組；簽名、SBOM 與套件比對不能代替。

### 5.11 K：發佈資格

執行計劃 8.2 的 7 個 gate（`EXT-CLUSTER`、`EXT-FEDERATION`、`EXT-COMPONENT`、`EXT-CLIENT`、`EXT-OPERATIONS`、
`EXT-CAPACITY`、`EXT-SECURITY`）都需要凍結的候選版本與隔離 VM 環境；R1（還原與備份）、R2（撤銷）也在環境中驗收。
程式碼無法關閉這些項目。開始前先凍結 commit，記錄 binary digest、schema、設定、拓撲與版本，事先定好通過門檻與
RPO／RTO；失敗就開程式或運維工作包，產出新候選再重跑受影響的 gate。實驗室配置見
[本地 VM 驗收](../LOCAL_VM_QUALIFICATION.md)。

### 5.12 L：可選產品範圍

XEP-0357（推送）、XEP-0447/0448（檔案分享）、XEP-0487（host-metadata）排在核心資格之後；宣告的支援必須符合實作的
profile 與互通證據（[XEP 矩陣](../XEP_MATRIX.md)、`PROFILE-XEP`）。新協議能力只在有明確互通需求時實作（`ARCH-OPTIONAL-XMPP`）。

## 6. 順序與並行

```text
S46  A0 契約 ─┬─ A1 重播快照
              ├─ A2 訂閱命令 ┐（先拆 service.rs、pubsub.rs）
              ├─ A3 寫入前提 ┘
              ├─ A4 PEP 政策層
              └─ A5 頭像 fence ── A6 收尾 ── 記錄
S47  B（已完成）：4 個修正 WP 可並行（檔案大多不重疊；B-甲 與 C2-13 都碰 MUC 聯邦檔，依序整合）
S48  D-room C3（已完成）：WP-695 契約先行，WP-696–701 平行，WP-702、703 依序，WP-715 修正 stack 溢位
S49  D-room C4（已完成）：WP-705 只移動、WP-706 型別先行，WP-707–714 平行，WP-716 修正叢集測試
S50  D-message C5（已完成）：WP-722 只移動、WP-723 單獨修正、WP-724 型別先行，WP-725–733 平行，WP-735 修正叢集測試
S51+ D：每個上下文先審計，再修正；審計可提前並行（唯讀），修正依順序
     E：D 的 room、message 審計已完成，可以開始
     F → G：可在 D 的空檔並行（G 的 migration 依領域逐一進行）
     I：隨時可做的小 WP
K、L：凍結候選版本後
```

並行的原則：

- 同一階段的 WP 檔案所有權不重疊；共用宣告（core 型別、port 簽名、模組註冊、DB 腳本、測試清單）由一個 WP 擁有，
  其他 WP 只使用。
- 會被兩個 WP 修改的大檔，先以只移動的拆分 WP 分開。
- 審計是唯讀的，可以和上一階段的修正同時進行。

## 7. 工作流程

1. **審計**：唯讀規格交給 codex（`-s read-only`），產出發現與工作包；架構負責人逐項抽查引用的檔案與行號。
2. **決策**：會改變線上格式、保存語義、需要 migration 或新外部套件的項目，先問使用者，再寫規格。
3. **規格**：每個 WP 一份規格，寫明：worktree 絕對路徑；「Never read anything outside this workspace」；禁止執行 cargo、
   建置與測試命令；要改的檔案與不准改的檔案；簽名；鎖順序；不變的行為（XML、錯誤條件、順序）；要加的單元與 DB
   測試及登記的 DB 腳本；行數上限；提交訊息草稿不需要（由架構負責人寫）。
4. **實作**：每個 WP 一個 `git worktree add --detach`，codex `gpt-6.2-sol`（agy 恢復後用 `gemini-3.8-flash-high`，小任務
   `claude-opus-5-5-high`），依難度選 effort；最多 16 個並行；執行前後比對其他 checkout 的指紋，越界寫入移回並還原。
5. **單一 WP 驗證**（第 8 節的 1–4）：失敗輸出回饋同一個 codex 對話，最多三輪；只差一點時架構負責人直接修。
6. **提交**：`[WP-xxx]` 標題、本文說明問題（含審計編號）、改法、不變的行為與新增的測試；行寬 ≤ 72；明確列出要加入的
   路徑；結尾 `Co-Authored-By`。
7. **整合鏈**：在階段基準上依序 cherry-pick；衝突由架構負責人合併（常見：`mod` 宣告、匯入、測試替身的欄位、DB 腳本的
   測試清單、room DB 實驗清單的計數）。
8. **整條鏈驗證**（第 8 節全部）。
9. **記錄 WP**：工程結構藍圖的階段表列、5.x 盤點、第 6 節的教訓、第 8 節的 WP 列；目標架構第 4、5 節；執行計劃的
   對應列；已知問題；進度報告的階段範圍。另外把本文件對應項目標為完成。
10. **推送**：直接推到 `dev`，不開 PR；推送前 `git fetch`，確認 `origin/dev` 是祖先、沒有進行中或排隊的 CI；推送後以
    該提交的完整 CI 為準。

## 8. 驗證

每個 WP 與整條鏈都要通過下列各項。repository 內的命令可以在任何環境重現；架構負責人本機另有包裝腳本（在 repository
之外），但內容相同。

1. **格式與 lint**：`cargo fmt --all --check`；受影響 crate 的 `cargo clippy --locked --offline -p <crate> --all-targets
   --all-features -- -D warnings`。也要在不啟用 test-support 的 crate 集合上跑一次（WP-660 的教訓）。
2. **單獨建置與測試**：每個受影響的 crate 各自 `cargo test --locked --offline -p <crate> --all-targets --all-features`
   （和 CI 一樣逐 crate 建置，能抓到 feature 統一掩蓋的缺漏）。
3. **workspace 測試與名稱比對**：完整 workspace 測試；測試名稱與基準比對，原有名稱不得消失（搬移時要有對應表）。
4. **門禁與腳本測試**：`node scripts/check-*.mjs`、`bash scripts/check-*.sh`、`python3 scripts/check-*.py` 全部與基準相同；
   `node --test scripts/test-*.mjs`；Python 腳本測試（`python3 scripts/test-room-db-experiments.py` 要從 repository 根目錄、
   不加 `-I` 執行，它會匯入 `scripts/lib`）。
5. **資料庫測試**：新的 ignored 測試一定要登記在 CI 執行的 `scripts/*-db-wsl.sh`，在本機一次性的 PostgreSQL 17
   （CI 固定的 `postgres:17-alpine` digest，rootless podman，tmpfs，只綁 127.0.0.1）上執行。每次一個新的隨機 schema；
   需要全新 schema 的測試逐一以 `--exact` 執行。
6. **repository conformance 測試**：需要 NOLOGIN 一般角色擁有的 `northstar_conformance_it_<32hex>` schema，並設定
   `TEST_DATABASE_ROLE`，照 `scripts/repository-conformance-db-wsl.sh` 的做法；只用 schema 前綴會失敗。
7. **room DB 實驗清單**：在 muc、mix、auth 腳本加測試時，同步 `scripts/room-db-experiments.py` 的 `EXPECTED_TESTS`
   （依宣告順序）與 `scripts/test-room-db-experiments.py` 的總數和缺漏數。
8. **離線 CI**：`node scripts/run-ci-offline.mjs`，`ci.yml` 中不需外部服務的步驟逐字執行；目前 11 個 PASS、2 個
   LOCAL-SKIP（需要 root 的套件安裝與 `sudo` 測試）是正常結果。
9. **文件**：`node scripts/check-documentation-consistency.mjs`。
10. **推送後**：該提交的完整 GitHub CI 全綠才算完成。

cargo 使用規則：所有 cargo 命令共用一個以 `CARGO_TARGET_DIR` 指定的 target 目錄，同一時間只跑一個，排進同一個
鎖。驗證一條鏈之前，touch 本階段所有 WP 改過的檔案，避免共用 target 把另一個 worktree 的同名
crate 當成最新（S44 的教訓）。不要在 codex、驗證或 cargo 正在使用的 worktree 上做任何寫入。

## 9. 注意事項與教訓

### 9.1 並發與 SQL

- 快照查詢用 `REPEATABLE READ READ ONLY`，第一個語句取 `statement_timestamp()` 或檢查帳號，之後所有判斷用同一時刻。
- 聯邦寫入 admission 用 READ COMMITTED，第一個語句以 `FOR SHARE` 鎖定 channel 或 room 列；所有改變授權或封存的寫入者先以
  `FOR UPDATE` 鎖定同一列。不要對熱表用 `LOCK TABLE`。
- 新增鎖時沿用既有鎖順序（例如 PubSub 的「擁有者配額 seed 0 → 建立者儲存 seed 1 → G → A → E」）；改動鎖順序是設計
  決定，要有理由與測試。
- 同一個判斷的 SQL 只寫一份（例如持久 occupancy 的 `cluster_muc/query.rs`），快照與叢集查詢共用。
- 政策在儲存時已改變：回滾、重讀並重試一次，第二次不符回既有錯誤，避免無限重試。
- 配額或容量拒絕要整批回滾，不留下部分前綴。
- PubSub outbox 的序號只在同一收件人內遞增；比較序號的測試要送給同一個收件人。
- PostgreSQL 的 `FOR SHARE`、`FOR KEY SHARE` 需要 UPDATE 權限，`LOCK TABLE ... IN SHARE MODE` 需要 UPDATE、DELETE 或
  TRUNCATE；只有 SELECT 的 runtime 角色無法取這些鎖。需要時以 migration 擁有、在函式內檢查呼叫者的 `SECURITY DEFINER`
  capability 取鎖（WP-690 的 `northstar_lock_legal_hold_export`），不要擴大表權限。
- 序列化衝突（`40001`、`40P01`）的重試：整個嘗試回滾後重試一次，重試前確認鎖已釋放、渲染可以重複呼叫；第二次衝突回既有的
  拒絕，不留前綴、不喚醒（WP-688、WP-690）。
- 讀取端的投影（tombstone、覆蓋層）在讀頁面的同一語句組合，不先讀再補查；受保留的原文不改寫，證據與顯示分開（WP-687、
  WP-690）。
- 雜湊鏈或匯出格式改變時使用新的 domain 與版本，進行中的租約以舊版完成，重放回傳儲存的回應（V2 → V3）。
- 交易寫入的名冊或成員變更由回條帶出（WP-707 的 `CommittedMixRosterDelta`），推送由回條渲染，不在提交後重讀最新列。
- 背景清掃以資料庫時鐘取一次 cutoff，分頁以 `SKIP LOCKED` 前進；空頁不等於完成，要以無鎖查詢確認沒有剩餘，被跳過的
  列以退避重試（WP-709）。
- 回覆與逾時這類互斥的結果共用一個消費 token 與單調期限，保證只有一個消費者（WP-712）。

### 9.2 測試

- 每個並發修正都要有暫停點的 DB 測試：在讀取或寫入中途提交競爭的變更，斷言結果與無副作用（列數、outbox、tombstone）。
- 查詢路徑的 DB 測試在唯讀連線上執行。
- `XmlElement` 以單引號序列化屬性，比對字串要用 `by='...'`，或解析後比較。
- 測試模組放在 `<module>/tests.rs`（`check-outbound-xml-construction` 的要求），不要內嵌在生產檔。
- 把交易前的檢查改為鎖下權威時，先找出依賴舊判斷順序的測試與 fixture（WP-678）。
- 有全域唯一索引的欄位（例如 PubSub 的 SubID）在 fixture 中每個節點用不同的值。
- 會改變 SQL 形狀或鎖時間的 WP，以 `northstar-db-it` 的 `pubsub::integration::lock_measure` 情境在獨立的資料庫量測前後（需要 `pg_stat_statements`，逐一執行）。
- 凍結既有行為的測試（例如 WP-659）要在提交訊息說明它固定的是哪個尚未決定的行為，以便日後有意識地改變。
- 只在 test 或 test-support 使用的 import 要加相同的 cfg。
- 有些 DB 測試自己建 schema、不跑 migration（例如 `room::muc` 的邀請原子性測試）。新增表或改動 SQL 時，搜尋所有手寫的
  fixture；單一 WP 的 DB 檢查要包含每個 fixture 碰到改動 SQL 的 `*-db-wsl.sh`，不只新增測試所在的腳本（S47 的 WP-688）。
- 自建 schema 的 DB 測試使用該 DB 腳本會清理的前綴（`muc-db-wsl.sh` 只接受 `muc_lifecycle_test_`、`muc_invite_test_`、
  `muc_history_test_`），規格要寫明（S48）。

### 9.3 整合

- 平行 WP 常在 `mod` 宣告、匯入、測試替身的欄位、DB 腳本清單與 room DB 實驗計數衝突；取兩邊的聯集，再 `rustfmt`，
  計數重新計算。
- 一個 WP 單獨通過，整合後可能失敗（未使用的匯入、glob 轉出失去使用者、行數超標）；整條鏈一定要重跑全部驗證。
- 平行 WP 的新測試是對階段基準的 API 寫的；另一個 WP 改了簽名時，整合後才會編譯失敗（S45 的 6 處 DB 測試）。規格中先
  列出本階段會改的公開簽名，接鏈後第一步建置 `northstar-db-it` 與 test harness 的測試，修正併入新增該測試的 WP。
- 單一 WP 的檢查不跑 ignored 的 DB 測試。每個 WP 新增或改動的 DB 測試在接鏈前各自跑過；S46 有兩個只在鏈上才出現的失敗
  （fixture 重用 SubID 撞上全域唯一索引、payload 政策移到鎖下後測試缺 payload）。
- 合併 DB 腳本的衝突後，檢查每個測試名稱的前一行都是 `run_exact_ignored \`，否則 CI 會把測試名稱當成命令。
- 改變共用行為（回傳型別、會話條件、事件內容）的 WP 會讓其他 WP 的測試只在鏈上失敗；修正併入改變行為的 WP（S48 的
  WP-696、WP-700），再重放之後的提交。
- 離線 CI 不包含 PostgreSQL protocol integration；改動 C2S、MUC 或 MIX 處理路徑的階段，推送前在本機 loopback
  PostgreSQL 跑這個 job（S48 的 WP-715）。
- 多個 WP 各自在同一模組加 `pub use` 時，合併後同一項目可能被轉出兩次（E0252）；匯入清單要三方合併（結果 = 我方 −
  （基準 − 對方）＋（對方 − 基準）），接鏈後掃描重複的 `use`（S49）。
- 兩邊都只新增行的衝突不能整行去重：只有含識別字的行算重複，`};` 與空行屬於各自一側。解決後確認 `#[allow]` 等屬性仍附在
  原本的項目上，沒有跟著插入的 `mod` 行移走（S49）。
- 新 port 的預設方法若回退到 `MixRepository`，它就不能成為 `MixRepository` 的 supertrait，否則測試替身形成 trait 循環；
  改由 host port 同時要求兩者（S49 的 WP-707）。
- 讀取改為不寫入時，搜尋依賴讀取副作用的測試，包括 `scripts/` 的叢集與整合腳本；清理改由維護完成時，測試要等維護
  （S49 的 WP-716）。
- 驗證時的 `cargo fmt --all` 會改寫委派產生的程式碼，格式化結果併入該 WP 的提交。
- 共用 target 的 touch 在每個 WP 的單獨檢查之前也要做，不只整條鏈。
- 其他工作階段可能同時推送到 `dev` 並使用尚未記錄的 WP 編號；推送前 fetch，已推送的編號不改，未推送的順延（S46 的 WP-681）。
- 兩個 WP 改同一個大檔時，先拆檔；整合後檢查行數。
- 改寫型別路徑時，先搜尋 `scripts/` 中引用舊路徑的門禁期望字串。
- 門禁本身通過不夠，也要跑門禁的自測（`node --test scripts/test-*.mjs`）。
- 平行的 WP 為同一個結構新增欄位時，其他 WP 新寫的 struct literal 只在鏈上編譯失敗；接鏈後在整個 workspace（包括
  `tools/`）搜尋該型別的每個 literal（`Type {`、`Some(Type {`、`&Type {`），S50 的兩次完整驗證各被一個漏掉的擋下。
- 委派的程式碼可能在生產程式用了只列在 dev-dependencies 的 crate（`futures`、`tokio::join!`）；該 crate 的測試通過，
  下游的 lib 建置才失敗。驗證要建置依賴它的 crate，能用 std 時改用 std（S50）。
- 需要專用 schema 前綴與隔離角色的資料庫測試要用自己的 runner（`repository-conformance-db-wsl.sh`）；新的 DB 腳本
  照 CI 的方式以一個共用 schema 在本機先跑一次（S50 的 `message-authority-db-wsl.sh`）。
- 新的 Redis 指令先對照 runtime 的 ACL，能用既有指令（pipeline 的 GET 取代 MGET）就不改 ACL（S50 的 WP-732）。
- 改變 wire 版本時，搜尋 `scripts/` 中比對 `protocol_version` 的夾具與載入它的離線測試；合成 payload 的離線測試抓不到
  夾具過時，只有 CI 的多節點 job 會失敗（S50 的 WP-735）。

### 9.4 委派

- codex 規格必須禁止 cargo 與任何建置、測試命令，寫明 worktree 絕對路徑與「Never read anything outside this workspace」。
- 不使用任何繞過沙箱或核准的旗標；codex 用 `workspace-write`（唯讀提案用 `read-only`），關閉網路。
- 執行前後比對其他 checkout 的指紋（`bash scripts/checkout-fingerprint.sh --exclude <worktree>`），越界寫入要移回並還原。
- 拆分的 WP 要求 codex 寫切割腳本依行號切檔，不手抄程式碼；結果以只移動檢查驗證。
- codex 會順手「改善」或漏抄；只移動檢查與逐 crate 測試會抓到，回饋一輪修正。

### 9.5 文件

- 每個階段由最後一個 WP 記錄：工程結構藍圖（階段表、5.x、第 6 節教訓、第 8 節 WP 列）、目標架構第 4、5 節、執行計劃、
  已知問題、進度報告的階段範圍，以及本文件的狀態。
- 不修改：`recovery/`、`scripts/fixtures`、`docs/evidence`、`docs/archive`、`docs/handoff`、有日期的審計文件、CHANGELOG 的歷史、
  ADR、已記錄的階段小節（S45 之前的 5.x）、各 crate 的 `MIGRATION.md`，以及凍結的 Stage 4 Python 工具
  （`scripts/lib/controlled_admission_supervision.py`、`direct_build_record.py`、`stage4_build_record.py`、`stage4_saved_case.py`、
  `scripts/test-stage4-saved-profile.py`、`test-direct-case.py`、`test-stage4-saved-profile-historical.py`、`test-direct-build-record.py`）。
- 審計報告不入庫；結論寫進盤點小節與已知問題。

### 9.6 安全與操作

- 推送只推 `dev`，不開 PR；任何其他對外動作（新套件、下載、發佈）先問使用者。
- 不修改系統或安全設定；本機 PostgreSQL 用 rootless podman，不把使用者加入 docker 群組。
- 共用 target 目錄一天內就會長滿；階段之間用清理腳本修剪，保留會重新產生的編譯產物。
