# Northstar 實驗式架構清晰化：執行計劃

版本：1.0；日期：2026-10-02；狀態：計劃已完成，實作尚未開始。

## 一、目標與完成的定義

目標是把 Northstar 變成「看得出誰負責、哪一步出錯、如何重現、哪些證據足夠」的系統。這不是以拆出更多 crate、縮短檔案或畫更多圖作為完成標準，也不把本輪變成微服務遷移。

本輪交付一個完整而有限的工程範圍：覆蓋目前支援的單程序／core／maintenance 執行架構，建立可檢查的全系統責任與實驗索引；把直接訊息、S2S 入站、房間訊息與認證 publication 這幾條尚難定位的主要路徑改成有明確 owner、階段和可注入失敗的流程；實際執行本機能完成的回歸、資料庫與 wire 實驗。

「架構清晰」不等於證明所有歷史問題已修復。歷史 non-SM MUC 第 73 輪 timeout、外部 federation、真實 OMEMO 客戶端及生產耐久性，要分別保留其證據狀態，不能用本輪通過的單元測試代替。

## 二、基線與既有成果

以目前工作目錄作為唯一來源，保留全部尚未推送的修復。開始前保存完整來源快照、逐檔 SHA256、Git 基線和既有 patch；本輪不 reset、不清除先前變更、不 push／merge／deploy。

已存在並應沿用的邊界：

- `main.rs`／`subservers.rs`：composition、listener、worker、關閉與程序角色
- `ProtocolSession`：協定順序與身分；TCP、WebSocket、BOSH adapter：位元組、傳輸順序、最後寫入與關閉
- `MessageService`、message application/core、repository：身分、admission、MAM／spool／outbox 的原子交易
- `DirectMessageRouter`：C2S 在 commit 之後的 live handoff、fallback、exact-claim rearm
- room application/core、`MucService`、`MixService`、repository：房間政策、occupancy／epoch、交易及 durable fan-out
- session／delivery core、SM、BOSH、direct-write lease：exact fence 與確認，不把 queue acceptance 當 delivery
- 各 purpose-specific service port、PostgreSQL adapter、`UploadStore`：現有資料權限與外部 I/O
- 既有 worker supervisor、readiness／watchdog、operation runtime：重啟、失敗仲裁與管理操作狀態

前輪證據為 2,312 passed、251 ignored；Python 36 tests；600 秒 mixed workload 有 844/844 次預期交付、816 組 trace 完整配對。這是比較基線，不能自動算成本輪驗證。

## 三、全系統責任地圖

每個族群都要在新的 machine-readable experiment catalog 中具有：唯一 ID、production owner、入口、交易／效果／ACK 所有者、禁止越界事項、deadline 與取消來源、成功／失敗判準、重現命令、test anchor、證據層級、剩餘缺口。

| 族群 | 保留的所有權 | 本輪處理方式 |
| --- | --- | --- |
| 啟動、設定、migration、程序角色 | Config／migration preflight／composition／DB 角色 | 建立明確啟動鏈與 gate，重新驗證先前修復 |
| C2S framing／auth／bind／resume | transport + ProtocolSession + authentication/session service | 保留既有 runner；補強 publication 的型別化結果與實驗 |
| C2S direct messages | message admission + DirectMessageRouter + transport fence | 保留 owner；納入完整 fault matrix，防止後續退化 |
| S2S／component／federation outbox | domain authentication／message transaction／各自 transport | 抽出 S2S direct-route owner；保留不同 checkpoint／history 語義，既有其他邊界列入索引 |
| MUC／federated MUC | room service/repository + handler + outbox/receipt | 補入政策、鎖等待、admission、fan-out 等可定位階段；不任意移除鎖 |
| MIX | channel service/repository + claim attempt + transport ownership | 明確區分 worker 完成、轉交可恢復 transport、lease／ACK；補足關鍵觀察與測試 |
| Roster／presence／privacy／blocking | 專用 service 與 immutable authority snapshot | 沿用既有 ports；索引政策及慢接收者／重播回歸 |
| PubSub／PEP／archive | 專用 application service + immutable audience outbox／archive port | 沿用交易及 outbox；索引 commit、wake 失敗與重播實驗 |
| Upload／object store／cleanup | upload service + object-store port + DB fence | 索引寫入、確認、補償與清理；不變更資料格式 |
| REST／admin／operation journal／recovery | endpoint context + service + operation runtime | 索引 request、commit、外部效果、indeterminate 與 reconciliation |
| Cluster／worker／retention／shutdown | 已注冊 supervisor、lease、readiness、角色邊界 | 連結目前受 gate 約束的 top-level tasks 與 workers；標記外部 Redis 實驗層級 |
| Backup／restore／security controls | 既有工具與獨立身份／受控恢復 | 索引既有證據與操作邊界，不宣稱本轮重做災難復原或安全稽核 |

上述索引描述目前支援的 runtime；不混入 `catalog/services.yaml` 中的微服務 prototype 作為已部署架構。

## 四、必須改動的邊界

### 4.1 S2S 的直接訊息流程

目前 `src/s2s/inbound.rs` 把 local queue、remote route、fallback privacy、health recheck、claim rearm、history 跟錯誤映射放在大段流程內。它不能直接改呼叫 C2S router：S2S 在 primary local handoff 後、fallback privacy await 後、fallback remote 前還有額外 health checkpoint；最後 health check 只在路由接受後執行；`history_committed` 也不是 durable delivery 的別名。

執行原則：先畫現有狀態／順序表，再抽出可注入的 S2S routing owner。共用能共用的 delivery 值、route 結果語義及現有窄 ports；若統一 orchestrator 會隱藏以上差異，就保留兩個具名策略 owner，而不是製造一個布林組合框架。協定 mapping、S2S telemetry、offline/history 決策保留在其明確 caller 邊界。

驗收要逐個 checkpoint 注入健康下降，確認與原行為一致；精確保留 recipient/message/claim tuple、原始 stanza、route 目標、至多一次 rearm、已接受後不要求客戶端重送。

### 4.2 房間操作的定位

MUC/MIX 的 repository／交易邊界已存在，不另造 room engine。補上真正執行路徑的固定詞彙階段，使房間鎖等待、權限／snapshot、admission、cluster dispatch／local fan-out、後續效果可區分。

MUC standalone mutex 目前為了 room admission 和 fan-out 順序而跨 await；不能為了形式上的「不跨 await」拆掉。新 trace 不攜帶 room、JID、payload 或資料庫錯誤字串。MIX 不把持久 claim 轉交 SM/BOSH 等 transport 當成 worker 已完成 ACK。

針對可注入 owner 使用 paused-clock／scripted-port deterministic tests；原有 transaction、lease、receipt、fan-out ordering 的真實資料庫測試要另外執行或明確列為未驗證。

### 4.3 認證 publication

認證成功位元組寫出後才做的 publication，TCP／WebSocket 目前沒有新增獨立 deadline；BOSH 還受外層 request budget 取消。這是明確政策差異，不是可隨便補一個 timeout 的地方。

本輪把被 bool 壓平的 backend failure、integrity/fence/route rejection、best-effort follow-up degradation 變成可識別的固定型別／觀察結果，保持現有 transport 布林成功／失敗決策和 recovery 行為。用暫停時鐘證明 pending publication 不會被 frame budget 誤取消、被外層取消時只記錄一個 terminal、延後 BOSH publication 仍歸屬原 operation。

## 五、故障模型與觀察契約

共同區分下列事實：received／validated、authorized、transaction committed、queue accepted、bytes written、SM/BOSH acknowledged、recovered。某一層成功不能推論下一層成功。

故障模型至少包括：政策拒絕、backend error、等待超時、future 被 drop、panic unwind、queue 滿／route 不存在、健康狀態在 await 前後改變、舊 claim／occupancy fence、commit 後 wake 失敗、重連／重播、慢接收者、logger 遺失與 malformed evidence。

觀察只用固定 stage/outcome／有界數值和臨時 operation ID；不取得 mutation authority、不捕獲 XML/JID/IP/credential、不新增獨立 task／queue／背景輪詢。panic=abort 或 hard kill 不保證 Drop terminal；缺少 trace 只能判為 evidence incomplete，不能判定 deadlock 根因。

索引和 summary 必須拒絕未知詞彙、失效來源／test anchor、重複 ID、缺少 owner、重複 terminal 等不可靠證據。靜態 gate、單元測試、資料庫實驗、wire 實驗、外部環境驗證分開記錄。

## 六、階段、依賴與產出

| 階段 | 工作 | 依賴 | 完成證據 |
| --- | --- | --- | --- |
| P0 計劃與基線 | 完整快照、差異與責任盤點，先交付本文件 | 無 | 原始計劃與 SHA256；程式碼尚未改動 |
| P1 可檢查地圖 | runtime experiment catalog、validator、validator mutation tests、CI gate、系統定位導覽 | P0 | 所有列出的 runtime 族群均有 owner／fault／test／gap；失效引用確實失敗 |
| P2 S2S owner | 狀態表、型別與窄 adapter、production caller 整合、checkpoint parity tests | P0 | 從 production owner 執行的 deterministic routing tests；独立 diff review |
| P3 房間與 publication | MUC/MIX 階段、typed publication observation、取消與資料保護測試 | P0；stage 名稱先協調 | trace 真實 JSON／順序／隱私／失敗測試；独立 diff review |
| P4 實驗與回歸 | fmt、workspace tests、Clippy、全部既有及新增 gates、owned DB tests、mixed wire、source freeze | P1–P3 | 命令、exit code、時間、來源 hash、結果與 cleanup |
| P5 驗收與交付 | 修復可恢復失敗、重跑受影響測試；更新完成矩陣、中文結果報告、來源／patch／證據封裝 | P4 | patch 實際可套用且與來源一致；Library ZIP |

所有程式修改先由另一位 reviewer 檢查，再进入最终验证。写入责任分开：S2S owner/adapter、room protocol、publication runner、catalog/CI/文件；共享檔案由單一 owner 協調整合。Cargo 僅由主執行者以單 job 序列執行，避免建置和 wire 壓測互相污染。

## 七、實驗矩陣與明確驗收條件

| 編號 | 可驗收條件 | 執行方式 |
| --- | --- | --- |
| A1 系統地圖完整 | 第三節所有族群有可讀與 machine-readable 入口；每個 entry 的 owner／invariant／failure／deadline／證據層級非空；來源和測試引用存在 | 新 validator + 故意刪改 fixture 的負向測試 |
| A2 S2S 行為等價 | 每個既有 health checkpoint 均有對應測試；history-only、durable、volatile、bare/full、drop/reject/offline 邊界不混用；exact tuple 與至多一次 rearm | production owner 上的 injected-port tests |
| A3 房間可定位 | MUC groupchat 和 MIX 主要 message 路徑具有能區分 policy／等待／commit／fan-out 的觀察；失敗保留最後階段，無 payload | 真實 trace 測試 + production hook gate + room DB/wire |
| A4 publication 可定位 | 相同成功／拒絕 wire 行為；故障分類可區分；無新增 timeout；取消／panic／delay 的 terminal 唯一；BOSH 配對保持 | paused-clock 和 JSON trace 測試 |
| A5 全回歸 | workspace all-targets/all-features tests、strict Clippy、fmt、architecture/session/subserver/plugin/migration/secret/CI gates 全過；251 ignored 等明確報數 | 序列命令完整留存，不把 ignored 當 passed |
| A6 真實資料庫 | 在本輪獨立、loopback-only、fixture-owned PostgreSQL 執行 MUC 與 MIX 的相關既有 ignored suites；沒有舊資料庫連線或遺留 listener | 捕捉 migration、測試結果、schema/child cleanup |
| A7 wire 與資源 | 至少一次 600 秒 non-SM direct+MUC mixed run，至少 200 rounds、交付數／MAM／no-store／重連／shutdown 都過；trace 完整配對；新 stages 有實測覆蓋 | 既有 owned fixture，10 秒 receive、20 秒 shutdown 不放寬 |
| A8 SM 差異 | 增加或沿用有明確 ACK 的 SM 實驗，區分 SM 與 non-SM；精確確認沒有被不斷重複／未 ACK 的 stanza 污染結果 | deterministic SM membership snapshot regression + bounded SM wire run |
| A9 性能與隱私 | 不新增 DB round trip、跨 await 的觀察 mutex、background task 或無界 buffer；本輪 wire 超過 throughput 下限且無 forced kill；logger 不反射敏感字串 | diff review、bounded parser tests、wire resource/latency samples |
| A10 可回退交付 | 所有先前修復保留；本輪 incremental patch 與從 Git 基線的 cumulative patch 分別可套用，SHA256 與完整來源相同 | 在獨立目錄實際套用比對 |

A7/A9 是本地 smoke/regression 門檻，不是正式性能 SLA；若觀察到明顯退化，要查明環境或程式原因再驗收，不將共享雲環境數據包裝成生產 benchmark。

SM wire 若無法在既有 fixture 正確建模，先補明確 enable／handled count／ACK 的 harness 和負向測試，再跑。不得只開 SM 卻漏計 ACK，也不得以重試掩蓋失敗。

## 八、風險與處理

- commit 後錯誤可能引起重複：保留 durable/history 與 queue 接受的獨立型別，嚴禁把 accepted recovery 變成重試錯誤
- protocol 差異被共用 helper 吃掉：S2S checkpoint 列表與測試先行，必要時保留具名 owner，不追求表面去重
- 鎖／取消改動破壞順序：本輪不改交易、mutex 的權限範圍或 transport ACK；觀察採同步有界事件
- 大型 gate 對 source shape 敏感：更新 gate 指向真實 owner，配負向 mutation test；不得直接刪除安全約束
- source 在壓測期間變動：P4 前 freeze；有修復就重新 build 並重跑相應 wire，保留失敗證據
- DB／工具問題：只使用自建 disposable PostgreSQL；先診斷並修復 fixture。若環境確實缺失，列出具體未達成條件及最小所需條件，不宣稱完成
- 歷史 round-73 timeout 沒有重現：保留未定位狀態；本輪價值是下次有 stage、thread、DB wait/lock、readiness 和 shutdown 證據，不能補寫根因
- 外部驗證：DNS/DANE、獨立 S2S peer、Redis/S3 實際部署、真實 OMEMO、長時間高負載不是本地通過就能認定；列在最終報告的環境限定欄

## 九、回退與停止條件

程式版本回退使用本輪開始前的 source snapshot 或反向 incremental patch；不回退 database schema，因為本輪不修改 migration/資料格式。每一階段若無法保留語義，先修復或縮小該 implementation 的改動，保留相同驗收目標；不能靜默把沒做的項目移出完成定義。

當 A1–A10 全部在其明訂層級達成，就結束本輪；若存在真正的權限／環境／產品決策阻礙，完成獨立工作後回報精確 blocker 和未達成 acceptance ID。沒有 push／deploy，沒有外部付費資源，沒有無限監控。

## 十、最終交付

1. 本計劃原始版與逐項完成矩陣，附命令、結果和未驗證層級
2. 中文架構與實作結果報告：責任圖、故障定位走查、行為保持／變更清單、風險
3. 完整來源、incremental／cumulative patch、檔案 manifest、SHA256SUMS
4. 可重現實驗索引、validator、測試程式、執行證據 ZIP；不包含 DB 資料目錄、private keys、credential 或 build cache
