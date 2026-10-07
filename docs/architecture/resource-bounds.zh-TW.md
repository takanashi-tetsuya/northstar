# Northstar 資源責任與上限查核

2026-10-07 · 第 6 階段 · 供架構文件審閱

CSI 位元組計帳修正與 HTTP 測試診斷已發布於 [1ab54a16](https://github.com/takanashi-tetsuya/northstar/commit/1ab54a16d26fdd689966869786632f2e90bc5da0)；CSI 本地 **17 項測試通過**，[該提交的 CI 37585061986](https://github.com/takanashi-tetsuya/northstar/actions/runs/37585061986) 為 **32 項成功、1 項略過**。BOSH 合併終止訊號已完成來源審閱及 **16 項指定本地測試**，新提交的發布與 CI 尚待完成。下表不代表整個程序或全域 HTTP 記憶體上限已獲驗證；數值為目前預設值。

| 區域與責任主體 | 准入位置與數量／位元組上限 | 背壓與釋放路徑 | 測試範圍與尚未確認事項 |
| --- | --- | --- | --- |
| **連線** · `ConnectionActorRegistry` | 建立工作前取得類別及總量許可；C2S 預設 4,096、每 IP 512、每帳號 64；S2S／元件另有配額 | 額滿立即拒絕；結束時釋放許可並移除索引；關閉准入後取消，限時等待及回收 | 既有測試涵蓋配額隔離、溢位檢查及關閉流程；尚未推導全程序記憶體上限。[來源](../../src/connection_actors.rs#L167-L368)／[設定](../../src/config.rs#L2638-L2680) |
| **輸入** · XMPP framing、HTTP body admission | XMPP frame 1 MiB；BOSH 讀取上限 128、每份 1 MiB、15 秒；REST 同時 128／每 IP 8、15 秒 | 讀取前取得許可；超量拒絕、超時結束；許可隨離開作用域釋放，REST 同步移除閒置 IP 項目 | 既有測試涵蓋 BOSH 大小、結構及讀取准入；讀取上限不等於後續 HTTP 請求總量上限。[XMPP](../../src/xmpp/mod.rs#L38-L47)／[BOSH](../../src/bosh.rs#L1510-L1549)／[REST](../../src/state/http_body_admission.rs#L23-L83) |
| **送出與 CSI** · transport channel、`DeferredQueue` | TCP／TLS／WS 各 512 項；CSI 設定為 512 項／2 MiB；合併後依投影總量淘汰 | 同步送出回報額滿；等待空間可由斷線取消；CSI 回傳淘汰項目，啟用時依 FIFO 清空 | 本輪 CSI：1 項單元＋16 項整合測試通過，含 3 項新回歸；一般送出項目的完整位元組界限仍待追蹤。超大單項及動態縮限另列下方。[背壓](../../src/outbound.rs#L594-L641)／[修正](../../crates/northstar-xep-0352/src/queue.rs#L178-L279)／[測試](../../crates/northstar-xep-0352/tests/csi_integration_and_invariants.rs#L568-L687) |
| **串流管理 SM** · `SmMemoryGovernor` | 先保留再接收；每佇列／快照 4 MiB、未確認 512 項；程序額度 1 GiB；復原額度 256 MiB／1,024 工作 | 活躍、快照及復原各持有許可；額滿拒絕；縮減及 RAII drop 歸還額度 | 既有測試涵蓋精確釋放、並行增長及工作／位元組獨立上限；本輪未重跑。[額度](../../src/services/sm_capacity.rs#L112-L210)／[預設](../../src/config.rs#L921-L938) |
| **BOSH 工作與輸出** · `BoshManager`／`BoshActor` | 工作階段 2,048；命令信箱 4；輸出 128 項／4 MiB；回應快取 2 份／8 MiB／300 秒，每份最多重送 2 次 | 獲准請求持有許可；新實作改用共用終止訊號，拒絕者不等待信箱；終止時移除工作階段並收尾 | **7 項新回歸＋9 項既有指定測試通過**；涵蓋准入、訊號、選取後完成模型及請求規則，未驗證完整工作階段／SQL／網路協定流程。[准入](../../src/bosh.rs#L242-L337)／[修正](../../src/bosh.rs#L434-L486)／[新回歸](../../src/bosh.rs#L2338-L2508)／[快取](../../src/bosh.rs#L1728-L1742) |
| **背景工作** · `WorkerRegistry`、聯邦喚醒通道 | 靜態名稱註冊，禁止重複；工作數由註冊點決定；聯邦喚醒通道只保留 1 項 | 取消時依個別寬限及共同期限收束；重啟退避有上限；喚醒可合併，持久化資料另有責任邊界 | 既有測試涵蓋取消、重啟及收束；衍生工作與持久化佇列的完整上限尚未由此表證明。[生命週期](../../src/workers.rs#L375-L460)／[收束](../../src/workers.rs#L735-L795)／[喚醒](../../src/services/federation_outbox.rs#L39-L97) |

## 保留事項

- **BOSH 已審閱語意與驗證邊界**：超額呼叫立即收到 `policy-violation`；已選定操作及其既有延續流程可完成或沿用原本超時。終止優先於後續排隊請求，禁止 SM 恢復；已持有／已緩衝回應仍用 `policy-violation`，信箱內回應在收尾及丟棄後沿用 `item-not-found`。一般關閉仍保留原本 SM 恢復政策，不承諾固定五秒內關閉；本地模型測試不等同完整收尾驗證。[選取邊界](../../src/bosh.rs#L528-L606)／[收尾](../../src/bosh.rs#L685-L713)／[終止](../../src/bosh.rs#L1285-L1307)
- **超大單項**：`DropOldest` 目前仍可在清空後放入大於位元組上限的項目。既有 `Reject` 會將原項目交回，供立即送出；但若同鍵舊項目仍在佇列，後續清空可能送出較舊狀態。拒絕與排序的契約尚未決定，本次未改動。[既有行為](../../crates/northstar-xep-0352/src/queue.rs#L325-L351)／[呼叫端](../../src/xmpp/protocol/csi.rs#L73-L86)
- **動態縮限**：公開的 `config_mut` 不會同步清理已保留項目；縮小上限後的行為尚未定義。正式 CSI 路徑使用固定預設設定；這與本次固定上限下的重複扣除問題分開處理。[介面](../../crates/northstar-xep-0352/src/queue.rs#L148-L151)
- **驗證狀態**：CSI 17 項、BOSH 指定 16 項皆通過；HTTP 診斷控制另有 17 項通過，僅證明診斷行為，未解決歷史 TLS 超時根因。除上述專項外，表列其他測試僅作來源查核；先前提交的 CI 結果另列頁首。第 4 階段「已儲存重播」驗收依使用者指示延後；第 5、6 階段完整驗收皆未完成。
