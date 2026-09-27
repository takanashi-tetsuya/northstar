# Northstar 開發與本地驗收交接

更新時間：2026-09-27 23:56 UTC。本文記錄當時的狀態；接手時以 `git`、GitHub Actions、systemd 與原始證據重新核對，不把本文的快照當成即時結果。

## 目標與邊界

本輪目標是完成 [模組化執行計劃](MODULARIZATION_EXECUTION_PLAN.md)中可在倉庫及隔離虛擬機驗證的工作，保持 `dev` 完整 CI 通過，並保存能讓他人複核的故障、恢復與互通證據。聯邦實驗只在本機六台 Debian 13 VM 的 `northstar-lab` 網路進行，不做公網實驗。沒有獨立安全審查者及實體離機備份目的地；這兩項必須維持待驗收，不能以自審或同一主機的另一台 VM 代替。

開發直接在 `dev`，使用者已授權提交與推送；不要建立新分支或 PR。任何 Rust 候選程式變更，都要重新評估哪些 VM 驗收必須以新 binary 重跑。正在進行的 24 小時浸泡以固定 binary 為對象，後續工具與文檔提交不能轉移它的受測身分。

## 倉庫與 CI 快照

本次交接前的遠端 `dev` 為 `36819cb461013c5e10dbfa794a3214d4e1278e49`。其 [完整 CI run 36359279817](https://github.com/takanashi-tetsuya/northstar/actions/runs/36359279817) 已完成：32 個 job 成功、1 個條件性跳過、0 失敗。

待推送的本地 `dev` 包含三個測試工具修正：`fccd8a1` 修正 `delv -a` trust-anchor 格式及經簽署的 TLSA 缺席回應；`4af9de3` 加入只在主機產生 TLSA RRset 暫存 zone 的工具及 CI 自測；`06491f5` 拒絕相對名稱等含糊的既有 TLSA 記錄。交接文檔另有一個提交。這些提交未改 Rust 伺服器。推送後須用最新 HEAD 的 CI run 核對所有 job 與匯總門禁；不要把上述舊 HEAD 的綠燈套用到新提交。

模組化已有實質端口與應用層整合，不能簡化描述為「只是拆檔」。[進度報告](MODULARIZATION_PROGRESS_REPORT.md)記錄了消息、房間、PubSub、Roster、Archive、Upload、Federation、Session 等邊界；四階段服務／DB 角色／MUC 批次／儲存還原工作也已有程式及 CI 證據。仍未完成的包括 PubSub 全部命令與查詢收斂、剩餘房間 join/leave 路徑、Session 對廣泛 `AppState` 的依賴、部分 Redis 能力邊界，以及依賴真實環境的發布驗收。以 [執行計劃](MODULARIZATION_EXECUTION_PLAN.md)的退出條件判定完成度，不以 crate 數量或單檔行數判定。

## 固定候選與持續浸泡

受測 Rust 來源提交是 `0ea54b06b3accb918309b594842f1b24d7974132`，兩台 Northstar VM 執行的 release-profile binary SHA-256 均為 `a73aa56296980ae7b24bdb9d3ddb76058365f7005a633cbaf38be7a59bbf4945`。此來源的 [CI run 36327062168](https://github.com/takanashi-tetsuya/northstar/actions/runs/36327062168) 已完成：32 成功、1 條件性跳過、0 失敗。這只證明該候選的 CI，不等於 24 小時浸泡或後續故障驗收完成。

六台隔離 VM 及私有證據位於 `target/vm-lab/20260927T1350Z/`。`ns-a`、`ns-b` 連同 Prosody、ejabberd、PostgreSQL/Redis/MinIO 與 DNS/CA 共六台。浸泡前的 MUC/MAM、上傳與跨節點物件讀回已通過，記錄在 `evidence/pre-soak-baseline/`；此時沒有更改 VM 配置。

24 小時浸泡在 **2026-09-27 15:04:55 UTC** 開始，最早應於 **2026-09-28 15:04:55 UTC** 結束。user systemd unit 是 `northstar-lab-soak-0ea54b0-20260927.service`，原始 JSONL 是 `target/vm-lab/20260927T1350Z/evidence/soak-24h-0ea54b0-20260927T1504Z.jsonl`。寫作時 unit 為 `active/running`、MainPID `70603`，第 527 輪於 23:51:55 UTC 通過；這只是進行中的觀測。既有失敗嘗試的原始記錄仍保留，不可與本輪混算。

每次接手先確認 **同一 unit 的當前狀態** 與 JSONL 新紀錄。只有滿 24 小時、每輪檢查通過、最後有 `candidate_end_verification` 且 systemd 成功退出，才能封存並稱這輪浸泡通過。若失敗，保留原始日誌及 VM 狀態，診斷後以新候選或新完整時段重測；不能把短暫重試當成 24 小時成功。封存工具是 `scripts/finalize-soak.sh`、`scripts/finalize-soak.py` 及 `scripts/verify-soak.py`，離線回歸在 CI 運行。

成功結束且最新工具 CI 通過後，執行：

```bash
bash scripts/finalize-soak.sh \
  --source /home/liu/XMPP/target/vm-lab/20260927T1350Z/evidence/soak-24h-0ea54b0-20260927T1504Z.jsonl \
  --unit northstar-lab-soak-0ea54b0-20260927.service \
  --candidate-sha256 a73aa56296980ae7b24bdb9d3ddb76058365f7005a633cbaf38be7a59bbf4945 \
  --output-directory /home/liu/XMPP/target/vm-lab/20260927T1350Z/evidence/soak-24h-release-0ea54b0-sealed
```

封存會建立不可覆寫的私有目錄與同名 `.tar.gz`，並輸出 archive SHA-256。先驗證封存，再進行同一 binary 的 active load。詳細執行卡及五個 guest helper 的預期 SHA-256 在私有 `target/vm-lab/20260927T1350Z/evidence/active-load-preflight-0ea54b0.md`。`ns-a` 尚缺 `local-vm-lab-mam.py`；**只在浸泡結束與封存後** 記錄缺檔、複製主機同版 helper、核對 SHA。active-load 前還要滿足最後一次 soak 上傳後 90 分鐘冷卻。預計跑 30 分鐘，輸出到封存目錄以外的新路徑。此負載沒有真實 OMEMO 或 Push，低頻 S2S/MAM 樣本也不足以單靠 p99 宣稱正式容量 SLA。

## DANE 與聯邦驗收準備

`target/vm-lab/20260927T1350Z/evidence/dane-preparation/` 只含公開 DNSKEY、公開 peer leaf 憑證、產生的 TLSA 候選與唯讀探針結果。`local-vm-lab-dane-proof.py` 已用 BIND 可接受的 trust-anchor 設定驗證兩個 peer 的 SRV、選定 A 記錄及 TLSA 缺席的經簽署否定回應。最初因錯誤 anchor 格式而失敗的原始輸出也保留，不應刪除或誤計為通過。

目前 unsigned `lab.test` zone 的唯讀快照與 SHA-256、正向 usage 1 及錯誤摘要的暫存 zone 在 `evidence/dane-preparation/zone-stage/`。三份暫存檔都以 VM 上的 `named-checkzone` 經 stdin 驗證；**沒有安裝 zone、重載 BIND 或更改 Northstar 服務**。暫存工具只處理 apex `lab.test` 的絕對 TLSA owner，遇到相對 owner 或 `$INCLUDE`／`$GENERATE` 會拒絕。尚缺帶排他鎖的安裝期 compare-and-swap：安裝前必須核對 guest 現行 unsigned zone 的 SHA-256 與 SOA serial，若與暫存基線不同便重新生成，避免舊 serial 覆寫。F8 的 `fed.lab.test` 壞簽章子 zone 另需獨立流程；現有暫存工具不能製作該案例。

完整 F1–F14 的預期結果與還原要求見 [聯邦矩陣](LOCAL_VM_FEDERATION_MATRIX.md)。DNS 的唯讀預檢不是 Northstar 自身的 DANE 授權或消息送達證據。後續須記錄 Northstar resolver 的驗證決策、選定 SRV/A/AAAA/TLSA、TLS/SNI/ALPN、對端與 outbox 原始日誌及每案還原；負例必須證明拒絕且沒有 PKIX/Dialback 降級。

## 後續順序與未完成證據

1. 前一個遠端 CI 已完成且通過；推送本地 `dev` 的工具修正與本文，追蹤新 HEAD 的完整 CI。若接手時已推送，直接查 `origin/dev` 與對應 run。保持工作樹乾淨，不開 PR。
2. 只觀察現有浸泡，暫不改六台 VM 的 DNS、服務、憑證、網路或儲存。滿時且最終驗證成功後封存原始證據。
3. 核對並補齊 guest helper、等待上傳冷卻，跑同一 binary 的 30 分鐘 active load。記錄各 lane 樣本數、延遲和資源指標，不把它當作完整容量驗收。
4. 完成後逐案執行本地聯邦/DANE/OCSP、獨立組件、客戶端、Redis Sentinel 與叢集分區、儲存/還原和告警演練。每案先定預期 RTO/RPO，保存原始輸出、配置與 binary 雜湊，結束時恢復基線。若修改 Rust 候選，重跑受影響的完整驗收。

[已知問題表](KNOWN_ISSUES.md)仍將 `EXT-CLUSTER`、`EXT-CAPACITY`、`EXT-FEDERATION`、`EXT-COMPONENT`、`EXT-CLIENT`、`EXT-SECURITY`、`EXT-OPERATIONS` 列為未關閉。OCSP 的 TLS 1.2/1.3 本地矩陣、WASM 可重現構建、備份相容與硬中斷復原也有未完成邊界。Gajim 有主機套件但尚無固定候選的隔離客戶端結果；Conversations、Monal 等缺相應裝置或環境的列必須明記未測。沒有外部安全審查者與離機目的地時，相關門禁保持開放。

`northstar-ci` 每小時 heartbeat 自動任務目前啟用，會在實質進展、失敗或需使用者處理時通知。接手者先檢查原 task 是否正在運行，避免同時操作同一 CI、封存路徑或 VM。交接不代表停止或宣告完成目前的 24 小時浸泡。
