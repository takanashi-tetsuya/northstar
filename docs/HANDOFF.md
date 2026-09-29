# Northstar 開發與本地驗收交接

更新日期：2026-09-29 UTC。本文記錄交接與本次接手的狀態；接手時以 `git`、GitHub Actions、systemd 與原始證據重新核對，不把本文的快照當成即時結果。

## 目標與邊界

本輪目標是完成 [模組化執行計劃](MODULARIZATION_EXECUTION_PLAN.md)中可在倉庫及隔離虛擬機驗證的工作，保持 `dev` 完整 CI 通過，並保存能讓他人複核的故障、恢復與互通證據。聯邦實驗只在本機六台 Debian 13 VM 的 `northstar-lab` 網路進行，不做公網實驗。沒有獨立安全審查者及實體離機備份目的地；這兩項必須維持待驗收，不能以自審或同一主機的另一台 VM 代替。

開發直接在 `dev`，使用者已授權提交與推送；不要建立新分支或 PR。任何 Rust 候選程式變更，都要重新評估哪些 VM 驗收必須以新 binary 重跑。24 小時浸泡以固定 binary 為對象，後續提交不能轉移它的受測身分。

## 2026-09-29 審計修復接續

另依 [安全審計](SECURITY_AUDIT_2026-09-29.zh-TW.md) 修復 S1：一般 REST 主體在 handler 前有 15 秒絕對讀取期限、256 KiB 上限、程序共享 128／每來源 8 個不排隊名額，408／429 拒絕及 HTTP/1 關閉；上傳 PUT、BOSH 與後續交易保留各自期限。固定 Caddy 範例加入分路由期限及連線策略，新增真實 socket、Caddy TLS 及完整應用程式慢速主體回歸。2,272 項 workspace 測試、完整 Clippy、8 項主體保護回歸、隔離 PostgreSQL 的完整 integration 通過；直連及 TLS Caddy 的 8 條未完成主體約 15 秒被拒絕，名額恢復成功。Caddy 補測確認 HTTP/2 拒絕後可重用同一連線，長上傳／BOSH／WebSocket 不受一般主體期限誤傷。私有 `target/security-fixes-2026-09-29/verification.json` 及後續 `ci-*` 目錄保存原始結果與逐項核對。既有 `27ae63d` 的 CI run `36509879792` 已核對 32 成功、1 條件性跳過與 CI required 成功；安全修復須另追蹤其新 HEAD，不能沿用。此次 Rust／Caddy 變更尚未部署至 VM。

依 [審計報告](AUDIT_2026-09-29.zh-TW.md) 修復 A1–A5：六個管理列表的手動分頁、僅 owner 可讀寫的本機 `.env`／備份、原型 RPC 空允許名單拒絕、以 XML 結構驗證且納入 CI 的 MIX 原子性回歸，以及 psql／SQLx 共用的非預設埠設定。私有 `target/audit-fixes-2026-09-29/` 保存結果；9 項分頁測試、20 項 foundation 測試與獨立 PostgreSQL 埠 60417 上的 13 組資料庫腳本通過，schema 清理及 fixture 停止成功。獨立 Chromium 的假資料 API 測試確認六個列表的 DOM 分頁可操作，沒有頁面錯誤。既有 `7522df2` 的 CI run `36453150155` 已核對為 32 成功、1 條件性跳過，包含 CI required；本次修復推送後須重新追蹤新 HEAD。

`.env` 及 `.env.bak` 的權限修復只作用於本機，未更換內容／憑證。審計原始結果與修復後證據分開保留。六台 VM 與原候選未變；原浸泡的退出證據缺口和待答覆的重跑決定仍有效。使用者要求修復審計問題，沒有因此授權替換 VM candidate 或自行重新浸泡。

## 倉庫與 CI 快照

本次修正前的遠端 `dev` 為 `6061669696e01000e7003f12ef80a94d2da3cb25`。其 [完整 CI run 36372302384](https://github.com/takanashi-tetsuya/northstar/actions/runs/36372302384) 已完成，逐項核對為 32 個 job 成功、1 個條件性跳過、0 失敗，包含 `CI required` 匯總門禁；原始 metadata、工具 job log 與核對結果保存在私有 `evidence/ci-6061669-36372302384/`。本次 systemd 退出證據修正須另核對推送後最新 HEAD 的完整 CI。

封存門禁修正 `5689e0f187994cb17a47755f2634b70746ab4f96` 的 [CI run 36444123459](https://github.com/takanashi-tetsuya/northstar/actions/runs/36444123459) 已核對為 30 成功、2 失敗、1 條件性跳過。`Web static checks`（包含封存回歸）通過；失敗的是 `Multi-node cluster and raw 1,000-session load` 及其 `CI required` 匯總。前者在 MUC 踢人、重用暱稱後，Redis 拒絕另一身分的快取更新，維護程序卻將它列為 Redis 命令故障，封鎖節點並關閉等候 `cluster-destroy` 的 WebSocket；還沒開始 raw 1,000-session 負載。該 Rust 路徑與固定候選 `0ea54b0` 相同，不能歸因於封存腳本修改。原始 job log 與 workflow metadata 位於私有 `evidence/ci-5689e0f-36444123459/`，失敗不能以之後的成功覆蓋。

本次針對 CI 失敗修正 `ClusterMaintenanceControl`：Redis `IdentityRejected` 仍回傳未完成的 projection，保留 CAS 與 PostgreSQL 授權邊界，但不旋轉健康 listener；真正的 join/refresh/reconcile 命令錯誤仍封鎖控制面。恢復中的節點仍須所有 projection 成功才可宣告 ready。新增健康狀態回歸可在舊行為下穩定失敗，叢集流程另注入舊 incarnation 並確認拒絕覆寫及跨節點送達。私有本機證據在 `target/ci-regressions/muc-projection-20260928/`。這是 **Rust 原始碼變更**，未部署至 VM；原 VM 的 binary 不包含修正，其浸泡結果也不能用來驗收這項修正。推送後必須另外核對最新 HEAD 全部 CI。

本機驗證：65 項相關 Rust 測試與 18 項日誌觀測回歸通過（另 2 項 opt-in Redis 單元測試未執行）。主機隔離 PostgreSQL/Redis 的完整 `cluster-wsl.sh` 於 16:42 UTC 通過，包括新增的快取身分衝突注入、原失敗 MUC 流程、Redis SIGSTOP 恢復、協議負例、ACK 故障與 SIGKILL 租約接管；schema、listeners、runtime dirs 清理均為零，fixture PostgreSQL 成功停止。結果在 `cluster-mz97c456/`。前次因新探針漏接日誌環境變數而失敗的 `cluster-dithaf_5/` 已保留，不能與成功結果混算。這些都是主機回歸，並非 VM active load。

先前的三個測試工具修正及交接文檔已推送：`fccd8a1` 修正 `delv -a` trust-anchor 格式及經簽署的 TLSA 缺席回應；`4af9de3` 加入只在主機產生 TLSA RRset 暫存 zone 的工具及 CI 自測；`06491f5` 拒絕相對名稱等含糊的既有 TLSA 記錄。本次新增 guest 端 CAS 安裝工具、離線故障回歸與操作文件，仍未改 Rust 伺服器或部署至 VM。推送後須用最新 HEAD 的 CI run 核對所有 job 與匯總門禁；不要把上述舊 HEAD 的綠燈套用到新提交。

模組化已有實質端口與應用層整合，不能簡化描述為「只是拆檔」。[進度報告](MODULARIZATION_PROGRESS_REPORT.md)記錄了消息、房間、PubSub、Roster、Archive、Upload、Federation、Session 等邊界；四階段服務／DB 角色／MUC 批次／儲存還原工作也已有程式及 CI 證據。仍未完成的包括 PubSub 全部命令與查詢收斂、剩餘房間 join/leave 路徑、Session 對廣泛 `AppState` 的依賴、部分 Redis 能力邊界，以及依賴真實環境的發布驗收。以 [執行計劃](MODULARIZATION_EXECUTION_PLAN.md)的退出條件判定完成度，不以 crate 數量或單檔行數判定。

## 固定候選與浸泡證據

受測 Rust 來源提交是 `0ea54b06b3accb918309b594842f1b24d7974132`，兩台 Northstar VM 執行的 release-profile binary SHA-256 均為 `a73aa56296980ae7b24bdb9d3ddb76058365f7005a633cbaf38be7a59bbf4945`。此來源的 [CI run 36327062168](https://github.com/takanashi-tetsuya/northstar/actions/runs/36327062168) 已完成：32 成功、1 條件性跳過、0 失敗。這只證明該候選的 CI，不等於 24 小時浸泡或後續故障驗收完成。

六台隔離 VM 及私有證據位於 `target/vm-lab/20260927T1350Z/`。`ns-a`、`ns-b` 連同 Prosody、ejabberd、PostgreSQL/Redis/MinIO 與 DNS/CA 共六台。浸泡前的 MUC/MAM、上傳與跨節點物件讀回已通過，記錄在 `evidence/pre-soak-baseline/`；此時沒有更改 VM 配置。

24 小時浸泡在 **2026-09-27 15:04:55.992492 UTC** 開始，最後的 `candidate_end_verification` 時間為 **2026-09-28 15:04:55.992496 UTC**。user systemd unit 是 `northstar-lab-soak-0ea54b0-20260927.service`，原始 JSONL 是 `target/vm-lab/20260927T1350Z/evidence/soak-24h-0ea54b0-20260927T1504Z.jsonl`。1,440 輪均記錄通過，首尾 binary 身分一致，24 份房間 MAM 原始檔仍保留；但本輪 **尚未通過封存門禁**。

每次接手先確認 **同一 unit 的當前狀態** 與 JSONL 新紀錄。只有滿 24 小時、每輪檢查通過、最後有 `candidate_end_verification` 且 systemd 成功退出，才能封存並稱這輪浸泡通過。若失敗，保留原始日誌及 VM 狀態，診斷後以新候選或新完整時段重測；不能把短暫重試當成 24 小時成功。封存工具是 `scripts/finalize-soak.sh`、`scripts/finalize-soak.py` 及 `scripts/verify-soak.py`，離線回歸在 CI 運行。

2026-09-28 15:20 UTC 發現臨時 unit 已被 systemd 回收。`LoadState=not-found`、`ExecMainCode=0`、退出時間為零；此時顯示的 `inactive`、`Result=success`、`ExecMainStatus=0` 是預設值，不能當作程序成功退出。該 invocation 的 journal 只保留啟動及資源用量，沒有退出碼。私有 `evidence/soak-exit-evidence-gap-20260928T1528Z/` 保存原始 unit 狀態、journal、原始證據雜湊與診斷。不要補造退出證據、重建原 unit 或將原 JSONL 宣告通過；原定 sealed 目錄與 active-load 輸出尚未建立。

原封存指令目前因上述缺口 **不得執行**：

```bash
bash scripts/finalize-soak.sh \
  --source /home/liu/XMPP/target/vm-lab/20260927T1350Z/evidence/soak-24h-0ea54b0-20260927T1504Z.jsonl \
  --unit northstar-lab-soak-0ea54b0-20260927.service \
  --candidate-sha256 a73aa56296980ae7b24bdb9d3ddb76058365f7005a633cbaf38be7a59bbf4945 \
  --output-directory /home/liu/XMPP/target/vm-lab/20260927T1350Z/evidence/soak-24h-release-0ea54b0-sealed
```

本次修正讓封存與 active-load 的封存核驗共用嚴格的退出檢查：要求 loaded unit、正常退出碼、已退出 PID 及非零起訖時間，拒絕不存在、未執行、仍在執行、失敗及重複矛盾屬性。支援 `RemainAfterExit=yes` 的 `active/exited` 完成狀態。9 項離線回歸與 active-load 自測通過；主機上獨立 true/false/不存在 unit 的真實 systemd 回歸亦符合預期，測試 unit 已清除，未碰 VM。

現有指示只授權觀察原 unit。若無法補足原 invocation 的真實退出證明，需先取得使用者同意，以同一 binary、新 unit、新輸出路徑重跑完整 24 小時。新 controller 應使用 `Type=exec` 與 `RemainAfterExit=yes`；封存成功前不要停止 retained unit。封存成功後再停止該已完成的主機 unit，讓 active-load 的「無 active soak unit」預檢通過。不可混入原輪、舊失敗輪或短測試資料。

封存會建立不可覆寫的私有目錄與同名 `.tar.gz`，並輸出 archive SHA-256。先驗證封存，再進行同一 binary 的 active load。詳細執行卡及五個 guest helper 的預期 SHA-256 在私有 `target/vm-lab/20260927T1350Z/evidence/active-load-preflight-0ea54b0.md`，新一輪須更新其 unit、來源與封存路徑。`ns-a` 尚缺 `local-vm-lab-mam.py`；**只在浸泡結束與封存後** 記錄缺檔、複製主機同版 helper、核對 SHA。active-load 前還要滿足最後一次 soak 上傳後 90 分鐘冷卻。預計跑 30 分鐘，輸出到封存目錄以外的新路徑。此負載沒有真實 OMEMO 或 Push，低頻 S2S/MAM 樣本也不足以單靠 p99 宣稱正式容量 SLA。

## DANE 與聯邦驗收準備

`target/vm-lab/20260927T1350Z/evidence/dane-preparation/` 只含公開 DNSKEY、公開 peer leaf 憑證、產生的 TLSA 候選與唯讀探針結果。`local-vm-lab-dane-proof.py` 已用 BIND 可接受的 trust-anchor 設定驗證兩個 peer 的 SRV、選定 A 記錄及 TLSA 缺席的經簽署否定回應。最初因錯誤 anchor 格式而失敗的原始輸出也保留，不應刪除或誤計為通過。

目前 unsigned `lab.test` zone 的唯讀快照與 SHA-256、正向 usage 1 及錯誤摘要的暫存 zone 在 `evidence/dane-preparation/zone-stage/`。三份暫存檔都以 VM 上的 `named-checkzone` 經 stdin 驗證；**沒有安裝 zone、重載 BIND 或更改 Northstar 服務**。暫存工具只處理 apex `lab.test` 的絕對 TLSA owner，遇到相對 owner 或 `$INCLUDE`／`$GENERATE` 會拒絕。本次新增 `local-vm-lab-dane-install.py`：在持久排他鎖內核對 guest 現行 unsigned zone 的 SHA-256 與 SOA serial，重建並比對唯一允許的 TLSA 變更，驗證後原子替換並 reload。reload 失敗時用更高 serial 還原原 RRset；外部寫入或還原失敗要求明確復原，保留原始、候選、還原檔與事件證據。24 項離線回歸已通過並加入 CI；guest 端實際安裝仍須待浸泡封存與 active load 完成後進行，不能把離線回歸當作 DANE 驗收。詳細命令與 `SIGKILL` 復原限制見聯邦矩陣。F8 的 `fed.lab.test` 壞簽章子 zone 另需獨立流程；現有工具不能製作該案例。

完整 F1–F14 的預期結果與還原要求見 [聯邦矩陣](LOCAL_VM_FEDERATION_MATRIX.md)。DNS 的唯讀預檢不是 Northstar 自身的 DANE 授權或消息送達證據。後續須記錄 Northstar resolver 的驗證決策、選定 SRV/A/AAAA/TLSA、TLS/SNI/ALPN、對端與 outbox 原始日誌及每案還原；負例必須證明拒絕且沒有 PKIX/Dialback 降級。

2026-09-28 03:04 UTC 以 stdin 對 DNS guest 執行六次唯讀 `named-checkzone`，三份既有候選及各自較高 serial 的還原 zone 均通過。原始檔案與輸出保存在私有 `evidence/dane-preparation/installer-bind-readonly-20260928T030411Z/`；只在主機寫入證據，沒有安裝 helper、zone 或 reload。這仍只是 zone 語法驗證。

## 後續順序與未完成證據

1. `7522df2` 的 MUC 修正與 `27ae63d` 的 A1–A5 修正完整 CI 已分別通過；本次 S1 安全修正推送後，追蹤新 HEAD 的完整 CI。直接查 `origin/dev` 與對應 run，不沿用舊綠燈。保持工作樹乾淨，不開 PR。
2. 原輪因 systemd 退出證據缺失而阻擋封存。保留原始證據及六台 VM 現狀，等待是否以保留退出狀態的新 unit 重跑完整 24 小時的決定；不要自行開始負載或補 helper。即使同意同 binary 重跑，也只驗證 `0ea54b0`，不能當作本次 Rust 修正的驗收；部署新 binary 仍未獲授權。
3. 核對並補齊 guest helper、等待上傳冷卻，跑同一 binary 的 30 分鐘 active load。記錄各 lane 樣本數、延遲和資源指標，不把它當作完整容量驗收。
4. 完成後逐案執行本地聯邦/DANE/OCSP、獨立組件、客戶端、Redis Sentinel 與叢集分區、儲存/還原和告警演練。每案先定預期 RTO/RPO，保存原始輸出、配置與 binary 雜湊，結束時恢復基線。若修改 Rust 候選，重跑受影響的完整驗收。

[已知問題表](KNOWN_ISSUES.md)仍將 `EXT-CLUSTER`、`EXT-CAPACITY`、`EXT-FEDERATION`、`EXT-COMPONENT`、`EXT-CLIENT`、`EXT-SECURITY`、`EXT-OPERATIONS` 列為未關閉。OCSP 的 TLS 1.2/1.3 本地矩陣、WASM 可重現構建、備份相容與硬中斷復原也有未完成邊界。Gajim 有主機套件但尚無固定候選的隔離客戶端結果；Conversations、Monal 等缺相應裝置或環境的列必須明記未測。沒有外部安全審查者與離機目的地時，相關門禁保持開放。

2026-09-29 重新核對本機 automation 設定時，已找不到 `northstar`，僅有已暫停的舊 `northstar-ci-dea8ec4`；不能假定每小時接續仍啟用，本次未重建自動任務。接手者先檢查原 task 是否正在運行，避免同時操作同一 CI、封存路徑或 VM。目前浸泡封存與 active load 仍未完成。
