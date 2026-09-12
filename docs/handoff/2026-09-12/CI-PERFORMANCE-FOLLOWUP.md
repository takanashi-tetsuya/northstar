# CI 耗時修復實作

本文件接續 [耗時調查](CI-TIMING-INVESTIGATION.md)，記錄使用者要求繼續後的實作。
基線為 `0c4ca9d9c442d94589620aee51fabaf66f4bfd03`。以下是工程紀錄，不新增操作授權。

## 已實作

- Observer 採樣仍以 3 秒為有效期限，PostgreSQL statement timeout 仍為 2 秒。
  對尚未收完整的逾期回應，再給最多 2 秒清空到 ReadyForQuery；逾期資料不算
  有效樣本，必須由同連線下一個新樣本證實恢復。連續 3 次可恢復錯誤仍失敗。
- Observer 啟動失敗時不啟動 workload；執行期間若 observer 無法提供必要證據，
  wrapper 立即要求自有 driver 收尾並回收後代。已完成的合法 failure window
  仍讓原業務故障清理完成，保留原退出狀態。沒有啟動 driver 時以明確 output
  跳過不存在的業務日誌，observer 證據仍必須上傳。
- 每個 pair 的 CA、RSA-3072 金鑰和測試憑證僅在同一 stress run 的第一輪生成，
  後續輪次從 parent 的私有暫存目錄還原。驗證 run/pair scope、到期時間、檔案
  集合、權限及 SHA-256；毀損直接失敗。pair 間 CA 獨立，應用 secrets 每輪重建。
  此快取隨 parent 清理，沒有放進 GitHub cache 或 artifacts。
- Federation smoke 兩個案例成功後，以當次 Cargo JSON 核對 runtime profile，
  上傳 executable 和 manifest。Regular/scheduled 只下載同一 run/attempt 的
  artifact，驗證 commit、所有 tracked source、Rust 1.97.1、作業系統/架構、
  profile 和 binary digest 後使用。還原錯誤直接失敗；本地入口保留原 Cargo
  build。Quality jobs 的編譯、測試和 clippy 命令不變。
- 時間紀錄把 fixture preparation 與 startup 拆開，供後續 run 分辨憑證準備、
  實際啟動與業務階段，而非把它們合併成一項。

## 驗證與限制

本地已通過 observer 39、wrapper 20、runtime profile 10、artifact 5、實際
OpenSSL 憑證 4 個測試，以及 workflow performance contract 4 個測試。
真實 PG17 的 10 個整合測試涵蓋 100 控制連線、3 秒邊界仍 pending 的回應、
同連線清空與恢復、固定 failure window 和清理。
完整 listener worker 與 GitHub CI supervisor 生命週期回歸亦通過；Actionlint、
workflow required policy、9 個 release gate 測試及文件一致性檢查均通過。

上述整合測試不啟動 100 個應用伺服器，不能取代 regular 20×50 的結果。
本機沒有 Rust 工具鏈與 runtime binary，本輪沒有本地重建 Rust；實際 artifact
跨 runner 交接及完整壓測耗時需由新提交的 CI 驗證。未聲稱已改善百分之多少。

Regular 20×50、scheduled 100×50、100 個同時存活伺服器與 all-live 屏障、
15 秒 readiness、900 秒 worker deadline 和 5 秒 runtime-control 心跳均未放寬。
原 Federation 第 8 輪的 runtime-control 故障尚未定位根因；本次改善診斷存活和
重複 fixture 工作，仍需新 CI 的完整日誌與 PG failure window 判斷應用故障。

## dea8ec4 的實際結果與後續修正

[CI run 34694967117](https://github.com/takanashi-tetsuya/northstar/actions/runs/34694967117)
的 Federation regular 在第 11 輪、第 40 對 A 節點失敗；前 10 輪通過。
同 run 的 runtime artifact 在 regular job 中於 5 秒內下載完成，沒有再次編譯。
第 2 至 10 輪每輪約 3.7 分鐘；完整 20 輪尚未成功，不能將這次提前失敗的
總時間當成整體加速結果。MIX regular 在這份紀錄提交時仍執行中。

這次 observer 全程有效：4,655 個樣本、最高 100 個 runtime backend、12 次
採樣錯誤全部由同連線恢復，pre/post failure window 完整。業務退出碼 2
完整保留，沒有被診斷狀態覆蓋。

失敗節點 `runtime-control-refresh` 在 13:42:07.369 UTC 回報 5,007 ms 心跳
靜默，當時 `rules-read` 已執行 878 ms。PG 採樣將該節點映射到 backend
19296，在 13:42:06.225 UTC 的樣本中為 active、`LWLock/LockManager`、
query age 2,497.826 ms、blocking PIDs 為空。其他節點同時也出現 LockManager
等待；failure window 沒有顯示此節點的一般 heavyweight lock 阻塞者。

Observer 原先對所有慢 active query 也呼叫 `pg_blocking_pids()`。這個函式
只能識別 heavyweight lock 阻塞，不能解釋 LWLock/CPU/I/O 等待，而且 PG17
實作會取得所有 lock hash partition 的共享 LWLock。這可能在高壓下增加
LockManager 競爭；目前證據不足以宣稱它是這次心跳故障的唯一原因。
參考 [PG17 函式文件](https://www.postgresql.org/docs/17/functions-info.html) 及
[GetBlockerStatusData 原始碼](https://github.com/postgres/postgres/blob/REL_17_STABLE/src/backend/storage/lmgr/lock.c)。

修正只在 `wait_event_type='Lock'` 時查詢 blocking PIDs；其他 backend 的
state、wait event、query age 及慢查詢事件仍完整採樣。所有心跳、採樣期限、
矩陣規模及失敗條件保持不變。39 個 observer 測試及 12 個真實 PG17 整合
測試通過；新增測試以會拋錯的探查函式證明慢 PgSleep 不會進入鎖管理器，
並以實際 advisory-lock 等待證明正確 blocker PID 仍被保留。新 CI 必須
完成完整矩陣後，才能判斷這項修正是否解決應用停機。

## dea8ec4 的完整 MIX 結果

[MIX regular job 103557501785](https://github.com/takanashi-tetsuya/northstar/actions/runs/34694967117/job/103557501785)
於 14:32 UTC 完成全部 20×50，業務及 observer 均通過。矩陣步驟由
13:01:43 至 14:32:02，耗時 90.317 分鐘；相較基線的 101.604 分鐘，
縮短約 11.1%。這是完整 MIX 工作負載的比較，不代表 Federation 已修復，
也不是整個 CI 已通過的結論。兩次共享 runner 的負載不同，仍需後續 run
確認穩定性。

同 run 執行檔下載 5 秒，驗證／還原階段 3.010 秒，沒有再次編譯。
第 2 至 20 輪平均 provision 24.076 秒、preparation 89.466 秒、startup
14.591 秒、workload 132.747 秒、cleanup 7.039 秒。準備與啟動合計
104.057 秒，低於基線 142.675 秒；業務階段與基線 131.323 秒接近。
這說明目前大部分改善來自避免重複 fixture 工作，完整矩陣仍由實際業務
與每輪準備時間主導。

Observer artifact `10299338235` 的 SHA-256 已與 Actions 上傳紀錄核對：
`ff1b1922a96b3a4d0b8e20f483099582642dee4692472814f06f376c52030f66`。
共 10,608 個樣本、最高 100 個 runtime backend，9 次採樣錯誤全部恢復，
沒有連續錯誤、failure marker 或遺失的必要證據；wrapper 的 observer、
diagnostic、cleanup、case map 和 evidence bounds 均成功。
此 run 的最終 CI required 仍因已記錄的 Federation 第 11 輪故障失敗。

## b998f65 的日誌轉送啟動故障

[Federation job 103572063185](https://github.com/takanashi-tetsuya/northstar/actions/runs/34700460041/job/103572063185)
在第 1 輪第 41 對的準備階段退出。第一個失敗是 supervisor 的
`console_delivery_stalled`，該 worker 僅輸出 `listener_certificate_cache=miss`。
Observer 全程正常、157 個樣本且最高 runtime backend 為 0，說明此時尚未
進入伺服器執行階段；不能把它歸因於之前的 runtime-control 心跳故障。
完整診斷 SHA-256：`2afffad6478744537843dc68899c0ec2ca41428ffb75cb1e439762def9eec4c3`；
observer SHA-256：`9d410d533570f534c96fd6512baf2cc83500fd860213b46b8f2fc9792ccf9db9`。

原 supervisor 啟動轉送子程序後立即啟動 fixture，未先確認轉送端已完成
Python 匯入與初始化，因此首筆輸出的 1 秒期限包含子程序啟動時間。
新流程先等待私有 pipe 的獨立啟動確認（最多 5 秒），確認後才啟動 fixture；
每筆輸出的傳送期限仍為 1 秒，真正阻塞仍失敗，未就緒的 helper 也必須
終止、回收並關閉管線。收到取消時不再啟動新的 fixture。

四個真實程序測試通過：延遲 1.5 秒才啟動仍可正確傳送兩筆資料、永不就緒、
錯誤確認位元組、提前退出。後三者皆驗證有界失敗、程序回收與 FD 無洩漏。
完整 supervisor 回歸（含真正阻塞的 stdout、程序群組與 failure marker）
通過。移除啟動確認的 mutation 會重現 `console_delivery_stalled`，證明
修正涵蓋一條可重現的故障路徑；遠端故障沒有 helper 啟動時間紀錄，不能
據此斷言所有傳送延遲都由啟動造成，仍須完整矩陣驗證。

### 後續失敗分類與發佈平台修正（UTC 2026-09-12 15:36）

- `b44736e` 的 Federation job `103569517567` 在第 7 輪失敗。
  pair 20 B 於 14:57:47 因 runtime-control heartbeat 5499 ms 超過原有
  5000 ms 邊界而退出（rules-read 4899 ms）；Python readiness 重試直到
  約 14:58:22，外層 failure marker 於 14:58:24 才建立，使 30 秒前窗
  錯過實際退出。新增 Linux pidfd 監看兩個經父子關係驗證的 server，
  任一退出即建立 lifecycle marker，停止並回收自身 workload；server
  仍由原 fixture shell 清理，所有後代保留原 supervisor process group。
  5 個真實程序測試涵蓋正常與失敗退出、已退出 server、非自有／重複
  PID、及拒絕 TERM 的 workload。原階段 31 項、worker lifecycle 與
  observer wrapper 20 項回歸通過。
- `41d8dc2` 的 Federation job `103566011083` 已通過前 19 輪；第 20 輪
  observer 出現未完成 drain 的 `client_query_deadline`（5000.323 ms）。
  既有邏輯正確中止 driver，但因沒有事先的業務 marker，只保存摘要。
  現在額外保留原 ring 中最近 30 秒內的已驗證樣本，使用獨立
  `observer_context_sample` 類型；不建立業務 marker、不宣稱 post window
  完成、不延長觀測。41 個 observer 單元測試與 12 個真實 PG17 測試通過。
  沒有樣本的 attestation 失敗仍只保留摘要。上述改動補齊診斷，**尚未
  證明修復 runtime-control／資料庫延遲本身**。
- `616de3b` PR job `103574205606` 尚未稽核 Cargo.lock 即失敗：原 action
  未鎖定安裝 `cargo-audit`，解析出的 `jiff 0.2.36` 缺少 include_str 所需
  文件。預先安裝 `cargo-audit 0.22.2 --locked`，驗證版本並使用專屬
  binary cache；官方該版本鎖定 `jiff 0.2.28`。保留原 RustSec 稽核及
  最新 advisory 資料庫，待新 runner 驗證冷安裝。
- `616de3b` Windows native job `103576313132` 已通過發佈包下載、雜湊、
  解壓與執行版本檢查；initdb 錯誤明確為讀取 fixture password 時
  `Permission denied`。Python 3.12.10 的 0700 ACL 授權 SYSTEM、
  Administrators 及 Owner Rights；PostgreSQL 會移除管理員 token 權限。
  對新建空白 fixture 目錄改授目前 user SID 與 SYSTEM 繼承權限，
  保持 private protected ACL，並以官方 `pg_ctl` 的 restricted-token
  路徑啟動 Windows PostgreSQL，持有實際 postmaster handle 至清理。
  Windows 尚待遠端實測；Linux 實際 `b44736e` 發佈包重新完成 PG17.11
  migration、readiness、web/Swagger 驗證（2181.094 ms）。這是 harness
  回歸證據，不替代新 HEAD 的正式發佈驗證。

核對的一手來源：
[audit-check 安裝行為](https://github.com/rustsec/audit-check/blob/69366f33c96575abad1ee0dba8212993eecbe998/src/main.ts)、
[cargo-audit 0.22.2 鎖檔](https://github.com/rustsec/rustsec/blob/cargo-audit/v0.22.2/Cargo.lock)、
[Python Windows mkdir ACL](https://github.com/python/cpython/blob/v3.12.10/Modules/posixmodule.c)、
[PostgreSQL 17 restricted token](https://github.com/postgres/postgres/blob/REL_17_11/src/common/restricted_token.c)、
[PostgreSQL 禁止管理員直接啟動](https://github.com/postgres/postgres/blob/REL_17_11/src/backend/main/main.c)。
