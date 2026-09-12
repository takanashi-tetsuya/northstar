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
