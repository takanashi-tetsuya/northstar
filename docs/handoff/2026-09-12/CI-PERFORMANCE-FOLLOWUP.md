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

`9c22e1c` job `103577542447` 已完成上述 locked 冷安裝（2m42s），但新增的
版本比較誤用了 top-level 工具名稱。上游 acceptance test 明確期待
`cargo-audit-audit 0.22.2`；改正精確比對並輸出實際版本，保留不符即失敗。
來源：[cargo-audit version acceptance test](https://github.com/rustsec/rustsec/blob/cargo-audit/v0.22.2/cargo-audit/tests/acceptance.rs)。

`70dd1f4` RustSec job `103578223533` 已通過 locked 冷安裝（2m44s）、
正確版本比對與正式 Cargo.lock 稽核：沒有漏洞或警告。

`9c22e1c` Windows job `103579356430` 的新失敗位於啟動舊版
`powershell.exe` 的 20 秒期限，沒有任何 ACL 腳本輸出，尚未重試 initdb。
改用與 workflow 相同的 `pwsh.exe`（PowerShell 7），關閉 stdin，
保留 20 秒界線並加入 ACL 開始／完成標記。Windows package build
在編譯之前先使用共用 helper 實測 initdb 私有密碼讀取、pg_ctl 降權
啟動、實際 data_directory 及 owned handle 清理，提早揭露平台問題；
之後仍須乾淨 runner 驗證完整原生發佈包。Linux harness 回歸重新通過
PG17.11 migration／readiness／assets（1603.906 ms），Windows 待實測。

`41d8dc2` MIX job `103566011129` 完整 20×50 通過，觀測期間
14:11:14.785—15:45:53.350 UTC（94.643 分鐘）。第 2—20 輪平均 provision
24.341s、preparation 98.753s、startup 16.441s、workload 134.831s、
cleanup 6.933s。observer 11061 samples、peak 100、7 errors／7 recovered，
無截斷，driver／observer／cleanup／map／bounds 全部通過。該 run
仍因 Federation observer 失敗而整體失敗。ZIP artifact `10300876146`
SHA-256 `db294b749356e9f9dbdce0cb942f99945fc7e8a9231b409c3312e994db6d3a57`
已下載核對；不將此舊提交的 MIX 成功替代最新 HEAD 資格。

## 508c8a0 發佈預演及新競態證據（UTC 16:41）

[release run 34704411391](https://github.com/takanashi-tetsuya/northstar/actions/runs/34704411391)
已完成非 tag 預演：Windows／Linux 原生包、三個 linux/amd64 映像、
實際 migration／readiness／web assets 和 checksum／attestation 彙整全部通過。
Windows 提前 PG fixture 測試 11 秒；乾淨 runner 上的 Windows 原生 runtime
驗證 4750 ms，Docker 預設 UID／entrypoint runtime 驗證 1834.021 ms。
`verified-release-assets-0.2.0` artifact `10301409817` 的 Actions SHA-256
為 `c2c6da7cfc6ccf840382d8779336ae6a78ab4736ef5599eb213205bee8630fdb`。
這是 build-only 預演，沒有 GHCR 發布、tag 資格或 GitHub draft 下載證據；
之後的 Rust 修復仍須以新提交重新驗證。

`616de3b` Federation job `103574886793` 已完整 20×50 通過，observer、
cleanup、map 和 evidence bounds 全部成功。`508c8a0` Federation job
`103583281822` 則於第 4 輪 pair 32 B 再現 5499 ms 心跳故障，rules-read
3123 ms，watchdog 最大排程延遲 1 ms。pidfd monitor 在 server 退出後即
停止 workload，外層 supervisor 於 16:33:29.182 建立 command_exit marker，
這次 30 秒前窗涵蓋 16:33:23.676 的實際停機。前窗 backend 6084 最後在
16:33:20.535 為 idle/ClientRead；其後 observer query 出現可恢復逾期，
其他 runtime backend 於 16:33:33 出現 LWLock/LockManager 慢等待。
仍不足以把單一查詢判定為根因。附件 `10301579020`、`10300878612`
已下載並核對 SHA-256，分別為
`25ecbbb35f2adf45e104728e6a17475bd21c9a800a4976d32e0a4424766dea06`、
`ff5c6b9b6c4a778ae7967721b54f99610aad952d323f90b088fad89f96de1d46`。

`9c22e1c` MIX job `103578694527` 第 10 輪 pair 6 等待反向投遞 30 秒失敗。
其 B 資料庫仍有兩個已到期、無 lease、無 predecessor 的收件人，但各自
`authority_present=false`，因此 claim 的 authority join 永遠不成立。
沒有死信、outbox 或 observer 錯誤可解釋這個狀態。診斷／observer 附件
`10300947769`、`10300578693` 的 SHA-256 已核對：
`5467bf1bd77f546ac9e6dff4c74deea83206a1689baffaffcaf8d588158e0402`、
`d5b3a4972396d8f446a52549c928e09a0152752f32a4bb1b7fd6889fefdce260`。

已用 PostgreSQL 17.11 的可更新 view 和 advisory barrier，令舊 GC 查詢先
取得 snapshot，再讓 producer 更新 authority／插入 recipient 並提交，
最後放行 GC 的 row lock。舊 sequence GC 穩定留下 1 recipient／0 authority；
同類舊 event GC 穩定連帶刪除剛 requeue 的 recipient。這與 PG 的
[Read Committed 跨資料列快照語義](https://www.postgresql.org/docs/17/transaction-iso.html)
一致，無需放寬任何 deadline 或以機率等待製造競態。

修復先以有界 SKIP LOCKED 查詢持有候選 row locks，再於同一個明確
READ COMMITTED transaction 的下一個 statement 重新判斷 dependencies。
排序 authority 的實際 Rust 回歸已通過（1 test，0.24 秒），涵蓋新 live／
dead-letter 依賴、空 authority 回收、忙碌 producer 與 page bound；event
路徑及完整編譯／CI 尚待驗證。沒有修改既有 migration 或擴大回收範圍。

本地已安裝隔離 Rust 1.97.1 並重建當時 508c8a0 的 runtime-test binary。
本地 1×50 Federation 診斷達到 100 個同時存活 server，observer 1275 samples、
max query 75.604 ms、0 errors，未重現遠端心跳故障；但本地主機 credential
排隊令案例跨越既有 300 秒 idle 上限而失敗，workload 約 506 秒。
此結果是診斷資料，不能替代完整 CI 或聲稱本地矩陣通過。

上述 `616de3b` push run 於 16:47:53 UTC 最終為 **success**，兩組
20×50 與 CI required 均通過（28 successful jobs）；它是完整成功的
歷史基準，不代表後續已重現的競態不存在，也不能替代新提交資格。

兩個新的實際 Rust GC 回歸已共同通過（2 tests，0.62 秒）。保留原
程式的 1,146 項預設 Rust 測試亦通過；測試預設忽略的資料庫案例另跑。

進一步在完成實際 0142 遷移的私有 PG17.11 資料庫量測空佇列查詢：
完整 `claim_mix_deliveries` SQL 持有 48 個 relation locks，18 fast-path、
30 shared-lock-table；單表 `EXISTS` 則為 8／8／0。兩者使用同一個
`pg_locks` 自身 backend 量測方式，數字含量測查詢本身的鎖。
為空佇列加上單表 committed presence read；只有為空才返回，有資料仍
執行原有完整 lease／transport owner／ordering claim，同一次 pool acquire
持有的連線用於兩個步驟。沒有缓存空結果、改動 retained wake、掃描間隔
或 deadline。新增真實 event-table exclusive lock 測試，要求空佇列仍能
返回，之後提交的正常投遞仍可領取／確認。完整 regression 與新 CI 待驗證。

空佇列真實鎖阻塞／新插入恢復案例及兩個 GC 競態均通過；同一 binary
的預設 Rust 測試為 1146 passed／192 ignored，Clippy all-targets 且
`-D warnings` 通過。擴大執行到 8 個 MIX 資料庫案例時，7 個通過，舊
`an_expired_unowned_head_blocks_until_terminalized` 在測試準備時違反
`expires_at > created_at`，尚未執行 claim。它先前未列於 CI script。
改將測試事件的 created_at 和 expires_at 一起設為合法過去時間，保留
資料庫 constraint，再確認終止後的 successor 並清理其實際 lease／容量；
新增此 exact ignored test 至正常 MIX CI。這是 fixture 修復，非放寬 expiry
或 ordering。最終 8 個案例尚待重新編譯驗證。

最終同一份 Rust test binary 已通過 **8 個真實 PG17.11 回歸（2.28 秒）**
及 **1146 個預設單元測試（4.18 秒；192 個 DB／外部 fixture 測試另行
忽略）**。8 個回歸包括原容量帳本、4 個 ordering／wake／requeue 案例，
以及新增的 3 個 GC／empty-claim 案例。38 項 MIX lifecycle boundary
mutation tests、格式與文件／程序隔離檢查也通過。新 CI 仍需驗證完整
20×50、角色邊界與所有發佈包。

## 159d521 的 relay 自測競態（UTC 17:20）

[Web static job 103590168253](https://github.com/takanashi-tetsuya/northstar/actions/runs/34707525558/job/103590168253)
在 relay 自測讀取空 PID 時失敗。子程序直接建立最終 ready 檔後才寫入，
父程序的 exists 檢查可能讀到未完成內容。改為寫完私有暫存檔後用 link
原子發布，診斷 flush 先於發布，且所有啟動錯誤均經 finally 回收自有
process group；此測試完成後才建立網路測試的 socket 和 thread。
刻意延遲寫入 200 ms 時，新發布方式通過；恢復直接發布則穩定重現
invalid PID，兩條路徑均確認沒有存活的自有後代。

本地 Python 3.14 的同一組 operational 回歸另揭露 Redis relay 測試 CA
缺少 keyUsage。補上 critical CA basicConstraints 與 keyCertSign/cRLSign，
保留完整 TLS 驗證。Python 3.13 起預設嚴格驗證的變更見
[官方 ssl 文件](https://docs.python.org/3/library/ssl.html#ssl.create_default_context)。
CI 的整個 operational script step、process-isolation 及文件一致性檢查
已在本地通過；Rust 程式仍為 159d521，遠端 MIX database/wire/federation
job 103590168274 已成功，完整 regular 矩陣尚待完成。

## cfae924 的 PubSub 重啟觀測期限（UTC 17:49）

[PR job 103591555248](https://github.com/takanashi-tetsuya/northstar/actions/runs/34707965152/job/103591555248)
在重啟後等第二個 `RESTART-DIGEST-EVENT` 20 秒失敗；伺服器正常啟動且
Bob 完成登入。同提交的 push 分片通過。原診斷沒有保存佇列與租約狀態，
不足以斷定遠端是哪一個未結算 claim；但測試期限確實短於程式既有的
30 秒 PubSub outbox lease 和 60 秒 digest lease。

在自有 PG17.11 fixture 中，於停止前建立這兩種合法的已提交租約：
outbox 案例先在 1.273 秒收到 delayed replay，再於 28.998 秒後收到
ordinary event；digest 案例先在 0.324 秒收到 replay，再於 58.998 秒後
收到 ordinary event。兩者完整 discovery/config/errors/overwrite/retract/
outcast/restart 檢查及重複投遞檢查均通過。恢復 20 秒等待會失敗，且新增
診斷明確保留 1 個 pending、1 個 leased digest、未來 claimed_until 和
0 個 dead letters；清理確認 schema 不存在且 listeners=0。

重啟案例改用兩個邏輯事件共用的 65 秒截止時間，涵蓋最長既有 lease 加
有界 worker tick 餘量；不清除有效 lease、不更改 production worker，亦
不增加固定 sleep。一般案例重新通過，兩事件等待分別為 1.316 秒和
0.001 秒。失敗前保存已收到的事件，並在刪除自有 schema 前以受限 SQL
取得 queue/lease/dead-letter 計數，不輸出 payload 或憑證。

上述本地 wire probe 使用既有 508c8a0 runtime；已核對其 PubSub DB、
outbox 和協議程式與本次來源完全相同。它證明測試期限的可重現問題，
不替代新提交的完整 CI。腳本語法、process-isolation、migration boundary、
文件一致性及 workflow required policy 檢查通過。

## MIX 空佇列權限與 Federation observer（UTC 18:06）

檢查 `159d521` 的空佇列優化時，在完成 0142 遷移的私有 PG17.11
重現權限回歸：原完整 claim 在 read-only session 回傳 SQLSTATE 25006，
SELECT-only role 回傳 42501；單表 EXISTS 卻在兩者皆回傳 false／成功。
快速路徑現在先以 catalog 檢查正常 runtime 所需表權限與 transaction
可寫性；不符合時執行原 claim，讓 PostgreSQL 保留原錯誤，也繼續接受
原查詢合法的 column grants。SELECT FOR UPDATE 的欄位 UPDATE 權限
語義見 [PG17 SELECT 文件](https://www.postgresql.org/docs/17/sql-select.html)。

相同實際遷移與量測方式下，含權限檢查的空路徑仍為 8 relation locks，
全部 fast-path、0 shared-lock-table；原完整 claim 為 48／18／30。
沒有恢復對無投遞事件表的資料鎖，也沒有變更非空 claim 的 predicates。
新增實際 Rust 回歸涵蓋 read-only、recipient 與 sequence UPDATE 缺失、
事件表 SELECT 缺失，以及合法 column grants。新 binary 的 9 個真實
PG17.11 MIX 回歸全過（5.69 秒），1146 個預設 Rust 測試全過（4.07 秒，
193 個外部／DB fixture 測試預設忽略）。後者首次因 sandbox 禁止建立
socket 有 10 個 permission errors；允許自有 loopback listener 後同一
binary 全過，沒有改動測試。38 項 MIX lifecycle mutation 與 9 項 release
gate 測試全過，Clippy all-targets 且 `-D warnings` 亦通過。

另 [cfae924 Federation job 103592415811](https://github.com/takanashi-tetsuya/northstar/actions/runs/34707961247/job/103592415811)
於第 6 輪 transport 階段被 observer 中止。Observer 有 2613 個有效樣本、
最高 100 backends，10 次錯誤中前 7 次已恢復，最後連續 3 次為 server
SQLSTATE 57014。最後有效樣本時間為 17:52:54.555 UTC；17:53:04.707
退出前沒有業務 failure marker，保留 37 個近期有效 context samples。
這次是必要觀測失效，不能聲稱已發現應用 heartbeat 失敗或指定慢查詢。

已下載並核對 observer artifact `10303300002` 的 SHA-256
`cce8b46f78dffd7cdb7c5f4709872e949d1c0506398d020cd9d830e9d4ddb103`，
以及診斷 `10303060535` 的
`5344bf81dd1953e70df01682a551a8ccb8fa4b9227a8a3e17d79e6b2a2352f35`。
採樣期限、連續錯誤門檻及 workload 仍維持原要求；尚未定位遠端延遲根因。

## 避免逐提交複製大型編譯快取（UTC 18:22）

[8f8275e Rust test job 103597947079](https://github.com/takanashi-tetsuya/northstar/actions/runs/34710377026/job/103597947079)
成功還原 `2832572` 的 debug cache，大小 2,555,088,912 bytes，接著又以
`8f8275e` 為 key 存一份。原 composite action 雖称兩個 profile buckets，
實際 key 尾端包含每個 commit SHA，因此相同配置的每次 push／PR 都可能
再產生大型 archive。現在 producer 和 consumers 共用一個固定配置 key，
仍包含 OS、OS version、architecture、Rust 1.97.1、profile、所有 Cargo
manifest／lockfile 與 Cargo／toolchain 設定雜湊。保留既有 prefix 作為
首次暖機來源；平台或依賴配置變更仍使用不同 key。

Windows／Linux 原生 release compiler cache 同樣去除逐提交尾碼，保留
runner image、target triple、static CRT、工具鏈和依賴設定邊界。其原有
locked、explicit-target Cargo build 每次仍執行。

此快取只省編譯工作，所有 Cargo 命令與來源檢查照常執行；stress runtime
仍由同一次 run／attempt 的 smoke 產生，精確核對 SHA、tracked source
digest、profile、toolchain 和 binary digest。沒有把編譯快取當成當前
artifact，也沒有刪除遠端快取、提高付費容量或改動必要 CI 工作。

`cfae924` 的 Docker app build 另花 6m42s 重新編譯，cache export 約
179 秒；PG17 工具也 cache miss，之後實際 container migration／readiness／
assets 驗證成功（2144.09 ms）。這些是可確認的未命中／成本，尚無權讀取
cache usage API，不能證實該 repo 的容量或淘汰原因。
[GitHub 官方快取政策](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#usage-limits-and-eviction-policy)
說明超過配置容量可能反覆淘汰；本次修正直接減少相同配置的 archive 數量。

4 項 CI performance contract、9 項 release gate、5 項 runtime artifact
身分／篡改回歸、Actionlint 及文件一致性全部通過。新 runner 上的共用 key
首次建立與後續命中仍需遠端驗證；Rust 與所有測試期限未改動。

## 啟動阶段計時與最新壓測證據（UTC 18:43）

`159d521` 的兩組完整 20×50 現已通過：Federation job `103591122358`
約 56 分鐘，MIX job `103591122428` 約 69 分鐘，後者 20 輪及 observer
完整性、清理全部成功。該提交的整體 CI 仍因已於 cfae924 修正的 relay
自測失敗而為 failure，不能作為當前 release commit 的資格。

`fa61a04` push Rust test job `103599878230` 從 8f8275e 舊配置 key 還原
2,690,466,255-byte cache，Cargo test compile 20.72 秒，並成功建立
`-shared` key。PR job `103599969110` 也建立其 PR scope 的共用 key。
這證實首次暖機／建立，尚不能聲稱後續 exact-key 命中或整體 CI 已縮短。

`cfae924` MIX job `103592415832` 在第 8 輪 pair 50 的 B 節點等待
backend HTTP `/readyz` 超過原共用 15 秒 deadline。角色檢查訊息為
18:03:51.835，ABUSE key 訊息為 18:04:01.900，readiness record 為
18:04:03.578；這 10 秒空白涵蓋 schema／容量／AppState 稽核，現有
日誌無法細分。Observer 3844 samples、peak 100、1 次已恢復 57014，
其 61 個 failure samples 與清理完整；前窗多為 idle/ClientRead，不能
把控制連線樣本當成啟動 primary-pool SQL 的慢查詢證據。附件
`10302473392`／`10302798033` 已核對 SHA-256：
`13bbdd9abcb0dc726bd42ac56abec909cd112d569bce53a8fa2eb8fc52fd571b`、
`0490bce0d7484fd3ba7b258bc34d4e67b5934cf6eba2c912ab46f03ca0b0b577`。

另 `2832572` Federation job `103596225849` 第 7 輪及 `fa61a04`
Federation job `103600818015` 第 1 輪都因 observer 無法在 3 秒有效期加
2 秒 drain 內完成而退出；此為單次未 drain 的 client_query_deadline，
不同於先前連續 3 次已 drain 的 57014。fa61a04 先取得 356 個有效样本，
最後一個為 18:35:48.204，18:35:54.409 退出，沒有較早業務 marker。
其 all-live 至 cleanup 前 14.506 秒，CPU usage 增加 57.974 秒，4 核
idle ticks 均未增加；可用記憶體仍有 6,884,972 KiB，I/O full pressure
未增加。可確認 CPU 飽和，尚未定位到特定程序／函式，不更改 observer
或 workload 的期限、並行數與通過判準。

2832572 附件 `10302764409`／`10303730144` 已核對 SHA-256：
`4445df7aa6aecfb2e4b2b04ed9d8a72bf308722f3834431f12c9d961796ad4b4`、
`32e6096dbe9c6cfb858d710f3bc7dc4d5419c47219ee67144773f74817a73442`。
fa61a04 附件 `10303103444`／`10303622363` 同樣已核對：
`313f52d1e48570f1f22af9dfde08070919c6b3c6fb46d87630dfb1d4c89d0b56`、
`dd155f4bf951799aa564e4a6336506b19436e5b49266deb888a1379d2c2cfd88`。

為填補啟動診斷空白，新增 12 個固定名稱的 INFO 階段開始／完成事件，
使用 monotonic elapsed_ms；錯誤或取消會留下未完成的階段。覆蓋控制
連線預留、primary pool 與角色、schema、deployment capacity、credential
maintenance、AppState、MIX／PAM／upload 稽核。只經原有 bounded logging
sink 寫入固定名稱與數字，不收集設定、SQL、身分或憑證，不新增 query、
task、retry 或 deadline。

新 runtime-test binary 在自有 PG17.11 fixture、primary pool=2、Tokio=1
通過 328.490 ms 健康啟動，12 個開始／完成事件皆完整。刻意破壞自有
migration checksum 時仍拒絕啟動，最後未完成階段正確為 schema_verification。
Clippy all-targets 且 `-D warnings`、架構／subserver／migration boundary
與文件一致性檢查通過；遠端壓測仍待新提交驗證。

## MIX 重啟租約窗口與 CPU 分組診斷（UTC 19:21）

`6ec53af` 的 [release preview 34712140594](https://github.com/takanashi-tetsuya/northstar/actions/runs/34712140594)
已完成 10 個成功工作和 3 個非 tag 預期跳過工作；Windows／Linux package、
fresh-runner 下載驗證、三個 Docker image 及組裝全部通過。Docker app
實際 PG17.11 migration、readiness、web assets 驗證耗時 3221.57 ms。
Rust test job `103602700512` 已命中精確 `-shared` key，還原
2,561,878,546 bytes，執行 Cargo test 並通過；結束時未另存逐提交快取。
這證明前次快取修正跨提交生效，並不表示完整 CI 已全綠。

`2832572` 的 [MIX job 103596225796](https://github.com/takanashi-tetsuya/northstar/actions/runs/34709407193/job/103596225796)
前 18 輪成功，第 19 輪 pair 5 在 `MIX reverse after restart` 逾時。
此時 B 的 recipient sequence authority 仍存在，兩筆 own recipient
分別因未到 retry 時間及 predecessor 尚在而不可 claim；沒有 dead letter。
B 的 S2S FIFO head 為 sequence 3、attempt 1、retry due、active lease，
後面另有 9 筆，與先前 authority GC race 不同。附件 `10303239844`
及 `10303604003` 已驗證 SHA-256，分別為
`28db28f3c669e8d59be8276859e592d30d3fc6985296e6050ca73ddd7dcad92e`、
`39aa2db05cdeb05736791bd1e8082e5f3009bf87c2851ca3b3e3ff088e7719e9`。

產品的 S2S claim 預設保留 120 秒；程序可以在已 claim、尚未結算時停止，
新程序仍須尊重有效租約。原 fixture 的單筆 30 秒等待無法涵蓋此情境。
現在 restart finish 的配送事件共用 150 秒 monotonic deadline，包含
既有 120 秒租約及原本 30 秒配送餘量；從 readiness 後、認證前開始，
不因其他 frame 或後續事件重設。一般 inbox、認證 I/O、readiness、
worker、observer 的期限和 production lease／FIFO 都未更改。

自有 PG17.11 與當前 `6ec53af` runtime 的實際雙節點驗證，在 B 停止後
注入一筆已 claim 且仍有完整 120 秒的 S2S FIFO head。固定 6ec53af 的
舊 client 在 reverse wait 失敗（整輪 53.262 秒）；新 client 通過完整
durable drain、雙向 delivery、PAM leave、SASL EXTERNAL 和零殘留清理
（136.920 秒）。125 秒的初始候選窗口仍失敗：租約到期後還需要逐筆
配送 FIFO successors，因此最終保留原有 30 秒配送餘量，而非只加
5 秒。兩項截止時間回歸驗證 unrelated frames／下一事件不重設 budget、
到期不再讀 socket，以及底層 timeout 仍失敗。
無注入租約的正常雙節點流程 15.692 秒成功，沒有固定等待；36 項 MIX
協調測試、8 項 failure diagnostics、listener worker lifecycle 契約及其
既有子測試、CI performance 與文件一致性檢查通過。

`6ec53af` push Federation job `103603945292` 仍在第 1 輪因一次未 drain
的 observer client_query_deadline 失敗；329 個有效樣本、peak 100、
0 slow event／disappearance，最大 query 5000.369 ms。沒有較早業務
marker。既有 phase-boundary host counters 已顯示部分失敗窗口 CPU
全滿，尚不能歸因某個程序。補充同一時點的 `/proc` 累積 CPU ticks，
只按 server／postgres／python／other 分組，保留 counts、讀取失敗與
truncation flag；最多 4096 個程序或 250 ms，沒有新增輪詢程序，亦不
讀取或輸出 arguments、environment、SQL、身分名稱。本機實際程序
樣本 545 個、2 server／16 postgres，11.504 ms 完成，無截斷。

本機額外 4 CPU affinity、1×50 的完整 observer 診斷未重現遠端 CPU
飽和：1149 個有效樣本、peak 100、0 query error，最大 76.136 ms；
業務仍因部分連線超過既有 idle 限制失敗，不能列作壓測通過。修正
SQL 靜態抽取範圍後，在空的已遷移資料庫規劃 1514 段 SQL 中的
1488 段，最高估計 cost 2737.3；upload authority audit 為 1127.15。
這不是 CI 內部函式／實際資料量的 JIT 排除證據，未據此修改 JIT。

## 區分 database cleanup 失敗（UTC 19:50）

`b5a3b9d` 的 [release preview 34714000974](https://github.com/takanashi-tetsuya/northstar/actions/runs/34714000974)
已完整通過 10 個適用工作，3 個 tag-only 工作預期跳過。Docker app
編譯層命中快取；映像建置／快取處理約一分鐘，實際 PG17.11 migration、
readiness 與 assets 驗證仍重跑並成功（1840.611 ms）。Windows／Linux
也通過 fresh-runner 下載和真實 PostgreSQL 驗證。

同一提交的 [push Federation job 103608673774](https://github.com/takanashi-tetsuya/northstar/actions/runs/34714000982/job/103608673774)
第一輪完整通過；第二輪 50 pairs 的業務全部成功，卻於 database cleanup
失敗。首批四個目標（pair 1、2 的 A／B）回報 `drop_failed`，cleanup
階段總耗時 36.997 秒。Observer 973 個有效樣本、peak 100、0 query
error，最大 1752.189 ms，90 個 failure-window 樣本完整；wrapper
明確顯示 `observer_ok=true` 且沒有因 observer 取消 workload。不能把
此次 failure 歸類為先前的 observer client_query_deadline。

附件 `10304322988`／`10304567554` 已核對 SHA-256：
`3b1b01215f4665462dbc500c6440cf5d4e0d672bcb404e704b487b1521eae8ad`、
`a3eaf77fdb71c77f42ee7b58d72c031f29c5fbc5e7a7fa127eca68c683a967c2`。
第一輪 CPU 分組樣本讀取 1221 個程序、完整包含 100 servers；第二輪
觸及 250 ms 界線並正確標成 truncated，故不使用不完整分組差值歸因。

cleanup helper 原本丟棄全部 psql stderr，只保留失敗階段。改用 psql
`VERBOSITY=sqlstate`，只抽取獨立五碼 SQLSTATE，另保留固定的 client
failure reason，隨同已驗證的自有 database name／phase 寫入既有
bounded parent diagnostic。其他 stderr 文字不轉存；stdout/stderr
回應各以 4096 bytes 檢查。schema v1 的逐庫結果、owner attestation、
post-delete absence、4-worker 上限、5 秒 lock／30 秒 statement／35 秒
client deadlines、取消與 reaping 都維持。首次清理失敗也會有明確的
`round-database-cleanup` phase，而非 unknown。沒有增加 retry。

10 項 cleanup 單元／取消／ledger 回歸通過。真實 PG17 的兩項回歸在
7.294 秒通過：只鎖住自有 database 的 catalog row 時，刪除仍失敗並
保留 `55P03`，資料庫仍在；解除鎖後才成功刪除。foreign-owner 資料庫
仍被保留，已刪除／本來不存在者正確回報。這驗證診斷及邊界，尚未
證明遠端的四筆失敗同為鎖逾時；需由後續精確提交的 CI 證據確認。

## 將 Federation client 初始化納入啟動上限（UTC 20:50）

`90609f0` 的 [release preview 34715350916](https://github.com/takanashi-tetsuya/northstar/actions/runs/34715350916)
完整通過 10 個適用工作，3 個 tag-only 工作預期跳過。Windows／Linux
fresh runner 的 PG17.11 migration、readiness、assets 及三個 amd64
container 驗證均成功；Docker app 的 compiler layer 命中快取。完整
CI 尚未通過，不具備 release qualification。

同一提交的 [push Federation 103612348496](https://github.com/takanashi-tetsuya/northstar/actions/runs/34715350918/job/103612348496)
及 [PR Federation 103613432686](https://github.com/takanashi-tetsuya/northstar/actions/runs/34715354448/job/103613432686)
前 8 輪成功，第 9 輪在 transport release 期間失敗。push 的最後 observer
query 未 drain，client deadline 為 5000.356 ms；PR 的 observer 則健康，
14 次錯誤均已 recover，實際 B runtime-control 在 rules-read 中超過
5 秒 heartbeat silence，phase elapsed 2655 ms、heartbeat elapsed
5546 ms。其 watchdog tick delay 僅 1 ms（attempt 最大 26 ms）。兩者
均非資料庫 cleanup failure。all-live 至 failure 的約 11–12 秒窗口
分別使用平均 3.988／3.999 CPU cores，IO／memory pressure 沒有相應
上升。all-live 的程序分組樣本均被截斷，不能拿它減去完整失敗樣本
來歸因 PostgreSQL、server 或 Python 的 CPU 增量。

原 shell 的 all-live release 同時退出 50 個 barrier interpreters，並
啟動 50 個 server monitors 和 50 個 Federation clients。只量測實際
client module imports、限制 4 CPU 的兩次 50-process burst，分別消耗
4.514／4.299 CPU 秒，wall 1.156／1.116 秒；這是可削減的集中開銷，
尚未證明它就是所有遠端 heartbeat／observer failure 的根因。

現在 shell 在兩個服務完成 nonce 和 HTTP readiness 後啟動 monitor
與 persistent client；client 載入 modules 後才以自己的 PID 加入 live
barrier，並提交原有兩個 server PIDs。parent 的 startup permission、
nonce、birth time、worker ancestry 和全體 100 servers 驗證維持，
後續 pair 要等前批 client 就緒才獲 startup slot。所有 transport probes
仍在全體 live release 後並行執行，之後才可進入 authentication；
MIX、rounds、pairs、poll cadence、protocol assertions、health 和
worker deadlines 均未改動。

20 項 startup scheduler、31 項 phase/readiness、5 項真實 pidfd monitor
測試通過。既有實際子程序測試現在同時驗證 client 在 all-live 前不得
開始 probe、較快 pair 在較慢 transport 結束前不得註冊。worker lifecycle、
CI performance 與文件一致性檢查亦通過。

本機 4 CPU、真實 PG17.11、1×4 Federation 全部業務與 cleanup 成功；
observer 80 個有效樣本、peak 8、0 query errors，最大 2.225 ms，wrapper
的 observer／diagnostic／map／cleanup 均成功。初次臨時 probe 的 map
預期值誤留 50，雖業務與 observer 成功，wrapper 正確拒絕；改用既有
`expected_pairs=4` 參數後完整重跑成功。這是本機修改驗證，不能替代
遠端完整 20×50 的通過證據。
