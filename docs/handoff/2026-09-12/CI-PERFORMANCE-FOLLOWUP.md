# CI 耗時修復實作

> 更新至 2026-09-13：`9bbc4a2` 的兩組 Federation 均在第一輪失敗，
> CPU affinity 實驗已撤回。Upload 重送修正與新增診斷見文末。

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

## 修正 detached-pipe 自測的退出競態（UTC 21:07）

`f62e689` 的 [PR Web static checks 103619660942](https://github.com/takanashi-tetsuya/northstar/actions/runs/34718318965/job/103619660942)
在既有 supervisor self-test 回報 `external pipe holder was not adopted
by the subreaper`；相同提交的 push Web static checks 已通過。真正的
Federation／MIX smoke 及 listener diagnostic preflight 亦通過。

該自測用 `tail -f /dev/null` 保留 inherited stdout，但 tail 會監看輸出
reader 並在它關閉後自行退出。監督器原本先完成 output finalization，
再掃描 adopted descendants，因此 tail 的自動退出與掃描會競爭。
本機 GNU 9.7／uutils 0.8.0 均實測在關閉 reader 後退出；未注入延遲
時，各自 25 次接管案例全過。只在臨時 supervisor 副本的 adoption
scan 前加入 1.1 秒排程延遲，舊案例第二次重現同樣失敗，stderr
保留 `command_output_drain_elapsed`／`command_output_pipe_held`。
監督器仍正確回報 lifecycle failure，不能把它描述成漏報成功。

自測改用保留同一 FD、繼承 ignored TERM 的 `sleep 30`，不隨 reader
關閉而退出；仍要求 detached detection、原本 9 秒 containment 上限、
精確 PID／birth-time 清理、程序消失及 exit 1。相同排程延遲下新案例
連續三次通過。此變更沒有修改 supervisor 或產品 deadlines，也沒有
等待完整 30 秒。若 detection 斷言再次失敗，現在會保留最多 16 KiB
的該案例 stderr，而不是只留下缺少診斷的泛用錯誤。
完整 `test-github-ci-supervisor.sh`（含其 16 項 marker 回歸）、shell syntax、
文件一致性與 diff 檢查通過。

`b5a3b9d` 的 [MIX 103608673765](https://github.com/takanashi-tetsuya/northstar/actions/runs/34714000982/job/103608673765)
完整 20×50 於 UTC 21:02:48 通過，observer、diagnostic、map、cleanup
均成功；其 Federation 已知 cleanup failure 仍使整體 CI 失敗。

## 首次 main 合約基準與過期開發 CI（UTC 22:43）

`f6c5f97` 的 [PR CI 34719096726](https://github.com/takanashi-tetsuya/northstar/actions/runs/34719096726)
完整通過 28 個必要工作，4 個 scheduled-only 工作預期跳過；Federation
及 MIX 均完成全部 20×50，observer／diagnostic／map／cleanup 成功。
[Release preview 34719094253](https://github.com/takanashi-tetsuya/northstar/actions/runs/34719094253)
亦通過全部 10 個適用工作，3 個 tag-only 工作預期跳過。fresh Linux、
Windows 及預設 UID 10001:10001 的 app image 均通過 PG17.11 startup、
migration、readiness 與 web assets 驗證。這是 preview，尚未發布 GHCR、
產生 tag-only attestations 或建立真正的 draft Release。

[PR #2](https://github.com/takanashi-tetsuya/northstar/pull/2) 已 squash 合併
到 `dev` 的 `ee407bf5a1aad5c972344a430f9ba1074048dbea`。GitHub 回報簽章
有效，檔案樹與 `f6c5f97` 完全相同。新的 dev push
[34722721446](https://github.com/takanashi-tetsuya/northstar/actions/runs/34722721446)
尚在壓測。[PR #3](https://github.com/takanashi-tetsuya/northstar/pull/3) 是
dev → main 的草稿，尚未合併。舊 f6 push 的
[Federation 103622681943](https://github.com/takanashi-tetsuya/northstar/actions/runs/34719094174/job/103622681943)
也於 22:37:35 完成全部 20×50 且 wrapper 全過；同一 push 的 MIX 此時仍在執行。
上述證據不能替代最後 main 提交自己的完整 CI。

PR #3 的 [Contract compatibility 103631528906](https://github.com/takanashi-tetsuya/northstar/actions/runs/34722769749/job/103631528906)
確定失敗於 resolver：舊 main `894f5e276d95418a722dca7c6900964453cf7165`
沒有 `contracts/proto`，其歷史也沒有 Protobuf 合約。現在分離首次加入
與既有比較：既有 module 繼續使用精確 event SHA 跑 Buf `FILE` breaking；
首次加入必須證明 checkout 完整、baseline 為 HEAD 祖先，而且 baseline
完整歷史沒有 module 或任何 `.proto`。不接受被刪除／搬移的舊合約、
shallow history、未知 SHA、錯誤 HEAD 或不存在／非目錄的 current module。
Buf 1.50.0 實測拒絕 empty image，因此首次加入執行真正的 `buf build`；
另一個必要 job 繼續執行 format、lint、generated-code drift。

新的 real-Buf 回歸在隔離 Git fixture 驗證：首次加入與相容欄位新增成功，
無效首次合約、既有欄位型別變更、刪除 message 及刪除 module 必須失敗；
resolver 另驗證歷史／SHA／路徑負例。實際 ee407bf → 舊 main 的首次加入、
ee407bf → 合併前 dev 的既有比較均成功。Buf binary 1.50.0 來自官方 release，
並以同一 release 的 SHA256 manifest 校驗。

本次同時套用先前暫存的排程改善：同一 PR、同一 `codex/*` push 只保留
最新 CI；`codex/release-*` 的新 push 可取消同分支舊 preview。main/dev、
tag、scheduled、manual CI 保留各自 run ID；tag release 仍依 tag 序列化
且不自動取消，manual preview 使用獨立 run ID。這不會追溯取消採用舊
group 的既有 run，不改任何必要工作、20×50／100×50 或失敗判準。
六項 CI performance 檢查含實際 workflow expression 的 event/ref 回歸，
release gates、aggregate coverage、actionlint、文件一致性與 diff 檢查通過。

### 未解決診斷與外部準備

`f62e689` 的舊 [Federation 103621410483](https://github.com/takanashi-tetsuya/northstar/actions/runs/34718313625/job/103621410483)
前 11 輪通過，第 12 輪因 observer client query 超過 5000.37 ms 而取消。
all-live 至失敗 8.396 秒使用約 4.00 CPU cores，最後有效觀察為 100 個
idle／ClientRead，無 SQLSTATE。all-live 分組被截斷，不能據此判定
PostgreSQL 或 server 的 CPU 占比；根因仍未證實，同一 run 的 MIX 全過。

更正之前本機「4 CPU」描述：早期 helper 在啟動 PostgreSQL 之後才限制
Python affinity，PostgreSQL 仍可用主機的 16 CPU；這些結果不能當成整個
fixture 共用 4 CPU 的容量證據。新的 transport-only probe 在最外層
`taskset -c 0-3`，確認 driver 和 postmaster 都只有這四顆 CPU。全部
50 pairs 完成四組原始 transport probes，observer 394 樣本、peak 100、
0 errors、最大 186.06 ms；但 pair 29 cleanup 的 port-number-only
listener 檢查失敗，因此整個 probe **未通過**。在 barrier 前後完整快照
之間的 15.114 秒，持續存在的 server／PG／Python 分別累積
8.71／7.72／4.84 CPU 秒；不包含快照間已退出的短命子程序。
未重現遠端 observer deadline，沒有據此放寬 deadline 或減少 probe。

main/dev 仍待啟用實際 rulesets，tag 簽署識別資訊與瀏覽器 GitHub 登入
仍待使用者提供。三個 GHCR 名稱的 anonymous token 請求均為 DENIED，
無法區分尚不存在或 private；正式流程仍須完成 public digest pulls。
尚未建立 `v0.2.0` tag，也未發布 GitHub Release。

## 2026-09-12 23:32 UTC：發佈預覽通過、排隊期限與啟動成本修正

`f6c5f97` 的 push `34719094174` 最終也完成 28 success／4 expected skips，
兩項 20×50 均通過；同 tree 的 dev／新提交仍須各自驗證。
`916e863` 的 [release preview 34723553326](https://github.com/takanashi-tetsuya/northstar/actions/runs/34723553326)
完成 10 success／3 tag-only skips。實際下載的 Windows／Linux artifact
分別以 SHA-256 `e719ffd7ef8326e2a457f51ee832350cd77136064ed714675bf62f711a621ec0`、
`8906f8897e8c237a0dfef04523236c17e4c9ac8b3f6a7e6b14dc006d6166bce1` 校驗，
並核對 package manifest、commit／version identity 與 raw/archive binary。
Linux 實際執行通過；Windows 在本機僅做 PE import／內容檢查，其實際
執行證據來自 fresh Windows runner。Windows／Linux fresh PG17.11 startup、
migration、readiness、web assets 均通過，分別 7922／1563.831 ms；Docker
app 的預設 entrypoint 同樣通過，3749.994 ms。組裝 artifact `10307781399`
成功；preview 未執行 signed-tag qualification、GHCR publication 或建立 draft。

`916e863` 的 PR [Federation 103635412668](https://github.com/takanashi-tetsuya/northstar/actions/runs/34723573535/job/103635412668)
前 5 輪通過，第 6 輪 pair 49 在 B 的共用 15 秒 HTTP readiness 期限失敗。
A／B 都已發布 nonce record；B 從首個 startup phase 至 record 為 13.739 秒，
接著 HTTP transport timeout。A 曾回覆 persistence authority probe timed out。
Observer 2991 樣本、peak 100、5 次 SQLSTATE 57014 全恢復、最大 4378.41 ms，
wrapper 的 observer／cleanup／diagnostic／marker／map／bounds 全部通過。
附件 `10307238348`／`10307323057` 已以各自 GitHub SHA-256 驗證；不能把這次
失敗歸為 observer client deadline，也尚未證明下述 CPU 修正能解決遠端問題。
舊 PR #3 的 MIX `103633629199` 另在 round 3 pair 49／50 的 A 尚未發布
nonce record 時逾時；前 2 輪成功，observer 健康。

dev `ee407bf` 的 [Federation 103632600732](https://github.com/takanashi-tetsuya/northstar/actions/runs/34722721446/job/103632600732)
則在前 14 輪通過後，第 15 輪遭 observer client_query_deadline 取消。
6655 樣本、peak 100，11 次 sample errors 中 10 次恢復，最後查詢
5000.264 ms。all-live 至 failure-before-cleanup 7.310 秒平均 3.985 CPU
cores、idle ticks 沒有增加；all-live 分組仍遭截斷，不能歸因到某類程序。
兩份附件 `10306879518`／`10307044028` 已通過 GitHub SHA-256 校驗。
這是另一種失敗，並非上述 pair 49 HTTP readiness 問題。

新的本機完整 MIX 1×50 診斷在最外層限制 PostgreSQL 與 driver 共用 CPU
0–3。原始 `916e863` 啟動成功（最後 batch 8638.447 ms），但 12 pairs 在
`finish()` 的第一次訊息檢查前便耗盡 150 秒。程式將等待共享認證 lane
也計入 recovery budget，違反其他認證階段既有的 admission／I/O 分工。
現在取得 lane 後、認證開始前才建立 recovery deadline，認證與四個
配送事件仍共用原本 150 秒，等待 lane 仍受原本 900 秒 worker 監督。
新增回歸模擬 200 秒排隊，確認四次認證消耗 20 秒、四個事件依序只剩
130／120／110／100 秒；用 `916e863` 原始 finish 跑同一測試確實失敗。
原始診斷 observer 1016 樣本、peak 100、0 errors、最大 66.878 ms；
wrapper cleanup 與所有診斷檢查通過，整個 business fixture **未通過**。

Phase helper 現在以一次即時 `/proc/<pid>/stat` 讀取同時驗證存活狀態與
birth time，仍做 signal permission probe、zombie／PID reuse／ancestry／
nonce 檢查，每次重新讀取，不快取 identity，也不改 25 ms 輪詢。
100 個自有子程序、100 次 50-pair live 檢查，3 組交替微型量測的平均
CPU 由 0.87823 降至 0.65794 秒（25.08%）；這不是整個 fixture 的改善幅度。
新增消失的 proc record、permission denied、真實未 reap zombie 負例。
23 startup scheduler、31 phase、37 MIX coordination 測試通過，文件一致性
通過。修正版完整 1×50 MIX 在 23:41 UTC 通過：最後 batch 啟動
8794.407 ms、業務 481485.209 ms、清理 6839.113 ms；observer 1303 樣本、
peak 100、0 errors、最大 21.033 ms，wrapper 全部成功且無 adopted descendants。
本機修正前失敗、修正後通過仍不替代新提交遠端兩項完整 20×50。

本機早期 HTTP 1 秒自測曾因 loopback 建連耗時失敗；在清理壓測並允許
自有 socket 的執行環境中，未改期限即可通過。沒有將此環境差異當成
遠端 readiness 的已知根因。GitHub 設定頁仍停在登入畫面，main/dev
rulesets、tag signing identifier 和正式 GHCR anonymous pull 尚待完成。

## 2026-09-13：Federation 連線排隊與真實 keepalive 驗證

`3b1c099` 的 [release preview 34726110875](https://github.com/takanashi-tetsuya/northstar/actions/runs/34726110875)
完成 10 success／3 tag-only skips。Windows／Linux fresh runner 的 PG17.11
startup、migration、readiness、web assets 均通過，分別 4719／1325.762 ms；
Docker app 預設 entrypoint 同樣通過，4258.439 ms，linux/amd64、10001:10001。
兩個 native build 都命中同分支共享 cache；Linux 還原 394 MiB 約 6 秒，
其後 workspace rebuild 6m11s，伺服器本體約 6m04s。Windows build 10m37s。
這批 compiler cache 已運作，但不能消除專案程式重新編譯；preview 沒有
正式 tag qualification、GHCR publication 或 actual draft Release。

舊 dev `ee407bf` push 的 MIX `103632600650` 最後通過完整 20×50；舊 PR #3
的 Federation `103633629151` 也通過完整 20×50。但它們各自 workflow
還有其他必要工作失敗，不能視為全部 CI 通過。`3b1c099` 的 push
`34726111044` 和 PR `34726112193` 此時均為 25 success／4 skips，兩項
20×50 在 2026-09-13 00:40 UTC 查詢時尚在執行。

本機 `3b1c099` 的完整 4 CPU、1×50 Federation 診斷啟動與四组 transport
斷言通過，observer 1100 樣本、peak 100、0 errors、最大 74.89 ms，
但整體失敗。保留的 6 份業務失敗中，3 份在 `initial-roster-a` 收到
policy-violation／close，另 3 份在 `fed-a-b` 遇到同樣關閉。第一種是在
Alice 已連線後仍排隊註冊／連接 Bob；其中一對 Alice／Bob 的 authentication
記錄相差約 409 秒。第二種是在新 Carbon client 的認證名額排隊期間，
既有 Alice／Bob 超過 300 秒閒置限制。另 pair 16 的業務全過但 cleanup
報告 port 41489 仍在 LISTEN；稍後唯讀 `ss` 已看不到該埠，尚不能判定
是重用或其他原因，沒有改動 listener cleanup 判準。wrapper 的診斷與
清理檢查本身皆成功，並不表示 fixture business／listener assertions 成功。

此輪相位檔案的時間戳顯示 transport 約 13.193 秒；連續 CPU sampler
完整落在其中的 6 個區間合計 12.252 秒，server／PG／Python 分別累積
7.73／6.23／5.23 CPU 秒。它不包含區間間已退出的短命程序，也不能
替代遠端遭截斷的分組資料；沒有重現遠端 observer 的 5 秒 query failure。

現在先完成雙方註冊，再一次取得 admission 建立初始兩條連線；第二條
認證失敗會關閉第一條。後續 Carbon／reconnect 等待名額時，由同一執行緒
每 60 秒對既有 clients 發送 WebSocket Ping。callback 只在未取得名額、
且沒有持有 slot／metadata descriptor 時執行；傳送失敗直接使 fixture
失敗。伺服器原有 WebSocket peer-traffic idle tracker 處理 Ping，300 秒
idle limit 不變；Pong 不進入 XMPP stanza assertions，也不重設 receive
deadline。取得名額後才開始新 credential exchange 原有 10 秒 deadline；
900 秒 worker 監督、runtime heartbeat、所有 transport／業務斷言均維持。

新增 170 秒分段排隊回歸在舊 initial setup 確實失敗；新 setup 通過。
另外覆蓋 360 秒排隊中的 Ping 節奏、傳送失敗阻止新認證、第二條連線
失敗清理，以及 Pong 不重設接收期限。23 startup／36 phase／37 MIX
coordination 測試、真實 flock admission 自測與文件一致性通過。含 keepalive 的
完整 4 CPU 1×50 Federation 通過：workload 49930.984 ms、cleanup
1629.761 ms，observer 189 樣本、peak 100、0 errors、最大 113.031 ms，
wrapper 全部成功。先前及此次連 preparation／provision 也有大幅速度
差異，因此不能把整體耗時差異全歸功於登入修正。

只針對自有雙節點 fixture 的真實 flock 排隊注入也已完成：Carbon
認證名額被佔用 320.264708 秒期間，既有 Alice／Bob 收到 5 輪共 10 個
實際 WebSocket Ping；釋放名額後完整 Federation 業務斷言通過。
workload 339667.509 ms、cleanup 485.267 ms 均 status 0，observer
689 樣本、peak 2、0 errors、最大 2.826 ms。產品 300 秒閒置限制未改。
原始 wrapper exit 2、case_map_ok=false：臨時 1-pair 診斷程式漏傳
`expected_pairs=1`，導致按預設 50-pair 驗證。保存的原始案例表以同一
validator 傳入實際 1 pair 驗證為 true；臨時程式已修正參數，但沒有
重跑或將原始 wrapper 結果改成成功。這是額外的真實 queue／keepalive
業務證據；完整 wrapper 成功證據仍以先前 1×50 run 為準。

修復已提交為 `fe82a5f`。push CI `34728864767`、PR CI `34728866857`
的 Web static checks 均在 `test-listener-stress-worker.sh` 失敗：舊靜態
契約仍逐字要求沒有 `on_wait` 參數的 `claim_login_slot` 呼叫。更新該
斷言以保留 `timeout_seconds=None` 並要求 forwarding callback，沒有
移除檢查或改動 runtime。已補跑 CI「Check operational script syntax」
全部 29 個命令（worker 群組獨立執行，其餘 28 個按原順序執行），
全部通過；worker 群組含 8 diagnostics／20 observed-entry／41 observer
測試及實際子程序生命週期清理。這補上先前 96 項測試未涵蓋的舊
靜態契約。新的提交仍須取得完整遠端 CI 證據。

## 2026-09-13：第 18 輪故障與取消期間的日誌保留

後續查明 `3b1c099` 的 push CI `34726111044` 已完整通過：28 success、
4 skips，Federation 與 MIX 均完成 20×50，required aggregate 成功。
這是歷史提交的證據，不能替代最新提交的驗證。

`15c7b3d` 的 release preview `34729253959` 完成 10 success、3 tag-only
skips。Windows／Linux fresh runner 與 Docker 預設 entrypoint 的 PG17.11
startup、migration、readiness、web assets 全部通過；組裝產物 artifact
`10308457995` 的 SHA-256 為
`39fa109c492bdc32b9e3098dfa08497fbdeb84f466493ce11bf42bb8e8ec5c32`。
尚未建立正式 tag、GHCR 發佈或實際 draft Release。

最新 push CI `34729253947` 的 Federation `103650472608` 完整 20×50
通過，耗時 53m10s；PR CI `34729256042` 的 MIX `103649715440` 也完成
20×50，耗時 55m52s。但 PR Federation `103649715403` 在第 18 輪失敗。
push MIX `103650472637` 隨後於 02:41:29 UTC 通過完整 20×50，
required aggregate `103661058298` 於 02:41:38 UTC 成功，push 全部
28 success／4 skips；PR 仍因 Federation 失敗而不合格。

push MIX 總耗時 91m25s。其 20 輪 phase 合計為 provision 8.36 分鐘、
preparation 27.30、startup 4.82、workload 47.32、cleanup 2.42；
runtime artifact 檢查僅 3.055 秒。相同提交的 PR MIX 對應合計為
7.04／12.87／0.88／29.86／4.14 分鐘，兩者皆回報 4 個 effective CPU、
1 login slot、2 startup pairs，全部 20 輪 phase status 0 且 wrapper
檢查全過。慢速 run 在每一輪的 preparation／startup／workload 都較慢，
並非單次卡住或重編譯；資料尚不足以判定底層 runner 硬體或排程根因。

PR 第 18 輪 all-live 後，`federation-transport-release-r18` 在
02:06:49.549 UTC 回報 `fixture exited before phase release`，parent
first-failure marker 為 02:06:49.880707 UTC。observer 最後成功樣本在
02:06:49.433512 UTC；它於 02:06:54.893915 UTC 才因 client query
deadline 失敗。因此 observer failure 晚於已知的 fixture failure。
02:06:55.2659 UTC wrapper 傳送 TERM 時，parent 已在 cleanup，卻已
恢復 TERM 預設處理，結果 exit -15；只留下 parent 初始附件，沒有
保留工作程序完成清理後的日誌，wrapper 也偵測到 adopted descendants。
兩個失敗附件已按 GitHub SHA-256 校驗：`10310230683`
`7da64a125912a739d8740986917fb0a7dafebb44bb5a6f1994aaa69f05e50019`；
`10310240669`
`330ab56ad9c4463b33ef7ff0df3639565e3801d6799639a9962ab4b5bb33a291`。

現在 cleanup 保留 INT／TERM handler：不重入 cleanup，保留原始
非零結果；成功 cleanup 期間收到訊號仍回報 130／143。外層原有
45 秒 TERM-to-KILL budget、工作程序停止與資料庫清理限制均不變。
phase helper 另輸出已退出 publisher 的 pair index，parent 僅用經過
範圍檢查的 index 選取自有日誌，使仍在清理的外層 worker 不會遮蔽
真正失敗的 pair。12 份、每份 32768 bytes、總量 524288 bytes 和
redaction 限制不變；診斷 index 不授權 signal 或資源操作。

使用實際 production cleanup 函式的控制訊號回歸，在原始 `15c7b3d`
確實得到 `-15 != 7`，修正版保留 exit 7、晚到的首個 fixture 錯誤、
移除自有 runtime 目錄並遮蔽秘密；成功 cleanup 收到 INT／TERM 的
非零退出亦通過。真實 nested publisher 退出、外層 leader 仍活著的
CLI 回歸確認 pair index 正確且不釋放 transport barrier。
CI operational step 全部 29 個命令通過，包含 12 diagnostics、
20 observed-wrapper、41 observer，以及 23 startup／37 phase／37 MIX
regressions。這些修正證明取消期間的診斷保留，尚未證明首個 fixture
退出原因已修復。

最後幾筆 PG 樣本顯示 pair 15 B 的 runtime-control backend 處於
idle／ClientRead，query age 最後到 6122.853 ms；這與 5 秒 critical
heartbeat 失效相容，但失去 worker 日誌，不能證明它就是退出程序或
確認根因。XML 分幀器已保存增量 cursor，不支持每次重新掃描整個
1 MiB stanza 的猜測。正在使用修正版執行完整 4 CPU、5×50 Federation
本機診斷；沒有增加 heartbeat／observer／認證期限或縮減遠端矩陣。

## 2026-09-13：取消修正驗證與 autovacuum 清理回歸

上述取消期間診斷修正已推送為 `ff6c444`。release preview
`34733776103` 再次完成 10 success／3 tag-only skips，Windows x64、
Linux x64 的下載後 fresh-runner 驗證及 Docker linux/amd64 預設
entrypoint 驗證均成功。組裝 artifact `10311005202` 的 SHA-256 為
`1f81075bd6782e8cb69caf9b86078218991176f548dad7b444865f14011d2e27`。
正式 tag、GHCR 發佈和實際 draft Release 尚未建立。

push `34733776036` 的 Federation `103662136537` 第一輪 observer
先失敗：最後成功取樣 02:55:08.567826 UTC、100 runtime backends，
最大 query age 1024.052 ms；02:55:14.051870 UTC 以 client query
deadline 結束，之後才產生 parent_cancel marker。取消前的 host
snapshot 仍有 100 server；all-live 至取消清理 8.855 秒，CPU 累積
35.425 秒、沒有新增 idle ticks。初始 process scan 在 250 ms 上限
截斷，不能用分組差值推定是哪一類程序耗盡 CPU。observer 共 378
樣本，1 error、最大 5001.346 ms。PR `34733777217` 的 Federation
`103662591382` 通過四輪後，第五輪發生同類 observer failure；1975
樣本、6 errors、最大 5000.573 ms，仍有 100 server，9.622 秒內 CPU
累積 38.413 秒。兩者 cleanup 均保留 exit 143、cleanup_ok=true、
adopted_descendants_detected=false，已保留 12 份 bounded worker tails。
這確認頂層取消清理修正生效，沒有證明 observer 逾時已修復。

失敗附件 SHA-256 均已校驗：push `10309768400`／`10310317819`，
PR `10311225222`／`10310841401`。壓測 supervisor 在直接子程序存活
時不掃整個 procfs；Federation client 也已在 bounded startup slot 內
完成 Python 初始化再加入 live barrier。這些既有機制不是待實作的修正。
03:18 UTC 查詢時，push MIX `103662136555` 和 PR MIX `103662591357`
仍在執行，兩邊其他 25 項前置工作均成功。

本機預定 5×50 的診斷在第二輪 cleanup 失敗而結束，不能記為 5×50
通過。前兩輪完整 business 均成功，workload 分別 617183.861／
613611.357 ms；第二輪有一個自有 database 的 DROP 回報 SQLSTATE
42501。最終 cleanup 已完成，driver 正確保留失敗；observer 3434
樣本、peak 100、0 errors、最大 65.634 ms，wrapper 診斷檢查均成功。

隔離 PG17 重現使用非 superuser 的 xmpp_test 作為 database owner，
觀察到 autovacuum worker 後執行 cleanup：原有 FORCE 回報 42501
（268.526 ms）；相同條件下一般 DROP 成功（286.912 ms）。因此 round
cleanup 現在先使用一般 DROP，僅在 SQLSTATE 55006（仍被使用）時
使用既有 FORCE 後備，兩次共用原本 35 秒 drop deadline。42501、
lock timeout、取消或其他錯誤不觸發 FORCE，也沒有增加角色權限。
owner／absence 驗證、四路並行上限、未清除資源的 ledger 均保持。

13 項 cleanup 單元測試通過，涵蓋共用期限、期限耗盡不啟動新 psql、
權限／其他錯誤不轉 FORCE。新增真實 PG17 回歸在原始 `ff6c444`
cleanup 確實因 42501 失敗，修正版則可清除 autovacuum database、
以 FORCE 清理仍存活的自有連線，並拒絕終止高權限外來連線。原有
PG17 integration 將 xmpp_test 直接當 bootstrap superuser，無法
撤銷 SUPERUSER；現在另設測試 bootstrap 身分，讓這項回歸能真正
驗證 NOSUPERUSER。完整 14 項 observer／cleanup integration 通過。
首次完整執行漏設本機 PG17 的 LD_LIBRARY_PATH 而失敗；補上 CI
同樣的 libpq 路徑後，全部通過（91.168 秒），未改測試期限。

## 2026-09-13：已到達的 observer 回覆與單次控制面查詢

`e0acbea` push `34735732835` 的 Federation `103667481230` 第一輪
通過，第二輪第 48 對 A 節點先失敗。新的診斷保留其完整錯誤：
03:47:05.460799 UTC，critical `runtime-control-refresh` 超過原有
5000 ms 心跳界線；當時 rules-read phase 2571 ms，距前次心跳
5802 ms。03:47:04.412778 UTC 同一節點的非 critical
pubsub-digest-delivery 也曾超時。父 barrier 隨後失敗，observer
直到 03:47:17.429291 UTC 才報 client deadline，不能倒置因果。

失敗附件 `10311092938`（SHA-256
`3e7d6ce54fc6102fa642d901858b65a40688a0dac77fbf5ead8e39574eb5c312`）
與 observer `10310823518`（SHA-256
`7b907ad48f80294b8fea9f1775bc30df48a4523266545d15ae86fe9504c8b7c9`）
已下載並驗證。case map 將該節點映射至 backend PID 2817、
backend_start 03:46:46.949842 UTC；03:47:04.957350 UTC 的樣本中，
它是 idle / ClientRead，query age 2092.925 ms、state age
2092.852 ms、無 blocking PID。這支持檢查客戶端接收與排程延遲，
不支持把這次失敗歸因於該查詢持續執行兩秒或 heavyweight lock。

控制面刷新現在在同一保留連線上用一個 UNION ALL statement 讀取
兩個投影，讓設定與規則共用 MVCC snapshot，並減少一次串行往返。
缺少必要設定仍失敗；規則順序、policy apply、service-control
polling、完整刷新後才更新健康的規則，以及 5 秒心跳界線未放寬。
診斷 phase 對應為 snapshot-read。

六項 Rust control-health 測試、45 項 subserver boundary 回歸及
architecture 檢查通過。Rust fmt 與 all-targets Clippy（runtime-test
profile、`-D warnings`）亦通過。實際 PG17 的三項管理命令測試通過，包含
新增的空規則、兩個設定旗標、blacklist／whitelist 排序與必要設定
遺失回歸。臨時測試適配器前兩次分別停在原腳本固定 5432、隔離
叢集尚未建立 xmpp_test 的環境檢查；建立測試角色自有資料庫並
使用本次隨機埠後，三項測試才完整執行通過，schema 已移除。

隔離 pgbench 使用 4 CPUs、100 連線、4 client threads、prepared
queries、空 federation rules，交錯執行前後版本各三次，每次
20000 次完整刷新。平均延遲的中位數由 2.586 ms 降至 2.092 ms
（約 19.1%）；這是 SQL 微量測，不能當成遠端整體壓測的改善比例。

另外，實際 PG17 重現新 observer 連線收到 100-row 回覆時，若
客戶端延後至 5.2 秒才執行，一次 PQconsumeInput 尚未讀完整個
socket 中的回覆，原實作便回報 client_query_deadline；失敗時
仍有 11671 bytes 可立即讀取。已暖機的連線則能正確排空並捨棄。
這是 [libpq 分段讀取行為](https://raw.githubusercontent.com/postgres/postgres/REL_17_STABLE/src/interfaces/libpq/fe-misc.c)
造成的已重現邊界問題，尚未證明它造成先前的遠端 observer failure。

observer 現在於等待期限耗盡後，最多額外進行 32 次立即可讀的
nonblocking reads，不再等待新資料；仍捨棄逾時樣本，要求同一
連線的新樣本恢復，未完成或超過上限仍失敗。原有 3+2 秒等待
預算、資料與結果上限、無 reconnect、三次連續錯誤規則均保持。
44 項 observer 單元測試及完整 15 項 PG17 integration 通過
（119.939 秒）；同一個新增實際回歸在原 `e0acbea` observer
確實得到預期的 client_query_deadline assertion failure。

`e0acbea` release preview `34735732791` 已完整通過 10 項工作，
三項 tag-only 工作按預期跳過。Windows／Linux fresh package
驗證為 `103668120635`／`103668120643`；Docker app
`103668193183` 驗證 linux/amd64、UID 10001 與實際 entrypoint。
組裝產物 `10310444714`，113427653 bytes，SHA-256
`c41c541ed41d4ed0f16efeea1b6cf61cc769cc8902984089397be608cb55f9cf`。
這些仍是該舊提交的 preview，不是實際 draft Release 或新修正的證據。

兩項新修正的本機 4 CPU、1×50 Federation 完整回歸已通過。
provision 55061.908 ms、preparation 168626.136 ms、startup
12250.454 ms、workload 688775.566 ms、cleanup 14079.696 ms，
各階段 status 0。observer 1887 樣本、peak 100、0 errors、最大
109.852 ms；wrapper 的 observer／diagnostic／marker／cleanup／
map／bounds 全部成功，無 adopted descendants。這輪整體耗時
沒有顯示相對先前本機回歸的加速，不能用 SQL 微量測代替它。

首次啟動這項回歸時，runtime-test binary 編譯已成功（300075.605
ms），但本機 16 GB tmpfs 的 /tmp 用滿，provision 後第 19 個
worker 未能建立 private session，後續診斷寫入也遭 ENOSPC。
原失敗記錄保留；該次未通過業務階段。只移除本工作已完成 Rust
單元測試的可重建 debug cache（5.2 GB），待原隔離 PG 清理結束
並恢復 7.7 GB 空間後，才重新完整執行上述成功回歸。

04:27 UTC 查詢時，`e0acbea` 的 push MIX 與 PR 兩組完整壓測
仍在執行；它們不是新修正的 CI 結果。

## 2026-09-13：合併後觀測器查詢中止與預備查詢量測

`d107126` 的 push `34738083195`、PR `34738084926` 均完整成功：
各有 28 個成功工作與 4 個政策預期跳過的工作，包含 CI required。
四組 Federation／MIX 20×50 全過，80 輪、408 個階段成功；四份
observer 附件 SHA-256 已核對。33,400 次有效取樣中共 22 次錯誤
均成功恢復，沒有 business failure marker，不能描述為零取樣錯誤。
release preview `34738083137` 亦通過全部 10 個適用工作。

PR #4 已 squash 合併至 `dev`，產生 GitHub 驗證簽章有效的
`d82bc56721d982d77112b6fc723fd3694205fc03`；其 tree 與 `d107126`
相同。舊 PR #3 已被關閉而未合併，因此建立新的 draft PR #5
（dev → main）。截至以下失敗，main 尚未合併新版本，也未建立
正式 tag、GHCR 映像或 Release 草稿。

合併後的 dev CI `34742180344`，Federation `103684385186` 前
9 輪成功，第 10 輪的 workload 在 6090.981 ms 後被取消，回傳
143。必要 observer 先於 06:56:57.066317 UTC 退出：
client_query_deadline、最大取樣時間 5000.457 ms、4106 有效樣本、
peak 100、11 次錯誤中 10 次恢復、最後連續錯誤數 1。此時尚無
failure marker，父程序之後才發佈 parent_cancel 並取消 driver。
wrapper 的 cleanup／marker／map／bounds 均成功，無 adopted
descendants；不能把取消導致的 worker 錯誤列為第一原因。

失敗附件 `10313573302`，SHA-256
`f8d1e134d79936308812b45c08a664080e44bceb0ad20e0b4557c1f65b9f6daf`；
observer 附件 `10313278971`，SHA-256
`fa94b3bfd619a2110c7e2a4eb4b2085033799931699f773dc8ca792bce38d6ff`。
兩份已下載校驗。最後有效取樣在 06:56:51.466080 UTC，100 個
backend 均為 idle／ClientRead，沒有 blocking PID；此前 48 個
上下文樣本也沒有 heavyweight lock。all-live 至清理前的約
7.81 秒耗用約 31.14 CPU 秒，四核全滿，但起始程序分組快照
被截斷，仍不能據此歸因某類程序，更不能宣稱已定位底層根因。

新增隔離 PG17 微量測在 postmaster 與 driver 共用四顆 CPU 下，
保留 100 個 runtime-control 與 400 個其他閒置 backend，交錯
比較各 40 次相同查詢。閒置條件下，simple／prepared 中位數為
3.333／2.484 ms；額外加入 100 條忙碌 pgbench 連線後，中位數
為 6.303／4.760 ms，最大值 34.768／16.088 ms，沒有取樣錯誤。
首次量測因測試角色無法連線至 bootstrap database 而未執行；
另建測試角色自有資料庫後才取得上述結果，隔離叢集已清理。

觀測器現在於同一條已 attested 連線上準備一次查詢，每次取樣
執行該預備查詢。只重用計畫，每次仍是新 transaction／backend
status snapshot；salt、完整欄位驗證、3+2 秒期限、逾時資料捨棄、
無 reconnect、三次連續可恢復錯誤規則與完整矩陣均保留。
準備步驟必須取得唯一完整的 command response，準備失敗、
逾時或尚未排空時不能宣告 ready。

46 項 observer 單元測試、16 項實際 PG17 回歸（66.698 秒）、
subserver／architecture 檢查通過。新增實際回歸確認預備查詢能
看到既有連線從 idle 變成 PgSleep，以及另一 backend 消失，
觀測器 backend PID 維持同一個。初版回歸誤將進入 PgSleep 前的
短暫 DataFileRead 判為失敗；改成在原三秒期限內等待目標狀態，
完整重跑後才成功。此量測證明觀測開銷下降，尚不能代替新提交的
完整 CI，也不證明它已解決遠端五秒中止。

## 2026-09-13：預備查詢完整 CI 通過，PR #6 合併

源提交 `b1a1655b3da5e1a0a13bb427d9b5c1db85c180fe` 的
[push CI](https://github.com/takanashi-tetsuya/northstar/actions/runs/34745032268)
與 [PR CI](https://github.com/takanashi-tetsuya/northstar/actions/runs/34745073283)
均完整通過，各有 28 個成功工作與 4 個事件政策預期跳過的工作。
兩個 CI required 工作分別為 `103700502130`、
`103701016395`，均確認 26 個必要工作群組成功。

四組 Federation／MIX regular 20×50 共完成 80 輪、408 個階段，
退出狀態均成功。Observer 記錄 33,093 次有效取樣、24 次錯誤，全部恢復。
各組 observer、wrapper、diagnostic、failure-marker 與 cleanup 檢查通過；
沒有 business failure marker 或 adopted descendants。下列附件均已下載並
核對 GitHub 記錄的 SHA-256：

| 工作 | 有效取樣 | 錯誤／恢復 | 附件 ID | 附件 SHA-256 |
| --- | ---: | ---: | --- | --- |
| [push Federation](https://github.com/takanashi-tetsuya/northstar/actions/runs/34745032268/job/103692486161) | 6,478 | 2/2 | 10314965570 | `e42bf1d4abbe7a7db07fa7483e304fe984d461a1764d3f2c5cf8821c642d8e05` |
| [push MIX](https://github.com/takanashi-tetsuya/northstar/actions/runs/34745032268/job/103692486146) | 8,633 | 0/0 | 10315340774 | `cc351e6cee2d67ebbd1430c178ed8a1bf50f0d3fa493f2207a0418d2cf2faa5a` |
| [PR Federation](https://github.com/takanashi-tetsuya/northstar/actions/runs/34745073283/job/103692616333) | 8,543 | 15/15 | 10315350806 | `b5043bc7db9c44958fd368915ab04c34fab7efe3224402e71ee60f92c9e4c399` |
| [PR MIX](https://github.com/takanashi-tetsuya/northstar/actions/runs/34745073283/job/103692616363) | 9,439 | 7/7 | 10315395993 | `3cba64eec5ea8f2d878654d0e9d021a8e0d73aa025a8efaa42e6704c9d082099` |

四個壓測工作的耗時依序為 54 分 58 秒、72 分 23 秒、73 分 23 秒和
79 分 38 秒。預備查詢的微量測改善已由前節記錄；這四組成功結果仍不足以
判定先前五秒中止的底層原因，或量化整體 CI 加速比例。

[PR #6](https://github.com/takanashi-tetsuya/northstar/pull/6) 由維護者於
2026-09-13 09:08:58 UTC 合併至 `dev`，產生已驗證簽章的提交
`761c56919cbca300bf4cd83dfc38ac03ab7659f6`。其 tree
`3e63088a66d4d433d84d577880c5ca810bb54eee` 與上述源提交相同。
截至 09:20 UTC，合併提交的
[push CI](https://github.com/takanashi-tetsuya/northstar/actions/runs/34749019591)
與 [PR CI](https://github.com/takanashi-tetsuya/northstar/actions/runs/34749024326)
仍在執行。

此紀錄只涵蓋上述提交。文件整理與 main 發佈候選需由各自的 CI 驗證；
正式簽名標籤、GHCR 映像與 Release 草稿尚未建立。後續依
[發佈流程](../../governance/release-roles.md)驗證最終 main 與製品，
由維護者執行最後的 Publish release。


## 2026-09-13：壓測 worker CPU 預留實驗（已撤回）

`664ff89` 的 [push CI](https://github.com/takanashi-tetsuya/northstar/actions/runs/34749896516)
在 Federation 第 7 輪失敗。Observer 查詢未能在 5 秒內收完整個回覆，
wrapper 隨後取消工作；其餘適用工作與 MIX 20×50 通過。
同提交的 [PR CI](https://github.com/takanashi-tetsuya/northstar/actions/runs/34749922456)
完成 28 success／4 expected skips，兩項 20×50 與 CI required 均成功。
[發佈預演](https://github.com/takanashi-tetsuya/northstar/actions/runs/34749896509)
亦完成 10 success／3 tag-only skips。

失敗期間的 8.257 秒內，四顆 CPU 累積使用 32.928 秒。有效前窗沒有
heavyweight lock 等待；較早 `761c569` 的 PR Federation 第 14 輪則捕捉到
多個控制連線等待 `LWLock/LockManager`，最長接近 4 秒。這些結果支持
排查共用 runner 的排程與資料庫競爭，尚不足以確定所有逾時的單一根因。

原 `scheduler_reserved_cpus` 只參與 Tokio 執行緒數計算，100 個 server
及 fixture helpers 仍可用滿四顆 CPU。`9bbc4a2` 於 worker session 啟動時套用
CPU affinity：四 CPU runner 的 worker 後代共用三顆，PostgreSQL、
observer 與 parent 保留完整四顆；單 CPU 主機共用唯一 CPU。選擇依
實際 inherited affinity 與 effective CPU budget 計算，日誌輸出
`workload_cpu_set`。矩陣、100 server all-live 屏障及所有期限保持原值。
CPU affinity 不預留 cgroup quota，也不能隔離其他主機負載。

新增真實程序回歸經過 production worker launcher 和 CI supervisor，
確認後代繼承 CPU set、parent affinity 不變；移除 taskset 的 mutation
確實使測試失敗。稀疏 CPU set、quota 較小與單 CPU 邊界亦有覆蓋。

本機將整個 fixture（含 postmaster）限制在同一組四顆 CPU，完整執行
5×50 Federation，25 個逐輪階段均成功，總觀測時間 501.750 秒。
100 台存活 server 的 affinity 均為 `0,1,2`，PostgreSQL／observer
為 `0,1,2,3`。Observer 1,003 次有效採樣、peak 100、0 errors，最大
78.173 ms；wrapper 的診斷、清理、case map 與容量限制均成功。
25 項 startup scheduler、37 項 phase、12 項 diagnostics、完整 worker
lifecycle、6 項 CI performance contract 與 9 項 release gate 測試通過。

同配置的 MIX 1×50 亦完整通過；observer 262 samples、peak 100、
0 errors，最大 20.444 ms，wrapper 檢查全過。遠端結果未通過，見下節。


## 2026-09-13：Upload 忙碌回應與控制連線傳輸診斷

`9bbc4a2` 的 [push Federation](https://github.com/takanashi-tetsuya/northstar/actions/runs/34754851173/job/103718169041)
與 [PR Federation](https://github.com/takanashi-tetsuya/northstar/actions/runs/34754853108/job/103718745213)
均在第一輪 transport 屏障失敗。這次 observer、failure window、case map
及清理驗證均成功，沒有因 observer 故障取消 driver。

Push 的 runtime-control snapshot-read 停滯約 5 秒，PR 為 3.674 秒，
加上此前未更新的 heartbeat，共超過原有 5 秒上限。Push pair 12/A
的 backend 在前窗持續為 idle/ClientRead，query age 增長至 6.672 秒；
不能據此認定是 SQL 執行或 heavyweight lock 阻塞，也不足以區分
用戶端排程、送收資料與核心傳輸延遲。四 CPU、另加兩個有時限 CPU
負載程序的本地 Federation 3×50 仍全部通過：834 samples、0 errors、
peak 100，最大 61.934 ms。CPU affinity 未改善遠端失敗，因此撤回；
worker 恢復繼承完整 affinity，原有啟動批次與執行緒限制不變。

[PR 協定整合測試](https://github.com/takanashi-tetsuya/northstar/actions/runs/34754853108/job/103717398808)
另在第一個 Upload 重送斷言失敗，原日誌沒有保留 HTTP 狀態碼。
檢查發現測試直接要求 201，漏掉 claim API 的 `409 upload_in_progress`。
修正只重試此明確錯誤碼，要求有效 `Retry-After`，所有嘗試共用十秒
重試預算；401、其他 409、429、503、傳輸錯誤仍直接交給原斷言處理。

本地在既有整合測試的首次成功下載後，持有相同 schema 的
`upload_storage_capacity_ledger` row lock 兩秒。真實 HTTP 得到兩次
busy 回應後，以相同 token/bytes 成功重送。完整整合測試、三次重送
上限、不同 bytes 拒絕、BOSH、WebSocket 及清理均通過，使用既有
`runtime-test` binary 和私有 PostgreSQL 連接埠。另有七項快速回歸
涵蓋錯誤分類、Retry-After、單一預算及逾時後不得新增請求。

Observer 現在保留自身連線的 Linux TCP_INFO 數值，包括重傳次數、
RTO、RTT、未確認封包和最近送收時間；失敗查詢也留下最後快照。
Phase boundary 同時記錄主機 TCP timeout/retransmit/drop 累積數。
沒有新增連線、背景採樣程序或封包內容，也不改變查詢與失敗期限。
49 項 observer 單元測試及 16 項真實 PG17 回歸通過。

| 證據 | Artifact ID | SHA-256 |
| --- | --- | --- |
| push 業務診斷 | 10317440977 | `442bbb119e4596126631d8805a0d689ef183879b612aec7d235347df0c84c910` |
| push observer | 10317191400 | `2353c0775fb155064acb069cf2eaf2c289192cbb2ef47c7ab7c97e75ab069e79` |
| PR 業務診斷 | 10317226671 | `b2cdde1a946de84efe9190e0470c89bb515e3c935e66babb964741ca2e256dc3` |
| PR observer | 10317161845 | `2841075c4b970d3275e34f27db00d4070264be0b9ad45bf73ad8da26900fa10a` |

[發佈預演](https://github.com/takanashi-tetsuya/northstar/actions/runs/34754851172)
完成 10 success／3 tag-only skips。完整 CI 尚未全綠，不能據此建立正式標籤。

## 2026-09-13：TCP 證據指向 PostgreSQL 端的等待

`2f0a676` 的 [push Federation](https://github.com/takanashi-tetsuya/northstar/actions/runs/34756492651/job/103723213377)
在第 2 輪失敗；[PR Federation](https://github.com/takanashi-tetsuya/northstar/actions/runs/34756494803/job/103722709967)
通過前 8 輪後，在第 9 輪失敗。兩次均由 observer 的
`client_query_deadline` 先觸發取消，尚未留下先於取消的應用程序故障。

兩條 observer 連線的 `total_retrans`、`unacked`、`lost` 都是零。
逾時時，最後送出資料和收到 ACK 都在約 5 秒前，最後收到資料在
5.403／5.432 秒前。請求已抵達對端 TCP stack，卻未收到 PostgreSQL
回應；這將調查範圍縮小到資料庫端，但仍不能區分排程與內部等待。
Push 共 736 samples、1 error；PR 共 2,962 samples、4 errors，
其中 3 次曾完成排空並恢復。兩次清理、case map 與證據大小檢查均成功。

本地改用 CI 相同 digest 的 PostgreSQL 17.11 Alpine 映像，在四 CPU、
672 connections 配置完成 5×50：1,739 samples、0 errors，最大
148.771 ms。這包含最初 252 秒的執行檔重建；測試環境、容器和
其匿名資料卷已清理。

在同樣四 CPU 上再加入兩個有期限的 CPU 負載程序，前兩輪通過，
第 3 輪有兩組因 WebSocket 關閉失敗。其中一組服務留下
`runtime-control-refresh` 五秒 heartbeat 逾時；observer 的一次查詢
則收到 PostgreSQL statement timeout，排空後恢復。其餘採樣正常，
wrapper、清理與證據檢查通過。獨立的程序計數顯示，這次慢查詢的
backend 連續多次處於 runnable 狀態而未增加 CPU 用量，隨後累計
2,677.951 ms runqueue 等待；容器的節流次數為零。
這證實本地高負載會延遲 PostgreSQL 排程，尚不能直接認定遠端原因相同。
負載程序與測試容器均已清理。

新增的診斷先驗證 postmaster PID／start tick，再以 namespace PID
找到 observer backend。每次查詢保存 CPU 與 runqueue 累積計數差，
等待期間最多讀取五次程序狀態。核心未提供排程計數、程序已退出、
PID 重用或讀取失敗時標記 unavailable。
可讀取 cgroup v2 時，另保留 PostgreSQL 容器本身的 CPU 用量、節流、
配額及權重；主機總量不能代替容器的資源限制。
沿用原本的 libpq 連線、SQL 與期限，沒有新增資料庫查詢或背景程序。
56 項單元測試、16 項真實 PG17、20 項 wrapper 與 6 項 CI performance
測試通過；短時容器測試驗證了 PID 對應、伺服器逾時與同連線恢復。

| 證據 | Artifact ID | SHA-256 |
| --- | --- | --- |
| push 診斷 | 10317743608 | `1b4a3b2f281e3d804710fb2448ad9d4452139aff81effa77f4ea2381766afff3` |
| push observer | 10317079680 | `dca19887b279e850ee30f196baaea2d48190cc9402e72ba27eccd25597ff4be5` |
| PR 診斷 | 10317969012 | `eef880598f83502a1299804550d2db07cdf7b2d334831baa7c5bdf18f3f2eaff` |
| PR observer | 10318440132 | `993045d7282683132a8f66c0459339e0a685c6d0f6cc6fb68a7d02d352f8e08f` |

此提交的兩條協定整合測試均通過，包含 Upload 重送檢查。
[發佈預演](https://github.com/takanashi-tetsuya/northstar/actions/runs/34756492600)
也完成 10 success／3 tag-only skips；完整 CI 仍因 Federation 失敗而未通過。
