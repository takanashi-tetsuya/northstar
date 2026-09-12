# Linux 接續開發紀錄

日期：2026-09-12。這是開發與驗證紀錄，不是新的使用者授權。

## 目前狀態

本次接續開始時，本地與遠端分支 `codex/subservers-ci-security` 的 HEAD 均為
`4e63fc466c2ab1aa48f54b8b2b1694399c202c10`。本地驗證完成後，使用者已明確
確認「提交、推送並繼續追蹤 CI」；清理和診斷修復分成獨立提交。
原交接報告中的 marker ctime 競態已修復，observer/wrapper 已完成輕量真實
PG17 整合驗證。Federation runtime-control 超時的根因仍未確定；沒有新版
20×50 壓力驗收或新 HEAD 的完整 CI 結果，不能宣稱專案已通過整體驗收。

## 本次接續完成

- 遷移前的 1146 個來源檔案 SHA256 全部吻合，保留既有未提交工作與有意刪除的
  1775 個 auth-core target 構建檔案，未恢復這些檔案。
- failure marker 改用 Linux `renameat2(RENAME_NOREPLACE)` 原子發布，保留首次
  不覆寫語義；成功後不再刪除同 inode 的暫存硬連結。系統或檔案系統不支援時
  明確失敗，沒有覆寫或 hardlink fallback。父目錄權限與讀取端要求一致為 0700。
- 補上真實 publisher/reader 跨發布收尾階段的競態回歸、並行發布讀取與不支援
  原子發布的失敗測試。讀取端 inode/ctime 完整性檢查保留。
- 跨檔案審查另發現 readiness JSON 寫入中的可見性競態。observer 的小型紀錄
  現在寫完才原子發布，避免 wrapper 將合法但未寫完的紀錄誤判為壞資料。
- 新增可重跑的 `scripts/test-listener-control-observer-pg17.py`，自行啟動普通
  使用者擁有的 PG17 暫存叢集，使用兩個控制連線與一個 observer 連線。涵蓋
  真實 PgSleep、PID/backend_start、round/pair/A/B 匿名映射、固定 15 秒後窗、
  正常消失與成功時不輸出 ring、取消清理，以及 CREATEDB attestation 拒絕。
- 更新 `docs/SUBSERVERS.md`，同步 observer 接線、601/651 连接預算與證據限制；
  Rust watchdog 回歸也確認新增最大延遲欄位。原並發規模與期限未降低。

## 已完成驗證

| 驗證 | 結果 |
| --- | --- |
| Rust fmt | 通過 |
| `cargo check --workspace --all-targets --all-features --locked -j4` | 通過 |
| `cargo test --bin rust-xmpp-server --all-features --locked -j4 workers::tests` | 19 passed，0 failed，0 ignored |
| `cargo clippy --workspace --all-targets --all-features --locked -j4 -- -D warnings` | 通過 |
| failure marker 回歸 | 16 passed |
| observer 純測試／假 libpq 回歸 | 32 passed；不等同真實 PG 測試 |
| wrapper 短程序回歸 | 13 passed |
| 真實生產診斷收集函式回歸 | 7 passed |
| 完整 supervisor 與 listener worker shell suites | 通過，包含前述相關回歸 |
| 真實 PG17 整合 | 4 passed，0 failed；自有 PostgreSQL 正常關閉並清理 |
| 架構／子伺服器／文件一致性／CI required／release gates | 通過 |
| 受影響 Python、Bash 語法與 diff whitespace | 通過 |

本輪沒有執行完整 Rust workspace 測試套件、runtime-test 應用二進位重建，
也沒有執行兩族 regular 壓力矩陣。這些不能由上述結果替代。

## 環境與證據

Linux 為 Ubuntu 26.04.1，Python 3.14.4，Node 22.22.1，Rust 1.97.1。
系統缺少 Rust/PG 工具且 sudo 需要驗證，因此將官方工具與已下載的 Ubuntu
套件解包到 `/tmp/northstar-dev-tools`，沒有安裝系統服務或使用業務資料庫。
這是暫存位置，不保證下次會話或重新開機後仍存在。

真實整合使用 PostgreSQL 17.11，官方原始碼 SHA256：
`dd27f2b3c59e73ed14aa3324901242bf69a032a6347805f274e6260322d42979`。
構建使用 `--without-readline --without-zlib --without-icu`，測試設定 fsync=on。
它不是 CI 固定 Alpine 容器的逐字重放，也不是應用壓力驗收。

`validated-sources.sha256` 記錄這批 17 個候選來源檔案；本目錄保存已完成的
測試輸出。整合測試在清理前斷言了真實採樣內容與隱私限制，不保留私有資料庫、
salt 或原始測試叢集。Rust 重新生成的根級 `target/` 留作後續建構快取，受
Git ignore 排除；未恢復已清理的子 crate target。

下一階段是依本輪已確認的授權提交、推送並檢查新精確 HEAD 的完整 CI。
若 Federation 再次失敗，應以 PG 等待採樣、backend 身份與 watchdog 歷史延遲
共同判斷根因。現有觀測改動不是最終 runtime-control 修復。
