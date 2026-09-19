# CI 耗時與失敗排查

日期：2026-09-12。依使用者要求排查耗時，使用 GitHub 插件讀取完成 jobs 的完整
日誌，以及兩族 observer 和 Federation 應用診斷 ZIP。本文件記錄調查結論。

## 結果

- [CI run 34688491041](https://github.com/takanashi-tetsuya/northstar/actions/runs/34688491041)
  對應 `0c4ca9d9c442d94589620aee51fabaf66f4bfd03`，已完成，結論 failure。
  32 個 jobs：25 success、4 按事件政策 skipped、3 failure。
- Federation：前 7 輪通過，第 8 輪應用失敗；observer 亦失敗。
- MIX：20×50 工作負載全部通過，driver exit 0；observer 失敗令 wrapper exit 2。
- CI required 正確拒絕上述失敗。兩族 observer 附件成功上傳，Federation 應用
  診斷成功上傳；MIX 應用診斷依成功 driver 規則跳過。

## 時間花在哪裡

[MIX 完整 job](https://github.com/takanashi-tetsuya/northstar/actions/runs/34688491041/job/103540733378)
的模板完成時間為 10:43:32.446 UTC，第 20 輪完成為 12:25:08.688 UTC，
共 **101.604 分鐘**。各階段由 `listener_stress_timing` 相加：

| 階段 | 20 輪合計 | 每輪平均 | 階段耗時佔比 |
| --- | ---: | ---: | ---: |
| 建庫 | 8.09 分鐘 | 24.28 秒 | 8.0% |
| fixture 準備、啟動、全體存活屏障 | 47.56 分鐘 | 142.67 秒 | 46.9% |
| 業務驗證與 worker 收尾 | 43.77 分鐘 | 131.32 秒 | 43.1% |
| round 資料庫清理 | 2.03 分鐘 | 6.10 秒 | 2.0% |

分段總和與 wall clock 有小量函式／紀錄開銷差距。Federation 前 7 輪對應平均
為建庫 24.85 秒、準備與啟動 163.54 秒、業務 110.93 秒、清理 6.56 秒。
因此只加速清理無法大幅縮短整體 CI；本地空資料庫的 2.66 倍不能當成 CI 加速比。

更接近本輪的 [5002ca1 run](https://github.com/takanashi-tetsuya/northstar/actions/runs/34684867162)
中，MIX 的同一區間為 101.619 分鐘，與本輪幾乎相同；Federation 為 79.535 分鐘。
更早的 run 34678817435 是 Federation 99.1／MIX 72.2 分鐘。不同 run 存在明顯
耗時差異，不能由單次比較認定實作帶來這些差異。此次 Federation 未完成 20 輪，
不能拿失敗前總時間當成加速後完整驗收時間。

## 已經失敗卻持續計算

兩族 observer 都在第 1 輪達到 100 個 runtime backends 後，於 10:46:22 UTC
以 `client_query_deadline` 結束。Federation 共 928 samples、最大採樣 3000.2 ms；
MIX 共 910 samples、最大採樣 3002.415 ms。兩者均沒有恢復，也未看到後續
failure marker，無法提供第 8 輪 PostgreSQL 等待證據。

`scripts/listener-readiness-observed-wsl.py:220` 只印出 observer early exit，
沒有終止 driver。因此 MIX 在診斷失敗後仍跑了 **98.772 分鐘**，最後才以診斷
失敗結束。前一個 run 的同樣額外時間為 Federation 73.114／MIX 83.334 分鐘。
這是延遲收到失敗結論的直接原因，與健康 workload 完整驗收所需時間是兩回事。

新 diagnostic preflight 本次成功且只花 2 分 57 秒，與 smoke 平行；它使用兩個
控制連線與一個 observer，尚未覆蓋 100 個 backends 和滿載 runner 的採樣情境。

## 編譯快取只省了一部分

本次是新 key 首次使用：debug producer 與 Federation smoke 均 cache miss，
並成功存入快取。Federation smoke 冷建構 502.088 秒；同 job 的第二次建構
只需 0.464 秒。Regular 兩族精確命中同提交的 runtime-test cache，但仍分別
建構 284.724／288.330 秒。還原本身只約 10／15 秒。

後續 Rust quality job 也命中 debug cache，日誌仍顯示大量 workspace crates
重新編譯。新的 checkout 時間晚於 producer 編譯完成時間，符合 Cargo 對本地
source mtime 的 freshness 判斷會使 workspace 重建的機制；這是有證據支持的
推論。現有輸出未保留 Cargo fingerprint dirty reason，無法逐 crate 證實所有
重建原因，或排除 profile／features 的額外影響。
[Cargo 官方 fingerprint 說明](https://doc.rust-lang.org/stable/nightly-rustc/cargo/core/compiler/fingerprint/index.html)。

## 重複 fixture 工作與實際應用故障

`scripts/federation-wsl.sh:252` 每個 pair 每輪產生 4 把 RSA-3072 私鑰；MIX
每個 pair 產生 3 把。因此完整 20×50 各是 4000／3000 把。它們在 prepared
屏障之前產生，屬於上表準備與啟動階段。4 CPU runner 同時只准入兩個冷啟動
pair，全部 100 個伺服器存活後才放行業務。現有分段未把憑證生成和真正啟動
拆開，不能把 47.56 分鐘全部歸因於任一單項。

Federation 第 8 輪 pair 5 的 A 端在 11:22:23.042 UTC 因
`runtime-control-refresh` 心跳沉默 5530 ms 超過 5000 ms 門檻而關閉。
當前 phase 為 rules-read，phase_elapsed 265 ms；watchdog tick delay 1 ms、
本 attempt 最大 tick delay 29 ms。父程序隨後在 transport 屏障發現 worker
退出。這些資料不能證明是單一 rules-read 查詢耗時 5 秒，也不能用最後一次
tick 正常就斷定之前完全沒有資源壓力。確切 PostgreSQL 等待原因仍缺採樣證據。

## 後續改善順序

1. 補滿載 observer 回歸與診斷修復；對無法繼續提供必要證據的 observer 失敗，
   以明確 failure 終止並回收自有 workload，縮短失敗回饋。保留成功驗收的全部
   20×50 規模、100 個伺服器屏障及應用健康期限。
2. 將憑證準備、啟動准入、readiness、業務子階段分開計時；評估同 run 內每個
   pair 專有測試憑證跨 round 重用，維持 pair 間 CA 隔離、TLS 斷言和私鑰清理。
3. 補 Cargo fingerprint 建構原因；評估同提交且可核對 provenance/profile/digest
   的 build-once artifact 傳遞，避免不同 job 重建同一份 runtime binary。
4. 按 PostgreSQL 等待證據修復 runtime-control，不能直接放寬心跳或略過健康檢查。

此次為排查紀錄，尚未實作以上後續方案。
