# CI 時間優化

日期：2026-09-12。由使用者在耗時分析後確認 proceed；本文件為實作紀錄。

## 基準與範圍

[run 34678817435](https://github.com/takanashi-tetsuya/northstar/actions/runs/34678817435)
中，模板準備完成至第 20 輪結束，Federation 花 99.1 分鐘、MIX 花 72.2 分鐘。
兩族原本就平行執行；本輪分析時 `5002ca1` 的 Rust 核心 jobs 各約 3–5 分鐘，
smoke 約 8 分鐘。沒有承諾將完整壓力驗收壓到固定分鐘數。

## 實作

- 新增共用 Rust 快取 action，區分 debug／runtime-test；key 包含 Ubuntu 版本、
  架構、Rust 1.97.1、profile、Cargo manifests／locks／設定與 commit。只有
  Rust test 和 Federation smoke 儲存，各工作仍執行原本 Cargo 命令。正式壓測
  使用 smoke 產生的快取，仍以 Cargo fingerprints 和當次 profile 證據檢查二進位。
  排除 incremental 子目錄，快取只含 registry、git db 與該 profile 建構目錄。
- `listener-diagnostics` 成為所有事件的必要 job。它與 smoke 平行執行，
  regular 20×50 和 scheduled 100×50 同時依賴兩者，CI required 直接包含新 job。
  它先跑 marker、observer、wrapper、清理與 CI 契約回歸，再跑真實 PG17 整合。
- PG17 工具由官方 17.11 原始碼建置，驗證固定 SHA256，只裝到 runner 暫存目錄，
  使用獨立平台／建構腳本快取；不安裝或使用系統 PostgreSQL 服務。
- 每輪輸出 monotonic 分段計時：build、templates、provision、startup、workload、
  cleanup；失敗或中斷的當前階段也有 status 和耗時。
- 保留串行建庫；將已記錄的 round 資料庫清理改為最多四路，並受有效 CPU 數限制。
  helper 再次 attestation 固定 loopback 測試身份，逐庫檢查 owner、DROP 後檢查不存在。
  原父程序只在完整、順序一致、符合原清單的結果通過驗證後移除成功項目。
  未確認結果、外部 owner 和失敗項目保留；取消回收自有 psql 子程序。

20×50、100 個同時存活的伺服器、同一環境的連續輪次、15 秒 readiness、900 秒
worker deadline、PG17 fsync 和既有失敗關閉規則均未縮減。

## 本機實測

私有 PG17（fsync=on），每批 16 個空資料庫，依 1、4、4、1 路順序測量，
中位數為串行 2.205 秒、四路 0.830 秒，清理階段約快 2.66 倍。
這是小型清理量測，不等同有完整 migration／業務資料的 CI，也不是整體 CI 加速比。
完整時間與快取命中效果需由新 HEAD 的 CI 分段資料確認。

已通過：清理單元／子程序 8 項、真實 PG17 整合 8 項（並另以生產 Bash 入口
驗證保留外部 owner／cleanup list）、diagnostic 計時與隱私 8 項、runtime profile
10 項、startup scheduler 20 項、CI 優化契約 3 項和 release gate 9 項。
YAML、actionlint 1.7.12、Python／Bash 語法與 CI job coverage 已檢查。
Rust 來源未改動，本輪未重建 Rust。
完整 supervisor 與 listener worker suites 也已通過。

`ci-performance-sources.sha256` 記錄這批來源；本地測試輸出保存在同目錄的
`ci-performance-*.log`（依既有規則不納入 Git）。

快取 action 固定為
[actions/cache v6.1.0](https://github.com/actions/cache/tree/55cc8345863c7cc4c66a329aec7e433d2d1c52a9)。
所有快取都只是編譯加速，沒有沿用先前提交的測試結論。
