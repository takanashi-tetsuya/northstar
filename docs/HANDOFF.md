# Northstar 開發與本地驗收交接

更新日期：2026-10-13 UTC。本文只記錄不屬於其他權威文件的現況：分支與推送、本機 VM 實驗室及接手步驟。結構、領域收斂、實驗重建、產品限制與發佈的狀態各有一份權威文件，見[狀態地圖](README.md#status-map)；本文只連結，不重述。接手時以 `git`、GitHub Actions、systemd 與原始證據重新核對，不把本文的快照當成即時結果。

## 分支與推送

`main` 為 `07870ce`（2026-09-21），[`v0.2.0`](https://github.com/takanashi-tetsuya/northstar/releases/tag/v0.2.0) 已於 2026-09-20 發佈。開發在 `dev`；遠端 `dev` 仍是結構工作的基線 `10d5982`，之後的結構工作提交只在本機 `dev`，尚未推送。推送後以該 HEAD 的完整 CI 為準，不沿用舊綠燈。本機以 `node scripts/run-ci-offline.mjs` 執行 CI 中不需外部服務的步驟（見[工程結構藍圖](architecture/engineering-structure.zh-TW.md)第 6 節）。

## 本機 VM 實驗室

2026-09-27 開始的 24 小時浸泡（固定候選 `0ea54b0`）因 systemd 退出證據缺失而沒有封存。原始證據保留在私有 `target/vm-lab/20260927T1350Z/`，其中沒有 2026-09-29 之後的浸泡或 active load 紀錄。2026-10-13 檢查時，六台 `northstar-lab-*` VM 均為 shut off，也沒有 `northstar*` user systemd unit。

浸泡、active load 與 F1–F14 聯邦／DANE 等 VM 驗收都未完成。重新開始需要使用者授權，並以新候選、新 unit 與新的完整時段進行，不能沿用原輪資料。原輪的封存條件、DANE 準備與驗收順序見 [2026-09-29 交接](handoff/2026-09-29/HANDOFF.md)。

## 接手步驟

1. 以 `gh api` 核對遠端 `dev`、`main` 的實際 HEAD；本機的 `origin/*` 參照可能過時。
2. 依[狀態地圖](README.md#status-map)讀各範圍的權威文件；結構工作的下一步見藍圖第 8 節。
3. 啟動 VM、負載或部署新 binary 前先取得使用者授權。沒有獨立安全審查者與離機備份目的地時，相關門禁保持開放（見[已知問題](KNOWN_ISSUES.md)）。
