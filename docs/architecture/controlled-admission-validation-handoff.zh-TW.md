# Controlled admission：來源修正後的獨立驗證交接

這是待執行清單，不是執行結果。Stage 2 仍未驗收；Stage 3–6 也未因此完成。
目前來源已修正先前五個 blocker：prospective fence、獨立 witness binding、actual coordinator
projection、shrink exact target/history、多 Unknown caller knowledge。已完成的本地檢查僅為
格式／語法／普通 normal/test target 編譯與只讀 source/evidence review。
後續 observed_at source 修正保留實際 SQL 分類時間及完整 reconciliation effect，controlled output
改為 v4；這項來源／編譯成果仍未經真 SQL 或 saved replay 驗證。

## 已有與尚缺的證據

- `247522e9`、`cca8f120`、`280da7d8`、`87ec1c2` 的既有 CI 各自完整成功，32 jobs 成功、1個 schedule-only skip
- CI 的 Rust test job 是 workspace/all-targets/all-features；其結果只屬各自 exact commit
- `.github/workflows/ci.yml` 目前沒有執行 `scripts/test-controlled-admission.py`，不可把普通 CI 當作 dedicated Python reader/oracle 通過
- 本輪尚未執行目前 v4 Rust CLI 的 saved corpus、真實 replay、縮減或相容 projection 重播；上述 CI 不包含 v4 增量
- 編譯檢查不執行 regression bodies；mocked reader tests 即使將來通過，也不能代替真 Rust replay

## 下一步驗證與必要退出

1. 先固定新 commit/tree、dirty patch、實際 source scope、Cargo.lock、toolchain、features及新建 binary SHA256；外層保留 build/check 前後相同來源 map
2. 執行 dedicated Python oracle/reader regressions，保留每個失敗及真實分類。確認 incomplete／Cancelled／InvalidScenario／ReplayDivergence 不互相代替
3. 用新建的 trusted Rust CLI 錄下完整 concrete inputs、effect order及真實 outcomes；prediction不能標作observed。比較既有同案例前後行為，刻意修正另列
4. 從保存檔真正重播每個case和固定 rejection fixture。移除或修改input、output、schema、correlation、target、provenance都須拒絕；不能接受自洽但錯誤的期待值
5. 執行固定3→2 counterexample縮減。原始／候選／positive control／reduced順序與因果關係要成立；保持同一cap failure target，positive control為精確既定的一列移除並得4096
6. 對multi-Unknown核對人工推導的bounds：在空initial storage、同actor不同key、TTL尚未到期且無其他filter／proof歧義的例子，A Unknown後B confirmed保留[1,2]，兩個Unknown保留[0,2]；TTL／真正交付的reconcile可縮小當前集合但不改寫歷史Unknown
7. 確認未知proof view、空集合、view／row／modeled-byte不足都不能猜測hidden world；null bounds及停止原因、compact first-failure summaries、Stage1 incomplete prefix必須正確；詳細event／receipt仍可受evidence budget裁切，不能宣稱完整歷史都已保存
8. 核對 reconciliation 的實際分類時間與完整 effect／attempt／unresolved／requested fence，確認只有已交付 observation 的時間可縮小 caller alternatives；Scripted 時間不是 SQL conformance
9. 取得針對以上實際artifact的獨立驗收，才討論Stage2 reservation/finalization子退出。SQL observed_at 的真 adapter 證據、actor-clock範圍與後續production ownership仍須逐項交接

目前 `reconcile_message_admission` 仍沒有 production runtime caller；保留它的 sample／effect 不代表
Stage3 已接上 recovery owner。ExactAccepted 沿用 accepted-before-token 語義，返回的 fence 綁定
原請求，不能改稱已驗證 accepted row 的舊 token、歷史 COMMIT、rollback 或新的 retry authority。

Caller-model的64 successor／1,000,000 row-copy／64MiB serialized-state上限不等於OS RSS或wall budget。
現有driver只量測wall time，並在subprocess完成後检查captured output；沒有外層hard timeout／RSS／
stream-output supervisor。專項執行前需另定有限step/event/wall/resource預算、合法fixture、結果保存與
自有process cleanup規則。這不是授權執行SQL、服務、process-loss、故障注入或已取消soak。

## 保存→縮減→重播的既有命令介面

以下只描述既有工具，這份交接沒有執行它們。`trusted-provenance.json` 必須由外部可信build記錄
提供完整source_files/hash、binary/hash、Cargo.lock/hash、toolchain與model/adapter/binding身分；
不可從待驗證corpus自行採信。source_files scope應經review且覆蓋核心、adapter、oracle及build inputs。

```sh
cargo build --locked -p northstar-test-harness --bin northstar-admission-replay
python3 -B scripts/test-controlled-admission.py
python3 -B scripts/test-controlled-admission.py --binary target/debug/northstar-admission-replay --trusted-provenance trusted-provenance.json --evidence-dir controlled-admission-run
python3 -B scripts/test-controlled-admission.py --binary target/debug/northstar-admission-replay --trusted-provenance trusted-provenance.json --replay controlled-admission-run
```

Record模式會執行cases、固定parser拒絕資料，並呼叫既有shrinker；`shrink/shrink.json`保存原始、
每次候選、positive control及最終reduced的真實執行。Replay模式再次呼叫指定Rust binary，並核對
外部trusted provenance與獨立oracle。輸出目錄必須是新目錄，失敗證據不能被覆寫。

此controlled composition不證明真PostgreSQL transaction、real-clock、cryptographic verification、
wire、process loss或production readiness；252個historical ignored tests也不是新DB驗證。
