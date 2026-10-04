# Controlled admission：來源修正後的獨立驗證交接

這是待執行清單，不是執行結果。Stage 2 仍未驗收；Stage 3–6 也未因此完成。
新增的窄型 supervisor 是來源實作與 mocked regression source；不代表已執行 regression bodies、
Rust record/replay、shrinker、SQL、服務或 process/fault experiments。來源 review、AST／compile-only
以及普通編譯不能代替上述專項驗證。後續必須固定 exact source identity 並取得獨立 review。
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

Caller-model 的64 successor／1,000,000 row-copy／64MiB serialized-state 上限不等於 OS RSS。
原本在 subprocess 完成後才檢查 captured output 的 v1 執行入口已關閉；歷史 readers 只保留給
明確 mocked regression source，不能取得新 supervised qualification。這不是授權執行 SQL、
服務、process-loss、故障注入、dedicated corpus 或已取消 soak。

## 新窄型 supervisor 的來源契約

拓樸只有一個專用 owner、一個可終止的 Python worker，以及至多一個固定可信 Rust child。
owner 在 worker fork 前啟用 Linux subreaper；監控期間僅做有限 nonblocking control、monotonic
deadline、已持有 pidfd 的 signals／reap。所有檔案、hash、oracle、fsync、atomic prefix 都由 worker
負責，不能放回 owner 的 watchdog critical path。沒有 generic executor／journal／DSL 或 CI workflow
搬移。平台不支援 required enforcement 就 fail closed，不能換成 unsupervised fallback。

child 在任何 workload 前設定 parent-death SIGKILL、核對 fork 前保存的 parent、安裝 limits，
關閉無關 FDs，停在 private gate。worker 在 direct child 尚未 reap 時取得 pidfd，經 SCM_RIGHTS
把同一 kernel handle 交给 owner；owner 登記並 ACK 後，worker 才開 gate。worker 若在登記前死亡，
parent-death／parent recheck 應使 gated bootstrap 退出，owner subreaper 在有限 cleanup window reap；
若退出／reap 無法確認，就明列 incomplete 並停止新 launch。signal 已送不等於 cleanup 成功。

外部可信 ExecutionContract 綁定 run／mode、source files、helper sources、binary、Cargo.lock、
toolchain 及全部有限 budgets。來源 scope 包含 supervisor、entry point、oracle、fixed fixture constructors
和 build inputs；不能採信待驗證 corpus 自己給的 provenance。worker 在 project imports 前先核對
helpers。owner 最後只在有限窗口送出小 receipt；外部 caller 必須實際捕獲完整 receipt 與 owner exit
status，並綁定自己原先信任的 contract。缺 receipt、部分 receipt、exit 不符或 cleanup 未確認不能
取得完整 supervision。caller 還必須自行約束 interpreter／owner 初始化前的 startup window。
caller 的證據須指出實際已 review 的 invocation mechanism identity、startup／total limits、實際
terminal exit 和所捕獲 receipt 的確切 bytes hash；單一 JSON boolean 不算 enforcement 證據。
replay 的可信 prior contract／capture／caller evidence 必須由外部契約提供，不能從 corpus 自行採信。

可信 caller 的必要前置條件包含 fresh single-thread interpreter、已 review 的 CPython/Linux signal
語義與乾淨 inherited FD table。owner 會在首次 fork 前設 SIGCHLD=SIG_DFL，避免 inherited SIG_IGN／
SA_NOCLDWAIT 破壞 unreaped PID 的穩定性；上游 CPython3.12.14／3.13 的 sigaction 來源可支持此機制，
但不等於驗證目前 executor 的 patched build。hard RLIMIT_NOFILE 不能證明不存在高於該 limit 的舊 FD。
Rust artifact 必須 non-setuid／non-setgid、無 file capabilities，且 metadata 保持穩定，否則 privileged
exec 可能清除 parent-death 行為。worker 驗證以上 metadata 並以 retained descriptor exec，保留前後
source／binary hashes 和 frozen-workspace 假設；持有 FD 不代表同一 inode 的 bytes 無法被改寫。
新 evidence directory 明確使用0700。owner 在任何 fork 前驗證 caller receipt 的 pipe／socket 與
nonblocking 支援；完成等待及 cleanup 共用一個 absolute deadline，不能各自重開5s窗口。

目前數值都是待校準的有限提案：每個互斥 record 或 replay mode 固定44 normal＋34 parser negatives＋
4 shrink starts＝82，各自 cap128；不能混成164，也不能漏掉 shrink tail。whole-work600s；每 case30s
從準備前開始，涵蓋 capture、oracle、保存到 CaseReady，並受 whole-work 截斷。startup10s、cleanup5s、
receipt2s 與 caller startup10s 分別列入契約。stdout8MiB、stderr4096 bytes；多出一 byte 就截斷並停止。

owner／worker 各60 CPU seconds；Rust setup 後 soft9／hard10。Rust bootstrap 初始繼承 worker60，
所以 initialized-owner 的保守 nominal CPU allowance 是60＋60＋128×60＝7800 seconds。
1400 只是 setup 後的60＋60＋128×10，不能當端到端 hard ceiling；owner 初始化和 kernel 計帳 granularity
仍須另外說明。每 process1GiB 是 RLIMIT_AS，並不是 RSS 或瞬間 aggregate hard cap。
512MiB persisted evidence 提案包含 immutable observations、evaluation、全部 prefix generations、安裝 temp 峰值與1MiB
terminal reserve；這些值尚未經 safe qualification／實測校準。
另有限制 source material64MiB、binary128MiB、contract128KiB、control／receipt4096 bytes、prefix64KiB，
用來約束 metadata／hash 輸入；這些也僅為未校準的有限來源提案。

v2 case／corpus／shrink 使用同一 strict reader。worker 必須先保存 input、有限 raw stdout／stderr、
實際 bounded process observation，再做 strict validation／assertions／oracle。若實際 observation 不符
契約，其已保存 bytes／process facts 仍保留並標為 unqualified；partial save 不會重寫同名 raw files 或
製造 empty observation。metadata 未能完整保存時，result 的 null observation reference、
`observation_loss` 的 phase／reason／capture availability 與 typed interruption 明列此缺口。
raw 超界時保存的是 prefix hash 與已觀察長度下界，
不能把截斷 JSON 當 invariant，也不能從 SIGKILL 自行推斷 OOM。第一 invariant 與第一 unexpected stop
各自保存。後续 replay 比較完整 semantic output 和重算 evaluation，不 byte-match 本來就會改變的 PID、
wall time 或 runtime metadata。

FixtureMatched 代表完整 source-fixed output／evaluation 精確符合；它與 domain qualified／complete／
replay_matched、owner lifecycle、cleanup completion 分層。預期 Cancelled、Inconclusive 以及精確4097
counterexample 都必須繼續跑完固定 plan；4096 positive control 保持既定的一列移除關係。unexpected
process／oracle／protocol／storage failure 先保存再停止；不能標成 Pass 或改成單純成功的環境檢查。
`stop_kind` 從實際 observation／result／CaseReady 綁定到 owner receipt；資源、process、environment、
protocol、storage 中斷即使已 clean reap，`supervision_complete` 仍為 false。只有完整觀察到的 fixture／
oracle mismatch 可成為 clean `UnexpectedStop`。第一 stop category 與後續 `interruption_kind` 分開，
後續 owner 中斷不能被較早的 oracle mismatch 掩蓋。

prefix 使用固定最多83個 immutable generations：初始 `prefix-000.json` 加上每個 case 一個，最多
到 `prefix-082.json`，每個最多64KiB。worker 先寫／fsync 私有 temporary，再用不覆寫的 atomic link
安裝新 generation，fsync directory，移除 temporary 並再次 fsync。owner 只引用已接收的確切
file／hash；worker 在下一個 CaseReady 被接收前死亡，也不會改掉上一代已 ACK 的 bytes。所有
已保留 generations 最多5,439,488 bytes，安裝時另外保守計入最多64KiB temporary peak，仍在上述
512MiB總額與 per-case reservation 內。這不是可無限增長的 journal，也不會刪除先前 evidence。

`scripts/test-controlled-admission.py` 現在只保留 pure／mocked regression 入口。專項入口是
`scripts/run-controlled-admission.py`，要求 isolated no-site no-bytecode Python、外部 compact contract JSON、
獨立 run_id／mode／contract SHA256，以及外部 caller 的有限 startup／receipt capture。輸出目錄必須新建；
replay 不覆寫 record artifacts。

## 供後續安全判定的精確介面（尚未執行）

實際 entry point 的 argv 如下；尖括號是尚待可信 build／caller 提供的資料，不是已存在的 artifact。
應以 argument array 傳遞 compact JSON，避免把路徑或 JSON 插值成 shell code。這份介面說明沒有授權
執行，也不宣稱已有可用的 caller enforcement。

```text
<reviewed-python-executable> -I -S -B <absolute-root>/scripts/run-controlled-admission.py
  --contract-json <externally-trusted-compact-ExecutionContract-JSON>
  --contract-sha256 <SHA256-of-canonical-ExecutionContract-JSON-without-newline>
  --run-id <same-run_id-as-contract>
  --mode record
```

Replay 使用完全相同的參數名，最後改為 `--mode replay`，並傳入下列 replay 資料差異；不能把兩個
mode 合併為一次 invocation。每次各有完整82 Rust starts，cap128。

ExecutionContract 必須是 exact-field JSON object：

- `schema`: `northstar-controlled-execution-contract-v1`
- `run_id`: 本次唯一識別；`mode`: `record` 或 `replay`
- `root`: 實際執行 helper 所在 checkout 的 absolute root
- `binary`: 外部已 build、hash、review 的固定 Rust ELF executable absolute path
- `evidence_dir`: 本次尚不存在的 private output directory absolute path
- record 的 `replay_dir`／`replay_authority` 都為 `null`
- replay 的 `replay_dir` 指向既有 record directory；`replay_authority` 必須含外部可信的
  `contract`、`capture`、`caller_evidence` 三個完整 objects，prior contract 的 mode 必須是 `record`
- `provenance`: exact fields `schema model adapter binding_version source_sha256 source_files binary_sha256
  cargo_lock_sha256 toolchain`；schema 是 `northstar-admission-controlled-provenance-v1`，model 是
  `admission-controlled-v1`，adapter 是 `controlled_rust`，binding 是 `synthetic-material-v1`，toolchain
  是實際 `rustc 1.97.1 ...` identity。所有 SHA256 為真實64位 lowercase hex，source manifest hash 是
  canonical `source_files` object 的 SHA256。不可填 fabricated hashes
- `helper_source_files`: 以下六個相對路徑到 SHA256 的 exact map；也必須逐一出現在 provenance 的
  reviewed `source_files` scope：`scripts/lib/controlled_admission_supervision.py`、
  `scripts/lib/controlled_admission.py`、`scripts/lib/experiment_contract.py`、
  `scripts/run-controlled-admission.py`、`scripts/test-controlled-admission.py`、
  `scripts/test-experiment-contract.py`
- `plan_counts`: `{"normal":44,"rejection":34,"shrink":4,"total":82}`
- `budgets`: 必須精確為下面的有限提案，不能自行加入 RSS 宣稱、提高 cap 或省略欄位

```json
{
  "launches": 128,
  "whole_work_ms": 600000,
  "case_ms": 30000,
  "startup_ms": 10000,
  "cleanup_ms": 5000,
  "receipt_ms": 2000,
  "caller_startup_ms": 10000,
  "owner_cpu_s": 60,
  "worker_cpu_s": 60,
  "rust_cpu_soft_s": 9,
  "rust_cpu_hard_s": 10,
  "address_space_bytes": 1073741824,
  "input_bytes": 33554432,
  "stdout_bytes": 8388608,
  "stderr_bytes": 4096,
  "evidence_bytes": 536870912,
  "terminal_reserve_bytes": 1048576,
  "evaluation_bytes": 8388608,
  "source_bytes": 67108864,
  "binary_bytes": 134217728
}
```

canonical JSON 使用 sorted keys、無多餘空白的 separators `(',', ':')`、拒絕 NaN／Infinity；contract
hash 不含換行。owner receipt 實際 bytes 則使用相同 canonical JSON 並帶結尾 newline，caller 必須保存
該 bytes hash 和實際 owner exit status。stdout 必須是 caller 捕獲的 nonblocking pipe／socket；直接
redirect 到普通檔案會在任何 fork 前拒絕。

caller capture 的 exact fields 是 `schema owner_exit_status stdout_complete receipt`，schema 為
`northstar-controlled-caller-capture-v1`。供 strict validator 使用的外部 caller evidence exact fields 是
`schema invocation_id mechanism_sha256 owner_exit_status receipt_sha256 startup_limit_ms total_limit_ms
observed_total_ms stdout_complete`，schema 為 `northstar-controlled-external-caller-v1`。startup limit
最多10000ms，total limit最多617000ms（caller startup＋600s owner work＋單一5s cleanup＋2s receipt）；
實際 observed total 必須在該上限內。識別與 hash 只有在它們來自實際已 review、被信任的 invoking
executor 時才有意義，不能從 corpus 任意字串推得信任。

record directory 的 `contract.json`、`prefix-000.json`～`prefix-082.json`、immutable per-case raw／observation／evaluation／result
與 `corpus.json` 由 worker 保存；`caller-capture.json` 必須由外部 caller 根據真實 capture 另外保存，
worker 不會替自己的 owner 作證。replay 會比對此檔與外部 `replay_authority.capture`，並核對 prior
FixtureMatched、完整82-case tail、prefix／terminal 一致性和全部 source-fixed semantic facts。

目前尚未交付或驗證具體 external caller mechanism、該 mechanism 的 source hash、真正的 capture，
或任何82-run artifacts。因此上述 argv 仍有明確前置缺口：先選定並 review 能提供這些實際限制與
observations 的 caller，再由另一次安全判定決定是否可執行。缺口不能用一個 enforcement boolean 補上。

此controlled composition不證明真PostgreSQL transaction、real-clock、cryptographic verification、
wire、process loss或production readiness；252個historical ignored tests也不是新DB驗證。
