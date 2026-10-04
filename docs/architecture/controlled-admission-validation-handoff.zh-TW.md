# Controlled admission：來源修正後的獨立驗證交接

這份清單區分已完成的受控驗證與後續production／real-adapter義務。Stage2 reservation/finalization
受控子退出已獨立驗收，見[接受範圍](../evidence/experimental-rebuild/stage2-acceptance.json)。
完整direct lifecycle／outer ownership、real adapters及Stage3–6未因此完成。

## 現在已有的證據

- Exact commit `1a9d7cbdfa6eaf90febec839f189282d2e1218fa`、tree
  `6787043ec17b44ed1444d8ed25833f8d257e9c22`，固定 41 檔來源與 Rust binary 綁定
- Offline／locked 普通 build，以及完整 113 項 pure/mock suite 已通過；兩次 120s 不完整
  與一次 fixture error 保留於[普通結果](../evidence/experimental-rebuild/stage2-ordinary-build-unit-results.json)
- 兩次分開的有限執行：record 82 starts／37,581ms，saved-input replay 82 starts／64,899ms；
  caller、timeout、owner、worker 皆 exit0，完整 receipt 與 cleanup 均成立
- 每次固定44 normal、34 parser negatives、4 shrink roles；domain 分別為36 Pass、5預期Safety、
  5 Cancelled、2 Inconclusive、34 InvalidScenario。FixtureMatched不會把這些語義改成全部Pass
- 82份 input、Rust stdout、evaluation 在 replay 與 record 逐位元相同；PID／wall 等執行資料另驗，
  不作相等要求。每次83份 immutable prefix及496個唯一reference已獨立唯讀核對
- 保存的3→2縮減保留同一op-2 cap target與cleanup-survival前提；精確一列移除的positive control為4096。
  舊相容案例最早Safety為case8/op-1，不能與native/shrink的op-2混用
- [51項具名Rust CI矩陣](../evidence/experimental-rebuild/stage2-named-rust-ci-matrix.md)補上
  multi-Unknown、proof歧義、first-failure、witness/effect與as-of的來源斷言；251項ignored全部排除
- [Record/replay短索引](../evidence/experimental-rebuild/stage2-record-replay-results.json)保存
  contract、source、binary、receipt與私有證據包hash。原始輸入輸出及binary已持久保存；公開Git不放私有定位資訊

現行 production repository 在原SQL交易與鎖之下使用相同純decision，service消耗相同Coordinator；
controlled Rust從具體saved commands/effect order取得真正outcomes，獨立Python oracle另行比對。
Prospective fence仍是未確認準備，與獨立retained witness／positive receipt分開；cancelled Waiting、
多Unknown alternatives、actual coordinator projection和reconcile實際as-of均保留各自scope。

## Stage 2 收口證據與後續交接

1. 用單一 reader-only 腳本在原record的byte copy上檢查actual v2 `replay_source`／`verify_prior_case`。
   原始record、外部prior authority與41檔bound source不改；先後完整82案正例，中間22個篡改。
   已在300s預算內實際完成，83.220093秒、exit0、zero blocked attempts；原582檔、41source、script與contract不變。精確結果见[reader短紀錄](../evidence/experimental-rebuild/stage2-v2-reader-results.json)，未用舊v1 mocked readers或34個Rust parser negatives替代
2. 區分reference/authenticity rejection與更深oracle branch。所有local refs重算後若固定外部authority
   不吻合，應明列為authority拒絕，不冒稱已執行該變造的semantic oracle
3. 短before/after矩陣分開：Stage1獨立synthetic model11案→目前Rust相容projection；原既有具名
   regression的前後CI；目前record→saved replay。前者不是舊production SQL的實測等價證明
4. 獨立最終子退出審查已通過；真SQL、actor-policy clock和後續production ownership逐項交接。
   新source/test/docs checkpoint仍須remote exact-save回讀，review本身不代表已持久保存

目前 `reconcile_message_admission` 仍沒有 production runtime caller；保留它的 sample／effect 不代表
Stage3 已接上 recovery owner。ExactAccepted 沿用 accepted-before-token 語義，返回的 fence 綁定
原請求，不能改稱已驗證 accepted row 的舊 token、歷史 COMMIT、rollback 或新的 retry authority。

Caller-model 的64 successor／1,000,000 row-copy／64MiB serialized-state 上限不等於 OS RSS。
原本在 subprocess 完成後才檢查 captured output 的 v1 執行入口已關閉；歷史 readers 只保留給
明確 mocked regression source，不能取得新 supervised qualification。目前專項只涵蓋上述兩次本地JSON record／replay；不涵蓋SQL、服務、process-loss、故障注入或已取消soak。

## 新窄型 supervisor 的來源契約

supervisor 拓樸是一個專用 owner、一個可終止的 Python worker，以及至多一個固定可信 Rust child。
加上固定 capture adapter 與 GNU timeout，整體最多五個 processes；下列 CPU／AS budgets 只適用
於明列的 owner／worker／Rust roles，不能宣稱 adapter／timeout 也受到相同限制。
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
取得完整 supervision。新版 caller 僅檢查 total launch／capture interval，不另外宣稱 interpreter
startup enforcement。caller 的證據須指出實際已 review 的 invocation mechanism identity、total limit、實際
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
receipt2s 分別列入內部契約；startup10s 從 owner 已初始化後計時，不涵蓋 interpreter bootstrap。
caller total 提案為617000ms。Rust stdout8MiB、stderr4096 bytes；多出一 byte 就截斷並停止。

owner／worker 各60 CPU seconds；Rust setup 後 soft9／hard10。Rust bootstrap 初始繼承 worker60，
所以 initialized-owner 的保守 nominal CPU allowance 是60＋60＋128×60＝7800 seconds。
1400 只是 setup 後的60＋60＋128×10，不能當端到端 hard ceiling；owner 初始化和 kernel 計帳 granularity
仍須另外說明。每 process1GiB 是 RLIMIT_AS，並不是 RSS 或瞬間 aggregate hard cap。
512MiB persisted evidence 提案包含 immutable observations、evaluation、全部 prefix generations、安裝 temp 峰值與1MiB
terminal reserve；其中64KiB保留給 caller 的獨立 packet。worker 每一個 write path，包含 terminal
與 prefix temporary 峰值，都受 `evidence_bytes - caller_artifact_bytes` ceiling 約束；terminal 的單次
上限也扣除64KiB。這些值尚未經 safe qualification／實測校準。
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
獨立 run_id／mode／contract SHA256，以及固定 caller 的 total／receipt capture。輸出目錄必須新建；
replay 不覆寫 record artifacts。

## 已使用的精確介面與重錄參考

實際 capture adapter 的 argv 形式如下；尖括號是每次重錄須重新核對的可信資料。
本輪實際 contract與tool identities已由前述短索引綁定。應以argument array傳遞compact JSON，
避免把路徑或JSON插值成shell code。此參考不會自動授權新的執行或擴大已驗證的監督範圍。

```text
<reviewed-python-executable> -I -S -B <absolute-root>/scripts/capture-controlled-admission.py
  --contract-json <externally-trusted-compact-ExecutionContract-JSON>
  --contract-sha256 <SHA256-of-canonical-ExecutionContract-JSON-without-newline>
  --run-id <same-run_id-as-contract>
  --mode record
  --invocation-id <unique-trusted-invocation-id>
```

Replay 使用完全相同的參數名，最後改為 `--mode replay`，並傳入下列 replay 資料差異；不能把兩個
mode 合併為一次 invocation。每次各有完整82 Rust starts，cap128。adapter 只組成下列固定 argv，
沒有任意 command 選項，不使用 `--foreground` 或 `--preserve-status`：

```text
/usr/bin/timeout --signal=TERM --kill-after=5s 612s <reviewed-python-executable>
  -I -S -B <absolute-root>/scripts/run-controlled-admission.py
  --contract-json <same-canonical-contract> --contract-sha256 <same-contract-hash>
  --run-id <same-run-id> --mode <record-or-replay>
```

ExecutionContract 必須是 exact-field JSON object：

- `schema`: `northstar-controlled-execution-contract-v2`
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
- `caller`: exact fields `schema python python_sha256 timeout_sha256`；schema 是
  `northstar-controlled-timeout-caller-v1`，python 是實際 reviewed interpreter 的 canonical absolute path
  及 SHA256。timeout 固定為 `/usr/bin/timeout`，本輪只讀 inspection 記錄 GNU coreutils9.7／Debian9.7-3，
  SHA256 `6ca1891dfc0b05d7680770c2884c0391b92467c7bb6500a5c84677e6481739f1`；不同 identity 必須另行 review
- `helper_source_files`: 以下七個相對路徑到 SHA256 的 exact map；也必須逐一出現在 provenance 的
  reviewed `source_files` scope：`scripts/lib/controlled_admission_supervision.py`、
  `scripts/lib/controlled_admission.py`、`scripts/lib/experiment_contract.py`、
  `scripts/run-controlled-admission.py`、`scripts/test-controlled-admission.py`、
  `scripts/test-experiment-contract.py`、`scripts/capture-controlled-admission.py`
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
  "caller_total_ms": 617000,
  "caller_artifact_bytes": 65536,
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
`northstar-controlled-caller-capture-v2`。供 strict validator 使用的外部 caller evidence exact fields 是
`schema invocation_id mechanism_sha256 owner_exit_status timeout_exit_status receipt_sha256 total_limit_ms
observed_total_ms stdout_complete stderr_complete`，schema 為 `northstar-controlled-external-caller-v2`。
total limit 精確617000ms；實際 monotonic nanosecond interval 必須在該上限內，milliseconds 向上取整，
不能用向下取整把超界包成成功。mechanism hash 綁定 caller contract、source manifest、固定 timeout
path／arguments、owner entrypoint 與 Python flags。識別與 hash 只有在它們來自實際已 review、被信任的 invoking
executor 時才有意義，不能從 corpus 任意字串推得信任。

record directory 的 `contract.json`、`prefix-000.json`～`prefix-082.json`、immutable per-case raw／observation／evaluation／result
與 `corpus.json` 由 worker 保存；adapter 在 post-work 建立獨立 private sibling `<evidence_dir>.caller`，
保存 `owner.stdout.bin`、`timeout.stderr.bin`、`caller-capture.json`、`caller-result.json`、最後
`caller-evidence.json`。每個 raw 最多4096 bytes、每個 JSON 最多8192 bytes，全部最多64KiB，
使用 create-only writes、file fsync 與 directory fsync，沒有額外 temporary copy；不重複保存128KiB
contract／argv。directory 分離使未知 worker 狀態不會導致兩個 writers 爭用其 evidence directory。
worker 不會替自己的 owner 作證。replay 會比對 sibling capture 與外部 `replay_authority.capture`，並核對 prior
FixtureMatched、完整82-case tail、prefix／terminal 一致性和全部 source-fixed semantic facts。

adapter 先核對外部 contract、helper／Python／timeout hashes，單次啟動 timeout，使用 clean FDs、
stdin DEVNULL、固定 PATH／LC_ALL，獨立 nonblocking stdout／stderr。每個 pipe 只讀4096 bytes 加一個
sentinel；超界只關閉該 stream，保存 prefix hash／observed lower bound，繼續有限監控另一 stream 與
wrapper。到617s cutoff 即關閉 read ends，不以無限 wait 等 EOF，也不新增 kill／reaper 機制。
只有正常 forwarded0／2、兩個 complete bounded EOF、完整 exact canonical receipt、正確 run／contract
及已確認 owner cleanup 才可能 qualify；124／125／126／127／137、signal、未知 terminal、missing EOF
與 persistence failure 都 unqualified。partial／noncanonical capture 的 owner status／receipt authority
保持 null，raw prefix hash 另存，不能冒稱 receipt hash。未知／未 reap wrapper 必須保留為未知，不能
授權新 launch 或宣稱 cleanup。單次 adapter 沒有 retry path。

[GNU timeout9.7 source](https://github.com/coreutils/coreutils/blob/v9.7/src/timeout.c#L487-L581)
顯示 timer 在 fork 後才設定；kill-after5s 從首次TERM算起，137不能區分 timeout 或 command 被殺，
更不能證明所有 descendants 已 reap。preflight、Popen／exec bootstrap stall、post-work hash／fsync
不受 universal hard wall guarantee；617s 是實際 observed interval 的 qualification check，加上成熟
timeout 的固定 timer semantics，並不是 hostile-process／whole-system cleanup 證明。
執行前後 frozen-workspace 與 trusted executable 假設仍然適用，source／version inspection 不等於
目前 Debian patched binary 的 runtime verification。adapter 自身的 actual terminal outcome 必須由可信
invoker 觀察；post-work保存失敗即使留下完整檔案也不能採為 caller authority。

Caller的pure/mock regression與上述兩次timeout包裹的82-case record／replay已實際完成。
這只證明固定素材在該執行環境的成功路徑與有限觀察，不證明所有timeout、bootstrap、OS資源或
process-loss邊界。Trusted invoking executor的實際exit仍是必要authority，保存JSON本身不是自我授權。

此controlled composition不證明真PostgreSQL transaction、real-clock、cryptographic verification、
wire、process loss或production readiness；252個historical ignored tests也不是新DB驗證。
