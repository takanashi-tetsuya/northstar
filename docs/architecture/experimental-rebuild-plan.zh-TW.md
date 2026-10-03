# Northstar 實驗架構重建台帳

更新日期：2026-10-03。這是由持久 Git 基線重新實作的台帳；不是遺失工作樹的還原證明。

## 來源與證據界線

重建起點是 `recovery/experimental-architecture-20261003` 的
`4f1b3b9032b98004eec2160172d5af3acbcc16b8`，Git tree
`5f9d26383daa2b6bc467966a84df74c756f94e37`。首次 checkout 為乾淨的 1,622 個追蹤檔案；
其中 1,618 個來源路徑來自舊 A1–A10 包，另有恢復說明。兩份舊完成文件已換成歷史說明，
Windows batch 只做既有 `.gitattributes` 要求的行尾正規化。
本輪基線以此 exact Git commit/tree 固定；不假造遺失的歷史 archive，也不以新 replay engine 作 Stage 0 前提。

2026-10-02 的《Northstar 理想實驗架構研究》是改造目標，特別是第 14–17 節；
《Northstar 架構改造階段成果與待決策事項》保存了先前的設計、審查發現與限制。
它們不是現在 checkout 的執行證據。失落的 shared admission/direct/auth/MIX 核心、
oracle、受控 corpus、真 SQL/wire artifacts 與有限 runner，不能因舊報告寫過通過而在此標為已恢復。

基線 CI [37107644451](https://github.com/takanashi-tetsuya/northstar/actions/runs/37107644451)
的 head 是上述 commit，conclusion 為 success；這只描述恢復基線的既有 CI。
每次新實作都要記錄自己的 commit、案例集合、工具鏈、執行／未執行項與限制。
`stage0-baseline.json` 保存本輪讀取的來源、config example 與工具鏈身分；該 source-only 記錄自身不包含服務或 wire 執行。

## 階段與退出條件

| 階段 | 必須交付的 production 路徑與實驗能力 | 可判定退出的證據 | 本輪狀態 |
|---|---|---|---|
| 0 責任與基線 | 既有 admission、commit、handoff、write、ACK、settlement 權威；Unknown 與 recovery 分類 | 乾淨 Git 身分、責任表、實際／缺失能力稽核、獨立只讀審查 | 本輪 source-only 已驗收並保存於 d9eb2e2；CI runtime 缺口另列 |
| 1 可執行規格 | 延伸既有 catalog/harness；actor/identity 初態、混合負載、TTL/capacity、預期 outcome、故障語義、budgets、termination、provenance、cleanup | 不合法正常負載先拒絕；4095→4096→4097、retained pending、mixed identity、TTL 前／恰好／後；精確 oracle 與負向測試 | 本輪限定 scope 已驗收並保存於 2bdfed9 |
| 2 Shared admission | production 與 controlled composition 呼叫相同 state/effect coordinator；SQL 交易內的 authority/version/fence 重驗不移除 | 正常、預期容量拒絕、replay、expiry、Unknown 的具體輸入與 effect order 可重播；重複／不符 completion 不推進 | 窄設計已只讀審查；實作中，未驗收 |
| 3 Direct lifecycle | 真正 mode-aware durable commit 接入既有 DirectMessageRouter、UnroutedClaim、exact OutboundItem、native write 與 SM/BOSH owner | admission→commit→finalization→handoff→write→settlement 的責任可判定；取消、owner replacement、舊 token、partial write 與 delayed ACK cases | 未重建 |
| 4 高風險域 | MUC gate/authority/admission/fanout、MIX atomic store/one-shot transfer、auth commit/write-or-exposure/publication、實際 worker claim/recovery | 每域 production 共用可控案例；auth write 後 failure/cancel；代表性縮減、mutation 與 saved replay | 未重建 |
| 5 Real adapters | 相同 observable contract 的 PostgreSQL／stock wire／independent peer；另落實已批准的 exact SM binding retention | 每個 model assumption 有 exact conformance 或明列限制；SQL 與 caller knowledge 分開；來源、binary、schema、roles、cleanup 明確 | 未重建；新增 service/fault 執行先另列範圍與安全判定 |
| 6 有限 qualification | 有效負載 preflight、有限 resource/step/event/wall budgets、恢復、backpressure 與獨立 cleanup | 正常／Cancelled／Inconclusive 分判；缺 terminal、觀測溢出不能 Pass；實際資源基線與停止證據 | 未重建；72h soak 已取消 |

Stage 2 的 reservation/finalization 子退出不能代替 Stage 3 的 durable-message workflow。
Stage 3 的受控 SM/BOSH 語義不能只以之後的 wire 結果補名義退出。
Stage 4 至少包括群聊、auth publication、worker 三類，不以一類代表整體。
Stage 5 的 SQL-aging 狀態不等同 production caller 可達性；Stage 6 的有限窗口不等同長期 readiness。

2026-10-03 的新 Stage 0 獨立只讀審查已通過，僅涵蓋 recovered baseline 與本台帳的責任／缺口範圍。
審查記錄見 `docs/evidence/experimental-rebuild/stage0-acceptance.json`；不沿用前一輪 acceptance，
也不代表 Stage 1–6 已實作或 remote 保存已完成。下一階段寫入須先核對這次 remote commit/tree/delta。

此交接條件已完成：remote commit `d9eb2e2dfa948f6a9d3e16b4ce0c08eca4f9c671`、
tree `89d6279f05fc314923132c59c490e782f0fb5b6e` 經回讀，精確六檔新增、無其他修改或刪除。
隨後的 [CI 37130305484](https://github.com/takanashi-tetsuya/northstar/actions/runs/37130305484)
有 MUC controls owner-affiliation assertion 失敗及 required 匯總失敗；不能把 source-only acceptance
寫成 runtime 穩定或 CI green。實際被選中的 peer frame 未保存，原因仍未確定，不能僅因 production
沒有 delta 就斷言是 fixture。保留的只讀 triage 見
`docs/evidence/experimental-rebuild/stage0-ci-muc-controls-triage.json`。

隨後以獨立小 commit `5519ff7e497e71a72224ee72af66f14cb60ab128` 修正 controls-room fixture
的 reply correlation，保留 exact owner／110／201 assertion 和原 deadline。九項純 fake
receive/clock cases 與獨立 source review 通過；新 [CI 37132305774](https://github.com/takanashi-tetsuya/northstar/actions/runs/37132305774)
為 32 success、1 schedule-only skip、0 failure，包含 PostgreSQL protocol integration。
這是新 commit 的結果，不能倒推原失敗的 wire frame 或根因。terminal record 已另存。

## Stage 1 新實作與證據

Catalog v2 保留 16 families／71 runtime identities／23 declared experiments，另連到一個
可執行 synthetic admission contract 和 11 個 exact cases。純模型預檢把 direct/MUC/MIX
合計到同 actor，保守保留 initial pending occupancy，並保留現有 4096／6h／30m／60s。
容量拒絕、replay／payload conflict、TTL 等號邊界、lease replacement、late finalize、
reservation Unknown 和取消都有獨立 golden projection。prediction 與 supplied observation
分開，固定 corpus 的 reader 不接受自行重算 evaluation 的損壞 observation。

既有 mixed fixture 的真實 main／run_owned_fixture 路徑接上 preflight 與 structured
execution/domain/evidence/cleanup。explicit operator cancellation、普通 EINTR、setup 錯誤、
typed observed invariant 和缺失證據不再只依 legacy failed 混為一類。這些 entry point 在本輪
以純 mocks 驗證；不是新 live fixture 執行或 Stage 6 的 resource enforcement。

正式來源 map `c6d4c8ed879dc5bd29abb18a6b3632b4d0a3a2fe0bede58f3e1f659ae4484e62`
的十檔 before／after 與 runner map 一致；actual HEAD 是 `5519ff7`，`d9eb2e2` 只作 declared
reconstruction anchor。51 項純 contract/fixture tests、46 項 Node catalog tests、11 saved cases、
9 項 MUC mocks 與 source/static checks 全部 exit 0。新增純 helper 已接入既有 CI，但本段
不把尚未發布的 Stage 1 CI 當已執行。

證據與 hash index 在 [stage1-verification.json](../evidence/experimental-rebuild/stage1-verification.json)，
39 個原始檔保存在同目錄的 `stage1-model-evidence-v1.tar.gz`；final 與三次 historical attempts
分開。reader false-success、fixture taxonomy 和 provenance 修正見 `stage1-review-findings.json`。
保存的 6→2 是手動縮減 synthetic oracle mismatch，保留 reserve→finalize 因果；真正 shared Rust
replay／自動縮減／SQL/wire conformance 仍在後續階段。late-finalize 4097 仍只是 conditional model
candidate，不能列為已證實的 production cap bug。Stage 1 新獨立限定 acceptance 已通過；記錄見 `stage1-acceptance.json`。此持久交接已完成：remote commit `2bdfed95c4516ce34296c5fa57a3eb3be49d158d`、tree `bd3b8b30aa448b7bc476d1c3ada2a11762df41bf`，精確 17 檔 delta 與 archive blob 回讀吻合，本地已乾淨快進。其 [CI 37135039680](https://github.com/takanashi-tetsuya/northstar/actions/runs/37135039680) 已完成，32 success／1 schedule-only skip／0 failure；終態摘要見 `stage1-ci-terminal.json`。

## 成功詞與現有權威

| 事實 | 目前來源與 authority | 不能附加的結論 |
|---|---|---|
| Guard-only permission | `src/abuse.rs` 的 `Proceed { lease: None }`；缺 identity 或無 persistence 的路徑 | 沒有逐 operation 的 durable reservation receipt |
| Durable admission reservation | `src/db/message_admission_repository.rs::begin_message_admission`；proof、actor、capacity 與 lease 在原交易內檢查 | 不等於 durable message 已提交，也不等於 wire write |
| Durable direct commit | C2S 實際使用 `MessageService::admit_personal_message_with_mode` → repository `commit_direct`／`commit_with_mode`；generic path 另使用 `MessageApplication::commit` | 只接 generic path 不能聲稱正式 C2S 已共用；DirectWritePort 不是此權威 |
| Admission finalized | `accept_message_admission` 獨立交易；exact key/payload 已 accepted 時先冪等返回，pending→accepted 才要求 exact token | 不是每次成功都重新驗 token；不與 durable message commit 合成一筆交易；失敗仍可能留下 pending／at-least-once 窗口 |
| Route handoff accepted | `DirectMessageRouter`、consuming `UnroutedClaim` 與既有 transport queue | queue 不等於 write 或 peer ACK |
| Native write returned | TCP/WS 的 actual write await，前面使用 `DirectWriteLease::prepare` 的 record/fence | 目前由 caller 順序保證；尚無新的 `WrittenDirectLease` capability |
| Native fallback settlement | `DirectWritePort` 在 write 後以 exact C2S/MIX claim 進行 ACK | 是非 SM 分支責任，不可冒稱 peer handled；通用錯誤不是 rollback 證據 |
| SM／BOSH completion | SM inbound checkpoint/outbound h 與 BOSH response RID 的既有各自 owner | inbound/outbound、response exposure/RID ACK 不互換 |

取消需按效果切點描述：尚未要求 commit、commit future 未決、receipt 已知、已 write 未 settle，
有不同責任。後一個 future 被取消不能擦除已知 receipt；前一個 reservation 也不能被
`direct NotRequested` 覆寫。沒有正面 row/receipt 只能標 PersistenceUnconfirmed／TerminalUnresolved，
不得假稱 ConfirmedTransfer 或 rollback。

本基線的 admission service 是 repository pass-through，協定層仍以 mutable lease/history/delivery/claim
locals 串流程。finalization 失敗只保留／記錄既有狀態，沒有已證明的 dedicated recovery owner。
後續 extraction 必須保留 original command/identity、順序依賴與 witness lifecycle；不能增加永久
session blockade，不能用一個 scratch slot 覆蓋舊 unresolved operation。

正面保留的 offline row 代表 recoverable storage，不代表 scheduled retry。後續 stage 應逐 mode
記錄實際 trigger，例如 lease reclaim、cluster wake、SM resume 或 later eligible session replay。
不新增 retry worker 或提升 delivery promise 來讓 label 成立。

Direct 的 privacy/blocking 是 commit 前的分開查詢，尚不是同一 durable transaction 內重驗的完整
policy snapshot。保留現有 SQL revalidation 不表示補上此保證。Guard-only 的 proof/actor persistence
也不自動納入後續 reservation commit witness；各交易的未知結果必須明列控制範圍。

逐行來源與控制分母見 [本輪責任稽核](../handoff/2026-10-03/experimental-authority-audit.md)。
完整領域差異與 SM eligibility 相依見 [本輪領域缺口稽核](../handoff/2026-10-03/experimental-domain-gap-audit.md)。

## 本輪已知缺口

- Catalog 已新增 synthetic workload validity、precise oracle 與固定 corpus replay；production-shared workflow 與真 adapter evidence 尚未重建
- Admission、mode-aware durable commit 與 handler continuation 仍未由可獨立於 AppState 的共同 workflow 驅動
- Native typed lease、typed router 與 MUC accepted fanout owner 應重用；不建立另一套平行 routing／SQL authority
- BOSH 仍有 actor-wide `auth_publication_pending`，歷史 exact queued-control marker 修正不在此基線
- Auth publication、MIX foreground/worker、MUC 三種共享 controlled core 與 saved case corpus 尚未重建
- 失落的 SQL/wire、minimization、replay checker、provenance、finite qualification 工具都必須以新來源重新建立及驗證

## 跨階段證據契約

每輪保留改造前後相同案例的 observable behavior，逐項說明等價性與刻意修正的差異。
BOSH exact queued-control 與已批准 SM retention 要各自保存原路徑反例、修正後結果及前提，
不能把新案例的成功當成舊案例已重跑。其他產品政策沿用既有語義，包括 native auth publication
deadline、各 domain delivery promise、client retry/backpressure；重構不得自行統一或提高保證。

每個 executable stage 保留 schema/model/scenario/adapter 版本，initial state、concrete commands、effect order、
fault/time/cancel schedule、operation/effect/causal identity、attempt、transition 與 domain time。
execution、domain fact、effect result、verdict、cleanup 分開，輸出為 payload-free 的有界 projection。
歷史完整 server log 不自動變成 sanitized evidence。

Replay 必須比較 exact expected/actual projection，並保存第一個 mismatch，不能把 prediction 標成 observed。
預期 invariant failure 仍須核對 invariant ID/class/location，不得接受任意錯誤。
固定 rejection fixtures 的 input/schema/unknown fields 必須有精確獨立契約；不能只看 mutation label。
至少一個代表性 counterexample 要保持前提、causality 與同一 fault class 縮減，再由真正共用核心重播。
先保存失敗，再修復；不要移除 assertion、降低 gate 或覆寫舊失敗來得到 Pass。

時鐘明列 Tokio、std、SQL、OS 的控制範圍；paused Tokio 不凍結其他時鐘。安全 entropy 保留 CSPRNG。
不引入通用 DSL、自製 global executor 或 wholesale event sourcing。每個新 port 要有真實 authority/
uncertainty 隔離及第二種 composition，不能是任意 AppState delegation。

## 已批准的 SM retention 方向

2026-10-03 已批准保留原租約方案。實作必須保護有效 SM recovery authority 精確匹配的 existing
binding/allocation，保持同一 lease_id、stable shard 與 capacity charge。runtime／startup reapers、
startup consistency 與 doomed-subset repair 必須用同一 eligibility。原 live lease 仍為 expired，
不授權 heartbeat 延長；保留 current-owner、revocation、explicit release 及既有 claim 跨 TTL activation。
missing binding 繼續 fail closed，禁止 INSERT/reacquire fallback。

預設 resume TTL 300s、live lease 120s、claim 30s 下，若 claim 在 TTL 前取得，保留可能接近 330s，
相較 live 約增加 210s，另有既有 cleanup 延遲。一般 TTL/claim 可設定，不能把預設例子稱為全域硬上限。
這項政策批准不是新實作通過證明；後續須記錄 migration、語義差異、regression 與未執行項。

## 全系統長期地圖與執行範圍

原研究的 auth/session、direct、delivery/SM、MUC/MIX、federation、archive/PubSub、roster/privacy、
upload/storage、workers/maintenance、REST/operations、startup/recovery、cluster、browser crypto、
diagnostics 全部保留。Password executor 的 global gate、DNS global cache、untracked upload cleanup，
及 production ACL、跨 node bus、外部 DANE/S3/Redis、真實多裝置 OMEMO 仍是具體隔離／資格缺口。
本計劃不要求每列新建 crate，也不能用 catalog 名稱關閉缺口。

普通 source/refactor、build/unit 與既有 CI 可執行。新增 service/fault/process-loss、adversarial wire、
resource exhaustion 等執行先提交明確 scope 與安全判定；不得把先前不明內容限制的操作改名、搬到 CI
或換路徑重試。72h soak 仍取消，不包含在本次授權。沒有 tag、merge、deploy 或付費資源操作。

## 持久交接方式

每個階段先記 source delta、普通 checks 與未執行項，經獨立 review 後以精確 file list 同步此 recovery branch。
遠端寫入以 fresh head 為 parent，拒絕 head drift 與 force update；完成後重新核對 commit、tree 及每項 delta。
進入下一階段前必須能從 remote 找回當前成果。未完成的子退出標記 work-in-progress，不能等待所有階段完成
才備份，也不能把發布 commit 當作執行驗收。

## Stage 2 進行中

在 `2bdfed9` 的乾淨來源先執行既有 abuse-policy 普通單元測試，26 項通過、0 failed／ignored；
已保存 same-case 名單、來源與新 binary SHA256，作改造前基準。這不包含真 SQL 或舊／新 adapter
等價證明。新設計分開 reservation、finalization 與 GuardOnly transaction knowledge，並要求
正式 service 使用同一 coordinator、正式 SQL 鎖內分支使用同一純 decision；目前仍在實作。
共同核心的 saved-input Rust replay 與 exact oracle 也在本階段建立，不能沿用 Stage 1 synthetic
通過來關閉這項退出。

Stage 2 另保存明確未驗收的 source WIP checkpoint：`stage2-wip-20261003-1630.json`。
它保留五項已知 review blocker，供工作區遺失時恢復與定位；不代表 Stage 2 tests 或退出通過。
修正 prospective authority、completion expected fence、actual coordinator projection、多個未决
operation 的 caller uncertainty，以及 shrink exact-target reader 後，仍須重新凍結來源與驗證。
