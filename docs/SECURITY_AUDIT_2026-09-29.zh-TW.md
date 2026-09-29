# Northstar 安全審計 — 2026-09-29

受測提交：`27ae63dfe37dba719dab42cd3422a4ec0e77f57d`。這輪聚焦安全邊界、未授權輸入與資源耗盡；以原始碼追蹤及隔離環境中的實際測試為依據。未修改產品程式、部署或秘密設定。

## 修復紀錄 — 2026-09-29

S1 已加入共用 REST 主體保護：256 KiB 上限、15 秒絕對讀取期限、同一程序跨 public／admin listener 共用的 128 個讀取名額，以及每來源 IP 8 個名額。取得名額不排隊；超額回傳 429／Retry-After，逾時回傳 408／`request_timeout`，HTTP/1 拒絕後關閉連線。正常讀完、讀取錯誤、逾時或取消均釋放名額，並移除閒置來源紀錄。涵蓋 ApiJson、ApiEmpty、直接 Axum Json 與 chunked；期限不包住後续資料庫操作，上傳 PUT 與 BOSH 保留各自串流策略。

Caddy 範例加入 10 秒標頭／1 分鐘 idle／64 KB 標頭限制；一般 REST 主體 20 秒、BOSH 主體 30 秒、上傳主體 15 分鐘，並對 408／413／429 關閉 HTTP/1 連線。分路由 read_timeout 以 Compose 固定的 Caddy 2.11.4 實測，升級時需重驗該 experimental 選項。修復後證據位於私有 `target/security-fixes-2026-09-29/`；原始審計證據保持獨立，不能將修復後通過回填到原輪。完整結果與候選 CI 核對在該目錄的驗證紀錄。

8 項真實 Axum socket／取消回歸通過；完整 workspace 測試為 109 個 target、2,272 通過、0 失敗、251 ignored，完整 Clippy 與格式檢查通過。隔離 PostgreSQL 的完整 `integration-wsl.sh` 通過，8 條未完成請求直連約 15.01 秒、經 TLS Caddy 約 15.06 秒收到 408；public／admin 共享名額、逾時及斷線後恢復均通過，測試 schema 與程序已清理。

Caddy fixture 核驗提前拒絕、EOF、分片 JSON、21 秒上傳、31 秒 BOSH 長輪詢、21 秒 WebSocket 與實際 10 秒標頭期限。HTTP/2 補測抓到拒絕回覆的 Connection 標頭會導致 GOAWAY，已將關閉策略限定於 HTTP/1，修正後同一 HTTP/2 連線的下一筆請求成功。CI 已加入以上 fixture 與真正應用程式的 TLS 慢速主體回歸，推送後須以修復提交逐項核對完整 CI。fixture 不代表正式入口滲透測試或 HTTP/2/3 飽和容量驗收；六台 VM 與原浸泡候選未部署變更。

以下保留修復前的原始發現與測試結果。

## 結論（修復前）

確認 **1 項新的 P2 安全風險**：一般 REST JSON 請求缺少應用層的主體讀取期限，未登入用戶可以長時間保留未完成的請求。沒有在本次範圍內確認帳號接管、管理權限繞過、跨帳號資料外洩、XML 外部實體讀取、上傳路徑穿越或 P0／P1 漏洞。

前次 A1–A5 的修復仍在目前提交中。本報告不是對整個系統無漏洞的保證，未測的部署及負載條件不能視為已通過。

## S1 — P2：REST 主體讀取沒有期限，可在驗證前保留連線

位置：[src/api/mod.rs:161](../src/api/mod.rs#L161)、[src/api/mod.rs:188](../src/api/mod.rs#L188)、[src/api/mod.rs:1447](../src/api/mod.rs#L1447)。代理範例：[deploy/Caddyfile:6](../deploy/Caddyfile#L6)。

`ApiJson::from_request()` 對 `to_bytes(request.into_body(), API_BODY_LIMIT_BYTES)` 直接 `.await`。目前限制主體總位元組數，沒有讀取期限。`ApiEmpty` 也直接等待主體結束；共用 HTTP middleware 沒有為一般 REST 安裝主體讀取期限或對應的全域／IP 讀取名額。公開登入路由須先完成 JSON extraction 才進入登入服務，因此此階段尚未執行帳號驗證、PoW 或登入服務的容量控制。

**實際重現：**在本次建立的 loopback fixture 中開啟 8 條 HTTP/1.1 連線，對 `/api/v1/login` 宣告 `Content-Length: 128`，只送出 JSON 開頭的 1 byte `{`，沒有登入 token。65.01 秒後，8 條全部仍等待主體；補上剩餘位元組後，8 條全部立即回傳 `400 Bad Request`。這證實請求仍存活，而非已被悄悄關閉。

**影響：**攻擊者若能把慢速主體傳入 backend，可占用 socket、task 與 request state，增加連線耗盡風險。沒有證實此階段占用資料庫連線，也沒有用大量連線壓垮服務。本次僅使用 8 條自有測試連線，沒有對正式服務做 DoS。

**暴露條件：**可直接到達 backend，或前方代理沒有有效的主體讀取期限／最低速率／連線限制。本機 fixture 經過的是無 HTTP 政策的 TCP relay，沒有實測正式 Caddy ingress。repository 的 Caddyfile 未顯式設定讀取期限；Caddy 版本可能另有預設保護，不能據此宣稱所有正式部署都可以被耗盡。設定語義可參閱 [Caddy 官方 timeouts 文件](https://caddyserver.com/docs/caddyfile/options#timeouts)。

**建議修復：**

1. 對一般 REST 的 JSON／空主體讀取設置明確期限，逾時回傳一致的 `408` 或相應錯誤，取消讀取並釋放連線資源；也應涵蓋直接使用 Axum `Json` 的 REST 路由。
2. 在讀取主體之前取得有界的全域及每來源名額，限制驗證前的並行占用。
3. 在正式 ingress 明確設定並測試主體讀取與連線策略；一般小型 JSON 與大型上傳、BOSH 長輪詢應有各自合適的期限。
4. 加入真實 socket 回歸：未登入、不完成主體的請求須在設定期限內終止；正常分片 JSON 不受影響，名額在取消或逾時後恢復。

證據：`target/security-audit-20260929/slow-body-results.json`、`adversarial-wire.py`、`adversarial-fixture.sh`、`database-wgyaaemz/adversarial.log`。重現程式僅連線至由 fixture 提供的 `127.0.0.1` 埠。

## 安全邊界檢查

| 邊界 | 原始碼及實測結果 |
| --- | --- |
| 管理入口與權限 | 公開入口不安裝管理 API；啟用 gateway credential 的獨立管理入口拒絕缺少、錯誤、重複標頭。僅 gateway 無使用者 bearer 仍為 401；一般帳號 bearer 為 403；gateway + 管理員 bearer 才可讀取。 |
| Bearer／代理標頭 | 重複 Authorization、順序互換、錯誤 scheme、逗號混合、query token 均不能授權。HTTP／歧義 `X-Forwarded-Proto` 被拒絕；來源 IP 解析對重複 XFF 退回可信 peer。 |
| 撤銷與競態 | 真實登出後 bearer 的讀取與刪除被拒絕。DB 測試涵蓋密碼輪換、admin 降權競態、FAST replay、持久化撤銷、交易內重新驗證，以及冪等重播重新授權。 |
| 資料所有權 | DB 測試驗證分頁隔離、查詢快照與 bearer／帳號鎖、操作 target 範圍、舉報證據的 reporter／peer 綁定、房間 retention 所有權與降權競態。不能用陌生 `user_id` 查詢參數覆寫 history 的所有者。 |
| WebSocket／Passkeys | 不可信／opaque／重複 Origin 被拒絕；Passkey 缺少 Origin 被拒絕。Passkey 的一次性與移除憑證後撤銷由 DB fixture 驗證。 |
| XML／BOSH | 實際傳送 DTD + 外部實體、300 層深度、NUL 與未定義 entity，均終止且不建立 SID。workspace 測試另涵蓋分片、UTF-8 邊界、屬性與元素數限制。 |
| 上傳與檔案 | 路徑 traversal／隱藏檔請求被拒絕；原始碼以 UUID 與受控 storage locator 定位物件，下載使用 attachment、nosniff、sandbox CSP。DB fixture 驗證配額競態、lease／fence、刪除與重播及 ACL 漂移偵測。公開下載本身是檔案 URL 的既定能力語義。 |
| 聯邦與 SSRF | 原始碼在 DNS 解析後驗證實際 socket address，再使用該位址連線；host-meta redirect 有 HTTPS、次數、回應大小與位址政策限制。workspace 的 private／special／IPv4-mapped 位址及 redirect 負面測試通過。未向真實內網 metadata endpoint 發請求。 |
| 密碼與瀏覽器 | SCRAM／FAST、Argon2 工作量上限與安全比較測試通過；Node Web auth、OMEMO tampering、recovery 及 session lifecycle 檢查通過。另在 Chromium 將惡意 HTML 放入舉報、申訴、房間與邀請文字，確認沒有產生 onerror／onload 節點或執行 script；API 使用 mock。這不等於全面 XSS 或密碼學認證。 |
| 秘密與錯誤 | 受追蹤敏感檔案掃描通過；一般內部錯誤對外使用統一訊息。沒有輸出本機 `.env`、密碼或實際 bearer 值。 |

## 測試結果

本次新執行的測試；沒有沿用前次結果充當本次通過。

| 驗證 | 結果 |
| --- | --- |
| `cargo test --workspace --all-targets --all-features --locked --offline` | 109 targets；2,264 passed、0 failed、251 ignored |
| 8 組安全相關 PostgreSQL suites | 全部 exit 0；73 個不同 Rust 測試通過 |
| 新增的隔離 HTTP／WebSocket／BOSH 攻擊探測 | 60 個正／負向案例通過；另確認 S1 慢速主體行為 |
| `runtime-tls-test-wsl.sh` | 17 次測試成功，10 個不同測試；實際憑證、client identity、TLS 1.2 EMS／TLS 1.3、CRL 與 OCSP fixtures |
| Chromium 管理 UI 注入探測 | 舉報、申訴、房間與邀請的惡意 HTML 保持文字，未產生執行節點；六個列表翻頁仍通過 |
| `integration-wsl.sh` | exit 0；REST、Passkeys、STARTTLS、WebSocket、MUC／PubSub／PEP 權限、MAM、上傳、會話與憑證撤銷、BOSH／WebSocket transport conformance |
| 7 組 Node／架構／秘密掃描 | Web auth、OMEMO security、OMEMO recovery、tracked secrets、parser-fuzz coverage、process isolation、session boundary 全部通過 |
| `cargo-audit` | 505 lockfile entries；既有例外之外 0 漏洞、0 warnings |

八組資料庫 suite：`auth-admin-db`、`authentication-service-db`、`api-pages-db`、`api-operations-db`、`abuse-reporting-db`、`upload-db`、`message-pow-db`、`privacy-db`。均使用新建 PostgreSQL 的非預設埠 `39573`，沒有改寫受測腳本的資料庫位址。

RustSec 本次更新所得 advisory database：`ef03605143a913024f864d2edf476adad5720c93`，1,273 advisories，資料時間 2026-09-28。既有 `RUSTSEC-2023-0071` 豁免保留；另外執行 `cargo tree --workspace --all-features --locked --offline -i rsa`，目前主機的 active dependency graph 沒有該 crate。未推定所有其他 target 也相同。

探測器最初兩次退出屬 fixture／測試預期錯誤：WebSocket 缺少可信 HTTPS assertion，先被 transport gate 拒絕；登出 API 的成功碼實為 200，探測器最初預期 204。修正後在新 schema 重跑 60 個案例全通過；初始日誌與結果保留，沒有把它們列為產品漏洞。

## 範圍與證據

人工檢查重點為 API 路由與 extractors、管理 gateway、principal／交易授權、Passkey／recovery 入口、upload read/write、S2S endpoint resolution、XML framing、Web UI 輸出及 production proxy 範例；不是對所有 source files 逐行審查。

這輪未做正式入口／VM 的滲透測試、飽和負載或長時間 DoS、Redis／S3 真實部署故障、外部 federation 互通、全瀏覽器 OMEMO E2E、Windows／macOS 或長時間 libFuzzer campaign。`parser-fuzz-coverage` 是 harness 覆蓋檢查，不是 fuzz campaign。PostgreSQL 測試使用隔離開發 role；不以它替代正式資料庫 grants 的部署驗證。

原始證據在 `/home/liu/XMPP/target/security-audit-20260929/`，屬 Git 忽略的本機資料；包含測試日誌、JSON 結果、重現腳本及 SHA-256 校驗清單。完整結果及清理紀錄見該目錄 `SUMMARY.json`。

完整 integration 與 federation 已成功完成，分別 exit 0。所有四個獨立 PostgreSQL fixture 均已正常停止、無殘留測試 schema，暫存 database data 已移除；server／federation 腳本亦確認 listener 清理。本次僅新增本安全報告，沒有修改產品原始碼。
