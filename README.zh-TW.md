[English](README.md) | **繁體中文**

# Northstar XMPP 伺服器

Northstar 是一個從零開始以 Rust 編寫、重視標準相容性的 XMPP 伺服器，主要部署目標是使用 PostgreSQL 的單一 Linux 主機。專案包含 1,000 個已認證 session/resource 的設計包絡測試，但這不等於 1,000 名同時活躍使用者的實際負載，也不是正式容量 SLA。它提供 TCP/WebSocket 用戶端、憑證驗證的伺服器聯邦、MUC 群聊、加密封存、OMEMO 所需的 PEP、獨立網頁用戶端、REST 管理 API、防濫用控制、日誌與 Prometheus 指標。

Northstar 仍是早期專案。目前開發版本有自動化協定與聯調測試，但尚未接受獨立安全稽核，也不宣稱完整實作每一項 XEP 的所有條款。公開部署前請先閱讀 [XEP_MATRIX.md](XEP_MATRIX.md)。

**名稱說明：** Northstar 是產品名稱；Cargo package 與從原始碼編譯出的
binary target 名稱是 `rust-xmpp-server`，release container 會把它安裝為
`xmpp-server`，正式環境指令均使用後者。

本文件刻意區分四種證據：

- **已實作**：目前程式碼與 migration 確實存在該行為。
- **本機自動化證據**：隔離的單元、PostgreSQL、雙程序、瀏覽器、聯邦或負載 fixture 已覆蓋該行為。
- **Gajim 人工證據**：僅指下方記錄的 localhost 時點觀察，不是相容性認證。
- **部署者必須驗證**：真實主機、公網 DNS、公信 CA 鏈、防火牆、反向代理、外部 peer、監控與備份系統；專案內測試無法代替。

部署或修改協定前請先閱讀[文件索引](docs/README.md)；回報或測試漏洞前請讀
[安全政策](SECURITY.md)，每個正式 artifact 與目標環境則應逐項完成
[release checklist](docs/RELEASE_CHECKLIST.md)；開發貢獻規則見
[CONTRIBUTING.md](CONTRIBUTING.md)。

## 隱私邊界

OMEMO 加密由相容的用戶端完成。正確加密時，Northstar 只路由及封存密文 XMPP 封裝，並不持有用戶端的 OMEMO 私鑰。預設的 `REQUIRE_ENCRYPTED_ARCHIVE=true` 會拒絕把明文訊息本文寫入個人或群組封存，也會在保存 OMEMO stanza 前移除誤附的明文 sibling。

這不等於絕對「零知識」。伺服器必然能看見路由中繼資料、帳號與房間成員關係、時間與大小、用戶端主動送出的明文，以及使用者刻意附在檢舉中的證據。擁有主機或資料庫權限的管理員可以檢視這些伺服器可見資訊。端到端隱私也取決於裝置指紋驗證、用戶端安全與正確的 TLS 部署。

## 已實作範圍

- `5222` 強制 STARTTLS、`5223` Direct TLS、RFC 7395 WebSocket，及選用的 XEP-0124/XEP-0206 BOSH 用戶端連線。
- SCRAM-SHA-256(+)、選用 SCRAM-SHA-1(+)、TLS 內的 PLAIN、EXTERNAL、SASL2、FAST、Bind2、resource binding、presence、roster version、privacy/blocking、離線訊息、Carbons、Stream Management、MAM、vCard、Private XML 與 HTTP Upload。
- 本機與跨域 MUC/MIX 的建立、設定、邀請、管理、加密歷史與受權限控制的 MAM。
- OMEMO 2 裝置清單、bundle 與頭像所需的 PEP。`pubsub.<domain>` 已實作 leaf/collection、設定與預設表單、publish-options、affiliation/access/subscription/options/lease、RSM、last-item、持久 digest、XEP-0248 collection graph，以及本機/跨域事件。由 mutation 觸發的即時通知及不可變收件者 snapshot 會與 mutation 一起提交至有界 PostgreSQL outbox，再以穩定 event ID 重試；最終 socket/S2S 邊界仍是 at-least-once，並非分散式 transaction。
- STARTTLS/Direct TLS S2S、受限 DNS SRV/Happy Eyeballs、網域憑證驗證與優先使用的 SASL EXTERNAL；另提供強制 TLS、權威回撥驗證的 XEP-0220 Dialback。可選用本機 DNSSEC/DANE usage 1/3 與本機 PEM CRL 驗證。
- HTTP 註冊、登入、歷史、檢舉/申訴、邀請碼、漸進式 rate limit 與 Proof-of-Work，以及受保護的管理 API。
- 選用且實驗性的 Redis 多程序 session/MUC 路由；遠端 Redis 必須使用驗證 hostname 的 `rediss://`，並可設定私人 CA 與 mTLS。可持久的一般 direct message、S2S/component outbox、PubSub/PEP mutation event outbox、PubSub digest 與可恢復狀態仍由 PostgreSQL 保護；MUC/presence/Carbons 跨節點時仍依賴非持久 Pub/Sub。共享 S3-compatible upload 已具備 PostgreSQL fencing 與可恢復 queue，但在易失性 cluster 類別及目標物件儲存供應商通過 runtime release gate 前，正式基準仍是單一 Northstar 程序。

精確邊界以 [XEP_MATRIX.md](XEP_MATRIX.md) 為準。表內 `Core` 只表示 Northstar 的既定 profile 有自動化測試，不代表標準的所有選用功能均已完成。由 CI 校驗的[實作與證據追蹤索引](docs/TRACEABILITY.md)會把每個目前問題及所有 Core profile 連到程式碼、migration、測試 harness 與權威文件。

## 安裝需求與快速啟動

正式環境使用 Linux；開發及整合測試可使用 WSL2。與 release 相同的原始碼編譯使用
`rust-toolchain.toml` 固定的 Rust `1.97.1`，並需要 PostgreSQL 15+。公開服務還需要
DNS 名稱及公信 CA 核發的憑證。

以下只適用於單程序 localhost 開發。先建立本機 PostgreSQL database/role，
再複製全 loopback 設定並替換兩個資料庫 URL：

```sh
cp .env.development.example .env
# 先編輯 DATABASE_URL 與 MIGRATOR_DATABASE_URL
bash scripts/generate-development-certificate.sh
cargo run --release --locked -- migrate
cargo run --release --locked
```

此開發 profile 將所有 listener 綁在 loopback、關閉 Redis 與 Dialback，並分別
明確允許程序臨時 FAST、dummy-SCRAM、防濫用及 API-control key；它也允許同一個
本機 PostgreSQL owner role 暫時供 migration、runtime 與 command 使用。這些 key
會在重啟後消失，因此 FAST credential、API replay state 與 keyed 防濫用 identity
不具穩定部署權威。公開 listener、非保留開發網域或 cluster 都會拒絕這些例外。

產生的 RSA-3072 localhost 憑證會被 Git 忽略，並具有 `CA:FALSE`、嚴格用途與
本機服務 SAN；它仍是 self-signed 開發憑證，不可代替公信 CA 憑證。

正式環境必須從 [.env.example](.env.example) 開始，依
[正式維運手冊](docs/PRODUCTION_OPERATIONS.md)拆分資料庫角色並掛載 secret files。
此外必須透過 `ADMIN_COMMAND_DATABASE_URL_FILE`（建議）或
`ADMIN_COMMAND_DATABASE_URL` 提供獨立且權限受限的 command identity；不得重用
runtime 或 migrator URL。

`migrate` 子命令只使用 `MIGRATOR_DATABASE_URL(_FILE)` 套用 migration 與
RFC 7622 canonicalization。一般啟動只使用 `DATABASE_URL(_FILE)`，以唯讀方式
核對 migration 版本、checksum 與 canonicalization marker；任何待套用、失敗、
未知或 checksum 漂移都會 fail closed，不會讓常駐程序自行取得 schema owner
能力。之後 Northstar 才會載入憑證並以前景程序啟動。任何必要 listener
非預期結束時，主程序會有序關閉，不會留下只運作一半的服務。

| 預設埠 | 功能 | TLS |
| ---: | --- | --- |
| `5222` | XMPP C2S | 強制 STARTTLS |
| `5223` | XMPP C2S Direct TLS | 先 TLS，支援 ALPN `xmpp-client` |
| `5269` | XMPP S2S | STARTTLS + SASL EXTERNAL |
| `5270` | XMPP S2S Direct TLS | 先 TLS，支援 ALPN `xmpp-server` |
| `8080` | REST、WebSocket、健康檢查與靜態網頁 | 預設僅 loopback；通常放在 Caddy 等 HTTPS 反向代理後方 |
| `9091` | 私有 Prometheus 指標 | 預設只監聽 loopback；非 loopback 必須使用掛載的 bearer token |

將測試用 self-signed 憑證留在本機。正式憑證的 `subjectAltName` 必須包含 XMPP 網域，建議 ECDSA P-256/P-384 或 RSA 3072+、自動續期，私鑰只讓服務帳號讀取。不要把 PostgreSQL、Redis、Prometheus 或 Grafana 直接暴露至網際網路。

## 設定重點

所有選項及說明位於 [.env.example](.env.example)：

- 網域/監聽：`XMPP_DOMAIN`、`PUBLIC_URL` 與五個 bind address。
- TLS：`TLS_CERT_PATH`、`TLS_KEY_PATH`；私人聯邦 CA 可另設 `FEDERATION_EXTRA_ROOT_CERT_PATH`。`FEDERATION_CRL_PATH` 覆蓋 outbound server-auth、inbound S2S client-auth 與 XEP-0487 HTTPS；`C2S_CLIENT_CRL_PATH` 必須搭配 C2S client trust root。原子 reload 會為新 handshake 啟用新一代 TLS snapshot，並重新檢查現有 C2S／inbound S2S／outbound S2S SASL EXTERNAL 連線所保留的完整憑證鏈；只有新且適用的 CRL 明確回報 `CertRevoked` 時才精確中斷該連線，憑證到期、一般續期、trust root 變更或其他驗證失敗不會造成全域踢線。
- PostgreSQL：一般啟動的 `DATABASE_URL`／`DATABASE_URL_FILE` 只能擇一；
  migration 子命令則獨立使用 `MIGRATOR_DATABASE_URL`／
  `MIGRATOR_DATABASE_URL_FILE`，同樣只能擇一。正式環境另須為受限 command
  role 設定 `ADMIN_COMMAND_DATABASE_URL`／`ADMIN_COMMAND_DATABASE_URL_FILE`
  其中之一，而且不得把 owner URL 提供給常駐服務。只有全 loopback、保留開發
  網域可藉由 `DATABASE_ALLOW_UNSAFE_ROLE_FOR_DEVELOPMENT=true` 明確重用本機 URL。
- 註冊：`OPEN_REGISTRATION`、`INVITATION_REQUIRED`、每小時速率。HTTP、XEP-0077 data form 與 XEP-0389 都可攜帶邀請碼與正文綁定的 PoW v2 欄位；XMPP 只在確定請求進入計量階段後簽發 challenge，並在同一資料庫交易中驗證、執行有界密碼運算及建立帳號。只理解標準欄位的用戶端在額外工作必要時會收到正常的 `resource-constraint`。
- SCRAM／FAST：`SCRAM_ITERATIONS` 用於新建或升級 verifier，預設 600,000，正式部署前應 benchmark。一般啟動必須掛載兩個彼此獨立的受保護檔案：`FAST_TOKEN_SECRET_FILE` 是 FAST token 的權威密鑰，`DUMMY_SCRAM_SECRET_FILE` 則為不存在或不可用帳戶導出依帳戶及機制區分的 dummy credentials，以避免 SCRAM 帳戶枚舉；兩者不得複製、重用或互相導出。兩項能力各有獨立的開發模式開關，只有未啟用 Redis、所有 listener 都是 loopback 且網域為保留開發名稱時，才能各自生成獨立的程序臨時密鑰；重啟後既有 FAST token 會刻意失效。
- 隱私/儲存：封存政策、離線訊息數量/容量/保存期、PubSub/PEP 節點與總容量配額、SM 恢復期、`UPLOAD_STORAGE_BACKEND=local|s3`、本機上傳目錄、受保護的 S3 credential file／workload identity 及上傳大小。公開 Redis cluster 必須使用共享 S3-compatible upload；完整 crash、fencing、刪除與備份邊界見 [upload storage contract](docs/UPLOAD_STORAGE.md)。
- 連線與 deployment 容量：C2S 全域/每 IP 上限、每帳號資源上限、未認證期限，以及 S2S 全域上限。帳號、MUC 房間、live binding 與保留中的 SM row 另由 PostgreSQL 權威 64-shard ledger 管理；調整上限必須推進下一個 `DEPLOYMENT_CAPACITY_EPOCH`，且系統不會為了套用降額而刪除既有資源。完整設計見 [docs/DEPLOYMENT_CAPACITY.md](docs/DEPLOYMENT_CAPACITY.md)。
- 聯邦：開關、優先 SASL EXTERNAL、使用掛載密鑰的 XEP-0220 Dialback、allow/deny list、DNS override；`FEDERATION_DANE_MODE=off|opportunistic|required` 控制本機 DNSSEC/TLSA，required 模式拒絕 override、XEP-0487 與不安全 fallback。`xmpps://` 選 Direct TLS，`starttls://` 或無前綴則選 STARTTLS。公網權威 DNS/TLSA 仍必須由部署者驗證。
- XEP-0157 聯絡 URI 與選用的 XEP-0215 STUN/TURN。設定 coturn shared secret 後，伺服器可核發短效且隱私化的 TURN REST 憑證；STUN/TURN 服務仍由管理員營運。
- 防濫用：PoW 基準/上限、觀察窗、冷卻與最大等待時間。正式環境、任何公開監聽或 Redis 模式都必須掛載 `ABUSE_STATE_HMAC_KEY_FILE`；隨機臨時密鑰只允許明確啟用的全 loopback 開發環境。PostgreSQL 保存單調遞增的 `ABUSE_STATE_HMAC_KEY_EPOCH` 與不可逆 current/previous key ID；啟動遇到漂移會 fail-fast，`/readyz` 亦持續驗證。三階段輪換讓舊節點可在 overlap 期間繼續服務，retiring 階段會先排除舊 generation，再經完整狀態失效期才允許移除 previous key。
- 監控：`/metrics` 僅存在於獨立的 `METRICS_BIND`。非 loopback 必須設定 `METRICS_BEARER_TOKEN_FILE`，且收集採單一併發、五秒快取與資料庫總逾時。
- `REDIS_URL` 或 `REDIS_URL_FILE`：一旦設定即啟用實驗性多節點路由。明文 `redis://` 僅允許 loopback；遠端必須使用 `rediss://`，自訂 CA 及 mTLS cert/key 只接受完整一致的設定。單機請保持未設定。

修改密碼或由管理員停用帳號時，REST token、在線 XMPP 與可恢復 session 會立即撤銷；API 回應帶有 `Cache-Control: no-store`。請勿提交 `.env`、憑證、私鑰、secret、log、upload 或備份。標準路徑已列入 `.gitignore`，外部路徑仍需由管理員自行保護。

## 用戶端與 OMEMO

Gajim、Conversations 等用戶端以 `使用者@你的網域` 登入。一般使用 `5222` STARTTLS；只有明確支援 XMPP Direct TLS 的用戶端才使用 `5223`。憑證必須對該網域有效。

OMEMO 裝置透過 PEP 發布 device list 與 bundle。Northstar 對不存在的節點回覆 `item-not-found`、保留多 item bundle、必要時產生 item ID、在 discovery 公告通知 feature，並在非匿名 MUC presence 揭示真實 JID，讓參與者能找到對方裝置。裝置信任仍完全由用戶端決定。若 Gajim 的信任清單為空，應先確認雙方 bundle 已發布並重新探索能力，最後才清除客戶端舊的 capability cache。

網頁端的 OMEMO 私鑰保存在瀏覽器。刪除瀏覽器 profile 可能同時失去金鑰與舊密文解密能力；伺服器沒有私鑰託管或復原金鑰。

網頁端已實作 OMEMO 2 device/bundle、X3DH、Double Ratchet、明確信任/TOFU、多裝置修復與退役、單聊/群聊、Stanza Content Encryption、XEP-0447/0448 加密檔案、XEP-0454 相容路徑及 trust-message/automatic-trust-management。這些是瀏覽器端密碼學行為，已有本機自動化證據；伺服器仍無法解密 payload。

人工證據較窄。2026 年 8 月 25 日的 localhost 驗證中，在接受開發憑證後，Gajim 帳號 `test1`、`test2`、`test3` 成功認證並加入既有的 members-only、non-anonymous 房間；`test2` 送出一則被 Gajim 顯示為端到端加密的訊息，對應 archive probe 只找到密文封裝。當時未記錄 Gajim 版本。這不證明所有 Gajim 版本、OMEMO 單聊、公網 CA/DNS，亦不代表之後修改過的最終 binary 已重新人工驗證；正式上線前須在 staging 重跑。

## 註冊、防濫用與檢舉

HTTP 註冊端點是 `POST /api/v1/register`。依政策可要求邀請碼，亦可先向 `POST /api/v1/anti-abuse/challenge` 取得 PoW challenge。註冊、訊息、檢舉與申訴會依 IP、帳號及行為作台階式加重；重複操作會提高工作量，之後加入硬等待，冷卻期間再逐階回落。設定的上限可避免手機無限計算。

actor window、penalty、challenge 與 message admission 都持久化於 PostgreSQL。免費 burst 後第 `n` 階使用 `n²` 倍基準工作量，並逐步加入 2/10/30/120 秒硬等待，再套用指數懲罰與逐階冷卻；8 秒只是中階手機的校準目標，真正硬上限是固定 maximum work factor。shared-IP 以 20:1 高流量訊號降低 NAT 使用者互相連坐。

訊息 admission 使用 opaque HMAC actor/subject key、payload MAC、XEP-0359 `origin-id` 或一次性 challenge identity、fencing lease，以及有界 pending/accepted row。tombstone 存在時會抑制完全相同 replay，payload 改變則衝突；離線投遞另有持久 queue/outbox/history dedupe 與 30 天 post-delivery tombstone。對本 deployment 內的收件者，可儲存的一般 `normal`/`chat` 訊息會先把 transient spool 與必要的 MAM 資料提交至 PostgreSQL，再進入本機或 Redis 跨節點 queue；socket write 成功後才完成該 row。因此崩潰可能造成穩定 XEP-0359 ID 的重送，但不再只靠記憶體 enqueue。

明確帶有 XEP-0334 `no-store` 的本地收件 direct message 不會進入 MAM、transient spool 或 offline storage，只嘗試本機及跨節點的在線易失路由。跨域收件人則只能使用已完成認證且可寫的既有 S2S 或 XEP-0288 bidi stream；伺服器會等待有界的 socket 寫入，且絕不降級到 PostgreSQL S2S outbox。即時路由接受才算成功；沒有路由、queue 飽和或寫入逾時均回覆 `wait/service-unavailable`，送到遠端的 stanza 仍保留 XEP-0334 hint。個人歷史撤回與 members-only direct MUC invitation 都需要持久歷史或授權變更，因此帶明確 `no-store` 時會被拒絕。這些語義都不等於端到端 exactly-once。

使用者可選取聊天內容作為檢舉證據；這代表使用者主動把該內容交給伺服器及授權管理員。申訴採更嚴格的速率限制，避免濫用管理通道。

## REST、監控與維運

HTTP 提供 liveness/readiness、Prometheus、公開設定、帳號、歷史、檢舉/申訴、上傳、XMPP WebSocket 與管理功能。REST 歷史與 XMPP MAM 共用同一個 repeatable-read 查詢與可見性邊界，支援 bare/full `with`、時間/UID 篩選與 XEP-0059 分頁，同時保留舊版 newest-first opaque cursor。舊資料沒有可信的 direction 欄位，因此 API 不會假裝提供方向篩選。完整契約在 [docs/openapi.yaml](docs/openapi.yaml)，亦可由 `/api/openapi.yaml` 取得；`/api/docs` 自託管固定的 Swagger UI 5.32.14，採嚴格同源 CSP，並停用授權輸入與所有送出請求功能。

每個已接受的長時間管理變更都會回傳 operation ID 與 `Location`。呼叫端應保留自行選定的 `Idempotency-Key`；HTTP 回應遺失時，以完全相同的請求重試會取回原 operation ID，而不會再次施加動作。管理員可依 ID 查詢 operation、檢視 fan-out targets，先以外部證據逐一 reconciliation 結果未定的 target，再處理 parent；reconciliation 本身也會驗證權限、保持冪等並寫入稽核紀錄。

- `/healthz` 只代表 HTTP 程序存活。
- `/readyz` 會檢查 PostgreSQL 及受監督背景工作，但只供內部編排系統使用；預設 Caddy 對公網 `/readyz` 回傳 404。重複探測共用兩秒快取與單一、有時限的資料庫檢查，不會讓匿名並發耗盡連線池。
- `/metrics` 僅由私有監控 listener 提供；在資料庫故障時仍可取得，並另外回報資料庫狀態。
- 管理端可處理使用者、sessions、邀請碼、檢舉/申訴、房間、離線 spool、broadcast、孤島模式、強制斷線與 TLS reload。

監控與還原演練請見 [docs/PRODUCTION_OPERATIONS.md](docs/PRODUCTION_OPERATIONS.md)；備份簽章、正式環境強制 age 加密、防回滾狀態與金鑰分離請見 [docs/BACKUP_SECURITY.md](docs/BACKUP_SECURITY.md)。Compose 將 PostgreSQL bootstrap superuser、一次性 migration owner、非 owner runtime、受限 command 與唯讀 backup 身分分開，並使用 mounted secrets、唯讀應用檔案系統、移除 Linux capabilities、內部資料庫網路，以及只監聽 loopback 的監控介面。

## Docker Compose

正式建置前，在不提交的 `.env` 設定 `NORTHSTAR_VERSION=1.1.0`，並將
`NORTHSTAR_VCS_REF` 設為確切 release commit；`unknown` 只適用於本機開發 image。

```sh
sudo install -d -o root -g root -m 0700 /etc/northstar
sudo env NORTHSTAR_SECRET_DIR=/etc/northstar/secrets \
  sh scripts/create-production-secrets.sh
sudo docker compose -f docker-compose.yml -f deploy/docker-compose.bootstrap.yml up -d postgres migrate database-grants xmpp caddy
sudo docker compose --profile monitoring up -d   # 選用
```

Compose 預設從原始碼目錄外的 `/etc/northstar/secrets` 掛載秘密。產生器會在
第一次寫入前鎖定並驗證預先建立的 `root:root`、`0700` 父目錄，且拒絕符號
連結、可替換路徑及格式錯誤、過弱、重複或不成對的既有秘密。

只有一次性的 `migrate` 與 `database-grants` 工作會取得資料庫 owner URL，完成 migration 與 ACL reconciliation 後即退出；常駐 `xmpp` 只取得非 owner runtime URL，啟動前僅做唯讀 migration/checksum 驗證。command issuer 與 `backup` profile 各自使用受限及唯讀 URL。舊版以 PostgreSQL `xmpp` superuser 建立的資料卷必須依維運手冊停機、備份、稽核及轉移 owner；只替換 Compose 檔並不構成安全升級。

先以 bootstrap 管理員登入並立即修改密碼，再只用基礎 Compose 檔重建 `xmpp`，並安全刪除主機上的 `bootstrap_admin_password`。一般重啟不應繼續掛載 bootstrap override。

正式上線前必須替換所有範例網域與秘密、配置相應 A/AAAA 和 XMPP SRV、從外部網路驗證各埠、建立離機加密備份，並至少使用兩種獨立用戶端測試。`scripts/release-preflight.sh --production` 會拒絕即將到期、SAN 不符、key 不匹配、自簽、SHA-1 簽章或弱金鑰憑證，且私鑰權限必須是 `0400` 或 `0600`。

## 驗證

### 安全的 repository-local 證據

最近一次完成的非對抗性工作區驗證共記錄 `1167` 個 Rust tests：`1002 passed`、
`165 ignored`、`0 failed`。format、all-target/all-feature 編譯、Clippy
零警告，以及架構、XML、parser coverage、敏感檔追蹤、Web auth 與制品完整性
靜態門禁亦通過。`ignored` 代表沒有執行；這些數字是開發證據，不是未來 commit、
release image 或正式環境的認證。

每次 release 變更後重新執行安全基線：

```sh
cargo fmt --all -- --check
cargo check --all-targets --all-features --locked
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
node scripts/check-architecture-boundaries.mjs
node scripts/check-documentation-consistency.mjs
node scripts/check-outbound-xml-construction.mjs
node scripts/check-parser-fuzz-coverage.mjs
node scripts/check-tracked-sensitive-files.mjs --include-untracked
node scripts/verify-crypto-artifacts.mjs
```

### 由部署者控制的隔離 harness

倉庫另包含 WSL/PostgreSQL wire integration、BOSH/WebSocket transport
conformance、parser fuzz、聯邦/component fixture、Redis cluster、備份還原、
故障注入及兩種 1,000-session 負載包絡。檔案存在不代表目前 artifact 已執行；
其中部分會產生畸形流量、施加極限負載、停止依賴服務或驗證 crash/recovery，必須
取得明確授權後在可丟棄隔離環境中執行。前置條件、指令、停止條件與預期結果見
[人工安全驗證手冊](docs/MANUAL_SECURITY_VALIDATION.md)，適用結果應記入
[release checklist](docs/RELEASE_CHECKLIST.md)。

1,000-session fixture 只代表連線與排程設計包絡，不是 1,000 名同時活躍使用者
模型、容量 SLA 或獨立安全稽核。其 load resource 刻意不送 initial presence，避免
把同一帳號 1,000 個同時 available resource 所造成、約一百萬則 stanza 的
presence storm 誤當一般流量。

DANE 本機測試不證明公網權威 DNS chain 或真實 peer 的 TLSA；`scripts/federation-external-preflight.sh` 必須由部署者明確授權執行，其存在不表示已執行。CRL 本機驗證與原子 reload 也不證明營運者會及時更新 CRL。S2S/components 在 socket-write/database-completion 崩潰窗仍是 at-least-once；可儲存的一般 direct C2S 訊息與 members-only direct/mediated MUC 邀請使用 PostgreSQL transient spool。啟用 XEP-0198 時，spool fence 僅在用戶端推進 `h`（包含 resume）後完成；未啟用 SM 的 BOSH 先把 fence 綁定 response RID，只有通過驗證的後續 `ack` 才完成。未確認的斷線或 lease 到期只會釋放 row 供重投；`no-store` 與其他 best-effort fan-out 保持易失。

歷史交接與驗證敘述統一保留於 [docs/archive/](docs/archive/)；這些時點報告不會取代目前的證據分級、相容性矩陣與已知限制。

## 已知限制與授權

主要限制包括：尚無獨立 RFC/XEP 與安全稽核、無 OCSP 或線上 CRL/AIA 下載、BOSH 不支援 multi-stream、S2S 不支援一般 multi-domain multiplex/additional-domain piggyback、XEP-0225/XEP-0487 仍屬 Deferred/Experimental、尚無公網 DNS/DANE 與廣泛第三方聯邦證據，以及 Redis clustering 尚未取得正式環境資格。詳見 [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md)。

Northstar 原始程式碼採 [AGPL-3.0-only](LICENSE)；第三方授權見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
