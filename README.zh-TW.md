[English](README.md) | **繁體中文**

# Northstar XMPP 伺服器

Northstar 是以 Rust 編寫、面向 Linux 與 PostgreSQL 的標準相容 XMPP
伺服器。它提供 TCP、Direct TLS、WebSocket 與選用 BOSH 連線，以及聯邦、
群聊、OMEMO 相容服務、網頁用戶端、REST 管理、防濫用、日誌及監控。

目前的發行候選版本為 `0.2.0`，仍屬 1.0 之前的版本，尚未正式發行或接受
獨立安全稽核。公開部署前請閱讀 [XEP 支援矩陣](XEP_MATRIX.md)、
[發行檢查表](docs/RELEASE_CHECKLIST.md)與[已知限制](docs/KNOWN_ISSUES.md)。

其他資料請參閱[文件索引](docs/README.md)、[安全政策](SECURITY.md)、
[正式維運手冊](docs/PRODUCTION_OPERATIONS.md)及
[貢獻指南](CONTRIBUTING.md)。

## 如何使用

### 發行套件

Northstar `0.2.0` 通過發行核准後，將透過
[GitHub Releases](https://github.com/takanashi-tetsuya/northstar/releases)
提供下列預定檔案。在 tag workflow 建立 draft，且 checksum、provenance 與
映像 digest 完成審核前，請勿視為已提供：

| 資產 | 用途 |
|---|---|
| `northstar-0.2.0-linux-amd64.tar.gz` | 完整 Linux AMD64 發行套件，包含 `xmpp-server`、Web 用戶端、Swagger UI、`.env.example` 及授權聲明 |
| `northstar-0.2.0-linux-amd64` | 裸 Linux AMD64 ELF binary |
| `northstar-0.2.0-windows-amd64.zip` | 完整 Windows AMD64 開發／評估套件，包含 `xmpp-server.exe` 及相同的 runtime 資產與授權聲明 |
| `northstar-0.2.0-windows-amd64.exe` | 供開發／評估使用的裸 Windows AMD64 executable |
| `SHA256SUMS` | 四個套件與 `IMAGE_DIGESTS` 的 SHA-256 checksum |
| `IMAGE_DIGESTS` | 成功 tag 執行為三個 GHCR 映像產生的精確 `name@sha256:digest` 參照 |

`AMD64` 即 Rust 的 `x86_64` targets。Linux AMD64 是正式環境基線；Windows
build 僅供開發及評估，不是支援的正式部署平台。裸 binary 不包含執行時所需的
Web、Swagger UI、設定及授權檔案。請使用完整 archive，或把裸 binary 與同一
tag archive 的內容放在一起，並從該目錄啟動。

下載所需檔案後，請在執行前核對 `SHA256SUMS` 中的對應項目，並驗證 GitHub
build provenance。Linux 範例：

```sh
mkdir northstar-0.2.0
sha256sum --check SHA256SUMS
tar -xzf northstar-0.2.0-linux-amd64.tar.gz -C northstar-0.2.0
cd northstar-0.2.0
./xmpp-server --version
```

Windows 請先用 `(Get-FileHash -Algorithm SHA256 <file>).Hash` 與
`SHA256SUMS` 的對應項目比較，再解開 ZIP。與套件來自同一 Release 的 checksum
可偵測傳輸損壞；provenance 驗證則是另一項來源／build 身分檢查。

正式部署需要 Linux、PostgreSQL 15+、DNS 名稱及公信 CA 核發的憑證。
正式環境基線為 Linux AMD64；WSL2 與 Windows AMD64 套件僅供開發及評估。
從原始碼建置使用 `rust-toolchain.toml` 所指定的 Rust toolchain。
Docker Compose、Caddy、Prometheus/Grafana 及 Redis 依部署方式選用。

以下命令會啟動僅監聽 loopback 的開發環境。請先建立本機 PostgreSQL
database/role，並修改複製後檔案中的兩個資料庫 URL：

```sh
cp .env.development.example .env
# 編輯 DATABASE_URL 與 MIGRATOR_DATABASE_URL。
bash scripts/generate-development-certificate.sh
cargo run --release --locked -- migrate
cargo run --release --locked
```

開發設定使用臨時本機密鑰及 self-signed 憑證，不得公開或用於正式環境。
正式部署請從 [.env.example](.env.example) 開始，並依照
[正式維運手冊](docs/PRODUCTION_OPERATIONS.md)設定分離的資料庫角色、受保護
secret files 及公信憑證。

| 預設埠 | 功能 | 預設暴露方式 |
| ---: | --- | --- |
| `5222` | XMPP C2S STARTTLS | 公開 |
| `5223` | XMPP C2S Direct TLS | 公開 |
| `5269` | XMPP S2S STARTTLS | 啟用聯邦時公開 |
| `5270` | XMPP S2S Direct TLS | 啟用聯邦時公開 |
| `5347` | External components | 預設停用／loopback |
| `8080` | REST、WebSocket、健康檢查及網頁 | loopback，置於 TLS proxy 後 |
| `9091` | Prometheus metrics | 僅 loopback／私有網路 |

不要把 PostgreSQL、Redis、Prometheus 或 Grafana 直接暴露至網際網路。


## 隱私邊界

OMEMO 加密由相容的用戶端完成。正確加密時，Northstar 只路由及封存密文 XMPP 封裝，並不持有用戶端的 OMEMO 私鑰。預設的 `REQUIRE_ENCRYPTED_ARCHIVE=true` 會拒絕把明文訊息本文寫入個人或群組封存，也會在保存 OMEMO stanza 前移除誤附的明文 sibling。

這不等於絕對「零知識」。伺服器必然能看見路由中繼資料、帳號與房間成員關係、時間與大小、用戶端主動送出的明文，以及使用者刻意附在檢舉中的證據。擁有主機或資料庫權限的管理員可以檢視這些伺服器可見資訊。端到端隱私也取決於裝置指紋驗證、用戶端安全與正確的 TLS 部署。


## 功能

- 強制 STARTTLS、Direct TLS、WebSocket 及選用 HTTPS 代理 BOSH。
- SCRAM-SHA-256/PLUS、選用相容機制、SASL2、FAST、Bind2、roster、
  presence、privacy list、blocking、Carbons 與 Stream Management。
- 單聊、離線投遞、MAM、vCard、Private XML 及 HTTP Upload。
- 支援邀請、moderation、存取控制及加密歷史的 MUC 與 MIX。
- OMEMO device list、bundle、avatar 與一般 publish/subscribe 所需的
  PEP/PubSub。
- 憑證認證的 federation、選用 DANE/CRL 驗證及 external components。
- REST 註冊與管理、檢舉與申訴、邀請碼、自適應限速、PoW、日誌及
  Prometheus metrics。
- 選用 Redis 路由及 S3-compatible 共享上傳。多程序部署仍屬實驗性；
  正式部署目前以單一 Northstar 程序為基準。

精確協定支援範圍請參閱 [XEP_MATRIX.md](XEP_MATRIX.md)。



## 設定

設定由環境變數或 `.env` 提供；完整且附註解的權威清單位於
[.env.example](.env.example)。

- **身分及 listeners：** `XMPP_DOMAIN`、`PUBLIC_URL`，以及 client、
  federation、HTTP、component、metrics bind addresses。
- **TLS：** 憑證與私鑰路徑，以及選用的聯邦／用戶端 trust roots 或 CRLs。
- **資料庫：** 正式環境應使用分離的 migrator、runtime 及 admin-command
  PostgreSQL 身分；請參閱[資料庫角色](docs/DATABASE_ROLES.md)。
- **註冊：** `OPEN_REGISTRATION` 控制公開註冊；
  `INVITATION_REQUIRED` 控制是否每次註冊都必須提供邀請碼。
- **認證：** 設定 SCRAM 成本及受保護的 FAST／dummy-SCRAM secret files；
  正式部署前應在目標主機 benchmark SCRAM。
- **儲存及容量：** 本機或 S3-compatible upload、upload/archive/offline
  限制、連線上限及 Stream Management recovery bounds。
- **聯邦及 components：** federation policy、DANE、Dialback、網域
  allow/deny lists，以及受保護的 external-component 設定檔。
- **瀏覽器 transports：** 公開 HTTPS URL、WebSocket origins 及選用 BOSH
  限制。
- **防濫用：** 訊息／註冊限制、PoW 校準，以及保存正式環境狀態所需的
  `ABUSE_STATE_HMAC_KEY_FILE`。
- **監控：** 日誌格式／輪替及私有 metrics listener；非 loopback metrics
  必須使用 bearer-token file。
- **Cluster：** 設定 `REDIS_URL(_FILE)` 會啟用實驗性多程序模式；單機部署
  應保持未設定。

長期 credentials 應使用受保護的 `*_FILE` 設定。不要提交 `.env`、憑證、
私鑰、產生的 secrets、日誌、uploads 或備份。

## 用戶端與 OMEMO

可使用 Gajim、Conversations 等相容用戶端，以 `使用者@你的網域` 登入。
`5222` 使用 STARTTLS；只有用戶端明確支援 XMPP Direct TLS 時才使用
`5223`。憑證必須對 XMPP 網域有效。

Northstar 提供 OMEMO 所需的 PEP、discovery 及非匿名房間資訊；裝置信任與
金鑰驗證仍由用戶端決定。若聯絡人的信任清單為空，請先確認雙方已發布 device
bundle 並重新整理 discovery，再考慮清除用戶端 cache。

網頁端將 OMEMO 私鑰保存在瀏覽器 profile。刪除 profile 可能永久失去金鑰及
舊密文的解密能力；伺服器不保存復原金鑰。裝置轉移 package 只在本機產生、
一次性使用、由獨立密碼保護且不會上傳；匯入後會重設聯絡人信任。詳見
[裝置轉移說明](docs/OMEMO_DEVICE_TRANSFER.md)。

## 註冊、防濫用與檢舉

啟用後，可透過 XEP-0077 或 `POST /api/v1/register` 註冊。依政策可能需要
邀請碼，以及由 `POST /api/v1/anti-abuse/challenge` 取得的 PoW challenge。

頻繁註冊、發訊、檢舉或申訴會逐步增加所需工作量，並可能加入強制等待；
冷卻後限制會逐階降低，且設定上限會避免用戶端無限計算。shared-IP 策略會
降低同一 NAT 後方使用者互相影響。

使用者可選取封存訊息作為檢舉資料；送出後，該內容會交給伺服器及獲授權的
moderator。使用者提供的 OMEMO 解密文字無法由伺服器獨立驗證。申訴的限制
比初次檢舉更嚴格。

## REST、監控與維運

HTTP 服務提供帳號管理、歷史、檢舉與申訴、uploads、XMPP WebSocket/BOSH、
健康檢查及管理功能。機器可讀契約位於
[docs/openapi.yaml](docs/openapi.yaml)，也由 `/api/openapi.yaml` 提供；
`/api/docs` 提供唯讀 Swagger UI。

長時間管理操作支援 `Idempotency-Key`，並回傳可查詢進度的 operation URL。

- `/healthz` 表示 HTTP 程序仍在運作。
- `/readyz` 檢查資料庫及關鍵背景工作，應只供部署平台內部使用。
- `/metrics` 只由獨立的私有 metrics listener 提供。

監控、升級及復原請參閱[正式維運手冊](docs/PRODUCTION_OPERATIONS.md)；
建立或還原正式備份前請先閱讀[備份安全](docs/BACKUP_SECURITY.md)。

## Docker 映像與 Compose 部署

Northstar 會建置三個非 root 映像。建議使用 Docker Compose 部署，由它管理
服務啟動順序、secrets、私有網路及持久卷。

| Dockerfile | 發行映像 | Compose 服務 | 用途 |
|---|---|---|---|
| `Dockerfile` | `ghcr.io/takanashi-tetsuya/northstar:0.2.0` | `migrate`、`xmpp` | 執行資料庫遷移及 XMPP/HTTP 服務 |
| `deploy/database-grants.Dockerfile` | `ghcr.io/takanashi-tetsuya/northstar-database-grants:0.2.0` | `database-grants` | 遷移後重新核對 PostgreSQL 權限 |
| `deploy/backup.Dockerfile` | `ghcr.io/takanashi-tetsuya/northstar-backup:0.2.0` | `backup`、`restore` | 已簽章／加密的備份、驗證及停機還原 |

完整正式環境流程請參閱[正式環境維運](docs/PRODUCTION_OPERATIONS.md)；
資料庫能力邊界請參閱[資料庫角色](docs/DATABASE_ROLES.md)；
備份與還原的信任邊界請參閱[備份安全](docs/BACKUP_SECURITY.md)。

### 前置條件

請使用支援 Linux containers 與 BuildKit 的近期 Docker Engine，以及
Docker Compose `2.24.4` 或更新版本。發行映像 override 使用 Compose 的
`!reset` merge tag。Docker Desktop 與 WSL2 適合 Windows 開發；正式部署應
使用原生 Linux。

在 repository 根目錄確認目前連線的 engine：

```sh
docker version
docker compose version
docker info --format '{{.OSType}}/{{.Architecture}}'
```

最後一個命令必須顯示 Linux 及預期的目標架構。

### 設定及建置

先建立已由 Git 忽略的設定檔：

```sh
cp .env.example .env
```

正式發行時，請填入真實網域及憑證路徑，並將 `NORTHSTAR_VERSION`
設定為發行版本、`NORTHSTAR_VCS_REF` 設定為完整且精確的 commit。
`unknown` 僅供開發使用。

```dotenv
NORTHSTAR_VERSION=0.2.0
NORTHSTAR_VCS_REF=<full-release-commit>
XMPP_DOMAIN=chat.example.org
TLS_CERT_HOST_PATH=/etc/northstar/tls/fullchain.pem
TLS_KEY_HOST_PATH=/etc/northstar/tls/privkey.pem
```

驗證必要 profile，然後建置全部 Northstar 映像：

```sh
docker compose config --quiet
docker compose -f docker-compose.yml -f deploy/docker-compose.bootstrap.yml config --quiet
docker compose --profile monitoring config --quiet
docker compose --profile backup --profile restore config --quiet

docker compose build --pull migrate database-grants xmpp
docker compose --profile backup --profile restore build --pull backup restore
```

第一次 Rust release 建置可能需要數分鐘；後續建置通常會使用 BuildKit cache。
`NORTHSTAR_VERSION` 與 `NORTHSTAR_VCS_REF` 會寫入 OCI labels。

如需在 Compose 以外建立可推送 registry 或離線傳輸的明確標籤單平台映像：

```sh
northstar_version=0.2.0
northstar_revision="$(git rev-parse HEAD)"

docker build --pull \
  --build-arg NORTHSTAR_VERSION="$northstar_version" \
  --build-arg VCS_REF="$northstar_revision" \
  --tag "northstar:$northstar_version" .

docker build --pull --file deploy/database-grants.Dockerfile \
  --build-arg NORTHSTAR_VERSION="$northstar_version" \
  --build-arg VCS_REF="$northstar_revision" \
  --tag "northstar-database-grants:$northstar_version" .

docker build --pull --file deploy/backup.Dockerfile \
  --build-arg NORTHSTAR_VERSION="$northstar_version" \
  --build-arg VCS_REF="$northstar_revision" \
  --tag "northstar-backup:$northstar_version" .
```

隨附的基礎 Compose 檔使用 `build:`，不會自動選用上述手動標籤。

### 使用發行映像

上表三個 Linux AMD64 發行映像的 immutable references 記錄於 Release 的
`IMAGE_DIGESTS`。請先把 `.env.example` 複製為 `.env` 並完成部署設定，再將
三個映像變數設為其中相符的 `name@sha256:digest`。`:0.2.0` tag 方便選取版本，
但正式環境身分應以 digest 為準。

```dotenv
NORTHSTAR_SERVER_IMAGE_REF=ghcr.io/takanashi-tetsuya/northstar@sha256:<digest>
NORTHSTAR_DATABASE_GRANTS_IMAGE_REF=ghcr.io/takanashi-tetsuya/northstar-database-grants@sha256:<digest>
NORTHSTAR_BACKUP_IMAGE_REF=ghcr.io/takanashi-tetsuya/northstar-backup@sha256:<digest>
```

先 render 合併後的設定再 pull。驗證全部三個映像時需啟用 backup 及 restore
profiles：

```sh
docker compose -f docker-compose.yml -f deploy/docker-compose.release.yml \
  --profile backup --profile restore config --quiet
docker compose -f docker-compose.yml -f deploy/docker-compose.release.yml \
  --profile backup --profile restore pull
docker compose -f docker-compose.yml -f deploy/docker-compose.release.yml up -d
```

override 會移除本機 `build:` 定義，不得靜默退回目前 checkout。對外開放服務
前，請確認 render 後的 `image:` 值與三個已審閱 digest 完全一致。

### 第一次正式啟動

安裝真實 TLS 憑證與私鑰，並建立受保護的外部 secret 目錄。
產生器會以各 container 使用者的數字 UID 建立 mode-`0600` 檔案；
不要把 secrets 複製到 repository，也不要放寬其權限。

```sh
sudo install -d -o root -g root -m 0700 /etc/northstar
sudo env NORTHSTAR_SECRET_DIR=/etc/northstar/secrets \
  sh scripts/create-production-secrets.sh
sudo sh scripts/release-preflight.sh --production
```

Bootstrap overlay 只能用於建立第一位管理員：

```sh
sudo docker compose \
  -f docker-compose.yml \
  -f deploy/docker-compose.bootstrap.yml \
  up -d postgres migrate database-grants xmpp caddy

sudo docker compose ps --all
sudo docker compose logs --tail=200 migrate database-grants xmpp caddy
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

立即更換 bootstrap 管理員密碼，以基本 Compose 檔重新建立 `xmpp`，
並安全刪除主機上的 `bootstrap_admin_password` 檔：

```sh
sudo docker compose up -d --force-recreate xmpp caddy
```

較舊的 PostgreSQL 超級使用者部署不能只替換 Compose 檔；
請依照[正式環境維運](docs/PRODUCTION_OPERATIONS.md)執行停機角色遷移。

### 使用映像

常用命令：

```sh
sudo docker compose ps --all
sudo docker compose logs --follow --tail=200 xmpp caddy
sudo docker compose restart xmpp
sudo docker compose --profile monitoring up -d
```

`restart` 不會套用新映像、環境變數、mount 或 secret。設定變更後應執行
`docker compose up -d --force-recreate xmpp`。

升級時不要自行猜測 migration 與 database-grant 的執行順序；請依照
[正式環境維運](docs/PRODUCTION_OPERATIONS.md)中的版本化流程操作。

使用已設定的 backup 映像建立正式備份：

```sh
sudo install -d -m 0700 -o 10001 -g 10001 ./backups
sudo docker compose --profile backup run --rm backup
```

備份驗證與還原必須依照[備份安全](docs/BACKUP_SECURITY.md)的受控流程。
還原具有破壞性；不要自行拼湊 `docker run` 還原命令。

### 重要參數

完整且附註解的權威參數清單位於 [.env.example](.env.example)。
最常調整的 Compose 輸入如下：

| 範圍 | 參數 |
|---|---|
| 發行資訊 | `NORTHSTAR_VERSION`、`NORTHSTAR_VCS_REF` |
| 身分／TLS | `XMPP_DOMAIN`、`SERVER_NAME`、`TLS_CERT_HOST_PATH`、`TLS_KEY_HOST_PATH` |
| 註冊 | `OPEN_REGISTRATION`、`INVITATION_REQUIRED`、`REGISTRATION_RATE_PER_HOUR` |
| 認證 | `SCRAM_ITERATIONS`、`SCRAM_SHA1_ENABLED`、FAST secret-file selectors |
| 容量 | `MAX_CLIENT_CONNECTIONS`、`MAX_CONNECTIONS_PER_IP`、`MAX_SESSIONS_PER_ACCOUNT` |
| 儲存 | `UPLOAD_STORAGE_BACKEND`、上傳限制、S3 檔案型 credentials |
| 聯邦 | `FEDERATION_ENABLED`、allow/deny lists、DANE、信任與 CRL 路徑 |
| 日誌 | `LOG_FORMAT`、`LOG_ROTATION`、`LOG_RETENTION_FILES`、`RUST_LOG` |

`OPEN_REGISTRATION=false` 會關閉公開 REST 與 XEP-0077 註冊。
`INVITATION_REQUIRED=true` 要求有效邀請，但仍會保留 PoW 與 rate limits。
長期 credentials 應放在受保護的 `*_FILE` 輸入，而不是直接寫進 `.env`。
Compose 只傳入明確映射的變數；自訂 override 後應以
`docker compose config --quiet` 驗證，避免把展開後的環境內容寫入日誌。

`docker compose down` 會保留 named volumes。不要把
`docker compose down --volumes` 當作日常清理，因為它會刪除資料庫、
上傳資料與 recovery 狀態。


## 已知限制與授權

Northstar 仍屬 1.0 之前的版本。Redis 多程序路由仍為實驗性，部分選用
XMPP profile 尚未實作，且尚未建立廣泛的公網 federation 相容性。部署前請
閱讀 [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md)。

Northstar 原始程式碼採 [AGPL-3.0-only](LICENSE)；第三方授權見
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
