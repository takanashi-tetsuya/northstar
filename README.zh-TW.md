[English](README.md) | **繁體中文**

# Northstar XMPP 伺服器

以 Rust 從零打造的輕量級 XMPP 伺服器。支援 OMEMO 端對端加密、多人聊天室、S2S 聯邦通訊、HTTP 檔案上傳、REST 管理 API，以及基於工作量證明的防濫用系統。

## 快速開始

```bash
# 1. 設定環境變數
cp .env.example .env
# 編輯 .env，至少需修改 DATABASE_URL 與 XMPP_DOMAIN

# 2. 編譯並啟動
cargo run
```

伺服器將同時監聽三個連接埠：
- **5222** — XMPP C2S（用戶端連線）
- **8080** — HTTP API + WebSocket + Web 用戶端
- **5269** — XMPP S2S（聯邦通訊）

## 支援的協定

| 標準 | 名稱 | 狀態 |
|------|------|------|
| RFC 6120 | XMPP 核心（Stream、TLS、SASL、Bind） | ✅ 完整 |
| RFC 6121 | 即時通訊與狀態（Roster、離線訊息） | ✅ 完整 |
| RFC 7395 | XMPP over WebSocket | ✅ 完整 |
| RFC 7677 | SCRAM-SHA-256 | ✅ 完整 |
| XEP-0030 | 服務探索 | ✅ 完整（含動態 PEP 注入） |
| XEP-0045 | 多人聊天室（MUC） | ✅ 完整 |
| XEP-0060 | PubSub / PEP | ✅ 完整（OMEMO 就緒） |
| XEP-0077 | 帶內註冊 | ✅ 完整 |
| XEP-0163 | 個人事件協定 | ✅ 完整 |
| XEP-0191 | 封鎖指令 | ✅ 完整 |
| XEP-0198 | 串流管理 | ✅ 完整 |
| XEP-0280 | 訊息副本同步 | ✅ 完整 |
| XEP-0313 | 訊息封存管理（MAM） | ✅ 完整（含 RSM 分頁） |
| XEP-0357 | 推播通知 | ✅ 基本 |
| XEP-0363 | HTTP 檔案上傳 | ✅ 完整 |
| XEP-0384 | OMEMO 加密（伺服端支援） | ✅ 完整 |

## 專案結構

```
src/
├── main.rs           # 進入點：啟動 TCP/HTTP/S2S 監聽器
├── config.rs         # .env 設定檔解析（envy）
├── state.rs          # 共享狀態（AppState、DashMap）
├── auth.rs           # SASL PLAIN + SCRAM-SHA-256 + 密碼雜湊
├── error.rs          # HTTP 錯誤類型
├── tls.rs            # TLS 憑證載入與熱重載
├── storage.rs        # 上傳儲存抽象層（trait UploadStore）
├── metrics.rs        # Prometheus 指標
├── abuse.rs          # PoW 防濫用 + 速率限制
├── api/              # REST API（驗證、管理、上傳、檢舉）
├── db/               # 資料庫層（使用者、名冊、PEP、MUC、封存…）
├── xmpp/             # XMPP 協定核心
│   ├── mod.rs        # TCP/WebSocket 連線驅動
│   ├── framing.rs    # XML 串流分幀器
│   ├── xml_util.rs   # XML 工具函式
│   └── protocol/     # 協定處理器（15 個子模組）
│       ├── dispatch.rs、messaging.rs、presence.rs、roster.rs、
│       ├── muc.rs、pep.rs、mam.rs、sm.rs、blocking.rs、
│       ├── discovery.rs、upload.rs、vcard.rs、ibr.rs、
│       ├── misc.rs、private.rs
└── s2s/              # S2S 聯邦（dns、tls、inbound、outbound）
```

## API 端點

| 方法 | 路徑 | 驗證 | 說明 |
|------|------|------|------|
| GET | `/healthz` | 無 | 健康檢查 |
| GET | `/readyz` | 無 | 就緒檢查 |
| GET | `/metrics` | 無 | Prometheus 指標 |
| POST | `/api/v1/register` | 無 | 註冊新使用者 |
| POST | `/api/v1/login` | 無 | 登入，回傳 Bearer Token |
| GET | `/api/v1/me` | Bearer | 目前使用者資訊 |
| PATCH | `/api/v1/me/password` | Bearer | 修改密碼 |
| GET | `/api/v1/history` | Bearer | 訊息紀錄 |
| GET/POST | `/api/v1/reports` | Bearer | 濫用檢舉 |
| PUT | `/api/v1/upload/{id}` | Bearer | 檔案上傳 |
| GET | `/uploads/{id}` | 無 | 檔案下載 |
| GET | `/api/v1/admin/stats` | Admin | 伺服器統計 |
| GET | `/api/v1/admin/users` | Admin | 使用者列表 |
| PATCH | `/api/v1/admin/users/{id}` | Admin | 更新使用者狀態 |
| POST | `/api/v1/admin/tls/reload` | Admin | 熱重載 TLS 憑證 |
| GET/POST | `/api/v1/admin/invitations` | Admin | 邀請碼管理 |

## 設定

所有設定皆透過 `.env` 檔案管理，完整清單請參閱 [`.env.example`](.env.example)。主要設定項：

| 變數 | 預設值 | 說明 |
|------|--------|------|
| `XMPP_DOMAIN` | `localhost` | 伺服器網域 |
| `DATABASE_URL` | — | PostgreSQL 連線字串 |
| `XMPP_BIND` | `0.0.0.0:5222` | C2S 監聽位址 |
| `HTTP_BIND` | `0.0.0.0:8080` | HTTP/WS 監聽位址 |
| `FEDERATION_ENABLED` | `true` | 啟用 S2S 聯邦通訊 |
| `OPEN_REGISTRATION` | `true` | 允許公開註冊 |
| `SCRAM_ITERATIONS` | `600000` | PBKDF2 迭代次數 |
