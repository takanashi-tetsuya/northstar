[English](README.md) | **繁體中文**

# Northstar XMPP 伺服器

Northstar 是一個從零開始使用 Rust 構建的現代化、輕量級且極速的 XMPP 伺服器。它秉承嚴格的**「零知識與隱私優先」**（Zero-Knowledge & Privacy-First）理念，專注於安全的通訊、端到端加密（OMEMO）以及極致的高並發效能。

## 🌟 核心理念與功能

- **隱私優先（零知識管理）**：伺服器絕對沒有能力攔截、讀取或審查使用者的聊天訊息。所有的管理工具（如：全站強制下線、聯邦孤島模式、帳號核彈重置）都只針對網路層和中繼資料進行操作，完全尊重並保護使用者隱私。
- **現代化加密**：全面支援 OMEMO (XEP-0384) 端到端加密。
- **極速與記憶體安全**：使用 Rust 語言編寫，底層採用 `tokio` 異步 I/O，徹底杜絕記憶體洩漏與執行緒競爭。
- **RESTful 管理架構**：內建 JSON HTTP API 用於伺服器管理，徹底取代傳統 XMPP 伺服器笨重且難用的 XML 管理流程。
- **內建 Web 用戶端與防濫用機制**：具備工作量證明（PoW）註冊限流機制與邀請碼系統。

## 🔐 帳號註冊流程（重要必讀）

不同於傳統的 XMPP 伺服器允許使用者直接在 Gajim 或 Conversations 等 App 內進行註冊（即 In-Band Registration），**為確保伺服器安全並有效阻斷惡意註冊，Northstar 強制要求所有註冊必須透過 HTTP REST API 進行。**

**一般使用者的註冊與登入步驟：**
1. 打開伺服器專屬的 **Web 網頁端**（或自行使用 curl / Postman 發送 `POST /api/v1/register` 請求）。
2. 在 Web 端的註冊表單中，填寫你想要的**使用者名稱**、**密碼**，以及管理員發放的**邀請碼 (Invitation Token)**。
3. 後端會透過 HTTP API 驗證邀請碼（及 PoW 工作量證明），驗證無誤後創建帳號。
4. **帳號創建成功後**，請打開你喜歡的第三方 XMPP 用戶端（例如：Gajim, Conversations, Siskin 等），填入剛才註冊的帳號密碼進行**登入並開始聊天**。

## 🚀 快速開始

### 1. 環境要求
- Rust (最新穩定版)
- PostgreSQL 資料庫

### 2. 設定環境變數
```bash
cp .env.example .env
# 編輯 .env 檔案 — 必須設定 DATABASE_URL 和 XMPP_DOMAIN
```

### 3. 編譯與執行
```bash
cargo run --release
```

伺服器啟動後會同時監聽以下三個主要連接埠：
- **5222** — XMPP C2S (用戶端連線)
- **5269** — XMPP S2S (伺服器間聯邦通訊)
- **8080** — HTTP API + 網頁用戶端 + WebSocket

## 📡 支援的協定 (XEPs)

| 標準 | 描述 | 狀態 |
|----------|-------------|--------|
| RFC 6120/6121 | XMPP Core, IM & Presence | ✅ 完整支援 |
| RFC 7395 | XMPP over WebSocket | ✅ 完整支援 |
| RFC 7677 | SCRAM-SHA-256 密碼雜湊驗證 | ✅ 完整支援 |
| XEP-0030 | 服務探索 (Service Discovery) | ✅ 完整支援 |
| XEP-0045 | 多人聊天室 (MUC) | ✅ 完整支援 |
| XEP-0060/0163 | 發布訂閱與個人事件協定 (PEP) | ✅ 完整支援 |
| XEP-0198 | 串流管理 (斷線重連) | ✅ 完整支援 |
| XEP-0280 | 訊息副本 (多設備同步) | ✅ 完整支援 |
| XEP-0313 | 歷史訊息歸檔 (MAM) | ✅ 完整支援 |
| XEP-0363 | HTTP 檔案上傳 | ✅ 完整支援 |
| XEP-0384 | OMEMO 端到端加密支援 | ✅ 完整支援 |

## 🛠️ API 與管理員端點

Northstar 在 `8080` 通訊埠提供了強大的 REST API。

**公開端點 (Public Endpoints):**
- `POST /api/v1/register`: 帳號註冊（需要包含邀請碼的 JSON 請求體）。
- `POST /api/v1/login`: 驗證身分並獲取用於 API 的 Bearer Token。
- `GET /healthz` & `/metrics`: 伺服器健康檢查與 Prometheus 監控指標。

**零知識管理端點 (需管理員 Token):**
- `POST /api/v1/admin/island_mode`: 瞬間切斷所有對外的 S2S 聯邦通訊（孤島模式）。
- `POST /api/v1/admin/registration`: 動態開啟/關閉全站註冊。
- `POST /api/v1/admin/panic_disconnect`: 一鍵強制所有在線使用者斷線。
- `GET /api/v1/admin/sessions`: 監控當前活動的網路連線。
- `DELETE /api/v1/admin/offline_messages`: 清空離線訊息緩衝池，釋放資料庫空間。
- `DELETE /api/v1/admin/muc_rooms/{localpart}`: 強制解散特定群聊（無需檢視群內訊息）。

詳細的 API 說明與管理操作，請參考內建的 Swagger UI 或 `docs/` 目錄。
