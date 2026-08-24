**English** | [繁體中文](README.zh-TW.md)

# Northstar XMPP Server

Northstar is a modern, lightweight, and incredibly fast XMPP server built from scratch in Rust. It is designed with a strict **Zero-Knowledge & Privacy-First** philosophy, focusing on secure communication, end-to-end encryption (OMEMO), and high-performance concurrency.

## 🌟 Core Philosophy & Features

- **Privacy First (Zero-Knowledge Admin)**: The server has absolutely no ability to intercept, read, or inspect user messages. All moderation tools (Panic Disconnect, Island Mode, Account Nuke) are designed to act on metadata and network layers, fully respecting user privacy.
- **Modern Encryption**: Fully supports OMEMO (XEP-0384) end-to-end encryption.
- **Blazing Fast & Safe**: Written in Rust, leveraging `tokio` for async I/O. Safe from memory leaks and thread races.
- **RESTful Administration**: Includes a built-in JSON HTTP API for server administration, completely replacing the clunky XML-based admin workflows of traditional servers.
- **Built-in Web Client & Anti-Abuse**: Features Proof-of-Work (PoW) registration limits and invitation code systems.

## 🔐 Registration Workflow (Important)

Unlike traditional XMPP servers where you can register directly inside clients like Gajim or Conversations (In-Band Registration), **Northstar requires registration via HTTP REST API for enhanced security and anti-abuse control.**

**How to get started as a user:**
1. Open the server's built-in **Web Client/Portal** in your browser (or use curl/Postman to hit `POST /api/v1/register`).
2. Fill out the registration form with your desired **Username**, **Password**, and the required **Invitation Token** (provided by the server administrator).
3. The backend securely validates the invitation token, verifies the Proof-of-Work (if enabled), and creates the account.
4. Once the account is created successfully via the Web, open your favorite XMPP client (e.g., Gajim, Conversations, Siskin) and **log in** using those credentials.

## 🚀 Quick Start

### 1. Prerequisites
- Rust (latest stable)
- PostgreSQL database

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env — you MUST configure DATABASE_URL and XMPP_DOMAIN
```

### 3. Build and Run
```bash
cargo run --release
```

The server binds to three primary ports:
- **5222** — XMPP C2S (Client-to-Server connections)
- **5269** — XMPP S2S (Server-to-Server federation)
- **8080** — HTTP API + Web Client + WebSockets

## 📡 Supported Protocols (XEPs)

| Standard | Description | Status |
|----------|-------------|--------|
| RFC 6120/6121 | XMPP Core, IM & Presence | ✅ Full |
| RFC 7395 | XMPP over WebSocket | ✅ Full |
| RFC 7677 | SCRAM-SHA-256 Authentication | ✅ Full |
| XEP-0030 | Service Discovery | ✅ Full |
| XEP-0045 | Multi-User Chat (MUC) | ✅ Full |
| XEP-0060/0163 | PubSub & Personal Eventing Protocol | ✅ Full |
| XEP-0198 | Stream Management (Session resumption)| ✅ Full |
| XEP-0280 | Message Carbons (Multi-device sync) | ✅ Full |
| XEP-0313 | Message Archive Management (MAM) | ✅ Full |
| XEP-0363 | HTTP File Upload | ✅ Full |
| XEP-0384 | OMEMO Encryption | ✅ Full |

## 🛠️ API & Administration

Northstar exposes a powerful REST API on port `8080`. 

**Public Endpoints:**
- `POST /api/v1/register`: Account registration (requires JSON payload with invitation token).
- `POST /api/v1/login`: Authenticate and receive a Bearer token for API access.
- `GET /healthz` & `/metrics`: Server health and Prometheus metrics.

**Zero-Knowledge Admin Endpoints (Requires Admin Token):**
- `POST /api/v1/admin/island_mode`: Cut off all S2S federation instantly.
- `POST /api/v1/admin/registration`: Toggle public registration on/off.
- `POST /api/v1/admin/panic_disconnect`: Force disconnect all active connections.
- `GET /api/v1/admin/sessions`: Monitor active network sessions.
- `DELETE /api/v1/admin/offline_messages`: Truncate offline message spools to free up space.
- `DELETE /api/v1/admin/muc_rooms/{localpart}`: Destroy a group chat without inspecting its contents.

For detailed API usage and administration, see the built-in Swagger UI or the `docs/` folder.
