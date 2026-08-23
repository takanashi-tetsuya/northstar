**English** | [繁體中文](README.zh-TW.md)

# Northstar XMPP Server

A lightweight XMPP server built from scratch in Rust. Supports OMEMO end-to-end encryption, multi-user chat, S2S federation, HTTP file upload, REST admin API, and proof-of-work anti-abuse.

## Quick Start

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env — at minimum set DATABASE_URL and XMPP_DOMAIN

# 2. Build and run
cargo run
```

The server listens on three ports simultaneously:
- **5222** — XMPP C2S (client connections)
- **8080** — HTTP API + WebSocket + Web client
- **5269** — XMPP S2S (federation)

## Supported Protocols

| Standard | Name | Status |
|----------|------|--------|
| RFC 6120 | XMPP Core (Stream, TLS, SASL, Bind) | ✅ Full |
| RFC 6121 | IM & Presence (Roster, Offline Messages) | ✅ Full |
| RFC 7395 | XMPP over WebSocket | ✅ Full |
| RFC 7677 | SCRAM-SHA-256 | ✅ Full |
| XEP-0030 | Service Discovery | ✅ Full (dynamic PEP injection) |
| XEP-0045 | Multi-User Chat (MUC) | ✅ Full |
| XEP-0060 | PubSub / PEP | ✅ Full (OMEMO-ready) |
| XEP-0077 | In-Band Registration | ✅ Full |
| XEP-0163 | Personal Eventing Protocol | ✅ Full |
| XEP-0191 | Blocking Command | ✅ Full |
| XEP-0198 | Stream Management | ✅ Full |
| XEP-0280 | Message Carbons | ✅ Full |
| XEP-0313 | Message Archive Management (MAM) | ✅ Full (with RSM paging) |
| XEP-0357 | Push Notifications | ✅ Basic |
| XEP-0363 | HTTP File Upload | ✅ Full |
| XEP-0384 | OMEMO Encryption (server-side) | ✅ Full |

## Project Structure

```
src/
├── main.rs           # Entrypoint: starts TCP/HTTP/S2S listeners
├── config.rs         # .env configuration parsing (envy)
├── state.rs          # Shared state (AppState, DashMap)
├── auth.rs           # SASL PLAIN + SCRAM-SHA-256 + password hashing
├── error.rs          # HTTP error types
├── tls.rs            # TLS certificate loading & hot-reload
├── storage.rs        # Upload storage abstraction (trait UploadStore)
├── metrics.rs        # Prometheus metrics
├── abuse.rs          # PoW anti-abuse + rate limiting
├── api/              # REST API (auth, admin, upload, reports)
├── db/               # Database layer (users, roster, pep, muc, archive...)
├── xmpp/             # XMPP protocol core
│   ├── mod.rs        # TCP/WebSocket connection driver
│   ├── framing.rs    # XML stream framer
│   ├── xml_util.rs   # XML helper functions
│   └── protocol/     # Protocol handlers (15 submodules)
│       ├── dispatch.rs, messaging.rs, presence.rs, roster.rs,
│       ├── muc.rs, pep.rs, mam.rs, sm.rs, blocking.rs,
│       ├── discovery.rs, upload.rs, vcard.rs, ibr.rs,
│       ├── misc.rs, private.rs
└── s2s/              # S2S federation (dns, tls, inbound, outbound)
```

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/healthz` | None | Health check |
| GET | `/readyz` | None | Readiness check |
| GET | `/metrics` | None | Prometheus metrics |
| POST | `/api/v1/register` | None | Register new user |
| POST | `/api/v1/login` | None | Login, returns Bearer token |
| GET | `/api/v1/me` | Bearer | Current user info |
| PATCH | `/api/v1/me/password` | Bearer | Change password |
| GET | `/api/v1/history` | Bearer | Message history |
| GET/POST | `/api/v1/reports` | Bearer | Abuse reports |
| PUT | `/api/v1/upload/{id}` | Bearer | File upload |
| GET | `/uploads/{id}` | None | File download |
| GET | `/api/v1/admin/stats` | Admin | Server statistics |
| GET | `/api/v1/admin/users` | Admin | User list |
| PATCH | `/api/v1/admin/users/{id}` | Admin | Update user status |
| POST | `/api/v1/admin/tls/reload` | Admin | Hot-reload TLS certs |
| GET/POST | `/api/v1/admin/invitations` | Admin | Invitation management |

## Configuration

All configuration is managed via the `.env` file. See [`.env.example`](.env.example) for the full list. Key options:

| Variable | Default | Description |
|----------|---------|-------------|
| `XMPP_DOMAIN` | `localhost` | Server domain |
| `DATABASE_URL` | — | PostgreSQL connection string |
| `XMPP_BIND` | `0.0.0.0:5222` | C2S listen address |
| `HTTP_BIND` | `0.0.0.0:8080` | HTTP/WS listen address |
| `FEDERATION_ENABLED` | `true` | Enable S2S federation |
| `OPEN_REGISTRATION` | `true` | Allow public registration |
| `SCRAM_ITERATIONS` | `600000` | PBKDF2 iteration count |
