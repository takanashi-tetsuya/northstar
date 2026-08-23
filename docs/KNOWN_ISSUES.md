# Known Issues & Future Improvements

Items marked ~~strikethrough~~ have been resolved. Remaining items are listed by severity.

---

## Resolved

- ~~**`protocol.rs` god file (115 KB)**: All protocol logic in one file~~ → Split into 15 submodules under `src/xmpp/protocol/`
- ~~**SASL only PLAIN**: No SCRAM support~~ → SCRAM-SHA-256 fully implemented in `src/auth.rs`
- ~~**No TLS hot-reload**: Certificate changes required restart~~ → Admin API endpoint `POST /api/v1/admin/tls/reload`
- ~~**No graceful shutdown**: Process kill dropped all connections~~ → `CancellationToken` + SIGTERM/SIGINT handler
- ~~**Storage not abstracted**: Raw filesystem functions~~ → `trait UploadStore` with streaming I/O
- ~~**Login not rate-limited**: No brute-force protection~~ → PoW anti-abuse module with per-IP/user sliding windows
- ~~**Internal errors leaked to clients**: `anyhow::Error` messages returned in API responses~~ → Generic `"internal server error"` returned; details logged server-side only
- ~~**Monolithic files**: `s2s.rs` (42 KB), `db.rs` (42 KB), `api.rs` (28 KB)~~ → All modularized into subdirectories
- ~~**Resource binding hardcoded to `"web"`**: RFC 6120 §7.7.1 violation~~ → Auto-generates UUID

---

## Remaining Design Limitations

### High Priority

| Issue | Description | Impact |
|-------|-------------|--------|
| **S2S per-stanza connections** | Outbound federation opens a new TCP+TLS+SASL connection for every stanza, then disconnects. No connection pooling, no DNS caching, no retry queue. | Federation messages may be silently lost; extremely inefficient for high-volume cross-domain traffic. |
| **All runtime state in memory** | Sessions, MUC occupancy, rate-limit windows, SM resume queues, PoW challenges, and upload slots are stored in `DashMap`. Server restart loses everything. | No horizontal scaling; abuse counters reset on restart; potential slow memory leak from expired entries without cleanup. |

### Medium Priority

| Issue | Description |
|-------|-------------|
| **No database index tuning** | Missing composite indexes on `message_archive (user_id, with_jid, timestamp)`, `offline_messages (user_id)`, `api_sessions (user_id)`, `abuse_reports (status)`, and `audit_log (actor_id, created_at)`. |
| **XML built via `format!`** | All outbound XML is constructed by string interpolation rather than a structured builder. Risk of stanza injection if `attr_escape` is missed at a new interpolation point. |
| **Prometheus metrics hand-rolled** | Does not use the `prometheus` crate; text format is manually constructed without `# HELP` / `# TYPE` declarations. No histogram or summary metrics for latency tracking. |

---

## Feature Gaps

| Area | Missing | XEP Reference |
|------|---------|---------------|
| MUC | Federated MUC (cross-domain group chat) | XEP-0045 §7 |
| MUC | Room creation / join limits (resource exhaustion risk) | — |
| MAM | User-configurable archive preferences | XEP-0313 §7 |
| MAM | Archive retention / purge policy | — |
| REST API | `GET /api/v1/history` lacks `before`/`after` cursor pagination and `start`/`end` time filters (XMPP MAM already supports these) | — |
| REST API | `GET /api/v1/reports` and admin reports have no `limit`/`offset` pagination | — |
| PEP/PubSub | Only OMEMO-related nodes are supported; not a general-purpose PubSub service | XEP-0060 |
| Account | No in-band account deletion | XEP-0077 §3.2 |
| SM | Resume state not persisted across server restarts | XEP-0198 |
