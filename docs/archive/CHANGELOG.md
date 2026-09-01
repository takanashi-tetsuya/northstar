# Changelog

> **Historical snapshot / 历史快照 — not current release notes and 不得作为当前能力或发布说明。**
> Use [the root changelog](../../CHANGELOG.md), [current known issues](../KNOWN_ISSUES.md),
> [the XEP matrix](../../XEP_MATRIX.md) and [the release checklist](../RELEASE_CHECKLIST.md)
> for the current artifact.

All notable changes to Northstar XMPP Server during the recent development engagement.

## [Unreleased] — 2026-08-23

### Fixed
- **Resource binding fallback**: Changed default resource from hardcoded `"web"` to `uuid::Uuid::new_v4()`, complying with RFC 6120 §7.7.1 and preventing `<conflict>` errors when multiple devices connect without specifying a resource.

### Changed
- **Configuration centralized to `.env`**: Replaced 250+ lines of manual `env::var` parsing in `src/config.rs` with the `envy` crate. All settings now deserialize automatically into a `RawConfig` struct via `#[derive(Deserialize)]`. Created `.env.example` as the canonical configuration template.
- **Auth module consolidated**: Merged `src/sasl.rs` into `src/auth.rs`. SASL mechanisms (PLAIN, SCRAM-SHA-256) and password hashing (Argon2, PBKDF2) now live in a single cohesive module. Fixed duplicate import errors introduced by the merge.
- **Config field names updated**: Renamed `db_max_connections` / `db_min_connections` to `database_max_connections` / `database_min_connections` in `src/main.rs` to match the new `RawConfig` struct.

### Removed
- **`src/db_recovered.rs`**: Deleted 1,200+ lines of abandoned database code left over from a prior refactoring attempt.
- **`src/xmpp/split_output/`**: Deleted an orphaned directory from a failed architectural split.

---

## [Earlier] — OMEMO / PEP / MUC Protocol Fixes

### Fixed — PEP Publish (`src/xmpp/protocol/pep.rs`)
- **Multi-item support**: `pep_publish` now iterates and persists all `<item>` children in a `<publish>` stanza, not just the first. Required for OMEMO batch key uploads.
- **Auto-generated UUIDs**: When a client publishes an `<item>` without an `id` attribute, the server now generates a `Uuid::new_v4()` instead of returning `<bad-request>`, per XEP-0060.
- **Normalized response**: Publish success now returns a clean `<iq type='result'/>` without redundant payload.

### Fixed — PEP Retrieval (`src/xmpp/protocol/pep.rs`)
- **`<item-not-found>` response**: When a client queries a PEP node that does not exist in the database, the server now returns `<error type='cancel'><item-not-found/></error>` instead of an empty `<items/>` list. This was the critical fix that triggered Gajim to initialize its OMEMO device list.
- **`from` attribute on IQ results**: Introduced `iq_result_from` to correctly stamp the target user's JID on PEP responses addressed to a third party. Without this, clients silently discarded the response.

### Fixed — Service Discovery (`src/xmpp/protocol/discovery.rs`)
- **Dynamic PEP feature injection**: `disco#info` responses for a user's bare JID now dynamically query the database for all PEP nodes the user has published, and inject them (along with `+notify` variants) as `<feature>` elements. This allows clients to detect OMEMO support.

### Fixed — MUC (`src/xmpp/protocol/muc.rs`)
- **Non-anonymous default**: Newly created MUC rooms default to `non_anonymous = TRUE`, exposing real JIDs to all occupants as required by OMEMO group encryption.
- **Real JID broadcast**: Presence stanzas in MUC rooms now always include `<item jid='real-jid@domain/resource'/>` in the `muc#user` extension, enabling clients to correlate occupants with OMEMO fingerprints.

### Changed — S2S Modularization
- Split monolithic `src/s2s.rs` (42 KB) into `src/s2s/` directory with submodules: `mod.rs`, `inbound.rs`, `outbound.rs`, `dns.rs`, `tls.rs`, `util.rs`.
