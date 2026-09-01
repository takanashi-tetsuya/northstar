# Changelog

All notable Northstar changes are documented here. Protocol support claims are
normative only in [XEP_MATRIX.md](XEP_MATRIX.md), and unresolved release
boundaries are normative only in [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md).

## [0.2.0] - Unreleased

- The complete change set from the previous committed `0.1.0` baseline is
  recorded in the [0.2 development changelog](changelog/v0.2.md).
- Cargo, Compose, OCI, backup and OpenAPI metadata now identify the current
  pre-1.0 development line as `0.2.0`. Version `1.0.0` is reserved until one
  exact artifact and target environment satisfy every applicable production
  qualification gate in the release checklist.
- Rebuilt the current documentation set around one compatibility matrix, one
  known-issues register, an operations manual, a release checklist and an
  explicitly historical archive; added a loopback-only development profile and
  contributor/security policies.
- Pinned the release Rust toolchain, added Cargo repository metadata, and added
  OCI source/revision/version/license labels plus project license notices to all
  Northstar images.
- Production preflight now validates the independent command database role and
  fails closed when its Compose/Docker validation cannot run. Parser fuzzing now
  joins the heavy runtime envelopes as a scheduled/manual-only CI job instead
  of running on ordinary push or pull-request events.
- Hardened incremental XML framing against stale UTF-8 byte offsets when a
  defensive adapter replaces a rejected incomplete buffer. RFC 7395 parsing now
  explicitly resets pending per-message scan state without discarding the XML
  entity's declaration state.
- PubSub Atom notification summaries now enforce their byte ceiling at a UTF-8
  character boundary instead of panicking when the limit intersects a
  multibyte character.
- Registration now fails closed if its durable runtime control row is missing;
  migration `0125` replaces the capability without weakening schema or role
  isolation. `INVITATION_REQUIRED` is documented as the shared REST/XEP-0077
  invitation-policy switch.
- CI now hashes canonical LF-only migration bytes, pins the exact Rust 1.97.1
  builder digest, uses a genuinely loopback PostgreSQL runtime fixture, and
  exercises production-shaped upload capacity and disaster-recovery rollback.
- Production qualification still requires the target-environment and external
  gates in [the release checklist](docs/RELEASE_CHECKLIST.md).

## [0.1.0] - Historical baseline

- Initial pre-1.0 Northstar baseline at Git commit
  `998396915ab38a9deadf47ae871be561e11f7ef2`, with migrations `0001`–`0013`.
- The complete delta from this baseline to `0.2.0` is maintained in
  [the 0.2 development changelog](changelog/v0.2.md).

## Historical development snapshots

Point-in-time handoff, validation and planning reports are retained under
[`docs/archive/`](docs/archive/). They are evidence of prior work, not current
feature or security declarations.
