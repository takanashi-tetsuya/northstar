# Changelog

All notable Northstar changes are documented here. Protocol support claims are
normative only in [XEP_MATRIX.md](XEP_MATRIX.md), and unresolved release
boundaries are normative only in [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md).

## [Unreleased]

- The complete change set from the previous committed `0.1.0` baseline is
  recorded in the [2.0 development changelog](changelog/v2.0.md).
- Release metadata remains `1.1.0` until a separate, atomic version-bump change
  updates Cargo, Compose, OCI and OpenAPI together.
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
- Production qualification still requires the target-environment and external
  gates in [the release checklist](docs/RELEASE_CHECKLIST.md).

## Historical development snapshots

Point-in-time handoff, validation and planning reports are retained under
[`docs/archive/`](docs/archive/). They are evidence of prior work, not current
feature or security declarations.
