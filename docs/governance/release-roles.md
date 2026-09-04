# Release identity and trust roles

This document defines the minimal release/operations trust model used for Northstar.

## Roles

### 1) Platform maintainer
- Controls source, merge decisions, and release branch preparation.
- Must have explicit authority for `main` branch merge paths.

### 2) Security signer
- Approves any security-path PR (auth, contracts, migrations, deploy, roles,
  telemetry/observability boundary changes).
- Can reject release candidates if evidence is not complete.

### 3) Operability lead
- Owns production rollout windows, runbooks and rollback plans.
- Ensures backup/restore test and DR evidence exists before release.

### 4) Emergency operator
- Temporary bypass role for production incidents only.
- Every bypass must create a follow-up trace issue before system handoff.

## Release credential policy

- Never persist PATs in repository or CI variables.
- Prefer OIDC federation to cloud providers and Sigstore keyless flows.
- Do not use long-lived signing keys on shared hosts.
- Release signing material must be short-lived and bound to the release workflow.

## Evidence required for release candidate closure

- Checked CI status at workflow `release` / tag run.
- Migrations and catalog checks executed at the tagged commit.
- Signed tag and immutable provenance artifact.
- Digest/manifest/metadata for release images.
- Manual release checklist sign-off with:
  - Security owner
  - Operability lead
  - Platform maintainer

## Release flow

1. Freeze release branch at `main`/`release/x.y.z`.
2. Run final release-local preflight from operations docs.
3. Create signed tag on the exact release commit.
4. Publish only after:
   - Signed tag accepted by policy.
   - Workflow artifacts recorded (`checksums`, `provenance`, image digests).
   - Governance docs cross-checked (`branch-rules.md`, `SECURITY.md`, `CONTRIBUTING.md`).

## Fail-open policy

If any required artifact is missing or evidence is stale, release is blocked.
Downgrade is not a release action and must follow incident rollback with a new commit.
