# Branch rules and required checks baseline (program-5 / aa2b0df)

This document defines the repository governance target that must be enabled in GitHub
Settings for main/dev before M00 is considered complete.

## 1. Required status: main

Main branch is release-critical and must be protected:

- Push to main is blocked.
- Linear commits are recommended.
- At least one PR approval required.
- Conversation must be resolved before merge.
- No force-push / no branch deletion.
- Required checks:
  - `fmt`
  - `check`
  - `test`
  - `clippy`
  - `build`
  - `buf-contracts`
  - `documentation-consistency`
  - `microservice-catalog`
  - `database-runtime-boundary`

## 2. Required status: dev

- PR-based workflow preferred, with merge blocked when checks fail.
- Draft PR must not be used to land protected paths.
- Required checks should be a subset of main, with `fmt` and `test` as mandatory:
  - `fmt`
  - `check`
  - `test`
  - `clippy`
  - `build`

## 3. Security-critical owners

The following paths require CODEOWNER approval in addition to check pass:

- `contracts/**`
- `crates/foundation-contracts/**`
- `services/**`
- `src/{auth.rs,auth/**,db/**,state.rs,main.rs,xmpp/**,api/**}`
- `src/s2s/**`
- `migrations/**`
- `.github/**`
- `deploy/**`
- `buf*.yml`, `Dockerfile*`
- `scripts/**` when touching deployment, migration, or security code paths
- `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, `docs/**`

The repo-level `.github/CODEOWNERS` should be kept synchronized with this list.

## 4. Emergency bypass policy

- Bypass is prohibited for normal production flow.
- If bypass is unavoidable, the operator must:
  1. Record a GitHub issue/incident.
  2. Tag the PR with `policy-bypass`.
  3. Attach a root-cause and compensating controls note.
  4. Include a rollback condition and approval by the designated emergency role.

## 5. Commit and tag signing expectation

- PR squash-merge is preferred for clean history.
- For release boundaries and security-path-only changes, signed commits are required.
- For releases, signed tags and provenance-attested artifacts are required.

## 6. Validation command

After applying branch rules in GitHub:

```sh
gh api repos/:owner/:repo/rulesets
```

expected summary:

- `main` has `block_creations`, `required_signatures` and `required_pull_request`,
  plus all required checks.
- `dev` has at least one required check set.
- branch deletion and force-push are blocked.
