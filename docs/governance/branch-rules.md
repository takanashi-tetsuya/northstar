# Branch rules and required checks

Northstar is maintained by `@takanashi-tetsuya`. Pull requests record review
and validation; CODEOWNERS routes changes to the maintainer.

## Required branch policy

Both `main` and `dev` require:

- A pull request, with zero required approving reviews and no mandatory
  CODEOWNER or last-push approval. The maintainer records self-review and
  validation in the PR before merging. Resolve all review conversations.
- Verified signed commits. GitHub's signed squash merge is suitable when the
  maintainer does not have a separate local commit-signing setup.
- The **`CI required`** status from GitHub Actions (GitHub.com app ID `15368`),
  with strict up-to-date checks.
- No branch deletion, force pushes, or configured bypass actors.

Live API verification on 2026-09-13 confirmed active
[branch ruleset 23116470](https://github.com/takanashi-tetsuya/northstar/rules/23116470)
for `main` and `dev`, with the requirements above and no bypass actors.
The corresponding API payload is [branch-ruleset.json](branch-ruleset.json).
Recheck the live rules before each release.

## Stable CI result

`CI required` directly depends on every job in `.github/workflows/ci.yml` and
runs even after a dependency fails. `scripts/ci-required-policy.mjs` explicitly
classifies every job:

- Normal build, test, dependency/security, contract, architecture, web,
  container, database, protocol, federation, listener smoke and recovery jobs
  must succeed for every supported event.
- Push and PR runs additionally require the regular listener stress matrix.
- Scheduled and manual runs instead require the timed parser fuzz suite,
  production envelope, cluster/load envelope and scheduled listener stress
  matrix. Those jobs are intentionally skipped on normal push/PR runs.

Failure, cancellation, missing results, unknown jobs and unexpected skips
make the aggregate fail. A matrix dependency must succeed as a whole. A
whole-run cancellation may prevent the aggregate from running; the absent
successful result cannot qualify a merge or release. Normal CI also checks
parser fuzz coverage, tests the coverage gate and compiles all fuzz targets
without executing fuzz inputs.

Use only the stable aggregate as the required check. Old labels such as `fmt`,
`test`, `buf-contracts` and `microservice-catalog` are not current GitHub check
names; some underlying controls are steps within a job. Job changes require
updating classification, dependencies and regression tests together. Tests
must not be removed merely to turn the aggregate green.

## Release trust

`dev` is the integration branch; release candidates enter `main` by PR.
Publication accepts only a signed annotated version tag directly identifying a
commit in `main` history. The latest trusted `main` push/schedule run of this
repository's CI workflow for that exact SHA must have completed successfully,
including the unique `CI required` job in the same run attempt. PR, manual,
tag, fork and unrelated-branch runs cannot qualify publication. A newer failed,
cancelled or running trusted run blocks reuse of older green evidence.
Main-push release builds remain build-only and are not ship approval.

`scripts/verify-release-ci.mjs` also requires active, effective `main` branch rules.
The workflow revalidates tag and CI evidence immediately before publishing
images, after both binary builds succeed. Release integrity depends on the
repository owner and anyone able to change Actions source or settings.

[Tag ruleset 23133333](https://github.com/takanashi-tetsuya/northstar/rules/23133333),
also verified active on 2026-09-13, prevents updates and deletion of `v*` tags
with no bypass actors. Its payload is [release-tag-ruleset.json](release-tag-ruleset.json).
Creation remains possible for the maintainer. Pushing a version tag starts
GHCR publication and draft Release preparation.

## Apply and verify

Review the JSON payloads and intended repository before applying either
ruleset. Enable the required check only after a commit containing `CI required`
has completed successfully, so the protected branch can supply that context.
Use GitHub Settings or an explicitly authorized ruleset API write; repository
tests never modify remote settings. After applying, read back the live rules:

```sh
gh api repos/takanashi-tetsuya/northstar/rulesets
gh api repos/takanashi-tetsuya/northstar/rules/branches/main
gh api repos/takanashi-tetsuya/northstar/rules/branches/dev
```

Verify active branch/tag targets, empty bypass actors, the required GitHub
Actions check, zero required outside approvals, signatures and deletion/push
restrictions. Read individual ruleset IDs to verify tag rules and bypass actors,
which effective branch rules do not fully show. See GitHub's
[REST repository rules](https://docs.github.com/en/rest/repos/rules) API.

## Emergency changes

Routine work must not bypass these rules. The maintainer records any emergency
settings change with an incident, reason, compensating controls, rollback
condition and restoration of protection before handoff. Record who performed
security, release and recovery checks.
