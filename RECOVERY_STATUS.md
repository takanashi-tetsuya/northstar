# Historical source recovery — 2026-10-03

This branch preserves a historical Northstar source snapshot from `northstar-system-clarity-2026-10-02.zip`. It is a recovery baseline, **not** the later Stage 4 / Stage 5 architecture implementation. Those later source changes were not present in the recovered archive and are not claimed here.

## Provenance and file integrity

- Source archive SHA-256: `d4480aff74c57901ba303009307e5c9d29cbfc05a39e002323420e4d04b9ec1d`
- Embedded `northstar-source.tar.gz` SHA-256: `05c660a2d6e852a306674037e01e67e12e6d674f0e24cb84d898a7e3a9b9e733`
- Historical baseline commit: `3dfc005657ab0e6f9b09d943a4d2bb4c83972fd2`
- Recovered historical source paths: **1,618**
- Original archive file hashes: [`recovery/source-manifest.json`](recovery/source-manifest.json)
- Published source file hashes: [`recovery/published-source-sha256.json`](recovery/published-source-sha256.json)

**Documentation-only adjustment:** two historical completion/results reports are replaced with explicit unverified-history notices. Their original hashes and published hashes are recorded in [`recovery/documentation-adjustments.json`](recovery/documentation-adjustments.json). Accordingly, this publication does not claim that all 1,618 files are byte-identical to the archive. The remaining 1,616 source files, including runtime code, original README, licenses and workflows, remain byte-identical. Original manifest assertions about previous patch application and acceptance are not republished; the manifests here are file-hash inventories only.

The outer archive's runtime logs, protocol traces, database state and execution evidence are not included. Static credential-pattern and path inspection found no production credentials or usable private keys in the recovered source; example values, synthetic test fixtures and security-detection strings remain part of the source. Static inspection cannot guarantee identification of every possible secret.

## Validation and CI

No application code, build, stress test or fault experiment was executed during source recovery. Earlier plans, historical notes and hash inventories are not evidence of a fresh test pass. Consult the GitHub checks on the actual recovery commit for current CI results.

The preserved CI workflow accepts branch pushes. The preserved release-preparation workflow accepts only `main`, `codex/release-*`, `v*` tags and explicit manual dispatch. This `recovery/*` branch matches none of those release-push filters. This backup creates no tag, pull request, merge or deployment.

## Future checkpoints

Save subsequent work with a descriptive commit and push it to this recovery branch or a separately agreed branch. Verify the remote commit before treating a checkpoint as backed up. Exclude credentials, personal configuration, runtime logs/traces and database snapshots. A local-only commit is not a remote backup.
