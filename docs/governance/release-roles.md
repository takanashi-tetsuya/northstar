# Release identity and trust roles

Northstar is maintained by `@takanashi-tetsuya`. These roles divide work and
evidence, not people by assumption. The maintainer currently performs every
role; neither self-review nor CI is an independent security audit.

## Responsibilities

| Responsibility | Required work | Authority boundary |
| --- | --- | --- |
| Platform maintainer | Review source/PR and CI evidence, choose the exact main release commit | Source and repository settings |
| Security reviewer and signer | Review auth, contracts, migrations, deployment, roles and telemetry; sign the annotated tag | A maintainer-controlled signing key, separate from application keys |
| Operations owner | Rehearse migration, backup/restore and rollback; approve the deployment window | Deployment/recovery credentials, separate from runtime identities |
| Emergency operator | Record incident/exception, recover service and restore protection | Explicit break-glass authority, never routine CI bypass |

No second human approval is required. The PR and release record must state the
maintainer's results for each responsibility, limitations and outstanding
external qualification. CODEOWNERS routes ownership; requiring its sole owner
to approve their own PR would not provide usable independent review.

## Release credentials

- Never persist PATs in repository files or long-lived CI variables.
- Use the scoped workflow `GITHUB_TOKEN` for GitHub/GHCR. Evidence jobs have
  only `contents: read` and `actions: read`; publication authority belongs only
  to jobs publishing images, attestations or draft assets.
- Prefer OIDC and keyless artifact attestations. Production application keys
  and database credentials must never be available to release jobs.
- Sign the annotated Git tag with a key registered to the maintainer's GitHub
  identity. Do not put that private key in a shared Actions runner. GitHub's
  tag API must report a valid verified signature before publication.

## Exact artifact evidence and release flow

1. Integrate on `dev`, then review and merge the candidate into `main`.
2. Wait for the latest `main` push/schedule **CI** run for the exact release SHA
   to succeed, including `CI required` in the current attempt. A successful
   `Release preparation` build is not CI evidence. An earlier successful run
   cannot override a newer failed, cancelled or running trusted run.
3. Run applicable release preflight and target-environment checks. Record the
   commit, configuration, results, exceptions and maintainer's ship decision.
4. Verify live protection from [branch-rules.md](branch-rules.md). Create a signed
   annotated `vMAJOR.MINOR.PATCH` tag directly at the reviewed main commit,
   matching the package version and release documents.
5. Push the immutable tag after the ship decision. Before artifact builds, the
   workflow verifies tag signature/identity, main ancestry, active branch rules
   and exact successful CI. Both binary packages must build before GHCR image
   publication; image jobs recheck current evidence before publication.
6. Retain image digests, SBOM/provenance, package checksums and tag run URL.
   Review the draft GitHub Release and perform fresh-download verification from
   `docs/RELEASE_CHECKLIST.md`. Publish the draft only after those checks.

The tag workflow publishes GHCR images before creating the draft GitHub
Release; the draft is not an approval boundary for those images. The gate uses
GitHub's [Git tag](https://docs.github.com/en/rest/git/tags) and
[workflow run](https://docs.github.com/en/rest/actions/workflow-runs) APIs.

## Failure and trust boundaries

Unavailable evidence, inactive protection, an unsigned/moved tag, missing or
failed CI and stale run attempts block publication. Correct the failure and
complete CI; do not disable gates or silently select older green evidence.
Do not reuse published tags or assets as corrected evidence.

The maintainer controls settings, workflow source and tags. This policy reduces
accidental release and authority mistakes; it does not claim separation of
personnel or protection against takeover of that entire identity. Independent
audit and target-environment evidence remain separate qualifications. Rollback
follows the documented data-safe procedure and recorded incident decision.
