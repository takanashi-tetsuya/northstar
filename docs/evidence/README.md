# Evidence directory (M00 baseline registry)

This directory stores evidence baselines that freeze architectural and operational
claims at a committed checkpoint.

## Layout

- `baselines/` — point-in-time snapshots that bind commit, workflow context and
  major evidence outcomes.
- `milestones/` — repository checkpoints that enumerate delivered structural
  work and its reproducible verification commands.
- Historical reports that are not baseline snapshots live under `docs/archive/`.

## Baseline file contract

Each baseline file should include:

- fixed `commit` and `commit_short`
- `workflow_run` identifier
- baseline title and date
- catalog-derived inventory summary (services / routes / table ownership)
- required governance assumptions
- known defects and risk level
- maturation gate map (`production = 0`, `integrated = 0` at this stage)

## Current baselines

- [`aa2b0df.yaml`](baselines/aa2b0df.yaml) — program-5 frozen checkpoint used
  for this cycle's governance and catalog normalization.

## Maturity templates

Use the templates in `templates/` when a service changes maturity. The status
must match `catalog/services.yaml`; an integrated, production-candidate, or
production claim also requires a verified commit and immutable evidence
artifacts. The Rust `catalog-validator` rejects missing or contradictory
metadata, so a YAML-only status change cannot promote a service.

## Validation rule

Any documentation or code path that claims a status outside the baseline must be
backed by a new baseline file and migration of linked references.
