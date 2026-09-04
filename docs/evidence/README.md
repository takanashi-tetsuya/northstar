# Evidence registry

This directory contains immutable, commit-bound records for claims about the
distributed-architecture program. An evidence record identifies the exact
commit, the CI run used for evaluation, the observed job results, known
limitations, and the maturity that may be claimed at that point.

## Layout

- `baselines/` contains frozen checkpoints. A baseline is an observation, not a
  release approval.
- `milestones/` is reserved for accepted task records. A milestone record must
  identify its exact result commit and CI run.

## Maturity rules

`catalog/services.yaml` is the sole inventory source. A service may not be
described as `integrated` or `production` merely because code or a directory
exists. Such a promotion needs immutable, commit-bound evidence for the
required dependencies and verification level.

The Program 5 baseline does not contain a maturity-evidence schema or a
validator that enforces that rule. That enforcement is deliberately deferred to
M01-07; this document does not claim otherwise.

## Current frozen record

- [Program 5 baseline (`aa2b0df`)](baselines/aa2b0df.yaml) records the exact
  GitHub Actions result observed for the recovery program. It establishes the
  modular monolith as the behavior reference and records that distributed
  services are not integrated or production-ready.
