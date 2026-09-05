# Dev integration boundary

`dev` is the sole integration branch for Program 6 recovery work. A commit
being reachable from `dev` is not task acceptance and does not change a
service's maturity.

M00-08 records the merge at `e02503b5d4a5491bb57002f4a5261552f4ec6772` and
classifies every path introduced by checkpoint
`94cb2622934d1329905b982e26377176f18a44bb`. The executable inventory is
derived from the exact `aa2b0df..94cb262` range and checked by
`scripts/check-program6-convergence.mjs`.

Until M00-G1 ratifies the recovery sequence, an asset is only one of:

- `accepted-by-M00-task` — accepted for its named M00 scope only;
- `dormant-unaccepted` — present in the tree but guarded from default
  distributed production authority;
- `historical-evidence` — retained as an auditable record, not an activation;
- `revert-required` — prohibited in the converged baseline.

The catalog remains at zero integrated and zero production services. A future
task must introduce commit-bound evidence before changing that fact.
