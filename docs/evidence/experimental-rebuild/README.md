# Experimental rebuild evidence

Each stage is tied to the current recovery branch. Historical October 2
acceptances do not qualify rebuilt code. The authoritative exit matrix is
[the rebuild ledger](../../architecture/experimental-rebuild-plan.zh-TW.md).

Stage 0 records freeze the recovered Git baseline and the newly reviewed
responsibility audit. The MUC triage preserves an unresolved CI assertion; the
separate matcher correction and successful later CI do not establish the
missing old peer frame or its cause.

`stage1-verification.json` indexes `stage1-model-evidence-v1.tar.gz` and every
member's bytes and SHA256. The archive contains:

- `final/`: the corrected current model/fixture run, concrete inputs, supplied
  projections, expected outcomes, saved replay, manual counterexample and
  external source-before/after envelope
- `historical/1502`, `historical/1504`, `historical/1518`: unchanged earlier
  attempts, including records made before evidence-reader and fixture fixes
- `recording/`: the exact outer recording command used for the final envelope;
  its workspace paths are historical, not a portable runner interface

The source digest scopes ten listed files. The envelope records actual HEAD,
declared reconstruction anchor and all command results separately. It does not
claim a full-tree or binary qualification. The old attempt source snapshots
are not included, so those attempts are retained records rather than newly
replayable historical executables. The current source and fixed corpus are
replayable together through the public helper CLI described in
[Runtime experiments](../../architecture/runtime-experiments.md).

`stage1-review-findings.json` preserves the discovered evidence-validator and
fixture-integration defects. The 4,097 late-finalization scenario preserves
existing source predicates under stated cleanup assumptions; no live caller
reachability or product bug is asserted.

Pure Stage 1 tests start no server, socket, child process or database. The
saved six-command to two-command counterexample is a manual synthetic oracle
probe. Production-shared transitions, concrete effect replay/minimization and
real adapter qualification remain later exits. The cancelled 72-hour soak is
not part of this evidence.
