# M05-04 database invariant framework evidence

Status: **test primitives implemented; live database matrix pending**.

`foundation-db-test` now provides shared checks for unique authority keys,
monotonic sequences, lease epoch compare-and-swap, service-local foreign keys,
SQLSTATE retry safety, and bounded query-plan baselines. The integration
fixture contract is documented under `tests/database-invariants/`.

The helpers intentionally do not replace PostgreSQL constraints or transaction
tests. They make the expected invariants executable in both unit models and
isolated PostgreSQL/CI jobs. The 100–1000 concurrent bind/ingress/claim matrix,
fault injection, and EXPLAIN artifact retention remain pending until the
database-per-service fixtures are available.
