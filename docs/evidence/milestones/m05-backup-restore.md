# M05-05 backup and restore model evidence

Status: **policy and verifier implemented; provider restore drill pending**.

`catalog/restore-order.yaml` declares all 25 stateful logical databases with
encrypted base backup, PITR/WAL, retention, dependency order, deletion-ledger,
and post-restore fencing requirements. `tools/restore-verifier` validates this
catalog deterministically and fails closed on missing controls or dependency
inversions. Operational procedures are in `docs/database/backup-restore.md`.

The remaining acceptance evidence is an isolated provider-backed restore drill
that replays events, reapplies crypto-shredding/deletion records, and measures
actual RPO/RTO. No documentation-only result is being promoted to production
evidence.
