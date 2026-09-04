# Backup, restore, and deletion propagation

Backups are a recovery input, not proof that a restore is safe. The canonical
logical-database order, dependencies, encryption, PITR/WAL, retention, and
post-restore fence checks live in `catalog/restore-order.yaml` and are checked
by `restore-verifier`.

## Required backup properties

Each stateful database has encrypted base backups, continuous WAL/PITR, a
declared retention window, and an isolated restore target. Keys are held by
the deployment KMS boundary; a database dump never contains the key-encryption
key. Backup identities are read-only and cannot disable triggers or mutate
legal-hold, audit, outbox, or deletion-ledger records.

## Restore sequence

1. Restore the identity authority and verify credential generation.
2. Restore the session/route authorities and verify `region_epoch`, lease CAS,
   and route incarnation fences.
3. Restore ingress, delivery, federation, and XEP databases in catalog order.
4. Reconcile outbox/inbox cursors before enabling consumers; replay is
   at-least-once and visible effects must remain idempotent.
5. Reapply deletion/crypto-shredding ledger entries before exposing any
   recovered data. A restored tombstone is authoritative over an older copy.
6. Run row-count, checksum, fence, and retention checks in an isolated target,
   then promote only after an operator-approved evidence bundle exists.

The restore verifier rejects missing encryption, WAL, deletion-ledger or fence
metadata, duplicate phases, unknown dependencies, and dependency inversions.
Automated restore drills still need to run against the real PostgreSQL/backup
provider; a green catalog check is not an RPO/RTO guarantee.
