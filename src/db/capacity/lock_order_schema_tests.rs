#[test]
fn bulk_capacity_locks_have_one_global_order_and_bounded_retry() {
    let migration = include_str!("../../../migrations/0090_deployment_capacity_ledger.sql");
    for required in [
        "northstar_capacity_lock_batch",
        "ORDER BY a.resource_kind,a.shard,a.entity_id",
        "FOR UPDATE OF s,a",
        "WHEN deadlock_detected",
        "attempt>=3",
    ] {
        assert!(
            migration.contains(required),
            "missing capacity lock invariant {required}"
        );
    }
}
