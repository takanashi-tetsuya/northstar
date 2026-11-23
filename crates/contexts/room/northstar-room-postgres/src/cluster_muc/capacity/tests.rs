use super::CapacityPlan;

#[test]
fn capacity_plan_orders_and_deduplicates_shards() {
    assert_eq!(CapacityPlan::new([63, 8, 0, 8, 63, 1]).0, [0, 1, 8, 63]);
    assert_eq!(CapacityPlan::all().0, (0..64).collect::<Vec<_>>());
}
