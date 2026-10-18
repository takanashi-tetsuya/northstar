#[test]
fn renewal_is_bounded_by_immutable_ack_age() {
    let migration = include_str!("../../../migrations/0096_bosh_ack_ownership_bounds.sql");
    let source = super::module_source();
    for required in [
        "first_owned_at TIMESTAMPTZ NOT NULL",
        "expires_at<=first_owned_at+INTERVAL '5 minutes'",
        "first_owned_at>clock_timestamp()-INTERVAL '5 minutes'",
        "response_count <= 2",
        "leases.len() <= 512",
    ] {
        assert!(
            migration.contains(required) || source.contains(required),
            "missing BOSH ACK ownership bound {required}"
        );
    }
}
