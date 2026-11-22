use super::{
    FixedPubSubClock, PreparedEventContext, PubSubClock, PubSubIdSource, PubSubTimeSources,
    SequentialPubSubIds,
};
use northstar_time::DateTime;
use std::sync::Arc;
use uuid::Uuid;

#[test]
fn fixed_clock_returns_the_supplied_instant() {
    let at = DateTime::from_timestamp(1_700_000_000, 123).unwrap();
    let clock = FixedPubSubClock(at);
    assert_eq!(clock.now(), at);
    assert_eq!(clock.now(), at);
}

#[test]
fn sequential_ids_start_at_one_and_are_distinct() {
    let ids = SequentialPubSubIds::default();
    assert_eq!(
        [ids.new_uuid(), ids.new_uuid(), ids.new_uuid()],
        [Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3)],
    );
}

#[test]
fn prepare_event_uses_the_injected_instant_and_draws_one_id() {
    let at = DateTime::from_timestamp(1_700_000_000, 456).unwrap();
    let sources = PubSubTimeSources::new(
        Arc::new(FixedPubSubClock(at)),
        Arc::new(SequentialPubSubIds::default()),
    );
    assert_eq!(sources.now(), at);
    assert_eq!(sources.new_uuid(), Uuid::from_u128(1));
    assert_eq!(
        sources.prepare_event(),
        PreparedEventContext {
            at,
            id: Uuid::from_u128(2),
        },
    );
    assert_eq!(sources.new_uuid(), Uuid::from_u128(3));
}

#[test]
fn default_sources_supply_a_non_nil_id() {
    assert!(!PubSubTimeSources::default().new_uuid().is_nil());
}
