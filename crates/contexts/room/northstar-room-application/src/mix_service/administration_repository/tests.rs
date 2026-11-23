use super::*;
use northstar_room_core::mix::FixedMixClock;

#[test]
fn fixed_clock_keeps_public_item_id_format() {
    let timestamp = DateTime::from_timestamp(0, 42).unwrap();
    let generations = Arc::new(Vec::new());
    let service = MixService::new(
        (),
        MixMessageContentKeyring::new(Arc::clone(&generations)),
        MixRetractionContentKeyring::new(generations),
        2,
        "public".to_owned(),
    )
    .unwrap()
    .with_item_clock(FixedMixClock(timestamp));
    for _ in 0..2 {
        assert_eq!(
            mix_timestamp_item_id(service.prepare_item_timestamp()),
            "1970-01-01T00:00:00.000000042Z"
        );
    }
}
