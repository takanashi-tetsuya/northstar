use super::*;
use northstar_room_core::{FixedMucClock, MucTimeSources, SequentialMucIds};
use std::sync::Arc;

#[test]
fn first_join_and_same_nick_rejoin_use_the_prepared_history_instant() {
    let at = northstar_time::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let facts = MucTimeSources::new(
        Arc::new(FixedMucClock(at)),
        Arc::new(SequentialMucIds::default()),
    )
    .prepare_request();
    let document = roxmltree::Document::parse(
        "<presence><x xmlns='http://jabber.org/protocol/muc'><history seconds='60'/></x></presence>",
    )
    .unwrap();
    let root = document.root_element();
    let initial = parse_muc_history_request(root, facts.at).unwrap();
    let explicit_rejoin = preflight_rejoin_history(root, true, || facts.at)
        .unwrap()
        .unwrap();
    let cutoff = northstar_time::DateTime::from_timestamp(1_699_999_940, 0).unwrap();
    assert_eq!(initial.since, Some(cutoff));
    assert_eq!(explicit_rejoin.since, Some(cutoff));
}
