use super::*;
use northstar_room_core::{FixedMucClock, SequentialMucIds};
use std::sync::Arc;

#[test]
fn sequential_source_fixes_join_incarnation_and_operation_ids() {
    let sources = MucTimeSources::new(
        Arc::new(FixedMucClock(northstar_time::DateTime::UNIX_EPOCH)),
        Arc::new(SequentialMucIds::default()),
    );
    for (incarnation, operation) in [(1, 2), (3, 4)] {
        assert_eq!(
            prepare_join_ids(sources.prepare_request(), &sources),
            (Uuid::from_u128(incarnation), Uuid::from_u128(operation)),
        );
    }
}
