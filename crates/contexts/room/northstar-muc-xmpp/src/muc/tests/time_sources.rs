use northstar_room_core::{FixedMucClock, MucTimeSources, SequentialMucIds};
use std::sync::Arc;

pub(super) fn test_sources() -> MucTimeSources {
    MucTimeSources::new(
        Arc::new(FixedMucClock(northstar_time::DateTime::UNIX_EPOCH)),
        Arc::new(SequentialMucIds::default()),
    )
}
