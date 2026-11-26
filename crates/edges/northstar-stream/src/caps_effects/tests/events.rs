use super::*;

impl CapsEventSource for RecordingCapsPorts {}

struct FixedCapsEvents {
    now: Instant,
    next_id: AtomicU64,
}

impl CapsEventSource for FixedCapsEvents {
    fn caps_now(&self) -> Instant {
        self.now
    }

    fn new_caps_protocol_id(&self) -> Uuid {
        Uuid::from_u128(u128::from(self.next_id.fetch_add(1, Ordering::Relaxed)))
    }
}

#[test]
fn caps_query_id_and_expiry_use_the_supplied_source() {
    let now = Instant::now() + Duration::from_secs(3_600);
    let events = FixedCapsEvents {
        now,
        next_id: AtomicU64::new(42),
    };
    let (first_id, first_expiry) = caps_query_correlation(&events);
    let (second_id, second_expiry) = caps_query_correlation(&events);
    assert_eq!(first_id, "caps-42");
    assert_eq!(second_id, "caps-43");
    assert_eq!(first_expiry, now + Duration::from_secs(30));
    assert_eq!(second_expiry, first_expiry);
}
