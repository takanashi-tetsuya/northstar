use super::*;

#[test]
fn fixed_clock_and_sequential_ids_are_deterministic() {
    let at = DateTime::from_timestamp(1_700_000_000, 123).unwrap();
    let clock = FixedMucClock(at);
    let ids = SequentialMucIds::default();
    assert_eq!([clock.now(), clock.now()], [at, at]);
    assert_eq!(
        [ids.new_uuid(), ids.new_uuid(), ids.new_uuid()],
        [Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3)],
    );
}

#[test]
fn request_facts_read_each_source_once() {
    struct CountingClock {
        at: DateTime<Utc>,
        reads: AtomicU64,
    }

    impl MucClock for CountingClock {
        fn now(&self) -> DateTime<Utc> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.at
        }
    }

    let at = DateTime::from_timestamp(1_700_000_000, 456).unwrap();
    let clock = CountingClock {
        at,
        reads: AtomicU64::new(0),
    };
    let ids = SequentialMucIds::default();
    assert_eq!(
        MucRequestFacts::prepare(&clock, &ids),
        MucRequestFacts {
            at,
            id: Uuid::from_u128(1),
        },
    );
    assert_eq!(clock.reads.load(Ordering::Relaxed), 1);
    assert_eq!(ids.new_uuid(), Uuid::from_u128(2));
}
