use super::{mix_presence_epoch_is_current, mix_presence_fallback_is_suppressed};
use uuid::Uuid;

#[test]
fn verified_mix_presence_requires_the_exact_live_resource_epoch() {
    let expected = Uuid::new_v4();
    assert!(mix_presence_epoch_is_current(
        expected, expected, 7, 7, true, true, true
    ));
    assert!(!mix_presence_epoch_is_current(
        Uuid::new_v4(),
        expected,
        7,
        7,
        true,
        true,
        true
    ));
    assert!(!mix_presence_epoch_is_current(
        expected, expected, 8, 7, true, true, true
    ));
    assert!(!mix_presence_epoch_is_current(
        expected, expected, 7, 7, false, true, true
    ));
    assert!(!mix_presence_epoch_is_current(
        expected, expected, 7, 7, true, false, true
    ));
    assert!(!mix_presence_epoch_is_current(
        expected, expected, 7, 7, true, true, false
    ));
}

#[test]
fn directed_mix_unavailable_suppresses_only_its_channel() {
    let suppressed = dashmap::DashSet::new();
    suppressed.insert("one@mix.example.test".to_owned());
    assert!(mix_presence_fallback_is_suppressed(
        &suppressed,
        "one@mix.example.test"
    ));
    assert!(!mix_presence_fallback_is_suppressed(
        &suppressed,
        "two@mix.example.test"
    ));
    suppressed.insert("*".to_owned());
    assert!(mix_presence_fallback_is_suppressed(
        &suppressed,
        "two@mix.example.test"
    ));
}
