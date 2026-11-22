use super::*;

#[test]
fn apply_to_changes_only_submitted_fields() {
    let deadline = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
    let base = PubSubSubscriptionOptions {
        digest: true,
        digest_frequency: 60_000,
        expire: Some(deadline),
        show_values: vec!["chat".to_owned()],
        ..PubSubSubscriptionOptions::for_node_type("collection")
    };
    let patch = SubscriptionOptionsPatch {
        deliver: Some(false),
        subscription_depth: Some(None),
        expire: Some(SubscriptionLeasePatch::Clear),
        ..SubscriptionOptionsPatch::default()
    };
    assert!(!patch.is_empty());
    assert_eq!(
        patch.apply_to(&base),
        PubSubSubscriptionOptions {
            deliver: false,
            subscription_depth: None,
            expire: None,
            ..base
        }
    );
}

#[test]
fn empty_patch_is_identity() {
    let patch = SubscriptionOptionsPatch::default();
    let base = PubSubSubscriptionOptions::for_node_type("leaf");
    assert!(patch.is_empty());
    assert_eq!(patch.apply_to(&base), base);
}
