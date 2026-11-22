use super::federated_mam_should_retry;

#[test]
fn federated_mam_retries_only_first_serialization_failure() {
    assert!(federated_mam_should_retry(1, Some("40001")));
    assert!(!federated_mam_should_retry(2, Some("40001")));
    for state in [None, Some("40P01"), Some("55P03"), Some("23505")] {
        assert!(!federated_mam_should_retry(1, state), "{state:?}");
        assert!(!federated_mam_should_retry(2, state), "{state:?}");
    }
}
