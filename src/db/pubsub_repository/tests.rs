use super::*;
use northstar_pubsub_application::is_pubsub_mutation_busy;

#[test]
fn database_pressure_is_retryable_without_hiding_other_failures() {
    for error in [
        anyhow::Error::from(sqlx::Error::PoolTimedOut),
        anyhow::Error::from(db::pubsub::PubSubMutationBusy),
    ] {
        assert!(is_pubsub_mutation_busy(&map_database_busy(error)));
    }
    let closed = map_database_busy(sqlx::Error::PoolClosed.into());
    assert!(!is_pubsub_mutation_busy(&closed));
    assert!(closed.downcast_ref::<sqlx::Error>().is_some());
    let integrity = map_database_busy(anyhow::anyhow!("stored audience is corrupt"));
    assert!(!is_pubsub_mutation_busy(&integrity));
    assert_eq!(integrity.to_string(), "stored audience is corrupt");
}
