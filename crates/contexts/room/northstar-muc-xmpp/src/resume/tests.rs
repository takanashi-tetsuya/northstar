use super::*;
use std::future::ready;

#[tokio::test]
async fn missing_or_stale_pg_authority_fails_closed_with_or_without_redis() {
    for redis_transport in [false, true] {
        let mode = MucResumeMode {
            postgres_authority: true,
            redis_transport,
        };
        assert!(mode.suspended_authority(ready(Ok(None))).await.is_err());
        assert!(mode
            .suspended_authority(ready(Err(anyhow::anyhow!("lookup failed"))))
            .await
            .is_err());
    }
    let no_pg = MucResumeMode {
        postgres_authority: false,
        redis_transport: false,
    };
    assert!(no_pg
        .suspended_authority(async { panic!("not a PG runtime") })
        .await
        .unwrap()
        .is_none());
}
