use super::{admit_offline_then_push, OfflineAdmissionOutcome};
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn failed_offline_commit_never_polls_push_provider() {
    let calls = AtomicUsize::new(0);
    let result = admit_offline_then_push(
        async { anyhow::bail!("offline transaction failed") },
        true,
        async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    )
    .await;
    assert!(result.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn replay_and_unaccepted_offline_outcomes_never_notify_again() {
    let calls = AtomicUsize::new(0);
    for (admission, history_committed) in [
        (OfflineAdmissionOutcome::Replay, true),
        (OfflineAdmissionOutcome::QuotaExceeded, false),
        (OfflineAdmissionOutcome::RecipientUnavailable, true),
    ] {
        let result = admit_offline_then_push(async { Ok(admission) }, history_committed, async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(result.admission, admission);
        assert!(result.push_error.is_none());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn committed_offline_or_mam_recovery_attempts_push_once() {
    let calls = AtomicUsize::new(0);
    for admission in [
        OfflineAdmissionOutcome::Stored,
        OfflineAdmissionOutcome::QuotaExceeded,
    ] {
        let result = admit_offline_then_push(async { Ok(admission) }, true, async {
            calls.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("provider failed")
        })
        .await
        .unwrap();
        assert_eq!(result.admission, admission);
        assert!(result.push_error.is_some());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
