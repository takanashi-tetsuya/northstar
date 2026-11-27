use super::*;
use std::cell::Cell;

#[tokio::test]
async fn selector_publication_and_compensation_follow_the_commit() {
    let step = Cell::new(0);
    let (allow_commit, commit_gate) = tokio::sync::oneshot::channel();
    let activation = publish_after_commit(
        async {
            commit_gate.await.unwrap();
            step.set(1);
            Ok(PrivacySelectionOutcome::Updated)
        },
        || {
            assert_eq!(step.get(), 1);
            step.set(2);
            false
        },
        || async {
            assert_eq!(step.get(), 2);
            step.set(3);
            Ok(())
        },
    );
    let observer = async {
        assert_eq!(step.get(), 0);
        allow_commit.send(()).unwrap();
    };
    let (result, ()) = tokio::join!(activation, observer);
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("lost its exact live route"));
    assert_eq!(step.get(), 3);
}

#[tokio::test]
async fn rejected_or_failed_commit_never_updates_the_live_selector() {
    for outcome in [
        Ok(PrivacySelectionOutcome::Missing),
        Ok(PrivacySelectionOutcome::Conflict),
        Err(anyhow::anyhow!("commit failed")),
    ] {
        let expected = outcome.as_ref().ok().copied();
        let actual = publish_after_commit(
            async { outcome },
            || panic!("publication without a successful commit"),
            || async { panic!("compensation without a successful commit") },
        )
        .await;
        assert_eq!(actual.ok(), expected);
    }
}
