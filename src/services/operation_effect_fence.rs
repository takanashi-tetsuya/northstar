//! Commit the exact operation/target point-of-no-return fence before running
//! a possibly irreversible administrator effect.

use anyhow::Result;
use std::future::Future;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectFenceDecision {
    Authorized,
    Denied,
}

pub(crate) enum FencedEffect<T> {
    Denied,
    Executed(T),
}

pub(crate) trait OperationEffectFenceRepository: Send + Sync {
    type Parent;
    type Target;

    fn commit_fence(
        &self,
        parent: &Self::Parent,
        target: &Self::Target,
    ) -> impl Future<Output = Result<EffectFenceDecision>> + Send;
}

#[derive(Clone)]
pub(crate) struct OperationEffectFenceService<R> {
    repository: R,
}

impl<R: OperationEffectFenceRepository> OperationEffectFenceService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    /// The repository has completed its transaction before the effect factory
    /// is called. A denied fence never constructs or runs the effect future.
    pub(crate) async fn execute_after_commit<T, F, Fut>(
        &self,
        parent: &R::Parent,
        target: &R::Target,
        effect: F,
    ) -> Result<FencedEffect<T>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        match self.repository.commit_fence(parent, target).await? {
            EffectFenceDecision::Denied => Ok(FencedEffect::Denied),
            EffectFenceDecision::Authorized => Ok(FencedEffect::Executed(effect().await?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct RecordingRepository {
        events: Arc<Mutex<Vec<&'static str>>>,
        decision: EffectFenceDecision,
    }

    impl OperationEffectFenceRepository for RecordingRepository {
        type Parent = ();
        type Target = ();

        async fn commit_fence(
            &self,
            _: &Self::Parent,
            _: &Self::Target,
        ) -> Result<EffectFenceDecision> {
            self.events.lock().unwrap().push("commit");
            Ok(self.decision)
        }
    }

    #[tokio::test]
    async fn effect_runs_only_after_authorized_fence_commit() {
        for (decision, expected) in [
            (EffectFenceDecision::Authorized, vec!["commit", "effect"]),
            (EffectFenceDecision::Denied, vec!["commit"]),
        ] {
            let events = Arc::new(Mutex::new(Vec::new()));
            let service = OperationEffectFenceService::new(RecordingRepository {
                events: Arc::clone(&events),
                decision,
            });
            let effect_events = Arc::clone(&events);
            let outcome = service
                .execute_after_commit(&(), &(), move || async move {
                    effect_events.lock().unwrap().push("effect");
                    Ok(())
                })
                .await
                .unwrap();
            assert_eq!(*events.lock().unwrap(), expected);
            assert_eq!(
                matches!(outcome, FencedEffect::Executed(())),
                decision == EffectFenceDecision::Authorized
            );
        }
    }
}
