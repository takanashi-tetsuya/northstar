//! Instance-local synchronization for the federated MAM database tests.

use super::PostgresMamRepository;
use anyhow::{Context, Result};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;

pub use northstar_federation_postgres::{
    claim_due_s2s_outbox_for_domains, complete_s2s_outbox, expire_s2s_outbox,
};

const PAUSE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FederatedMamPausePoint {
    AfterRender,
    BeforeRetry,
}

pub struct FederatedMamPause {
    reached: oneshot::Receiver<()>,
    release: oneshot::Sender<()>,
}

impl FederatedMamPause {
    pub async fn wait(&mut self) {
        tokio::time::timeout(PAUSE_TIMEOUT, &mut self.reached)
            .await
            .expect("timed out waiting for federated MAM pause")
            .expect("federated MAM admission ended before reaching pause");
    }

    pub fn release(self) {
        self.release.send(()).expect("federated MAM pause ended");
    }
}

struct Pause {
    attempt: u8,
    point: FederatedMamPausePoint,
    reached: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

#[derive(Clone, Default)]
pub(super) struct AdmissionPauses(Arc<Mutex<Vec<Pause>>>);

impl AdmissionPauses {
    pub(super) async fn pause(&self, attempt: u8, point: FederatedMamPausePoint) -> Result<()> {
        let pause = {
            let mut pauses = self.0.lock().expect("federated MAM pause lock poisoned");
            pauses
                .iter()
                .position(|pause| pause.attempt == attempt && pause.point == point)
                .map(|index| pauses.remove(index))
        };
        if let Some(pause) = pause {
            pause
                .reached
                .send(())
                .ok()
                .context("federated MAM pause abandoned")?;
            tokio::time::timeout(PAUSE_TIMEOUT, pause.release)
                .await
                .context("federated MAM pause timed out")?
                .context("federated MAM pause release abandoned")?;
        }
        Ok(())
    }
}

impl PostgresMamRepository {
    pub fn pause_admission_at(
        &self,
        attempt: u8,
        point: FederatedMamPausePoint,
    ) -> FederatedMamPause {
        let (reached_tx, reached) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        self.admission_pauses
            .0
            .lock()
            .expect("federated MAM pause lock poisoned")
            .push(Pause {
                attempt,
                point,
                reached: reached_tx,
                release: release_rx,
            });
        FederatedMamPause { reached, release }
    }
}
