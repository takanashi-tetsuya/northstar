use super::OnlineSession;
use std::sync::{atomic::Ordering, Mutex};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct Watermark {
    epoch: u64,
    delivered: Option<i64>,
    wanted: i64,
    fence: CancellationToken,
}

pub struct BlocklistObservation {
    watermark: Mutex<Watermark>,
    wake: watch::Sender<()>,
}

impl Default for BlocklistObservation {
    fn default() -> Self {
        Self {
            watermark: Mutex::default(),
            wake: watch::channel(()).0,
        }
    }
}

impl BlocklistObservation {
    pub fn begin_snapshot(&self) -> u64 {
        let mut state = self.watermark.lock().unwrap();
        state.epoch += 1;
        state.delivered = None;
        state.wanted = 0;
        state.fence.cancel();
        state.fence = CancellationToken::new();
        self.wake.send_replace(());
        state.epoch
    }

    pub fn finish_snapshot(&self, epoch: u64, revision: i64) -> bool {
        let mut state = self.watermark.lock().unwrap();
        if state.epoch != epoch || state.delivered.is_some() {
            return false;
        }
        state.delivered = Some(revision);
        true
    }

    pub fn cursor(&self, epoch: u64) -> Option<i64> {
        let state = self.watermark.lock().unwrap();
        if state.epoch == epoch {
            state.delivered
        } else {
            None
        }
    }

    pub fn fail_snapshot(&self, epoch: u64, disconnect: impl FnOnce()) -> bool {
        let mut state = self.watermark.lock().unwrap();
        if state.epoch != epoch {
            return false;
        }
        state.delivered = None;
        state.fence.cancel();
        disconnect();
        true
    }

    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.wake.subscribe()
    }

    pub fn enqueue_next<E>(
        &self,
        epoch: u64,
        revision: i64,
        enqueue: impl FnOnce(&CancellationToken) -> Result<(), E>,
    ) -> Option<Result<(), E>> {
        let mut state = self.watermark.lock().unwrap();
        if state.epoch != epoch
            || state.delivered.and_then(|cursor| cursor.checked_add(1)) != Some(revision)
        {
            return None;
        }
        let result = enqueue(&state.fence);
        if result.is_ok() {
            state.delivered = Some(revision);
        }
        Some(result)
    }
}

impl OnlineSession {
    pub fn signal_blocklist_revision(&self, revision: i64) -> bool {
        if !self.blocklist_requested.load(Ordering::Acquire) {
            return false;
        }
        let observation = &self.blocklist_observation;
        let mut state = observation.watermark.lock().unwrap();
        if state.epoch == 0 {
            self.sender.disconnect_backpressured_transport();
            self.disconnect.cancel();
            return false;
        }
        if revision > state.delivered.unwrap_or_default().max(state.wanted) {
            state.wanted = revision;
            observation.wake.send_replace(());
        }
        true
    }
}
