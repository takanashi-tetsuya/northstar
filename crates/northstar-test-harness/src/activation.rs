use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result};
use tokio::sync::oneshot;

/// A one-shot readiness handoff for listener activation.
#[derive(Debug)]
pub struct Activation {
    service: String,
    tx: oneshot::Sender<SocketAddr>,
}

impl Activation {
    /// Send the local address once the listener is ready.
    pub fn announce(self, address: SocketAddr) -> Result<()> {
        self.tx
            .send(address)
            .map_err(|_| anyhow::anyhow!("{} readiness receiver was dropped", self.service))
    }

    pub fn service(&self) -> &str {
        &self.service
    }
}

/// Receive a listener handoff from the producer side.
#[derive(Debug)]
pub struct Readiness {
    service: String,
    rx: oneshot::Receiver<SocketAddr>,
}

impl Readiness {
    /// Await the activated listener address within an explicit deadline.
    pub async fn wait_for(self, deadline: Duration) -> Result<SocketAddr> {
        tokio::time::timeout(deadline, self.rx)
            .await
            .with_context(|| format!("timed out waiting for {} readiness", self.service))?
            .with_context(|| format!("{} exited before announcing readiness", self.service))
    }

    pub fn service(&self) -> &str {
        &self.service
    }
}

/// Create a pair of readiness sender/receiver entries.
pub fn channel(service: impl Into<String>) -> (Activation, Readiness) {
    let (tx, rx) = oneshot::channel();
    let service = service.into();
    (
        Activation {
            service: service.clone(),
            tx,
        },
        Readiness { service, rx },
    )
}
