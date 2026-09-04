use std::net::SocketAddr;
use tokio::sync::oneshot;

/// A one-shot readiness handoff for listener activation.
#[derive(Debug)]
pub struct Activation {
    service: String,
    tx: oneshot::Sender<SocketAddr>,
}

impl Activation {
    /// Send the local address once the listener is ready.
    pub fn announce(self, address: SocketAddr) {
        let _ = self.tx.send(address);
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
    /// Await the activated listener address.
    pub async fn wait(self) -> Option<SocketAddr> {
        self.rx.await.ok()
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
