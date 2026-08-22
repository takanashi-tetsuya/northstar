pub mod dns;
pub mod inbound;
pub mod outbound;
pub mod tls;
pub mod util;

pub(crate) use dns::*;
pub use inbound::*;
pub(crate) use outbound::*;
pub(crate) use tls::*;
pub(crate) use util::*;

use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct FederationEnvelope {
    pub target_domain: String,
    pub bounce_to: Option<String>,
    pub stanza: String,
}

pub struct FederationRouter {
    pub tx: mpsc::Sender<FederationEnvelope>,
}

impl FederationRouter {
    pub fn channel() -> (Self, mpsc::Receiver<FederationEnvelope>) {
        let (tx, rx) = mpsc::channel(10000);
        (Self { tx }, rx)
    }

    pub fn send(&self, target_domain: &str, stanza: String, bounce_to: Option<String>) {
        let _ = self.tx.try_send(FederationEnvelope {
            target_domain: target_domain.to_owned(),
            bounce_to,
            stanza,
        });
    }
}

pub const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
