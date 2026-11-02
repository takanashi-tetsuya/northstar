use std::{sync::Arc, time::Duration};

use dashmap::DashMap;
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore},
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::util::S2sInputState;
use northstar_federation_core::AdvertisedStreamLimits;
use northstar_security::tls::CertificateSessionGuard;

pub const WINDOW: Duration = Duration::from_secs(60);
const MAX_SESSIONS: usize = 128;
const REPLAY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct Scope {
    pub local: String,
    pub remote: String,
    pub external: bool,
    pub bidi: bool,
}

pub struct Transport {
    pub stream: tokio_rustls::server::TlsStream<TcpStream>,
    pub input: S2sInputState,
    pub limits: AdvertisedStreamLimits,
    pub disconnect: CancellationToken,
    pub _certificate: Option<CertificateSessionGuard>,
}

pub struct Request {
    pub transport: Transport,
    pub h: u32,
    pub epoch: Uuid,
    // Rejection returns the new transport so normal negotiation can continue.
    pub result: oneshot::Sender<Result<(), Box<Transport>>>,
}

#[derive(Clone)]
struct Entry {
    scope: Scope,
    epoch: Uuid,
    sender: mpsc::Sender<Request>,
    expires_at: Option<Instant>,
}

pub struct Registry {
    entries: Arc<DashMap<String, Entry>>,
    slots: Arc<Semaphore>,
    pub replay_bytes: Arc<Semaphore>,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            slots: Arc::new(Semaphore::new(MAX_SESSIONS)),
            replay_bytes: Arc::new(Semaphore::new(REPLAY_BYTES)),
        }
    }
}

pub struct Registration {
    pub id: String,
    pub epoch: Uuid,
    expires_at: Option<Instant>,
    entries: Arc<DashMap<String, Entry>>,
    _slot: OwnedSemaphorePermit,
}

impl Registration {
    pub fn suspend(&mut self, deadline: Instant) {
        self.expires_at = Some(deadline);
        if let Some(mut entry) = self.entries.get_mut(&self.id) {
            entry.expires_at = Some(deadline);
        }
    }

    pub fn expired(&self) -> bool {
        self.expires_at
            .is_some_and(|deadline| deadline <= Instant::now())
    }

    pub fn advance(&mut self) {
        self.epoch = Uuid::new_v4();
        self.expires_at = None;
        if let Some(mut entry) = self.entries.get_mut(&self.id) {
            entry.epoch = self.epoch;
            entry.expires_at = None;
        }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.entries.remove(&self.id);
    }
}

impl Registry {
    pub fn has_suspended_scope(&self, scope: &Scope) -> bool {
        let now = Instant::now();
        self.entries.iter().any(|entry| {
            entry.scope == *scope
                && entry.expires_at.is_some_and(|deadline| deadline > now)
                && !entry.sender.is_closed()
        })
    }

    pub fn register(&self, scope: Scope, sender: mpsc::Sender<Request>) -> Option<Registration> {
        let slot = self.slots.clone().try_acquire_owned().ok()?;
        let id = Uuid::new_v4().to_string();
        let epoch = Uuid::new_v4();
        self.entries.insert(
            id.clone(),
            Entry {
                scope,
                epoch,
                sender,
                expires_at: None,
            },
        );
        Some(Registration {
            id,
            epoch,
            expires_at: None,
            entries: self.entries.clone(),
            _slot: slot,
        })
    }

    pub fn lookup(&self, id: &str, scope: &Scope) -> Option<(Uuid, mpsc::Sender<Request>)> {
        let entry = self.entries.get(id)?;
        (entry.scope == *scope
            && !entry.sender.is_closed()
            && entry
                .expires_at
                .is_none_or(|deadline| deadline > Instant::now()))
        .then(|| (entry.epoch, entry.sender.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrations_bind_identity_authentication_and_connection_generation() {
        let registry = Registry::default();
        let scope = Scope {
            local: "local.example".into(),
            remote: "remote.example".into(),
            external: true,
            bidi: true,
        };
        let (sender, _receiver) = mpsc::channel(1);
        let mut registration = registry.register(scope.clone(), sender).unwrap();
        let id = registration.id.clone();
        let (old, _) = registry.lookup(&id, &scope).unwrap();
        assert!(!registry.has_suspended_scope(&scope));
        for foreign in [
            Scope {
                local: "conference.local.example".into(),
                ..scope.clone()
            },
            Scope {
                remote: "evil.example".into(),
                ..scope.clone()
            },
            Scope {
                external: false,
                ..scope.clone()
            },
            Scope {
                bidi: false,
                ..scope.clone()
            },
        ] {
            assert!(registry.lookup(&id, &foreign).is_none());
        }
        registration.advance();
        assert_ne!(old, registry.lookup(&id, &scope).unwrap().0);
        registration.suspend(Instant::now() + Duration::from_secs(30));
        assert!(registry.has_suspended_scope(&scope));
        assert!(!registry.has_suspended_scope(&Scope {
            local: "conference.local.example".into(),
            ..scope.clone()
        }));
        // Expiry must not depend on the owning actor getting CPU time to clean up.
        registration.suspend(Instant::now());
        assert!(registration.expired());
        assert!(!registry.has_suspended_scope(&scope));
        assert!(registry.lookup(&id, &scope).is_none());
        registration.advance();
        assert!(!registration.expired());
        assert!(registry.lookup(&id, &scope).is_some());
        drop(registration);
        assert!(registry.lookup(&id, &scope).is_none());
        assert_eq!(registry.slots.available_permits(), MAX_SESSIONS);
    }
}
