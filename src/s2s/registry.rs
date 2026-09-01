use super::{BidiS2sSession, FederationEnvelope, OutboundS2sSession};
use dashmap::{mapref::entry::Entry, DashMap};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Result of atomically publishing a newly-created outbound connection.
/// A live incumbent always wins; a closed incumbent is replaced in-place.
pub(crate) enum OutboundRegistration {
    Inserted,
    Existing(mpsc::Sender<FederationEnvelope>),
}

/// Guard-free snapshot of one bidirectional route. No DashMap guard crosses
/// the registry boundary or survives queue admission.
pub(crate) struct BidiRouteSnapshot {
    pub(crate) local_domain: String,
    pub(crate) sender: mpsc::Sender<FederationEnvelope>,
}

/// Process-local ownership boundary for live S2S routes.
///
/// Outbound workers are fenced by their exact mpsc channel identity, while
/// XEP-0288 bidirectional streams are fenced by their server-generated
/// connection UUID. Callers receive cloned senders/snapshots only and can
/// never retain a shard lock or mutate the underlying maps directly.
#[derive(Default)]
pub(crate) struct S2sConnectionRegistry {
    outbound: DashMap<String, OutboundS2sSession>,
    bidirectional: DashMap<String, BidiS2sSession>,
}

impl S2sConnectionRegistry {
    pub(crate) fn live_outbound_sender(
        &self,
        key: &str,
    ) -> Option<mpsc::Sender<FederationEnvelope>> {
        self.outbound
            .get(key)
            .and_then(|session| (!session.sender.is_closed()).then(|| session.sender.clone()))
    }

    pub(crate) fn register_outbound(
        &self,
        key: String,
        session: OutboundS2sSession,
    ) -> OutboundRegistration {
        match self.outbound.entry(key) {
            Entry::Occupied(entry) if !entry.get().sender.is_closed() => {
                OutboundRegistration::Existing(entry.get().sender.clone())
            }
            Entry::Occupied(mut entry) => {
                entry.insert(session);
                OutboundRegistration::Inserted
            }
            Entry::Vacant(entry) => {
                entry.insert(session);
                OutboundRegistration::Inserted
            }
        }
    }

    pub(crate) fn remove_outbound_if_sender(
        &self,
        key: &str,
        owner: &mpsc::Sender<FederationEnvelope>,
    ) -> bool {
        self.outbound
            .remove_if(key, |_, session| session.sender.same_channel(owner))
            .is_some()
    }

    pub(crate) fn authenticated_outbound_sender(
        &self,
        key: &str,
    ) -> Option<mpsc::Sender<FederationEnvelope>> {
        self.outbound.get(key).and_then(|session| {
            (session.is_authenticated() && !session.sender.is_closed())
                .then(|| session.sender.clone())
        })
    }

    pub(crate) fn register_bidirectional_if_vacant(
        &self,
        key: String,
        session: BidiS2sSession,
    ) -> std::result::Result<(), BidiS2sSession> {
        match self.bidirectional.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(session);
                Ok(())
            }
            Entry::Occupied(_) => Err(session),
        }
    }

    pub(crate) fn bidirectional_route(&self, key: &str) -> Option<BidiRouteSnapshot> {
        self.bidirectional
            .get(key)
            .map(|session| BidiRouteSnapshot {
                local_domain: session.local_domain.clone(),
                sender: session.sender.clone(),
            })
    }

    pub(crate) fn remove_bidirectional_if_connection(
        &self,
        key: &str,
        connection_id: Uuid,
    ) -> bool {
        self.bidirectional
            .remove_if(key, |_, session| session.connection_id == connection_id)
            .is_some()
    }

    /// Island mode intentionally drains only client-initiated outbound
    /// workers, matching the previous behavior. Established inbound streams
    /// remain registered but routing policy rejects their federation traffic.
    pub(crate) fn clear_outbound_for_island_mode(&self) {
        self.outbound.clear();
    }

    pub(crate) fn outbound_count(&self) -> usize {
        self.outbound.len()
    }
}
