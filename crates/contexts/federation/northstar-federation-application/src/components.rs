//! Component domains, their owners and their metric cells.

use crate::outbox::ComponentRoute;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use dashmap::{mapref::entry::Entry, DashMap};
use northstar_config::ComponentCredential;
use northstar_telemetry::metrics::{DurationHistogram, DurationTimer};
use northstar_xml_builder::XmlElement;
use roxmltree::{Document, Node};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;
use uuid::Uuid;
use zeroize::Zeroize;

mod wire;

pub use self::wire::*;

pub const COMPONENT_ACCEPT_NS: &str = "jabber:component:accept";

pub const COMPONENT_CONNECT_NS: &str = "jabber:component:connect";

pub const COMPONENT_BIND_NS: &str = "urn:xmpp:component:0";

pub const SASL_NS: &str = "urn:ietf:params:xml:ns:xmpp-sasl";

pub const STREAMS_NS: &str = "http://etherx.jabber.org/streams";

/// The five metric cells needed by component transport tasks.
pub struct ComponentTelemetry<'a> {
    connections_active: &'a AtomicU64,
    delivery_duration: &'a DurationHistogram,
    failures: &'a AtomicU64,
    deliveries: &'a AtomicU64,
    outbox_lease_lost: &'a AtomicU64,
}

impl<'a> ComponentTelemetry<'a> {
    pub fn new(
        connections_active: &'a AtomicU64,
        delivery_duration: &'a DurationHistogram,
        failures: &'a AtomicU64,
        deliveries: &'a AtomicU64,
        outbox_lease_lost: &'a AtomicU64,
    ) -> Self {
        Self {
            connections_active,
            delivery_duration,
            failures,
            deliveries,
            outbox_lease_lost,
        }
    }

    pub fn active_connection(&self) -> ActiveComponentConnection<'a> {
        ActiveComponentConnection::new(self.connections_active)
    }

    pub fn outbox_delivery_timer(&self) -> DurationTimer<'a> {
        self.delivery_duration.start_timer()
    }

    pub fn connection_failed(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn outbox_written(&self) {
        self.deliveries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn outbox_lease_lost(&self) {
        self.outbox_lease_lost.fetch_add(1, Ordering::Relaxed);
    }
}

pub struct ActiveComponentConnection<'a>(&'a AtomicU64);

impl<'a> ActiveComponentConnection<'a> {
    pub fn new(counter: &'a AtomicU64) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}

impl Drop for ActiveComponentConnection<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub fn same_component_domain(left: &str, right: &str) -> bool {
    matches!(
        (
            northstar_xmpp_types::jid::prepare_domainpart(left),
            northstar_xmpp_types::jid::prepare_domainpart(right)
        ),
        (Ok(left), Ok(right)) if left == right
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentProtocol {
    Legacy0114Accept,
    Legacy0114Connect,
    Modern0225,
}

impl ComponentProtocol {
    pub fn relay_grant(self) -> ComponentRelayGrant {
        match self {
            Self::Legacy0114Connect => ComponentRelayGrant::LocalOnly,
            Self::Legacy0114Accept | Self::Modern0225 => ComponentRelayGrant::FederationRelay,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentRelayGrant {
    LocalOnly,
    FederationRelay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentRouteTarget {
    LocalService,
    ConfiguredComponent,
    Federation,
    Denied,
}

pub fn component_route_target(
    local_domain: &str,
    target: &str,
    configured_component: bool,
    relay_grant: ComponentRelayGrant,
) -> ComponentRouteTarget {
    if northstar_federation_core::classify_hosted_domain(local_domain, target).is_some() {
        ComponentRouteTarget::LocalService
    } else if configured_component {
        ComponentRouteTarget::ConfiguredComponent
    } else if relay_grant == ComponentRelayGrant::FederationRelay {
        ComponentRouteTarget::Federation
    } else {
        ComponentRouteTarget::Denied
    }
}

#[derive(Clone)]
pub struct ComponentSession {
    connection_id: Uuid,
    /// Edge-triggered wake-up only. PostgreSQL is the source of truth for
    /// server-to-component delivery; the bounded channel never owns a stanza.
    sender: mpsc::Sender<()>,
}

/// Concurrent ownership index for authenticated external-component domains.
///
/// The backing map stays private so callers cannot bypass the atomic vacant
/// registration and owner-fenced removal rules. Clones share the same index;
/// this is required by the component listeners and the federation router.
#[derive(Clone, Default)]
pub struct ComponentRegistry {
    sessions: Arc<DashMap<String, ComponentSession>>,
}

impl ComponentRegistry {
    /// Atomically claim a component domain for one authenticated connection.
    pub fn register_domain(
        &self,
        domain: &str,
        connection_id: Uuid,
        sender: mpsc::Sender<()>,
    ) -> Result<()> {
        match self.sessions.entry(domain.to_owned()) {
            Entry::Vacant(entry) => {
                entry.insert(ComponentSession {
                    connection_id,
                    sender,
                });
                Ok(())
            }
            Entry::Occupied(_) => anyhow::bail!("component hostname is already bound"),
        }
    }

    pub fn contains_connected_domain(&self, domain: &str) -> bool {
        self.sessions.contains_key(domain)
    }

    /// Wake the currently authenticated owner while retaining the map guard.
    /// Holding the guard through `try_send` preserves the former ownership
    /// snapshot: an owner-fenced unbind cannot replace the session midway
    /// through this decision.
    pub fn wake_route(&self, configured_domains: &HashSet<String>, target: &str) -> ComponentRoute {
        let Some(domain) = target_domain(target) else {
            return ComponentRoute::NotConfigured;
        };
        if !configured_domains.contains(&domain) {
            return ComponentRoute::NotConfigured;
        }
        let Some(session) = self.sessions.get(&domain) else {
            return ComponentRoute::Unavailable;
        };
        if session.sender.try_send(()).is_ok() {
            ComponentRoute::Delivered
        } else {
            ComponentRoute::Unavailable
        }
    }

    pub fn connection_owns_domain(&self, domain: &str, connection_id: Uuid) -> bool {
        self.sessions
            .get(domain)
            .is_some_and(|session| session.connection_id == connection_id)
    }

    /// Remove a domain only if the same authenticated connection still owns
    /// it. A newly registered incarnation can never be removed by stale
    /// cleanup from its predecessor.
    pub fn remove_domain_if_owner(&self, domain: &str, connection_id: Uuid) -> bool {
        self.sessions
            .remove_if(domain, |_, session| session.connection_id == connection_id)
            .is_some()
    }

    /// Drop every domain owned by a closing multi-domain connection while
    /// preserving domains already transferred to another incarnation.
    pub fn remove_connection(&self, connection_id: Uuid) {
        self.sessions
            .retain(|_, session| session.connection_id != connection_id);
    }
}

impl crate::outbox::ComponentWake for ComponentRegistry {
    fn wake_route(&self, configured_domains: &HashSet<String>, target: &str) -> ComponentRoute {
        ComponentRegistry::wake_route(self, configured_domains, target)
    }
}

pub fn target_domain(jid: &str) -> Option<String> {
    northstar_xmpp_types::jid::CanonicalJid::parse(jid)
        .ok()
        .map(|jid| jid.domainpart().to_owned())
}

#[cfg(test)]
mod tests;
