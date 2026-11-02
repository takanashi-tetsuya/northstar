//! The view of the node that drains the durable federation outbox: the dispatch service and its
//! failure effects (telemetry and bounces to the local sender), the routes and policies an
//! envelope is checked against, and the domains the node serves itself. The node builds one per
//! drain or per failure, so a drain sees one consistent policy.

use arc_swap::ArcSwap;
use northstar_config::ExternalRouteDomainPolicy;
use northstar_federation_application::dispatch::S2sOutboxDispatchService;
use northstar_federation_application::registry::{BidiRouteSnapshot, S2sConnectionRegistry};
use northstar_federation_application::telemetry::OutboundDispositionTelemetry;
use northstar_federation_application::write_policy::FederationWritePolicy;
use northstar_federation_application::FederationEnvelope;
use northstar_federation_core::policy::RuntimeFederationPolicy;
use northstar_federation_core::wire::client_namespace;
use northstar_xmpp_types::jid::{prepare_domainpart, CanonicalJid};
use roxmltree::Document;
use std::sync::{atomic::AtomicU64, Arc};

/// Hands a stanza error to every local session of the entity whose stanza the outbox gave up on.
pub trait LocalBounce: Send + Sync {
    fn bounce_to_local(&self, origin: &str, error: &str);
}

/// What an envelope's delivery failure does: the disposition counters and the bounce to its
/// local sender.
pub struct S2sOutboxFailureEffects<R> {
    pub service: S2sOutboxDispatchService<R>,
    pub local: Arc<dyn LocalBounce>,
    pub connection_failure: Arc<AtomicU64>,
    pub lease_lost: Arc<AtomicU64>,
    pub delivered: Arc<AtomicU64>,
    pub permanent_failure: Arc<AtomicU64>,
    pub expired: Arc<AtomicU64>,
    pub retry: Arc<AtomicU64>,
}

impl<R> S2sOutboxFailureEffects<R> {
    pub fn service(&self) -> &S2sOutboxDispatchService<R> {
        &self.service
    }

    pub fn telemetry(&self) -> OutboundDispositionTelemetry<'_> {
        OutboundDispositionTelemetry::new(
            &self.connection_failure,
            &self.lease_lost,
            &self.delivered,
            &self.permanent_failure,
            &self.expired,
            &self.retry,
        )
    }

    pub fn bounce(&self, envelope: &FederationEnvelope, condition: &str) {
        let Some(origin) = &envelope.bounce_to else {
            return;
        };
        let Some(error) = delivery_failure_stanza(&envelope.stanza, condition) else {
            return;
        };
        self.local.bounce_to_local(origin, &error);
    }
}

/// The routes and policies one outbox drain checks its envelopes against.
pub struct S2sOutboxDispatchContext<R> {
    pub failure: S2sOutboxFailureEffects<R>,
    pub registry: Arc<S2sConnectionRegistry>,
    pub island: Arc<FederationWritePolicy>,
    pub static_policy: ExternalRouteDomainPolicy,
    pub runtime_policy: Arc<ArcSwap<RuntimeFederationPolicy>>,
    pub component_domains: Vec<String>,
    pub local_domain: String,
}

impl<R> S2sOutboxDispatchContext<R> {
    pub fn service(&self) -> &S2sOutboxDispatchService<R> {
        self.failure.service()
    }

    pub fn failure(&self) -> &S2sOutboxFailureEffects<R> {
        &self.failure
    }

    pub fn registry(&self) -> &S2sConnectionRegistry {
        &self.registry
    }

    pub fn component_domains(&self) -> &[String] {
        &self.component_domains
    }

    pub fn local_domain(&self) -> &str {
        &self.local_domain
    }

    pub fn island_mode_enabled(&self) -> bool {
        self.island.enabled()
    }

    pub fn federation_domain_allowed(&self, domain: &str) -> bool {
        let Ok(domain) = prepare_domainpart(domain) else {
            return false;
        };
        self.static_policy.federation_domain_allowed(&domain)
            && self.runtime_policy.load().allows_domain(&domain)
    }

    pub fn federation_entity_allowed(&self, entity: &str) -> bool {
        let Ok(entity) = CanonicalJid::parse(entity) else {
            return false;
        };
        if !self
            .static_policy
            .federation_domain_allowed(entity.domainpart())
        {
            return false;
        }
        self.runtime_policy.load().allows_entity(&entity)
    }

    pub fn component_domain_configured(&self, domain: &str) -> bool {
        prepare_domainpart(domain).is_ok_and(|domain| self.component_domains.contains(&domain))
    }

    pub fn bidirectional_route(&self, key: &str) -> Option<BidiRouteSnapshot> {
        self.registry.bidirectional_route(key)
    }
}

/// The stanza error a local sender receives when the outbox gives up on its stanza.
pub fn delivery_failure_stanza(stanza: &str, condition: &str) -> Option<String> {
    // Restrict element names to the conditions emitted by this outbox. This
    // keeps the generic reflector from ever receiving an attacker-controlled
    // XML name if a future caller passes through a remote diagnostic string.
    if !matches!(
        condition,
        "internal-server-error"
            | "policy-violation"
            | "remote-server-not-found"
            | "remote-server-timeout"
    ) {
        return None;
    }
    let client_stanza = client_namespace(stanza);
    let document = Document::parse(&client_stanza).ok()?;
    let root = document.root_element();
    if root.attribute("type") == Some("error") {
        // RFC 6120 section 8.3.1 forbids responding to a stanza error with
        // another stanza error.
        return None;
    }
    Some(northstar_xml_builder::stanza::stanza_error(
        root,
        northstar_xml_builder::stanza::stanza_error_type(condition),
        condition,
    ))
}
