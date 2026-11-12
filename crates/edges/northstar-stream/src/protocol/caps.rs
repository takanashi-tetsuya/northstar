use super::ProtocolSession;
use crate::protocol::SessionHost;
pub use northstar_protocol_runtime::caps::*;
use northstar_session_application::telemetry::CapsEffectTelemetry;
use northstar_session_core::LocalCapsEpoch;
use northstar_xep_0115::{
    generate_canonical_verification_string, parse_caps_from_presence, parse_disco_info_element,
    CapsHashAlgorithm,
};
use northstar_xml_builder::stanza::iq_result_from;
use roxmltree::Node;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

pub trait CapsEffectDispatcherExt {
    fn hint(
        &self,
        full_jid: String,
        local: bool,
        telemetry: &CapsEffectTelemetry<'_>,
    ) -> CapsEffectAdmission;
}

impl CapsEffectDispatcherExt for CapsEffectDispatcher {
    fn hint(
        &self,
        full_jid: String,
        local: bool,
        telemetry: &CapsEffectTelemetry<'_>,
    ) -> CapsEffectAdmission {
        let admission = self.enqueue_hint(full_jid, local);
        match admission {
            CapsEffectAdmission::Coalesced => {
                telemetry.coalesced();
            }
            CapsEffectAdmission::Saturated => {
                telemetry.queue_saturated();
            }
            _ => {}
        }
        admission
    }
}

pub const DISCO_INFO_NS: &str = northstar_xep_0115::DISCO_INFO_NS;
const MAX_DISCO_PAYLOAD_BYTES: usize = northstar_xep_0115::MAX_DISCO_PAYLOAD_BYTES;

pub(super) fn local_caps_epoch_is_current<H: SessionHost>(
    state: &H,
    full_jid: &str,
    epoch: LocalCapsEpoch,
) -> bool {
    state.local_caps_epoch_is_current(full_jid, epoch, None)
}

/// Cleanup-side route removal is synchronous and deliberately cannot await
/// the async MIX gate. This fence closes the complementary interleaving: if
/// route removal happened after the handler's initial check but before one of
/// its index/queue insertions, Drop compare-removes only that exact epoch.
struct LocalCapsObservationFence<'a, H: SessionHost> {
    state: &'a H,
    full_jid: &'a str,
    epoch: LocalCapsEpoch,
}

impl<H: SessionHost> Drop for LocalCapsObservationFence<'_, H> {
    fn drop(&mut self) {
        if local_caps_epoch_is_current(self.state, self.full_jid, self.epoch) {
            return;
        }
        self.state
            .pending_caps()
            .remove_local_epoch(self.full_jid, self.epoch);
        self.state
            .caps_by_jid()
            .remove_local_epoch(self.full_jid, self.epoch);
    }
}

fn hint_caps_effects<H: SessionHost>(state: &H, full_jid: String) {
    let local = state
        .caps_by_jid()
        .owner(&full_jid)
        .is_some_and(CapsObservationOwner::is_local);
    match state
        .caps_effect_dispatcher()
        .hint(full_jid, local, &state.caps_effect_telemetry())
    {
        CapsEffectAdmission::Queued | CapsEffectAdmission::Coalesced => {}
        CapsEffectAdmission::Saturated => {
            tracing::debug!("caps wake-hint queue saturated; observation remains pending");
        }
        CapsEffectAdmission::Closed => {
            tracing::debug!("caps wake hint ignored during service shutdown; observation retained");
        }
    }
}

fn allocate_local_caps_epoch(
    connection_id: uuid::Uuid,
    generation: &std::sync::atomic::AtomicU64,
) -> LocalCapsEpoch {
    LocalCapsEpoch {
        connection_id,
        generation: generation.fetch_add(1, Ordering::AcqRel).wrapping_add(1),
    }
}

impl<H: SessionHost> ProtocolSession<H> {
    /// Rebind a persisted XEP-0115 advertisement to a newly activated
    /// XEP-0198 transport incarnation.
    ///
    /// The staged resume route is deliberately invisible when this method is
    /// armed. Publication consumes the value exactly once, crosses the same
    /// resource gate used by presence/cleanup, revalidates the new route, and
    /// then runs the ordinary observation pipeline. The pipeline allocates a
    /// fresh `(connection_id,generation)` epoch and sends any disco query to
    /// the replacement transport.
    pub(crate) async fn rebind_captured_caps_observation(
        &self,
        intent: Option<crate::auth_publication::CapsIntent>,
    ) {
        let Some(intent) = intent else {
            return;
        };
        let full_jid = &intent.key;
        let Ok(document) = roxmltree::Document::parse(&intent.presence) else {
            tracing::warn!(
                connection_id = %intent.connection,
                "discarded malformed persisted presence while rebinding entity capabilities"
            );
            return;
        };
        let presence = document.root_element();
        if presence.tag_name().name() != "presence"
            || presence
                .attribute("type")
                .is_some_and(|kind| kind != "available")
        {
            return;
        }

        let _resource_epoch = Arc::clone(&intent.gate).lock_owned().await;
        let route_is_current = self.host.local_caps_observer_connection_is_current(
            full_jid,
            intent.connection,
            &intent.gate,
        );
        if route_is_current {
            self.commit_caps_observation_for(
                presence,
                full_jid,
                intent.connection,
                &intent.gate,
                &intent.generation,
            );
        }
    }
}

impl<H: SessionHost> ProtocolSession<H> {
    pub fn advertised_mix_capability(
        &self,
        presence: Node<'_, '_>,
        full_jid: &str,
    ) -> northstar_room_core::mix::MixSessionCapability {
        if !self.host.xmpp_extension_enabled(northstar_xep_0115::XEP_ID) {
            return northstar_room_core::mix::MixSessionCapability::Unknown;
        }
        let Ok(full_jid) = northstar_xmpp_types::jid::canonical_session_key(full_jid) else {
            return northstar_room_core::mix::MixSessionCapability::Unknown;
        };
        let Some(key) = observed_caps_key(presence, &full_jid) else {
            return northstar_room_core::mix::MixSessionCapability::Unknown;
        };
        let summary = self
            .host
            .caps_by_jid()
            .snapshot(&full_jid)
            .filter(|observation| observation.key.as_ref() == Some(&key))
            .and_then(|observation| observation.summary)
            .or_else(|| self.host.caps_cache().query(&key, Instant::now()));
        let Some(summary) = summary else {
            return northstar_room_core::mix::MixSessionCapability::Unknown;
        };
        if summary.has_feature("urn:xmpp:mix:core:1") || summary.has_feature("urn:xmpp:mix:pam:2") {
            northstar_room_core::mix::MixSessionCapability::Supported
        } else {
            northstar_room_core::mix::MixSessionCapability::Unsupported
        }
    }
}

impl<H: SessionHost> ProtocolSession<H> {
    /// Commit the latest caps observation only after the surrounding presence
    /// handler has durably applied the matching MIX projection and updated
    /// availability while holding `mix_presence_gate`.
    pub fn commit_caps_observation(&self, presence: Node<'_, '_>, full_jid: &str) {
        self.commit_caps_observation_for(
            presence,
            full_jid,
            self.connection_id,
            &self.presence.mix_presence_gate,
            &self.presence.caps_observation_generation,
        );
    }

    fn commit_caps_observation_for(
        &self,
        presence: Node<'_, '_>,
        full_jid: &str,
        connection: uuid::Uuid,
        gate: &Arc<tokio::sync::Mutex<()>>,
        generation: &std::sync::atomic::AtomicU64,
    ) {
        if !self.host.xmpp_extension_enabled(northstar_xep_0115::XEP_ID) {
            return;
        }
        let Ok(full_jid) = northstar_xmpp_types::jid::canonical_session_key(full_jid) else {
            return;
        };
        let connection_is_current = self
            .host
            .local_caps_observer_connection_is_current(&full_jid, connection, gate);
        if !connection_is_current {
            return;
        }
        let epoch = allocate_local_caps_epoch(connection, generation);
        let _observation_fence = LocalCapsObservationFence {
            state: &*self.host,
            full_jid: &full_jid,
            epoch,
        };
        // Every presence is a latest-wins observation, including an available
        // stanza without `<c/>`. Retire only this connection's older state so
        // a late old actor cannot cancel a replacement's pending work.
        self.host
            .pending_caps()
            .remove_local_resource(&full_jid, connection);
        if presence
            .attribute("type")
            .is_some_and(|kind| kind != "available")
        {
            self.host
                .caps_by_jid()
                .remove_local_resource(&full_jid, connection);
            return;
        }
        let now = Instant::now();
        let key = observed_caps_key(presence, &full_jid);
        let cached = key
            .as_ref()
            .and_then(|key| self.host.caps_cache().query(key, now));
        self.host
            .caps_by_jid()
            .observe_local(full_jid.clone(), epoch, key, cached, now);
        hint_caps_effects(&*self.host, full_jid.clone());
    }

    pub(crate) async fn handle_caps_response(
        &self,
        id: &str,
        kind: &str,
        root: Node<'_, '_>,
        raw: &str,
    ) -> bool {
        let Some(pending) = self.host.pending_caps().take(id) else {
            return false;
        };
        let CapsObservationOwner::Local(epoch) = pending.owner else {
            // A C2S actor can never authorize a federated correlation. Put it
            // back only if it is still live; the S2S response path will own it.
            let _ = self.host.pending_caps().insert(
                id.to_owned(),
                pending.full_jid,
                pending.key,
                pending.owner,
                pending.expires_at,
            );
            return false;
        };
        let _epoch_guard = Arc::clone(&self.presence.mix_presence_gate)
            .lock_owned()
            .await;
        if epoch.connection_id != self.connection_id
            || !local_caps_epoch_is_current(&*self.host, &pending.full_jid, epoch)
        {
            return true;
        }
        let _observation_fence = LocalCapsObservationFence {
            state: &*self.host,
            full_jid: &pending.full_jid,
            epoch,
        };
        // RFC 6120 §8.1.2.1 permits a client to omit `from`; in that case the
        // receiving server supplies the authenticated full JID.  An explicit
        // value is still untrusted input and may authorize this correlation
        // only when it is the authenticated full JID.  The federated handler
        // below deliberately keeps requiring an explicit, authenticated S2S
        // sender instead of using this C2S rule.
        let response_from =
            effective_c2s_caps_sender(self.full_jid.as_deref(), root.attribute("from"));
        if pending.expires_at <= Instant::now()
            || response_from.as_deref() != Some(pending.full_jid.as_str())
        {
            tracing::debug!(
                authenticated = ?self.full_jid,
                explicit_from = ?root.attribute("from"),
                effective_from = ?response_from,
                expected_from = %pending.full_jid,
                stanza_type = %kind,
                expired = pending.expires_at <= Instant::now(),
                "rearming entity capabilities after an invalid response envelope"
            );
            if self
                .host
                .caps_by_jid()
                .rearm_expired(id, &pending, Instant::now())
            {
                hint_caps_effects(&*self.host, pending.full_jid.clone());
            }
            return true;
        }
        if kind != "result" {
            self.host.caps_by_jid().mark_invalid(
                &pending.full_jid,
                pending.owner,
                &pending.key,
                id,
            );
            return true;
        }
        let Some(query) = root.children().find(|node| {
            node.is_element()
                && node.tag_name().name() == "query"
                && node.tag_name().namespace() == Some(DISCO_INFO_NS)
        }) else {
            self.host.caps_by_jid().mark_invalid(
                &pending.full_jid,
                pending.owner,
                &pending.key,
                id,
            );
            return true;
        };
        let expected_node = format!("{}#{}", pending.key.node, pending.key.version);
        if query.attribute("node") != Some(expected_node.as_str()) {
            tracing::debug!(jid = %pending.full_jid, "discarded entity capabilities with a mismatched node");
            self.host.caps_by_jid().mark_invalid(
                &pending.full_jid,
                pending.owner,
                &pending.key,
                id,
            );
            return true;
        }
        let range = query.range();
        let Some(payload) = raw.get(range) else {
            return true;
        };
        if payload.len() > MAX_DISCO_PAYLOAD_BYTES {
            self.host.caps_by_jid().mark_invalid(
                &pending.full_jid,
                pending.owner,
                &pending.key,
                id,
            );
            return true;
        }
        let Ok(verification) = verification_string(query) else {
            tracing::debug!(jid = %pending.full_jid, "discarded malformed entity capabilities");
            self.host.caps_by_jid().mark_invalid(
                &pending.full_jid,
                pending.owner,
                &pending.key,
                id,
            );
            return true;
        };
        if !caps_hash_matches(&pending.key.algorithm, &verification, &pending.key.version) {
            tracing::warn!(jid = %pending.full_jid, "discarded entity capabilities whose hash did not verify");
            self.host.caps_by_jid().mark_invalid(
                &pending.full_jid,
                pending.owner,
                &pending.key,
                id,
            );
            return true;
        }
        let Ok(summary) = verified_caps_summary(query, payload) else {
            self.host.caps_by_jid().mark_invalid(
                &pending.full_jid,
                pending.owner,
                &pending.key,
                id,
            );
            return true;
        };
        let summary = Arc::new(summary);
        self.host.caps_cache().insert(
            pending.key.clone(),
            payload.to_owned(),
            Arc::clone(&summary),
            Instant::now(),
        );
        let full_jid = pending.full_jid.clone();
        tracing::debug!(
            jid = %full_jid,
            node = %pending.key.node,
            version = %pending.key.version,
            "cached verified entity capabilities"
        );
        match self.host.caps_by_jid().mark_verified(
            &full_jid,
            pending.owner,
            &pending.key,
            id,
            summary,
        ) {
            CapsVerificationCommit::Applied => hint_caps_effects(&*self.host, full_jid),
            CapsVerificationCommit::ResourceLimited => {
                self.host.caps_effect_telemetry().failed(1);
                tracing::warn!(jid = %full_jid, "caps semantic memory budget exhausted; verification remains pending");
                hint_caps_effects(&*self.host, full_jid);
            }
            CapsVerificationCommit::Stale => {}
        }
        true
    }
}

fn observed_caps_key(presence: Node<'_, '_>, full_jid: &str) -> Option<CapsKey> {
    let caps = parse_caps_from_presence(presence).ok()??;
    let algorithm = caps.hash.as_deref()?;
    // SHA-1 is the mandatory verification algorithm. Unsupported algorithms
    // are namespaced by this exact full JID before entering the bounded cache,
    // so an unverified claim cannot be shared with or collide with another
    // resource's capability mapping.
    let parsed_algorithm = CapsHashAlgorithm::parse_name(algorithm);
    let algorithm = if parsed_algorithm.is_supported() {
        parsed_algorithm.as_str().to_owned()
    } else {
        scoped_algorithm(algorithm, full_jid)
    };
    Some(CapsKey {
        algorithm,
        node: caps.node,
        version: caps.ver,
    })
}

fn effective_c2s_caps_sender(
    authenticated_full_jid: Option<&str>,
    explicit_from: Option<&str>,
) -> Option<String> {
    let authenticated =
        northstar_xmpp_types::jid::canonical_session_key(authenticated_full_jid?).ok()?;
    match explicit_from {
        None => Some(authenticated),
        Some(from) => {
            let claimed = northstar_xmpp_types::jid::canonical_session_key(from).ok()?;
            (claimed == authenticated).then_some(authenticated)
        }
    }
}

fn current_caps_observation<H: SessionHost>(
    state: &H,
    target: &str,
) -> Option<CapsObservationSnapshot> {
    let snapshot = state.caps_by_jid().snapshot(target)?;
    if let CapsObservationOwner::Local(epoch) = snapshot.owner {
        if !local_caps_epoch_is_current(state, target, epoch) {
            state.pending_caps().remove_local_epoch(target, epoch);
            state.caps_by_jid().remove_local_epoch(target, epoch);
            return None;
        }
    }
    Some(snapshot)
}

/// Observes an authenticated federated resource's XEP-0115 advertisement.
/// Remote claims are never trusted directly: the advertised disco payload is
/// requested over the already-authenticated S2S route and hash-verified before
/// it can influence PEP fan-out.
pub async fn observe_federated_caps<H: SessionHost>(
    state: &H,
    presence: Node<'_, '_>,
    full_jid: &str,
    connection_id: uuid::Uuid,
    resource_epoch: &FederatedCapsGuard<'_>,
) -> FederatedCapsObservationResult {
    if !state.xmpp_extension_enabled(northstar_xep_0115::XEP_ID) {
        return FederatedCapsObservationResult::Accepted;
    }
    let Ok(full_jid) = northstar_xmpp_types::jid::canonical_session_key(full_jid) else {
        return FederatedCapsObservationResult::StaleOwner;
    };
    if resource_epoch.resource() != full_jid {
        debug_assert_eq!(resource_epoch.resource(), full_jid);
        return FederatedCapsObservationResult::StaleOwner;
    }
    if presence
        .attribute("type")
        .is_some_and(|kind| kind != "available")
    {
        if state
            .caps_by_jid()
            .owner(&full_jid)
            .is_some_and(|owner| owner.federated_connection() != Some(connection_id))
        {
            return FederatedCapsObservationResult::StaleOwner;
        }
        state
            .caps_by_jid()
            .remove_federated_resource_if_connection(&full_jid, connection_id);
        state
            .pending_caps()
            .remove_federated_resource_if_connection(&full_jid, connection_id);
        return FederatedCapsObservationResult::Accepted;
    }
    let domain = northstar_xmpp_types::jid::CanonicalJid::parse(&full_jid)
        .expect("canonical full JID was parsed above")
        .domainpart()
        .to_owned();
    let now = Instant::now();
    let key = observed_caps_key(presence, &full_jid);
    let cached = key
        .as_ref()
        .and_then(|key| state.caps_cache().query(key, now));
    state.pending_caps().remove_resource(&full_jid);
    if state
        .caps_by_jid()
        .observe_federated(full_jid.clone(), connection_id, domain, key, cached, now)
        .is_none()
    {
        return FederatedCapsObservationResult::Saturated;
    }
    hint_caps_effects(state, full_jid);
    FederatedCapsObservationResult::Accepted
}

/// Retires every observation owned by one authenticated federation/component
/// transport. Each resource crosses the same gate as presence, responses and
/// effects, while the compare-remove still checks the exact connection so a
/// newer stream's same-full-JID observation survives teardown ABA.
pub async fn federated_caps_connection_closed<H: SessionHost>(
    state: &H,
    connection_id: uuid::Uuid,
) {
    loop {
        let resources = state
            .caps_by_jid()
            .federated_resources_for_connection(connection_id);
        if resources.is_empty() {
            break;
        }
        for resource in resources {
            let _resource_epoch = state.federated_caps_gates().lock(&resource).await;
            state
                .caps_by_jid()
                .remove_federated_resource_if_connection(&resource, connection_id);
        }
    }
    state
        .pending_caps()
        .remove_federated_connection(connection_id);
}

/// Consumes a disco result generated by `observe_federated_caps`. Returns
/// false for unrelated IQs so normal S2S routing remains untouched.
pub async fn handle_federated_caps_response<H: SessionHost>(
    state: &H,
    id: &str,
    kind: &str,
    root: Node<'_, '_>,
    raw: &str,
) -> bool {
    // Peek only the routing key, then acquire the same authority as presence.
    // Consume the pending entry after the gate is held: an unavailable which
    // linearized first removes it, while a response which linearized first
    // completes before that unavailable can commit its removal.
    let Some(resource) = state.pending_caps().federated_resource(id) else {
        return false;
    };
    let _resource_epoch = state.federated_caps_gates().lock(&resource).await;
    let Some(pending) = state.pending_caps().take(id) else {
        return true;
    };
    debug_assert_eq!(pending.full_jid, resource);
    if !matches!(pending.owner, CapsObservationOwner::Federated { .. }) {
        let _ = state.pending_caps().insert(
            id.to_owned(),
            pending.full_jid,
            pending.key,
            pending.owner,
            pending.expires_at,
        );
        return false;
    }
    if !state
        .caps_by_jid()
        .current_owner(&pending.full_jid, pending.owner)
    {
        return true;
    }
    let response_from = root
        .attribute("from")
        .and_then(|jid| northstar_xmpp_types::jid::canonical_session_key(jid).ok());
    if pending.expires_at <= Instant::now()
        || response_from.as_deref() != Some(pending.full_jid.as_str())
    {
        if state
            .caps_by_jid()
            .rearm_expired(id, &pending, Instant::now())
        {
            hint_caps_effects(state, pending.full_jid.clone());
        }
        return true;
    }
    if kind != "result" {
        state
            .caps_by_jid()
            .mark_invalid(&pending.full_jid, pending.owner, &pending.key, id);
        return true;
    }
    let Some(query) = root.children().find(|node| {
        node.is_element()
            && node.tag_name().name() == "query"
            && node.tag_name().namespace() == Some(DISCO_INFO_NS)
    }) else {
        state
            .caps_by_jid()
            .mark_invalid(&pending.full_jid, pending.owner, &pending.key, id);
        return true;
    };
    let expected_node = format!("{}#{}", pending.key.node, pending.key.version);
    let range = query.range();
    let Some(payload) = raw.get(range) else {
        state
            .caps_by_jid()
            .mark_invalid(&pending.full_jid, pending.owner, &pending.key, id);
        return true;
    };
    if query.attribute("node") != Some(expected_node.as_str())
        || payload.len() > MAX_DISCO_PAYLOAD_BYTES
    {
        state
            .caps_by_jid()
            .mark_invalid(&pending.full_jid, pending.owner, &pending.key, id);
        return true;
    }
    let Ok(verification) = verification_string(query) else {
        state
            .caps_by_jid()
            .mark_invalid(&pending.full_jid, pending.owner, &pending.key, id);
        return true;
    };
    if !caps_hash_matches(&pending.key.algorithm, &verification, &pending.key.version) {
        tracing::warn!(jid = %pending.full_jid, "discarded federated entity capabilities whose hash did not verify");
        state
            .caps_by_jid()
            .mark_invalid(&pending.full_jid, pending.owner, &pending.key, id);
        return true;
    }
    let Ok(summary) = verified_caps_summary(query, payload) else {
        state
            .caps_by_jid()
            .mark_invalid(&pending.full_jid, pending.owner, &pending.key, id);
        return true;
    };
    let summary = Arc::new(summary);
    state.caps_cache().insert(
        pending.key.clone(),
        payload.to_owned(),
        Arc::clone(&summary),
        Instant::now(),
    );
    let resource = pending.full_jid;
    match state
        .caps_by_jid()
        .mark_verified(&resource, pending.owner, &pending.key, id, summary)
    {
        CapsVerificationCommit::Applied => hint_caps_effects(state, resource),
        CapsVerificationCommit::ResourceLimited => {
            state.caps_effect_telemetry().failed(1);
            tracing::warn!(%resource, "caps semantic memory budget exhausted; verification remains pending");
            hint_caps_effects(state, resource);
        }
        CapsVerificationCommit::Stale => {}
    }
    true
}

pub fn cached_disco_result<H: SessionHost>(
    state: &H,
    id: &str,
    target: &str,
    requested_node: Option<&str>,
) -> Option<String> {
    let target = northstar_xmpp_types::jid::canonical_session_key(target).ok()?;
    let observation = current_caps_observation(state, &target)?;
    let key = observation.key?;
    if observation.summary.is_none() {
        tracing::debug!(%target, "entity capability cache lookup has no resource mapping");
        return None;
    }
    let expected_node = format!("{}#{}", key.node, key.version);
    if requested_node != Some(expected_node.as_str()) {
        tracing::debug!(
            %target,
            requested_node = ?requested_node,
            %expected_node,
            "entity capability cache lookup used a mismatched node"
        );
        return None;
    }
    let Some(query) = state.caps_cache().raw_query(&key, Instant::now()) else {
        tracing::debug!(%target, node = %key.node, version = %key.version, "entity capability cache lookup missed verified content");
        return None;
    };
    Some(iq_result_from(id, &target, &query))
}

/// MIX/PEP consumers share the strict top-level feature parser used at caps
/// verification time. Text, identities and nested data-form elements cannot
/// impersonate a disco feature. Successful use refreshes both LRU layers.
pub fn verified_caps_has_any_feature<H: SessionHost>(
    state: &H,
    target: &str,
    features: &[&str],
) -> Option<bool> {
    let Ok(target) = northstar_xmpp_types::jid::canonical_session_key(target) else {
        return None;
    };
    current_caps_observation(state, &target)
        .and_then(|observation| observation.summary)
        .map(|summary| features.iter().any(|feature| summary.has_feature(feature)))
}

fn scoped_algorithm(algorithm: &str, full_jid: &str) -> String {
    if algorithm == "sha-1" {
        algorithm.to_owned()
    } else {
        // The separator cannot occur in a prepared JID or accepted algorithm,
        // and the prefix prevents collision with a registered hash name.
        format!("jid-scoped\u{1f}{full_jid}\u{1f}{algorithm}")
    }
}

pub fn wants_pep_node<H: SessionHost>(state: &H, target: &str, node: &str) -> bool {
    let Ok(target) = northstar_xmpp_types::jid::canonical_session_key(target) else {
        return false;
    };
    current_caps_observation(state, &target)
        .and_then(|observation| observation.summary)
        .is_some_and(|summary| summary.wants_node(node))
}

pub fn interested_resources_for_bare<H: SessionHost>(
    state: &H,
    bare: &str,
    node: &str,
) -> Vec<String> {
    state
        .caps_by_jid()
        .interested_resources_for_bare(bare, node)
}

fn verified_caps_summary(query: Node<'_, '_>, raw_query: &str) -> Result<VerifiedCapsSummary, ()> {
    if raw_query.len() > MAX_DISCO_PAYLOAD_BYTES {
        return Err(());
    }
    let disco = parse_disco_info_element(query).map_err(|_| ())?;
    generate_canonical_verification_string(&disco).map_err(|_| ())?;
    let mut mix_core = false;
    let mut mix_pam = false;
    let mut notify_storage = String::new();
    let mut notify_ranges = Vec::new();
    for feature in disco.features {
        let feature = feature.var();
        mix_core |= feature == "urn:xmpp:mix:core:1";
        mix_pam |= feature == "urn:xmpp:mix:pam:2";
        if let Some(node) = feature.strip_suffix("+notify") {
            if !node.is_empty() {
                // No secondary item limit is applied here. The complete list
                // is already bounded by the 64-KiB payload and 512 top-level
                // child parser limits enforced above.
                let start = u32::try_from(notify_storage.len()).map_err(|_| ())?;
                notify_storage.push_str(node);
                let end = u32::try_from(notify_storage.len()).map_err(|_| ())?;
                notify_ranges.push((start, end));
            }
        }
    }
    Ok(VerifiedCapsSummary {
        mix_core,
        mix_pam,
        notify_storage,
        notify_ranges,
    })
}

fn verification_string(query: Node<'_, '_>) -> Result<String, ()> {
    let disco = parse_disco_info_element(query).map_err(|_| ())?;
    generate_canonical_verification_string(&disco).map_err(|_| ())
}

fn caps_hash_matches(algorithm: &str, verification: &str, advertised: &str) -> bool {
    let algorithm = CapsHashAlgorithm::parse_name(algorithm);
    !algorithm.is_supported() || algorithm.verify(verification, advertised).unwrap_or(false)
}

#[cfg(test)]
mod tests;
