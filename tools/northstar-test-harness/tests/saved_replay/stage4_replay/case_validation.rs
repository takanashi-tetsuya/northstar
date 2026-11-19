use super::{
    sha256, ArchiveReply, AuthDrive, AuthInput, BoshRequest, BoshSessionInput, Case, ClaimOrigin,
    CommitCut, Composition, ControlInput, CredentialKind, EndpointCut, FixedAuthPadding,
    FlushReply, Id, IdentityMap, Introduction, Jid, LabelContext, Lifecycle, MixBoshTransport,
    MucDrive, MucInput, MucPrincipal, Nullable, PublicationReply, Rejection, Responder,
    RouteEnvironment, RouteProvenance, Text, TransportKind, ValidatedCase, Walk,
    WorkerAttemptInput, WorkerInput, WriteScript, ADAPTER_CONTRACT, CASE_SCHEMA,
    MAX_BINDING_LEASE_SECONDS, MAX_INPUT, MAX_NONPADDING, MAX_STANZA, OUTPUT_BYTES, RESPONSE_BYTES,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
};

pub(crate) fn read_input(reader: impl Read) -> Result<Vec<u8>, Rejection> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_INPUT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Rejection::Encoding)?;
    if bytes.len() > MAX_INPUT {
        return Err(Rejection::TooLarge);
    }
    Ok(bytes)
}
pub(crate) fn decode(bytes: &[u8]) -> Result<ValidatedCase, Rejection> {
    if bytes.len() > MAX_INPUT {
        return Err(Rejection::TooLarge);
    }
    let case: Case = serde_json::from_slice(bytes).map_err(|_| Rejection::Json)?;
    case.validate()?;
    case.validate_actors()?;
    let mut input = case.clone();
    let mut labels = IdentityMap::default();
    input
        .walk(
            &mut LabelContext {
                identities: &mut labels,
                seq: 0,
            },
            Introduction::UnexpectedObservedIdentity,
        )
        .map_err(|_| Rejection::Bound)?;
    let frame_limit = if matches!(case.composition, Composition::ReplayMixQueuedAuth(_)) {
        3
    } else {
        2
    };
    require(
        labels.input_frames.len() <= frame_limit
            && labels.input_connections.len() <= 2
            && labels.input_sessions.len() <= 2,
    )?;
    require(case.nonpadding_bytes() <= MAX_NONPADDING)?;
    Ok(ValidatedCase {
        case,
        fixed_ids: labels.fixed,
        input_sha256: sha256(bytes),
    })
}
pub(super) fn require(value: bool) -> Result<(), Rejection> {
    if value {
        Ok(())
    } else {
        Err(Rejection::Relationship)
    }
}
fn full_jid(value: &Jid) -> Result<String, Rejection> {
    let jid = northstar_xmpp_types::CanonicalJid::parse(value.as_str())
        .map_err(|_| Rejection::Encoding)?;
    require(
        jid.localpart().is_some()
            && jid.resourcepart().is_some()
            && jid.to_string() == value.as_str(),
    )?;
    Ok(jid.bare().to_owned())
}
fn bare_jid(value: &Jid) -> Result<(), Rejection> {
    let jid = northstar_xmpp_types::CanonicalJid::parse(value.as_str())
        .map_err(|_| Rejection::Encoding)?;
    require(
        jid.localpart().is_some()
            && jid.resourcepart().is_none()
            && jid.to_string() == value.as_str(),
    )
}
fn xml(value: &str) -> Result<roxmltree::Document<'_>, Rejection> {
    roxmltree::Document::parse(value).map_err(|_| Rejection::Encoding)
}
fn write_plan(plan: &WriteScript, item_len: usize) -> Result<(), Rejection> {
    require(plan.chunk_limit > 0 && plan.chunk_limit as usize <= MAX_STANZA)?;
    let calls = item_len.div_ceil(plan.chunk_limit as usize);
    // All saved native paths require real successful write/flush. Failure
    // scripts remain outside this finite inventory's input language.
    require(
        calls <= 32
            && plan.fail_after_accepted_bytes.get().is_none()
            && plan.flush == FlushReply::Ok,
    )
}
pub(super) fn auth_xml(auth: &AuthInput) -> &str {
    match &auth.control {
        ControlInput::Binding(c) => c.xml.as_str(),
        ControlInput::UnboundFast(c) => c.xml.as_str(),
    }
}
pub(super) fn validate_auth(
    auth: &AuthInput,
    kind: CredentialKind,
    transport: TransportKind,
) -> Result<(), Rejection> {
    // The finite auth bridge does not capture NotificationIntent. Reject that
    // requested scope here, before owners, so rejected-envelope validation and
    // the adapter agree. Never silently clear it or infer it from an epoch.
    if auth.notification_expected {
        return Err(Rejection::Unsupported);
    }
    // Every saved auth frame owns exactly one actual credential invocation.
    // The frame assigns ordinal zero even when another frame owns a control.
    require(
        auth.credential_kind == kind
            && auth.frame.transport == transport
            && auth.ordinal == 0
            && auth.auth_generation >= 0,
    )?;
    require(auth.preparation.generation_allowed && auth.preparation.commit == CommitCut::Complete)?;
    require(auth.preparation.stage_epoch.get().is_some() == auth.preparation.stage_present)?;
    // publish_credential_commit derives Some(epoch) only from a staged login and
    // passes that presence through COMMIT and the returned result.
    // Validate supplied reply shape only. No epoch value is matched to a hint,
    // and actual returned observation values remain independently retained.
    match &auth.publication {
        PublicationReply::Committed(reply) | PublicationReply::CommitPending(reply) => {
            require(reply.epoch.get().is_some() == auth.preparation.stage_present)?
        }
        _ => {}
    }
    xml(auth.frame.input.as_str())?;
    let doc = xml(auth_xml(auth))?;
    let root = doc.root_element();
    match (&auth.control, kind, auth.binding.get()) {
        (ControlInput::Binding(c), CredentialKind::Binding, Some(binding)) => {
            full_jid(&c.full_jid)?;
            require(
                c.full_jid == binding.full_jid
                    && !binding.resource.as_str().is_empty()
                    && (1..=MAX_BINDING_LEASE_SECONDS).contains(&binding.lease_seconds),
            )?;
            require(
                c.full_jid
                    .as_str()
                    .rsplit_once('/')
                    .is_some_and(|(_, r)| r == binding.resource.as_str()),
            )?;
            require(
                auth.preparation.binding_reserved
                    && auth.preparation.stage_present == auth.device_id.get().is_some(),
            )?;
            // None means actual stage_returned(Ok(None)), Stage::Absent and no
            // stage operation ID. Some requests a reply matched to the actual
            // invocation's device/user/connection/generation and newly generated
            // stage operation ID; it never supplies a stage identity as authority.
            require(
                root.tag_name().name() == "iq"
                    && root.tag_name().namespace() == Some("jabber:client")
                    && root.attributes().len() == 2
                    && root.attribute("id") == Some(c.iq_id.as_str())
                    && root.attribute("type") == Some("result"),
            )?;
            let children: Vec<_> = root.children().filter(|n| n.is_element()).collect();
            require(
                children.len() == 1
                    && children[0].tag_name().name() == "bind"
                    && children[0].tag_name().namespace()
                        == Some("urn:ietf:params:xml:ns:xmpp-bind")
                    && children[0].attributes().len() == 0,
            )?;
            let jids: Vec<_> = children[0].children().filter(|n| n.is_element()).collect();
            require(
                jids.len() == 1
                    && jids[0].tag_name().name() == "jid"
                    && jids[0].tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-bind")
                    && jids[0].attributes().len() == 0
                    && jids[0].children().all(|n| n.is_text())
                    && jids[0].text() == Some(c.full_jid.as_str()),
            )?;
        }
        (ControlInput::UnboundFast(c), CredentialKind::UnboundFast, None) => {
            bare_jid(&c.authorization_identifier)?;
            // The saved U path is the narrower no-device/no-stage/no-bearer
            // NoSQL path. Other FAST stage shapes remain outside this grammar.
            require(
                auth.device_id.get().is_none()
                    && !auth.preparation.binding_reserved
                    && !auth.preparation.stage_present
                    && !auth.notification_expected,
            )?;
            require(
                root.tag_name().name() == "success"
                    && root.tag_name().namespace() == Some("urn:xmpp:sasl:2")
                    && root.attributes().len() == 0,
            )?;
            let children: Vec<_> = root.children().filter(|n| n.is_element()).collect();
            require(
                children.len() == 1
                    && children[0].tag_name().name() == "authorization-identifier"
                    && children[0].tag_name().namespace() == Some("urn:xmpp:sasl:2")
                    && children[0].attributes().len() == 0
                    && children[0].children().all(|n| n.is_text())
                    && children[0].text() == Some(c.authorization_identifier.as_str()),
            )?;
            require(matches!(auth.publication, PublicationReply::NoSql(_)))?;
        }
        _ => return Err(Rejection::Relationship),
    }
    // These controlled paths never issue a bearer or include token extensions.
    require(!auth_xml(auth).contains("<token") && !auth_xml(auth).contains("<additional-data"))
}
fn validate_request(request: &BoshRequest, session: Id) -> Result<(), Rejection> {
    require(request.rid > 0 && request.responders.as_slice().contains(&Responder::Open))?;
    require(request.fingerprint == sha256(request.request_xml.as_str().as_bytes()))?;
    let doc = xml(request.request_xml.as_str())?;
    let body = doc.root_element();
    require(
        body.tag_name().name() == "body"
            && body.tag_name().namespace() == Some("http://jabber.org/protocol/httpbind"),
    )?;
    require(body.attribute("rid").and_then(|v| v.parse::<u64>().ok()) == Some(request.rid))?;
    require(body.attribute("sid") == Some(session.0.to_string().as_str()))
}
fn validate_session(session: &BoshSessionInput) -> Result<(), Rejection> {
    require(
        session.max_response_bytes == RESPONSE_BYTES
            && session.max_output_bytes == OUTPUT_BYTES
            && session.ttl_seconds > 0
            && session.ttl_seconds <= 3600,
    )?;
    require(
        session.governor.max_bytes >= OUTPUT_BYTES
            && session.governor.max_bytes <= 1024 * 1024
            && session.governor.max_recovery_bytes <= 1024 * 1024
            && session.governor.max_recovery_jobs <= 2
            && session.governor.max_snapshot_bytes <= 1024 * 1024,
    )?;
    // Actual SmMemoryGovernor::new constructor relationships.
    require(
        session.governor.max_recovery_jobs > 0
            && session.governor.max_bytes >= session.governor.max_snapshot_bytes
            && session.governor.max_recovery_bytes >= session.governor.max_snapshot_bytes,
    )?;
    require(session.bind.commit == CommitCut::Complete)?;
    validate_request(&session.response, session.session_id)
}
fn validate_route(route: &RouteEnvironment) -> Result<(), Rejection> {
    require((1..=2).contains(&route.queue_capacity))?;
    let mut keys = BTreeSet::new();
    for entry in route.targets.as_slice() {
        full_jid(&entry.full_jid)?;
        require(
            keys.insert(entry.full_jid.as_str())
                && entry.user_id == route.enabled_account_id
                && entry.auth_generation >= 0,
        )?;
        require(entry.caps.connection_id == entry.connection_id)?;
        let unique: BTreeSet<_> = entry.caps.verified_features.as_slice().iter().collect();
        require(unique.len() == entry.caps.verified_features.len())?;
        match &entry.provenance {
            RouteProvenance::InitiallyPublished(_) => require(entry.routable)?,
            RouteProvenance::ActivatedByAuth(_) => require(!entry.routable)?,
        }
    }
    Ok(())
}
pub(super) fn validate_worker(worker: &WorkerInput) -> Result<(), Rejection> {
    validate_attempt(&worker.attempt)?;
    if let ClaimOrigin::InitialDurableRow(row) = &worker.origin {
        bare_jid(&row.channel_jid)?;
        bare_jid(&row.recipient_jid)?;
        xml(row.stanza.as_str())?;
        require(
            row.source.lease_token == worker.attempt.claim.lease_token
                && row.attempt_count == worker.attempt.claim.attempt_count
                && row.route_wake_generation == worker.attempt.claim.route_wake_generation,
        )?;
        require(row.archive && row.authoritative_stanza_id.get().is_some())?;
        for target in worker.attempt.route.targets.as_slice() {
            require(full_jid(&target.full_jid)? == row.recipient_jid.as_str())?;
        }
    }
    Ok(())
}
fn validate_attempt(attempt: &WorkerAttemptInput) -> Result<(), Rejection> {
    require(
        attempt.claim.limit == 1
            && attempt.claim.max_bytes > 0
            && attempt.claim.max_bytes <= MAX_STANZA as i64
            && attempt.claim.attempt_count >= 0
            && attempt.claim.route_wake_generation >= 0,
    )?;
    require(
        attempt.claim.commit == CommitCut::Complete
            && attempt.archive.commit == CommitCut::Complete,
    )?;
    validate_route(&attempt.route)
}
fn delivered_environment(environment: &RouteEnvironment) -> Result<(), Rejection> {
    require(!environment.privacy_blocked && environment.targets.len() == 1)?;
    let target = &environment.targets.as_slice()[0];
    require(
        !target.disconnected
            && target.lifecycle == Lifecycle::Active
            && !target.caps.verified_features.is_empty(),
    )
}
fn validate_mix_transport(
    worker: &WorkerInput,
    transport: &MixBoshTransport,
    with_ack: bool,
) -> Result<(), Rejection> {
    validate_session(&transport.session)?;
    delivered_environment(&worker.attempt.route)?;
    require(
        transport.transfer.commit == CommitCut::Complete
            && transport.session.bind.commit == CommitCut::Complete,
    )?;
    let delivery = match &worker.origin {
        ClaimOrigin::FreshProjection(p) => p.declared_delivery_id,
        ClaimOrigin::InitialDurableRow(r) => r.source.delivery_id,
    };
    require(transport.transfer.returned_source.delivery_id == delivery)?;
    require(
        transport.session.bind.membership.c2s_message_ids.is_empty()
            && transport
                .session
                .bind
                .membership
                .mix_delivery_ids
                .as_slice()
                == [delivery],
    )?;
    require(
        worker
            .attempt
            .route
            .targets
            .as_slice()
            .iter()
            .any(|r| r.connection_id == transport.session.connection_id),
    )?;
    require(transport.ack.get().is_some() == with_ack)?;
    if let Some(ack) = transport.ack.get() {
        validate_request(&ack.request, transport.session.session_id)?;
        require(
            ack.acknowledged_rid == transport.session.response.rid
                && ack.request.rid > ack.acknowledged_rid
                && ack.deleted == transport.transfer.returned_source,
        )?;
        let doc = xml(ack.request.request_xml.as_str())?;
        require(
            doc.root_element()
                .attribute("ack")
                .and_then(|v| v.parse::<u64>().ok())
                == Some(ack.acknowledged_rid),
        )?;
        require(ack.commit == CommitCut::Complete && ack.renewal == CommitCut::Complete)?;
    }
    Ok(())
}
pub(super) const P_OPEN: &str = "<presence><status>";
pub(super) const P_CLOSE: &str = "</status></presence>";
pub(super) const FIXED_FEATURES: &str =
    "<stream:features xmlns:stream=\"http://etherx.jabber.org/streams\"/>";
pub(super) fn validate_padding(
    padding: &FixedAuthPadding,
    unbound: &AuthInput,
    bound: &AuthInput,
) -> Result<(), Rejection> {
    let u = auth_xml(unbound).len();
    let b = auth_xml(bound).len();
    let target = (RESPONSE_BYTES as usize)
        .checked_sub(256 + u)
        .ok_or(Rejection::Bound)?;
    let count = target
        .checked_sub(P_OPEN.len() + P_CLOSE.len())
        .ok_or(Rejection::Bound)?;
    let p = padding.presence_xml.as_str();
    require(p.len() == target && p.starts_with(P_OPEN) && p.ends_with(P_CLOSE))?;
    require(
        p[P_OPEN.len()..p.len() - P_CLOSE.len()]
            .bytes()
            .all(|x| x == b'x')
            && count <= 16384,
    )?;
    require(
        padding.features_xml.as_str() == FIXED_FEATURES
            && b + 256 <= RESPONSE_BYTES as usize
            && u + 256 <= RESPONSE_BYTES as usize,
    )
}
fn validate_muc(muc: &MucInput) -> Result<(), Rejection> {
    let c = &muc.command;
    let a = &c.authority;
    let MucPrincipal::Local(principal) = &a.principal else {
        return Err(Rejection::Unsupported);
    };
    require(
        muc.frame.transport == TransportKind::Tcp
            && c.retention_days >= 0
            && c.retention_days <= 3650,
    )?;
    require(
        !a.clustered
            && a.cluster_target.get().is_none()
            && a.connection_uuid == muc.frame.connection_id,
    )?;
    require(
        c.actor_scope == a.actor_scope
            && c.sender_jid == a.full_jid
            && c.nick == a.nick
            && principal.local_domain == muc.configured_domain,
    )?;
    bare_jid(&c.actor_scope)?;
    require(full_jid(&c.sender_jid)? == c.actor_scope.as_str())?;
    require(
        northstar_xmpp_types::CanonicalJid::parse(c.actor_scope.as_str())
            .map_err(|_| Rejection::Encoding)?
            .domainpart()
            == muc.configured_domain.as_str(),
    )?;
    xml(c.stanza.as_str())?;
    require(
        muc.admission.begin_commit == CommitCut::Complete
            && muc.admission.finalize_commit == CommitCut::Complete,
    )?;
    for recipient in muc.recipients.as_slice() {
        full_jid(&recipient.full_jid)?;
        require(!recipient.blocked)?;
    }
    match (
        &muc.repository.original_id,
        muc.repository.commit,
        muc.drive,
    ) {
        (Nullable::Null(()), CommitCut::Complete, MucDrive::Complete) => {
            require(
                c.archive
                    && c.origin_id.get().is_some()
                    && muc.recipients.len() == 1
                    && muc.recipients.as_slice()[0].endpoint == EndpointCut::Return,
            )?;
            let native = muc.native.get().ok_or(Rejection::Relationship)?;
            require(native.connection_id == muc.recipients.as_slice()[0].connection_id)?;
            write_plan(&native.write, c.stanza.as_str().len())?;
        }
        (Nullable::Value(_), CommitCut::Complete, MucDrive::Complete) => require(
            c.origin_id.get().is_some() && muc.recipients.is_empty() && muc.native.get().is_none(),
        )?,
        (Nullable::Null(()), CommitCut::Complete, MucDrive::DropSecondEndpoint) => {
            require(
                !c.archive
                    && c.origin_id.get().is_none()
                    && muc.recipients.len() == 2
                    && muc.native.get().is_none(),
            )?;
            require(
                muc.recipients.as_slice()[0].endpoint == EndpointCut::Return
                    && muc.recipients.as_slice()[1].endpoint == EndpointCut::Pending,
            )?;
        }
        (Nullable::Null(()), CommitCut::Pending, MucDrive::DropCommit) => {
            require(muc.recipients.is_empty() && muc.native.get().is_none())?
        }
        _ => return Err(Rejection::Unsupported),
    }
    Ok(())
}
fn validate_auth_drive(auth: &AuthInput, drive: AuthDrive) -> Result<(), Rejection> {
    require(matches!(
        (&auth.publication, drive),
        (PublicationReply::BackendError(_), AuthDrive::Complete)
            | (
                PublicationReply::CommitPending(_),
                AuthDrive::DropPublicationCommit
            )
    ))
}
fn independent_lanes(
    m: &MixBoshTransport,
    a: &BoshSessionInput,
    worker: &WorkerInput,
    bound: &AuthInput,
) -> Result<(), Rejection> {
    require(
        m.session.connection_id != a.connection_id
            && m.session.session_id != a.session_id
            && m.session.response.rid != a.response.rid,
    )?;
    let binding = bound.binding.get().ok_or(Rejection::Relationship)?;
    full_jid(&binding.full_jid)?;
    for r in worker.attempt.route.targets.as_slice() {
        require(
            r.full_jid != binding.full_jid
                && r.connection_id != a.connection_id
                && matches!(r.provenance, RouteProvenance::InitiallyPublished(_)),
        )?;
    }
    Ok(())
}
// Count canonical account actors, not room/participant IDs, sessions, devices,
// archive candidates or repeated copies of the same account's fixed identity.
// Account UUID and canonical bare-JID aliases must agree where both are supplied.
#[derive(Default)]
struct ActorBudget {
    bare: BTreeSet<String>,
    by_id: BTreeMap<Id, String>,
    by_bare: BTreeMap<String, Id>,
}
impl ActorBudget {
    fn bare(&mut self, bare: &Jid) -> Result<(), Rejection> {
        bare_jid(bare)?;
        self.bare.insert(bare.as_str().to_owned());
        require(self.bare.len() <= 2)
    }
    fn bind(&mut self, id: Id, bare: &Jid) -> Result<(), Rejection> {
        self.bare(bare)?;
        require(
            self.by_id
                .get(&id)
                .is_none_or(|existing| existing == bare.as_str()),
        )?;
        require(
            self.by_bare
                .get(bare.as_str())
                .is_none_or(|existing| *existing == id),
        )?;
        self.by_id.insert(id, bare.as_str().to_owned());
        self.by_bare.insert(bare.as_str().to_owned(), id);
        Ok(())
    }
    fn full(&mut self, id: Id, full: &Jid) -> Result<(), Rejection> {
        self.bind(id, &Text::new(full_jid(full)?)?)
    }
    fn auth(&mut self, auth: &AuthInput) -> Result<(), Rejection> {
        match &auth.control {
            ControlInput::Binding(c) => self.full(auth.user_id, &c.full_jid),
            ControlInput::UnboundFast(c) => self.bind(auth.user_id, &c.authorization_identifier),
        }
    }
    fn route(&mut self, route: &RouteEnvironment) -> Result<(), Rejection> {
        for target in route.targets.as_slice() {
            self.full(target.user_id, &target.full_jid)?;
        }
        Ok(())
    }
    fn worker(&mut self, worker: &WorkerInput) -> Result<(), Rejection> {
        if let ClaimOrigin::InitialDurableRow(row) = &worker.origin {
            self.bind(worker.attempt.route.enabled_account_id, &row.recipient_jid)?;
        }
        self.route(&worker.attempt.route)
    }
}
impl Case {
    fn validate_actors(&self) -> Result<(), Rejection> {
        let mut actors = ActorBudget::default();
        match &self.composition {
            Composition::Muc(c) => {
                let MucPrincipal::Local(principal) = &c.command.authority.principal else {
                    return Err(Rejection::Unsupported);
                };
                actors.bind(principal.user_id, &c.command.actor_scope)?;
                for r in c.recipients.as_slice() {
                    actors.full(r.user_id, &r.full_jid)?;
                }
            }
            Composition::AuthThenMixNative(c) => {
                actors.auth(&c.auth)?;
                actors.bare(&c.foreground.ingress.actor_bare)?;
                actors.worker(&c.worker)?;
                if let Some(p) = c.foreground.stored.projection.get() {
                    for r in p.recipients.as_slice() {
                        actors.bare(&r.participant.jid)?;
                    }
                }
            }
            Composition::ReplayMixQueuedAuth(c) => {
                actors.auth(&c.auth.unbound)?;
                actors.auth(&c.auth.bound)?;
                actors.bare(&c.mix.foreground.ingress.actor_bare)?;
                actors.worker(&c.mix.worker)?;
            }
            Composition::MixRecoveryNative(c) => {
                actors.worker(&c.worker)?;
                actors.route(&c.replacement.route)?;
                if let ClaimOrigin::InitialDurableRow(row) = &c.worker.origin {
                    actors.bind(c.replacement.route.enabled_account_id, &row.recipient_jid)?;
                }
            }
            Composition::MixDefer(c) => actors.worker(&c.worker)?,
            Composition::NativeAuth(c) => actors.auth(&c.auth)?,
            Composition::BoshAuth(c) => {
                actors.auth(&c.auth.bound)?;
                if let Some(m) = c.mix.get() {
                    actors.worker(&m.worker)?;
                }
            }
        }
        Ok(())
    }
    // Count distinct *logical supplied occurrences*, not unique strings and
    // not repeated copies of one item's bytes in command/projection/frame data.
    // These finite recipes each have a fixed number of logical message/control
    // occurrences. Equal bytes at two endpoints or in U/B still count twice.
    fn nonpadding_bytes(&self) -> usize {
        let initial = |w: &WorkerInput| match &w.origin {
            ClaimOrigin::InitialDurableRow(r) => r.stanza.as_str().len(),
            ClaimOrigin::FreshProjection(_) => 0,
        };
        match &self.composition {
            Composition::Muc(m) => m.command.stanza.as_str().len() * m.recipients.len().max(1),
            Composition::AuthThenMixNative(c) => {
                auth_xml(&c.auth).len()
                    + c.foreground
                        .stored
                        .projection
                        .get()
                        .map_or(0, |p| p.stanza_template.as_str().len() * p.recipients.len())
            }
            Composition::ReplayMixQueuedAuth(c) => {
                initial(&c.mix.worker)
                    + auth_xml(&c.auth.unbound).len()
                    + auth_xml(&c.auth.bound).len()
                    + c.auth.padding.features_xml.as_str().len()
            }
            Composition::MixRecoveryNative(c) => initial(&c.worker) * 2,
            Composition::MixDefer(c) => initial(&c.worker),
            Composition::NativeAuth(c) => auth_xml(&c.auth).len(),
            Composition::BoshAuth(c) => {
                auth_xml(&c.auth.bound).len() + c.mix.get().map_or(0, |m| initial(&m.worker))
            }
        }
    }
    pub(super) fn validate(&self) -> Result<(), Rejection> {
        require(
            self.schema.as_str() == CASE_SCHEMA
                && self.adapter_contract.as_str() == ADAPTER_CONTRACT,
        )
        .map_err(|_| Rejection::Schema)?;
        require(!self.case_id.as_str().is_empty() && self.case_id.as_str().is_ascii())?;
        // Descriptive identity is intentionally never matched, parsed or used
        // to choose behavior. Each closed recipe carries its own domain inputs.
        match &self.composition {
            Composition::Muc(muc) => validate_muc(muc)?,
            Composition::AuthThenMixNative(c) => {
                validate_auth(&c.auth, CredentialKind::Binding, TransportKind::Tcp)?;
                require(matches!(c.auth.publication, PublicationReply::Committed(_)))?;
                require(
                    c.auth.frame.connection_id == c.auth_native.connection_id
                        && c.auth.frame.frame_id != c.foreground.frame.frame_id,
                )?;
                write_plan(&c.auth_native.write, auth_xml(&c.auth).len())?;
                validate_worker(&c.worker)?;
                delivered_environment(&c.worker.attempt.route)?;
                require(
                    matches!(
                        c.worker.attempt.archive.reply,
                        ArchiveReply::StoreCandidate(_)
                    ) && c.delivery_native.ack_commit == CommitCut::Complete,
                )?;
                let ClaimOrigin::FreshProjection(origin) = &c.worker.origin else {
                    return Err(Rejection::Relationship);
                };
                require(
                    origin.foreground_frame == c.foreground.frame.frame_id
                        && c.foreground.commit == CommitCut::Complete,
                )?;
                let stored = &c.foreground.stored;
                let command = &c.foreground.command;
                let ingress = &c.foreground.ingress;
                require(
                    c.foreground.frame.transport == TransportKind::Tcp
                        && stored.authoritative_id == command.item_id
                        && stored.channel_id == ingress.channel_id
                        && command.channel_id == ingress.channel_id
                        && stored.channel_jid == ingress.channel_jid,
                )?;
                require(
                    command.actor == ingress.actor_bare
                        && command.identity == ingress.identity
                        && command.delivery_payload == ingress.children
                        && command.encrypted == ingress.encrypted,
                )?;
                require(
                    command
                        .visible_jid
                        .get()
                        .is_none_or(|jid| jid == &ingress.actor_bare),
                )?;
                require(full_jid(&ingress.actor_full)? == ingress.actor_bare.as_str())?;
                bare_jid(&ingress.channel_jid)?;
                require(
                    northstar_xmpp_types::CanonicalJid::parse(ingress.channel_jid.as_str())
                        .map_err(|_| Rejection::Encoding)?
                        .domainpart()
                        == c.foreground.configured_domain.as_str(),
                )?;
                let projection = stored.projection.get().ok_or(Rejection::Relationship)?;
                // One outstanding delivery source. No second independently
                // supplied fresh row is possible in this input variant.
                require(
                    projection.recipients.len() == 1
                        && origin.recipient_ordinal == 0
                        && projection.recipients.as_slice()[0].delivery_id
                            == origin.declared_delivery_id,
                )?;
                require(
                    projection.event_id == stored.authoritative_id
                        && projection.channel_id == stored.channel_id
                        && projection.channel_jid == stored.channel_jid
                        && projection.authoritative_stanza_id.get()
                            == Some(&stored.authoritative_id)
                        && projection.archive
                        && projection.encrypted == command.encrypted
                        && projection.recipients.as_slice()[0].sequence > 0,
                )?;
                require(!projection.stanza_template.as_str().is_empty())?;
                require(
                    c.delivery_native.returned_fence.delivery_id == origin.declared_delivery_id,
                )?;
                require(c.worker.attempt.route.targets.len() == 1)?;
                let route = &c.worker.attempt.route.targets.as_slice()[0];
                bare_jid(&projection.recipients.as_slice()[0].participant.jid)?;
                require(
                    full_jid(&route.full_jid)?
                        == projection.recipients.as_slice()[0].participant.jid.as_str(),
                )?;
                require(
                    route.connection_id == c.auth.frame.connection_id
                        && route.connection_id == c.delivery_native.connection_id
                        && route.user_id == c.auth.user_id
                        && route.auth_generation == c.auth.auth_generation,
                )?;
                require(
                    matches!(&route.provenance, RouteProvenance::ActivatedByAuth(a) if a.frame_id == c.auth.frame.frame_id),
                )?;
                require(
                    c.auth
                        .binding
                        .get()
                        .is_some_and(|b| b.full_jid == route.full_jid),
                )?;
                write_plan(
                    &c.delivery_native.write,
                    projection.stanza_template.as_str().len(),
                )?;
            }
            Composition::ReplayMixQueuedAuth(c) => {
                validate_auth(
                    &c.auth.unbound,
                    CredentialKind::UnboundFast,
                    TransportKind::Bosh,
                )?;
                validate_auth(&c.auth.bound, CredentialKind::Binding, TransportKind::Bosh)?;
                validate_session(&c.auth.session)?;
                validate_worker(&c.mix.worker)?;
                validate_mix_transport(&c.mix.worker, &c.mix.transport, true)?;
                independent_lanes(
                    &c.mix.transport,
                    &c.auth.session,
                    &c.mix.worker,
                    &c.auth.bound,
                )?;
                require(
                    c.auth.unbound.frame.connection_id == c.auth.session.connection_id
                        && c.auth.bound.frame.connection_id == c.auth.session.connection_id,
                )?;
                require(
                    c.auth.unbound.frame.frame_id != c.auth.bound.frame.frame_id
                        && c.mix.foreground.frame.frame_id != c.auth.unbound.frame.frame_id
                        && c.mix.foreground.frame.frame_id != c.auth.bound.frame.frame_id,
                )?;
                require(
                    c.auth.session.bind.membership.c2s_message_ids.is_empty()
                        && c.auth.session.bind.membership.mix_delivery_ids.is_empty(),
                )?;
                validate_padding(&c.auth.padding, &c.auth.unbound, &c.auth.bound)?;
                let ClaimOrigin::InitialDurableRow(row) = &c.mix.worker.origin else {
                    return Err(Rejection::Relationship);
                };
                require(matches!(
                    c.mix.worker.attempt.archive.reply,
                    ArchiveReply::Replay(_)
                ))?;
                require(
                    row.event_id == c.mix.foreground.original_id
                        && row.authoritative_stanza_id.get() == Some(&c.mix.foreground.original_id)
                        && c.mix.foreground.existing.authoritative_id
                            == c.mix.foreground.original_id
                        && c.mix.foreground.ingress.identity.get().is_some(),
                )?;
                require(
                    row.channel_id == c.mix.foreground.ingress.channel_id
                        && row.channel_jid == c.mix.foreground.ingress.channel_jid,
                )?;
                bare_jid(&c.mix.foreground.ingress.actor_bare)?;
                require(
                    full_jid(&c.mix.foreground.ingress.actor_full)?
                        == c.mix.foreground.ingress.actor_bare.as_str(),
                )?;
                require(
                    northstar_xmpp_types::CanonicalJid::parse(row.channel_jid.as_str())
                        .map_err(|_| Rejection::Encoding)?
                        .domainpart()
                        == c.mix.foreground.configured_domain.as_str(),
                )?;
            }
            Composition::MixRecoveryNative(c) => {
                validate_worker(&c.worker)?;
                validate_attempt(&c.replacement)?;
                delivered_environment(&c.worker.attempt.route)?;
                delivered_environment(&c.replacement.route)?;
                require(
                    matches!(c.worker.origin, ClaimOrigin::InitialDurableRow(_))
                        && c.worker.attempt.claim.lease_token != c.replacement.claim.lease_token,
                )?;
                let (ArchiveReply::Replay(first), ArchiveReply::Replay(replacement)) = (
                    &c.worker.attempt.archive.reply,
                    &c.replacement.archive.reply,
                ) else {
                    return Err(Rejection::Relationship);
                };
                require(first.original_archive_id == replacement.original_archive_id)?;
                let old_route = &c.worker.attempt.route.targets.as_slice()[0];
                let new_route = &c.replacement.route.targets.as_slice()[0];
                require(
                    matches!(old_route.provenance, RouteProvenance::InitiallyPublished(_))
                        && old_route.routable
                        && matches!(new_route.provenance, RouteProvenance::InitiallyPublished(_))
                        && new_route.routable
                        && old_route.connection_id != new_route.connection_id,
                )?;
                // Actual PendingMixLocalHandoff::drop cancels the old sender and
                // disconnect token. Recovery must create an independent queue,
                // lifecycle and cancellation token for new_route, retaining the
                // old cancelled objects as evidence; never clear or relabel them.
                let ClaimOrigin::InitialDurableRow(row) = &c.worker.origin else {
                    unreachable!()
                };
                require(c.native.returned_fence.delivery_id == row.source.delivery_id)?;
                require(
                    c.replacement
                        .route
                        .targets
                        .as_slice()
                        .iter()
                        .any(|r| r.connection_id == c.native.connection_id),
                )?;
                for target in c.replacement.route.targets.as_slice() {
                    require(full_jid(&target.full_jid)? == row.recipient_jid.as_str())?;
                }
                require(c.native.ack_commit == CommitCut::Complete)?;
                write_plan(&c.native.write, row.stanza.as_str().len())?;
            }
            Composition::MixDefer(c) => {
                validate_worker(&c.worker)?;
                require(
                    matches!(c.worker.origin, ClaimOrigin::InitialDurableRow(_))
                        && c.worker.attempt.route.targets.is_empty()
                        && !c.worker.attempt.route.privacy_blocked
                        && c.settlement_commit == CommitCut::Complete
                        && c.updated,
                )?;
                // There is no renewal start, timer, or interval in the grammar.
            }
            Composition::NativeAuth(c) => {
                validate_auth(&c.auth, CredentialKind::Binding, TransportKind::Tcp)?;
                validate_auth_drive(&c.auth, c.drive)?;
                require(c.native.connection_id == c.auth.frame.connection_id)?;
                write_plan(&c.native.write, auth_xml(&c.auth).len())?;
            }
            Composition::BoshAuth(c) => {
                validate_auth(&c.auth.bound, CredentialKind::Binding, TransportKind::Bosh)?;
                validate_auth_drive(&c.auth.bound, c.auth.drive)?;
                validate_session(&c.auth.session)?;
                require(
                    c.auth.session.connection_id == c.auth.bound.frame.connection_id
                        && auth_xml(&c.auth.bound).len() + 256 <= RESPONSE_BYTES as usize,
                )?;
                require(
                    c.auth.session.bind.membership.c2s_message_ids.is_empty()
                        && c.auth.session.bind.membership.mix_delivery_ids.is_empty(),
                )?;
                if let Some(mix) = c.mix.get() {
                    validate_worker(&mix.worker)?;
                    require(
                        matches!(mix.worker.origin, ClaimOrigin::InitialDurableRow(_))
                            && matches!(
                                mix.worker.attempt.archive.reply,
                                ArchiveReply::StoreCandidate(_)
                            ),
                    )?;
                    validate_mix_transport(&mix.worker, &mix.transport, false)?;
                    independent_lanes(&mix.transport, &c.auth.session, &mix.worker, &c.auth.bound)?;
                } else {
                    require(c.auth.drive == AuthDrive::Complete)?;
                }
            }
        }
        Ok(())
    }
}
