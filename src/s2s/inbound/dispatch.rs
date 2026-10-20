//! Authorize and validate inbound component and federation traffic before protocol dispatch.

use super::*;

pub(crate) async fn route_inbound_component(
    state: &Arc<AppState>,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
    raw: &str,
) -> Result<Option<String>> {
    if !valid_inbound_wire_namespace(raw) {
        return Ok(None);
    }
    let client_raw = client_namespace(raw);
    if let MixDispatch::Handled(reply) =
        route_inbound_mix(state, authenticated_domain, &client_raw, false).await?
    {
        return Ok(reply);
    }
    route_inbound_scoped(
        state,
        authenticated_domain,
        InboundRouteAuthority::Component { connection_id },
        raw,
    )
    .await
}

/// Owned actor boundary for external-component routing.  Component sockets
/// are supervised as `Send + 'static` actors; keeping the state and both XML
/// identities owned here prevents parser/frame borrows from leaking into that
/// task's opaque future while preserving the same authorization path below.
pub(crate) async fn route_inbound_component_owned(
    state: Arc<AppState>,
    authenticated_domain: String,
    connection_id: uuid::Uuid,
    raw: String,
) -> Result<Option<String>> {
    route_inbound_component(&state, &authenticated_domain, connection_id, &raw).await
}

pub(crate) async fn route_inbound_for_connection(
    state: &Arc<AppState>,
    authenticated_domain: &str,
    local_domain: &str,
    connection_id: uuid::Uuid,
    raw: &str,
) -> Result<InboundFederationRoute> {
    if state.island_mode_enabled() {
        return Ok(InboundFederationRoute::Reply(None));
    }
    if invalid_inbound_core_namespace(raw) {
        return Ok(InboundFederationRoute::StreamError("invalid-namespace"));
    }
    if !valid_inbound_wire_namespace(raw) {
        return Ok(InboundFederationRoute::Reply(None));
    }
    if let Some(condition) = s2s_stream_address_error(raw, authenticated_domain, local_domain) {
        return Ok(InboundFederationRoute::StreamError(condition));
    }
    let client_raw = client_namespace(raw);
    if let MixDispatch::Handled(reply) =
        route_inbound_mix(state, authenticated_domain, &client_raw, true).await?
    {
        return Ok(InboundFederationRoute::Reply(reply));
    }
    Ok(InboundFederationRoute::Reply(
        route_inbound_scoped(
            state,
            authenticated_domain,
            InboundRouteAuthority::Federation { connection_id },
            raw,
        )
        .await?,
    ))
}

pub(super) async fn route_inbound_for_connection_owned(
    state: Arc<AppState>,
    authenticated_domain: String,
    local_domain: String,
    connection_id: uuid::Uuid,
    raw: String,
) -> Result<InboundFederationRoute> {
    route_inbound_for_connection(
        &state,
        &authenticated_domain,
        &local_domain,
        connection_id,
        &raw,
    )
    .await
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum InboundFederationRoute {
    Reply(Option<String>),
    StreamError(&'static str),
}

/// Enforce the hop-by-hop S2S address authorization rules before any stanza
/// reaches an application handler. RFC 6120 sections 8.1.1.2 and 8.1.2.2
/// require these failures to terminate the stream, rather than being reflected
/// as ordinary stanza errors.
pub(super) fn s2s_stream_address_error(
    raw: &str,
    authenticated_domain: &str,
    local_domain: &str,
) -> Option<&'static str> {
    let document = Document::parse(raw).ok()?;
    let root = document.root_element();
    let from = root
        .attribute("from")
        .and_then(|value| CanonicalJid::parse(value).ok());
    let to = root
        .attribute("to")
        .and_then(|value| CanonicalJid::parse(value).ok());
    let (Some(from), Some(to)) = (from, to) else {
        return Some("improper-addressing");
    };
    if !same_s2s_domain(from.domainpart(), authenticated_domain) {
        return Some("invalid-from");
    }
    if !same_s2s_domain(to.domainpart(), local_domain) {
        return Some("host-unknown");
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InboundRouteAuthority {
    Federation { connection_id: uuid::Uuid },
    Component { connection_id: uuid::Uuid },
}

pub(super) enum MixDispatch {
    NotMix,
    Handled(Option<String>),
}

pub(super) async fn route_inbound_mix(
    state: &Arc<AppState>,
    authenticated_domain: &str,
    client_raw: &str,
    enforce_federation_policy: bool,
) -> Result<MixDispatch> {
    let document = Document::parse(client_raw).context("invalid federated stanza")?;
    let root = document.root_element();
    match validate_inbound_core_stanza(root) {
        InboundCoreValidation::Valid => {}
        InboundCoreValidation::Drop => return Ok(MixDispatch::Handled(None)),
        InboundCoreValidation::Error(condition) => {
            return Ok(MixDispatch::Handled(Some(s2s_stanza_error(
                root, "modify", condition,
            ))));
        }
    }
    let from = root.attribute("from").unwrap_or_default();
    let to = root.attribute("to").unwrap_or_default();
    if enforce_federation_policy && !state.federation_entity_allowed(from) {
        return Ok(MixDispatch::Handled(Some(s2s_stanza_error(
            root,
            "auth",
            "not-authorized",
        ))));
    }
    let target_is_mix = CanonicalJid::parse(to).is_ok_and(|jid| {
        same_s2s_domain(jid.domainpart(), &format!("mix.{}", state.local_domain()))
    });
    let source_is_mix = prepare_domainpart(authenticated_domain).is_ok_and(|domain| {
        domain.strip_prefix("mix.").is_some()
            && CanonicalJid::parse(from).is_ok_and(|jid| same_s2s_domain(jid.domainpart(), &domain))
    });
    if !target_is_mix && !source_is_mix {
        return Ok(MixDispatch::NotMix);
    }
    if !authenticated_s2s_sender(from, authenticated_domain) {
        return Ok(MixDispatch::Handled(Some(s2s_stanza_error(
            root,
            "auth",
            "not-authorized",
        ))));
    }
    let stanza_name = root.tag_name().name().to_owned();
    let unsupported_error = s2s_stanza_error(root, "cancel", "unsupported-stanza-type");
    drop(document);
    let consumed = match stanza_name.as_str() {
        "iq" => {
            federated_mix_iq_owned(
                Arc::clone(state),
                authenticated_domain.to_owned(),
                client_raw.to_owned(),
            )
            .await?
        }
        "message" => {
            federated_mix_message_owned(
                Arc::clone(state),
                authenticated_domain.to_owned(),
                client_raw.to_owned(),
            )
            .await?
        }
        "presence" => {
            federated_mix_presence_owned(
                Arc::clone(state),
                authenticated_domain.to_owned(),
                client_raw.to_owned(),
            )
            .await?
        }
        _ => false,
    };
    Ok(MixDispatch::Handled(
        (!consumed).then_some(unsupported_error),
    ))
}

pub(super) async fn federated_mix_iq_owned(
    state: Arc<AppState>,
    authenticated_domain: String,
    raw: String,
) -> Result<bool> {
    crate::xmpp::protocol::mix::federated_mix_iq(state, &authenticated_domain, raw).await
}

pub(super) async fn federated_mix_message_owned(
    state: Arc<AppState>,
    authenticated_domain: String,
    raw: String,
) -> Result<bool> {
    crate::xmpp::protocol::mix::federated_mix_message(state, &authenticated_domain, raw).await
}

pub(super) async fn federated_mix_presence_owned(
    state: Arc<AppState>,
    authenticated_domain: String,
    raw: String,
) -> Result<bool> {
    crate::xmpp::protocol::mix::federated_mix_presence(state, &authenticated_domain, raw).await
}

pub(super) async fn route_inbound_scoped(
    state: &AppState,
    authenticated_domain: &str,
    authority: InboundRouteAuthority,
    raw: &str,
) -> Result<Option<String>> {
    if matches!(authority, InboundRouteAuthority::Federation { .. }) && state.island_mode_enabled()
    {
        return Ok(None);
    }
    if !valid_inbound_wire_namespace(raw) {
        return Ok(None);
    }
    let client_raw = client_namespace(raw);
    let document = Document::parse(&client_raw).context("invalid federated stanza")?;
    let root = document.root_element();
    match validate_inbound_core_stanza(root) {
        InboundCoreValidation::Valid => {}
        InboundCoreValidation::Drop => return Ok(None),
        InboundCoreValidation::Error(condition) => {
            return Ok(Some(s2s_stanza_error(root, "modify", condition)));
        }
    }
    let raw_from = root.attribute("from").unwrap_or_default();
    let raw_to = root.attribute("to").unwrap_or_default();
    let (Ok(from_jid), Ok(to_jid)) = (CanonicalJid::parse(raw_from), CanonicalJid::parse(raw_to))
    else {
        return Ok(Some(s2s_stanza_error(root, "modify", "jid-malformed")));
    };
    let from = from_jid.to_string();
    let to = to_jid.to_string();
    if matches!(authority, InboundRouteAuthority::Federation { .. })
        && !state.federation_entity_allowed(&from)
    {
        return Ok(Some(s2s_stanza_error(root, "auth", "not-authorized")));
    }
    let from_is_authenticated = authenticated_s2s_sender(&from, authenticated_domain);
    let to_domain = to_jid.domainpart();
    if matches!(authority, InboundRouteAuthority::Component { .. })
        && (!from_is_authenticated || !component_local_target(state, to_domain))
    {
        return Ok(Some(s2s_stanza_error(root, "auth", "not-authorized")));
    }
    let to_is_muc_service =
        same_s2s_domain(to_domain, &format!("conference.{}", state.local_domain()));
    if to_is_muc_service {
        if !from_is_authenticated {
            return Ok(Some(s2s_stanza_error(root, "auth", "not-authorized")));
        }
        let connection_id = match authority {
            InboundRouteAuthority::Federation { connection_id }
            | InboundRouteAuthority::Component { connection_id } => connection_id,
        };
        return match root.tag_name().name() {
            "presence" => {
                crate::xmpp::protocol::federated_muc::federated_muc_presence(
                    state,
                    authenticated_domain,
                    connection_id,
                    root,
                    &client_raw,
                )
                .await
            }
            "message" => {
                crate::xmpp::protocol::federated_muc::federated_muc_message(
                    state,
                    authenticated_domain,
                    connection_id,
                    root,
                    &client_raw,
                )
                .await
            }
            "iq" => {
                crate::xmpp::protocol::federated_muc::federated_muc_iq(
                    state,
                    authenticated_domain,
                    connection_id,
                    root,
                    &client_raw,
                )
                .await
            }
            _ => Ok(Some(s2s_stanza_error(
                root,
                "cancel",
                "unsupported-stanza-type",
            ))),
        };
    }
    let to_is_upload_service = to_jid.localpart().is_none()
        && to_jid.resourcepart().is_none()
        && same_s2s_domain(to_domain, &format!("upload.{}", state.local_domain()));
    if matches!(authority, InboundRouteAuthority::Component { .. }) && to_is_upload_service {
        // Upload reservations are owned and quota-accounted by a local user
        // row. An external component domain is authenticated, but is not a
        // local user and must never be converted into one implicitly.
        return Ok(Some(s2s_stanza_error(root, "auth", "not-authorized")));
    }
    if from_is_authenticated && state.s2s_component_domain_configured(to_domain) {
        return if state
            .federation_outbox()
            .send(to_domain, client_raw.clone(), None)
            .await
        {
            Ok(None)
        } else {
            Ok(Some(s2s_stanza_error(
                root,
                "cancel",
                "service-unavailable",
            )))
        };
    }
    let to_is_local_domain = same_s2s_domain(to_domain, state.local_domain());
    let to_is_pubsub_service = matches!(root.tag_name().name(), "iq" | "message")
        && to_jid.localpart().is_none()
        && same_s2s_domain(to_domain, &format!("pubsub.{}", state.local_domain()));
    if !from_is_authenticated || (!to_is_local_domain && !to_is_pubsub_service) {
        return Ok(Some(s2s_stanza_error(root, "auth", "not-authorized")));
    }
    let connection_id = match authority {
        InboundRouteAuthority::Federation { connection_id }
        | InboundRouteAuthority::Component { connection_id } => connection_id,
    };
    match root.tag_name().name() {
        "message" if to_is_pubsub_service => {
            crate::xmpp::protocol::pubsub::handle_authorization_response(state, &from, root)
                .await?;
            Ok(None)
        }
        "message" => {
            route_inbound_message(state, root, &client_raw, &from, &to, authenticated_domain).await
        }
        "iq" => route_inbound_iq(state, root, &client_raw, &from, &to).await,
        "presence" => {
            route_inbound_presence(state, root, &client_raw, &from, &to, connection_id).await
        }
        _ => Ok(Some(s2s_stanza_error(
            root,
            "cancel",
            "unsupported-stanza-type",
        ))),
    }
}

pub(super) fn component_local_target(state: &AppState, domain: &str) -> bool {
    locally_hosted_identity_domain(state.local_domain(), domain)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InboundCoreValidation {
    Valid,
    /// Unknown/wrong-namespace top-level elements and malformed error stanzas
    /// are ignored. Reflecting them would either create an error loop or emit
    /// another non-stanza element on an authenticated stream.
    Drop,
    Error(&'static str),
}

pub(super) fn valid_inbound_wire_namespace(raw: &str) -> bool {
    Document::parse(raw).is_ok_and(|document| {
        let root = document.root_element();
        matches!(root.tag_name().name(), "iq" | "message" | "presence")
            // A child which inherited the stream's `jabber:server` default
            // namespace appears unqualified when parsed as a standalone
            // frame. An explicit client namespace on an S2S stream is never
            // accepted and must not be normalized into a valid stanza.
            && matches!(root.tag_name().namespace(), None | Some("jabber:server"))
    })
}

pub(super) fn invalid_inbound_core_namespace(raw: &str) -> bool {
    Document::parse(raw).is_ok_and(|document| {
        let root = document.root_element();
        matches!(root.tag_name().name(), "iq" | "message" | "presence")
            && !matches!(root.tag_name().namespace(), None | Some("jabber:server"))
    })
}

pub(super) fn validate_inbound_core_stanza(root: roxmltree::Node<'_, '_>) -> InboundCoreValidation {
    if root.tag_name().namespace() != Some("jabber:client")
        || !matches!(root.tag_name().name(), "iq" | "message" | "presence")
    {
        return InboundCoreValidation::Drop;
    }
    if root
        .attribute("from")
        .and_then(|value| CanonicalJid::parse(value).ok())
        .is_none()
    {
        // There is no trustworthy return address for a stanza error.
        return InboundCoreValidation::Drop;
    }
    if root
        .attribute("to")
        .and_then(|value| CanonicalJid::parse(value).ok())
        .is_none()
    {
        return if root.attribute("type") == Some("error") {
            InboundCoreValidation::Drop
        } else {
            InboundCoreValidation::Error("jid-malformed")
        };
    }
    if root.tag_name().name() == "iq" && root.attribute("id").is_none() {
        // An IQ error cannot be correlated without the request ID.
        return InboundCoreValidation::Drop;
    }
    match crate::services::stanza_validation::validate_client_stanza(root) {
        Ok(()) => InboundCoreValidation::Valid,
        Err(_) if root.attribute("type") == Some("error") => InboundCoreValidation::Drop,
        Err(condition) => InboundCoreValidation::Error(condition),
    }
}
