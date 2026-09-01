use crate::services::privacy::PrivacyStanzaKind;
use crate::state::bare_jid;
use crate::xmpp::protocol::{Action, ProtocolSession};
use crate::xmpp::xml_util::*;
use anyhow::Result;
use roxmltree::{Document, Node};
use std::sync::atomic::Ordering;

fn xmpp_version_os() -> &'static str {
    match std::env::consts::OS {
        "linux" => "Linux",
        "windows" => "Windows",
        "macos" => "macOS",
        other => other,
    }
}

fn map_pubsub_capacity_result(id: &str, result: Result<Action>) -> Result<Action> {
    match result {
        Err(error) if crate::services::pubsub::is_pubsub_mutation_busy(&error) => {
            Ok(Action::Send(iq_error(id, "resource-constraint")))
        }
        result => result,
    }
}

impl ProtocolSession {
    pub async fn handle(&mut self, xml: &str) -> Result<Action> {
        self.state
            .metrics
            .stanzas_in_total
            .fetch_add(1, Ordering::Relaxed);
        let stream_open = crate::xmpp::protocol::sasl2::is_tcp_stream_opening(xml)
            || (self.websocket && is_websocket_open(xml));
        if stream_open {
            if self.stream_opened {
                return Ok(Action::CloseWith(stream_error("unexpected-request")));
            }
            if let Err(error) = self.capture_stream_from(xml) {
                return Ok(Action::CloseWith(stream_error(error.condition())));
            }
            self.stream_opened = true;
            return Ok(Action::Send(self.open_stream()));
        }
        if is_stream_close(xml) {
            self.sm_resume_allowed = false;
            self.stream_opened = false;
            self.stream_language = None;
            return Ok(Action::Close);
        }
        let doc = match Document::parse(xml) {
            Ok(document) => document,
            Err(error) => {
                tracing::debug!(?error, "malformed XML stanza");
                return Ok(Action::CloseWith(stream_error("not-well-formed")));
            }
        };
        // Keep the exact client frame separate from the authoritative stanza
        // the server builds below. PoW v2 commits the client's pow-less bytes;
        // RFC-mandated `from` and inherited `xml:lang` materialization are
        // server assertions and must never be values a client has to predict.
        let client_xml = xml;
        let root = doc.root_element();
        if root.tag_name().name() == "close"
            && root.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-framing")
        {
            self.sm_resume_allowed = false;
            self.stream_opened = false;
            self.stream_language = None;
            return Ok(Action::Close);
        }
        if !self.stream_opened {
            return Ok(Action::CloseWith(stream_error("not-well-formed")));
        }
        if root.tag_name().name() == "starttls"
            && root.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-tls")
        {
            if root.attributes().len() != 0
                || root.children().any(|child| child.is_element())
                || root.text().is_some_and(|text| !text.trim().is_empty())
                || self.websocket
                || self.secure_transport
                || self.authenticated.is_some()
            {
                // RFC 6120 section 5.3.3 defines TLS negotiation failure as
                // an empty <failure/> in the TLS namespace followed by a
                // terminal stream close. A stanza-style nested condition is
                // not part of this protocol and continuing would permit
                // negotiation state confusion.
                self.sm_resume_allowed = false;
                self.stream_opened = false;
                return Ok(Action::SendManyAndClose(vec![tls_failure()]));
            }
            self.stream_opened = false;
            self.stream_language = None;
            self.sasl_attempts = 0;
            self.sasl_state = None;
            self.legacy_sasl_awaiting_initial_response = false;
            self.sasl2_state = None;
            return Ok(Action::StartTls);
        }
        // XEP-0388 permits only SASL2 continuation elements while an
        // authentication exchange is active. Treating application stanzas as
        // ordinary traffic here would allow cross-protocol state confusion.
        if self.sasl2_state.is_some()
            && !matches!(
                (root.tag_name().name(), root.tag_name().namespace()),
                (
                    "response" | "abort",
                    Some(crate::xmpp::protocol::sasl2::SASL2_NS)
                )
            )
        {
            self.sasl_state = None;
            self.sasl2_state = None;
            return Ok(Action::Close);
        }
        // RFC 6120 carries legacy SASL as an exclusive stream negotiation.
        // Once a challenge is outstanding, application stanzas and other
        // negotiation protocols cannot be interleaved with the response.
        if self.sasl_state.is_some()
            && self.sasl2_state.is_none()
            && !matches!(
                (root.tag_name().name(), root.tag_name().namespace()),
                (
                    "response" | "abort",
                    Some("urn:ietf:params:xml:ns:xmpp-sasl")
                )
            )
        {
            self.sasl_state = None;
            self.legacy_sasl_awaiting_initial_response = false;
            return Ok(Action::CloseWith(stream_error("unexpected-request")));
        }
        // A selected XEP-0389 flow is a stateful stream negotiation. Do not
        // allow SASL or application stanzas to interleave with its challenge.
        if self.ibr_flow == Some(crate::xmpp::protocol::ibr::IbrFlowTransport::Stream)
            && !matches!(
                (root.tag_name().name(), root.tag_name().namespace()),
                (
                    "response" | "cancel",
                    Some(crate::xmpp::protocol::ibr::IBR2_NS)
                )
            )
        {
            self.ibr_flow = None;
            return Ok(Action::CloseWith(stream_error("unexpected-request")));
        }
        if root.tag_name().namespace() == Some("urn:xmpp:sm:3") {
            return self.stream_management(root).await;
        }
        if root.tag_name().namespace() == Some("urn:xmpp:csi:0") {
            if self.authenticated.is_none() {
                return Ok(Action::CloseWith(stream_error("not-authorized")));
            }
            if !super::csi::valid_indication(root) {
                return Ok(Action::CloseWith(stream_error("bad-format")));
            }
            return match root.tag_name().name() {
                "active" => Ok(self.client_state(true)),
                "inactive" => Ok(self.client_state(false)),
                _ => Ok(Action::CloseWith(stream_error("unsupported-stanza-type"))),
            };
        }
        if matches!(root.tag_name().name(), "iq" | "message" | "presence") {
            if !valid_client_stanza_namespace(root, self.websocket, xml) {
                return Ok(Action::CloseWith(stream_error("invalid-namespace")));
            }
            if let Err(condition) = crate::xmpp::stanza_validation::validate_client_stanza(root) {
                if root.attribute("type") == Some("error") {
                    return Ok(Action::None);
                }
                return Ok(Action::Send(stanza_error(root, "modify", condition)));
            }
            // XEP-0077/0389 may run before SASL only on an already protected
            // stream. Before STARTTLS, RFC 6120 mandatory negotiation permits
            // no application stanza exception: terminate instead of returning
            // an IQ error on the plaintext stream.
            if self.authenticated.is_none()
                && !(self.secure_transport && pre_auth_registration_iq(root))
            {
                return Ok(Action::CloseWith(stream_error("not-authorized")));
            }
            if self.authenticated.is_some() && self.full_jid.is_none() && !resource_binding_iq(root)
            {
                return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
            }
        }
        // RFC 6120 section 4.7.4 requires a receiving entity to materialize
        // the stream's default language on a stanza that omitted xml:lang
        // before routing or delivery.  An explicit stanza language never
        // changes the stream default.
        let language_xml = matches!(root.tag_name().name(), "iq" | "message" | "presence")
            .then(|| {
                self.stream_language.as_deref().and_then(|language| {
                    root.attribute(("http://www.w3.org/XML/1998/namespace", "lang"))
                        .is_none()
                        .then(|| set_root_attribute(xml, "xml:lang", language))
                })
            })
            .flatten();
        let language_doc = language_xml
            .as_deref()
            .map(Document::parse)
            .transpose()
            .expect("server language injection must remain well-formed XML");
        let root = language_doc
            .as_ref()
            .map(Document::root_element)
            .unwrap_or(root);
        let xml = language_xml.as_deref().unwrap_or(xml);

        // RFC 6120 section 8.1.2.1 makes the receiving server authoritative
        // for a C2S stanza's `from`: it MUST add or override the value supplied
        // by the client.  Subscription presence is stamped with the account's
        // bare JID; all other bound stanzas use the connected full JID.  Do
        // this once at the dispatch boundary so no downstream route can
        // accidentally trust or reflect a client-spoofed sender.
        let authoritative_xml = self.full_jid.as_deref().and_then(|full_jid| {
            matches!(root.tag_name().name(), "iq" | "message" | "presence")
                .then(|| authoritative_client_stanza(xml, root, full_jid))
        });
        let authoritative_doc = authoritative_xml
            .as_deref()
            .map(Document::parse)
            .transpose()
            .expect("server-stamped stanza must remain well-formed XML");
        let root = authoritative_doc
            .as_ref()
            .map(Document::root_element)
            .unwrap_or(root);
        let xml = authoritative_xml.as_deref().unwrap_or(xml);

        let counted = matches!(root.tag_name().name(), "iq" | "message" | "presence");
        if counted && self.full_jid.is_some() {
            *self
                .last_activity
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = std::time::Instant::now();
        }
        let action = match root.tag_name().name() {
            "authenticate"
                if root.tag_name().namespace() == Some(crate::xmpp::protocol::sasl2::SASL2_NS) =>
            {
                match self.begin_sasl_attempt() {
                    Some(action) => Ok(action),
                    None => self.authenticate2(root).await,
                }
            }
            "auth" if root.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-sasl") => {
                match self.begin_sasl_attempt() {
                    Some(action) => Ok(action),
                    None => self.authenticate(root).await,
                }
            }
            "response"
                if root.tag_name().namespace() == Some(crate::xmpp::protocol::ibr::IBR2_NS) =>
            {
                self.handle_ibr_response(root).await
            }
            "response"
                if root.tag_name().namespace() == Some(crate::xmpp::protocol::sasl2::SASL2_NS) =>
            {
                self.sasl2_response(root).await
            }
            "response"
                if root.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-sasl") =>
            {
                self.sasl_response(root).await
            }
            "abort"
                if root.tag_name().namespace() == Some(crate::xmpp::protocol::sasl2::SASL2_NS) =>
            {
                Ok(self.sasl2_abort(root))
            }
            "abort" if root.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-sasl") => {
                Ok(self.sasl_abort(root))
            }
            "register"
                if root.tag_name().namespace() == Some(crate::xmpp::protocol::ibr::IBR2_NS) =>
            {
                self.handle_ibr_register(root).await
            }
            "cancel"
                if root.tag_name().namespace() == Some(crate::xmpp::protocol::ibr::IBR2_NS) =>
            {
                Ok(self.handle_ibr_cancel(root))
            }
            "iq" => self.iq(root, xml).await,
            "message" => self.message(root, xml, client_xml).await,
            "presence" => self.presence(root, xml).await,
            _ => Ok(Action::CloseWith(stream_error("unsupported-stanza-type"))),
        }?;
        let action = if root.tag_name().name() == "iq"
            && matches!(root.attribute("type"), Some("get" | "set"))
        {
            match action {
                Action::Send(response) => {
                    let reflected = reflect_iq_error_response(root, &response);
                    Action::Send(reflected.unwrap_or(response))
                }
                action => action,
            }
        } else {
            action
        };
        if counted && self.sm_enabled {
            self.sm_inbound_h = self.sm_inbound_h.wrapping_add(1);
            self.checkpoint_sm().await?;
        }
        Ok(action)
    }

    pub(crate) async fn iq(&mut self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        // `validate_client_stanza` has already checked that every IQ has a
        // non-empty, bounded id and one of the four RFC 6120 IQ types.
        let id = root.attribute("id").unwrap_or_default();
        let kind = root.attribute("type").unwrap_or_default();
        if matches!(kind, "result" | "error") && self.handle_caps_response(id, kind, root, raw) {
            return Ok(Action::None);
        }
        if matches!(kind, "result" | "error") && self.handle_push_response(id, kind, root).await? {
            return Ok(Action::None);
        }
        if let Some(action) = self.try_mix_iq(raw).await? {
            return Ok(action);
        }
        if let (Some(user), Some(from), Some(to)) = (
            self.authenticated.as_ref(),
            self.full_jid.as_deref(),
            root.attribute("to"),
        ) {
            let target = crate::jid::CanonicalJid::parse(to)
                .expect("validated client stanza target must be canonicalizable");
            let target_domain = target.domainpart();
            let owner = format!("{}@{}", user.username, self.state.config.domain);
            if self
                .state
                .presence_service()
                .is_blocked_for_account(user.id, &owner, to)
                .await?
            {
                return if matches!(kind, "get" | "set") {
                    Ok(Action::Send(blocked_stanza_error(root)))
                } else {
                    Ok(Action::None)
                };
            }
            let active_privacy = self
                .privacy_active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            if self
                .state
                .privacy_service()
                .denies(
                    user.id,
                    active_privacy.as_deref(),
                    to,
                    PrivacyStanzaKind::Iq,
                )
                .await?
            {
                return if matches!(kind, "get" | "set") {
                    Ok(Action::Send(iq_error(id, "service-unavailable")))
                } else {
                    Ok(Action::None)
                };
            }
            if target_domain == self.state.config.domain && target.localpart().is_some() {
                if let Some(recipient) = self
                    .state
                    .presence_service()
                    .find_enabled_user(target.localpart().unwrap_or_default())
                    .await?
                {
                    let recipient_bare =
                        format!("{}@{}", recipient.username, self.state.config.domain);
                    if self
                        .state
                        .presence_service()
                        .is_blocked_for_account(recipient.id, &recipient_bare, from)
                        .await?
                    {
                        return if matches!(kind, "get" | "set") {
                            Ok(Action::Send(iq_error(id, "service-unavailable")))
                        } else {
                            Ok(Action::None)
                        };
                    }
                }
            }
        }
        let child = root.children().find(|node| node.is_element());
        if kind == "set"
            && child.is_some_and(|child| {
                child.tag_name().name() == "jingle"
                    && child.tag_name().namespace()
                        == Some(crate::xmpp::protocol::jingle::JINGLE_NS)
            })
        {
            let Some(full_jid) = self.full_jid.as_deref() else {
                return Ok(Action::Send(iq_error(id, "not-authorized")));
            };
            if let Err(condition) = crate::xmpp::protocol::jingle::validate_jingle_iq(
                root,
                child.expect("checked above"),
                Some(full_jid),
            ) {
                return Ok(Action::Send(iq_error(id, condition)));
            }
        }
        let muc_domain = self.muc_domain();
        let upload_domain = self.upload_domain();
        let caps_disco_get = is_caps_disco_get(root);
        if let Some(to) = root.attribute("to") {
            if let Ok(target_jid) = crate::jid::CanonicalJid::parse(to) {
                let domain = target_jid.domainpart();
                if domain == self.state.config.domain
                    && target_jid.localpart().is_some()
                    && self
                        .state
                        .presence_service()
                        .find_enabled_user(target_jid.localpart().unwrap_or_default())
                        .await?
                        .is_none()
                {
                    // RFC 6121 section 8.5.1 requires service-unavailable for
                    // an IQ request addressed to a nonexistent local account.
                    // IQ responses remain terminal under RFC 6120 section
                    // 8.2.3 and therefore cannot be answered here.
                    return if missing_full_jid_iq_needs_error(kind) {
                        Ok(Action::Send(stanza_error(
                            root,
                            "cancel",
                            "service-unavailable",
                        )))
                    } else {
                        Ok(Action::None)
                    };
                }
                if domain == self.state.config.domain && target_jid.resourcepart().is_some() {
                    // RFC 6121 section 8.5.3.1 applies this presence-leak
                    // protection to every IQ get/set addressed to an exact
                    // full JID, not only to capability discovery.  The same
                    // account is necessarily entitled to address its own
                    // resources; other entities need a from/both subscription
                    // or a directed-presence grant from the target resource.
                    if matches!(kind, "get" | "set") {
                        let Some(target_name) = target_jid.localpart() else {
                            return Ok(Action::Send(stanza_error(
                                root,
                                "cancel",
                                "service-unavailable",
                            )));
                        };
                        let Some(target_user) = self
                            .state
                            .presence_service()
                            .find_enabled_user(target_name)
                            .await?
                        else {
                            return Ok(Action::Send(stanza_error(
                                root,
                                "cancel",
                                "service-unavailable",
                            )));
                        };
                        let requester = self.full_jid.as_deref().unwrap_or_default();
                        let requester_bare = crate::jid::canonical_bare_key(requester)
                            .expect("authenticated full JIDs are canonical");
                        let same_account = requester_bare
                            == format!("{}@{}", target_user.username, self.state.config.domain);
                        let subscribed = self
                            .state
                            .presence_service()
                            .roster_subscription(target_user.id, &requester_bare)
                            .await?
                            .is_some_and(|subscription| {
                                matches!(subscription.as_str(), "from" | "both")
                            });
                        let directed =
                            self.state
                                .session_entries_for(to)
                                .into_iter()
                                .any(|(_, session)| {
                                    session.directed_presence.iter().any(|authorized| {
                                        super::presence::directed_recipient_matches(
                                            authorized.key(),
                                            requester,
                                        )
                                    })
                                });
                        if !full_jid_iq_visible(same_account, subscribed, directed) {
                            return Ok(Action::Send(stanza_error(
                                root,
                                "cancel",
                                "service-unavailable",
                            )));
                        }
                    }
                    // RFC 6121 section 8.5.3.2.3 requires
                    // service-unavailable when an IQ request targets a
                    // missing exact resource. Its broad wording cannot make
                    // an IQ response into a new request: RFC 6120 section
                    // 8.2.3 says an entity MUST NOT respond to an IQ
                    // result/error (and section 8.3.1 independently forbids
                    // an error loop). Check this before a server-side
                    // XEP-0115 cache can answer for a stale resource.
                    let local_resource_matches = !self.state.session_entries_for(to).is_empty();
                    let remote_resource_matches = self
                        .state
                        .cluster
                        .lookup_nodes(to)
                        .await
                        .is_ok_and(|nodes| {
                            nodes
                                .iter()
                                .any(|node_id| node_id != &self.state.cluster.node_id)
                        });
                    if !local_resource_matches && !remote_resource_matches {
                        return if missing_full_jid_iq_needs_error(kind) {
                            Ok(Action::Send(stanza_error(
                                root,
                                "cancel",
                                "service-unavailable",
                            )))
                        } else {
                            Ok(Action::None)
                        };
                    }
                    if caps_disco_get {
                        if let Some(result) = super::caps::cached_disco_result(
                            &self.state,
                            id,
                            to,
                            child.and_then(|child| child.attribute("node")),
                        ) {
                            return Ok(Action::Send(result));
                        }
                    }
                    let from = self.full_jid.as_deref().unwrap_or("");
                    let rewritten = set_from(raw, from);
                    let targets = self.state.session_entries_for(to);
                    let mut delivered = false;
                    for (_, target) in targets {
                        if self
                            .state
                            .privacy_allows_session(&target, from, PrivacyStanzaKind::Iq)
                            .await?
                            && target.sender.try_send(rewritten.clone()).is_ok()
                        {
                            delivered = true;
                            break;
                        }
                    }
                    if !delivered {
                        if let Ok(nodes) = self.state.cluster.lookup_nodes(to).await {
                            for node_id in nodes {
                                if node_id != self.state.cluster.node_id
                                    && self
                                        .state
                                        .cluster
                                        .send_to_node(&node_id, to, &rewritten, false, None)
                                        .await
                                        .unwrap_or(false)
                                {
                                    delivered = true;
                                    break;
                                }
                            }
                        }
                    }
                    if delivered {
                        return Ok(Action::None);
                    } else {
                        if kind == "get" || kind == "set" {
                            return Ok(Action::Send(iq_error(id, "service-unavailable")));
                        } else {
                            return Ok(Action::None);
                        }
                    }
                } else if domain == muc_domain && target_jid.resourcepart().is_some() {
                    let to_jid = target_jid;
                    let room_jid = to_jid.bare();
                    let Some(target_nick) = to_jid.resourcepart() else {
                        return Ok(Action::Send(iq_error(id, "jid-malformed")));
                    };
                    let is_ping = kind == "get"
                        && root.children().filter(|node| node.is_element()).count() == 1
                        && root.children().any(|node| {
                            node.is_element()
                                && node.tag_name().name() == "ping"
                                && node.tag_name().namespace() == Some("urn:xmpp:ping")
                        });
                    if is_ping
                        && self
                            .authorized_muc_occupant(&room_jid)
                            .await?
                            .is_some_and(|occupant| occupant.nick == target_nick)
                    {
                        let full_jid = self.full_jid.as_deref().unwrap_or_default();
                        return Ok(Action::Send(set_to(&iq_result_from(id, to, ""), full_jid)));
                    }
                    let target_key =
                        crate::xmpp::xml_util::muc_occupant_key(&room_jid, target_nick);
                    let Some(target) = self
                        .state
                        .muc_occupants
                        .get(&target_key)
                        .map(|entry| entry.value().clone())
                    else {
                        if kind == "get" || kind == "set" {
                            return Ok(Action::Send(iq_error(id, "item-not-found")));
                        } else {
                            return Ok(Action::None);
                        }
                    };
                    let Some(own) = self.authorized_muc_occupant(&room_jid).await? else {
                        if kind == "get" || kind == "set" {
                            return Ok(Action::Send(iq_error(id, "not-acceptable")));
                        } else {
                            return Ok(Action::None);
                        }
                    };
                    // XEP-0191 applies before MUC-mediated IQ delivery.  The
                    // recipient may have blocked either the visible occupant
                    // address or the sender's real JID.  The latter is not
                    // placed on the wire, but the local MUC service knows it
                    // and must enforce it without disclosing which rule
                    // matched.  IQ errors are never answered with another
                    // error.
                    let own_nick = own.nick;
                    let mut blocking_candidates = vec![format!("{room_jid}/{own_nick}")];
                    if let Some(full_jid) = self.full_jid.as_deref() {
                        blocking_candidates.push(full_jid.to_owned());
                    }
                    let blocked = self
                        .state
                        .blocked_muc_recipient_accounts(
                            std::slice::from_ref(&target),
                            &blocking_candidates,
                        )
                        .await;
                    if crate::jid::canonical_bare_key(&target.full_jid)
                        .is_ok_and(|owner| blocked.contains(&owner))
                    {
                        if kind == "get" || kind == "set" {
                            return Ok(Action::Send(iq_error(id, "service-unavailable")));
                        }
                        return Ok(Action::None);
                    }

                    let rewritten = set_to(
                        &set_from(raw, &format!("{}/{}", room_jid, own_nick)),
                        &target.full_jid,
                    );
                    tracing::debug!(room=%room_jid, from=%own_nick, to=%target.full_jid, "MUC routing IQ");
                    let _ = self.state.deliver_to_muc_occupant(&target, rewritten).await;
                    return Ok(Action::None);
                }
            }
        }

        let remote_iq_domain = root.attribute("to").and_then(|to| {
            let target = crate::jid::CanonicalJid::parse(to).ok()?;
            let domain = target.domainpart();
            (domain != self.state.config.domain
                && domain != muc_domain
                && domain != upload_domain
                && domain != self.pubsub_domain()
                && domain != self.mix_domain())
            .then(|| domain.to_owned())
        });
        if let Some(domain) = remote_iq_domain.as_deref() {
            let Some(from) = self.full_jid.as_deref() else {
                return Ok(Action::Send(iq_error(id, "not-authorized")));
            };
            if !self.state.config.external_route_domain_allowed(domain) {
                return Ok(Action::Send(iq_error(id, "remote-server-not-found")));
            }
            if !self
                .state
                .federation
                .send(domain, set_from(raw, from), Some(from.to_owned()))
                .await
            {
                return Ok(Action::Send(iq_error(id, "remote-server-timeout")));
            }
            return Ok(Action::None);
        }
        // Results and errors addressed to the server are responses, never new
        // requests.  Known correlations were consumed above; silently ignore
        // anything else rather than creating an IQ error loop.
        if matches!(kind, "result" | "error") {
            return Ok(Action::None);
        }
        let Some(child) = child else {
            // Defensive fallback; get/set cardinality is checked before this
            // method is entered.
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        let ns = child.tag_name().namespace().unwrap_or_default();
        let is_local_muc_room = root
            .attribute("to")
            .is_some_and(|to| super::muc::canonical_local_muc_room(to, &muc_domain).is_some());
        match (child.tag_name().name(), ns, kind) {
            ("command", "http://jabber.org/protocol/commands", "set") => {
                super::commands::handle(self, id, root, child).await
            }
            ("query", "jabber:iq:register", "get") if is_local_muc_room => {
                self.muc_register_get(id, root).await
            }
            ("query", "jabber:iq:register", "set") if is_local_muc_room => {
                self.muc_register_set(id, root, child).await
            }
            ("query", "jabber:iq:register", "get") => self.registration_form(id, child).await,
            ("query", "jabber:iq:register", "set") if self.authenticated.is_none() => {
                self.register(id, child).await
            }
            ("query", "jabber:iq:register", "set") => self.change_password(id, child).await,
            ("register", crate::xmpp::protocol::ibr::IBR2_NS, "get") => {
                Ok(self.ibr_flows_iq(id, child))
            }
            ("register", crate::xmpp::protocol::ibr::IBR2_NS, "set") => {
                self.select_ibr_flow_iq(id, child).await
            }
            ("response", crate::xmpp::protocol::ibr::IBR2_NS, "set") => {
                self.handle_ibr_response_iq(id, child).await
            }
            ("cancel", crate::xmpp::protocol::ibr::IBR2_NS, "set") => {
                Ok(self.handle_ibr_cancel_iq(id, child))
            }
            ("bind", "urn:ietf:params:xml:ns:xmpp-bind", "set") => {
                if !valid_bind_payload(child) {
                    Ok(Action::Send(iq_error(id, "bad-request")))
                } else {
                    self.bind(id, child).await
                }
            }
            ("session", "urn:ietf:params:xml:ns:xmpp-session", "set") => {
                if valid_empty_iq_payload(child) {
                    Ok(Action::Send(iq_result(id, "")))
                } else {
                    Ok(Action::Send(iq_error(id, "bad-request")))
                }
            }
            ("query", "jabber:iq:roster", "get") => self.roster_get(id, root, child).await,
            ("query", "jabber:iq:roster", "set") => self.roster_set(id, root, child).await,
            ("query", "jabber:iq:privacy", "get") => self.privacy_get(id, root, child).await,
            ("query", "jabber:iq:privacy", "set") => self.privacy_set(id, root, child).await,
            ("unique", "http://jabber.org/protocol/muc#unique", "get") => {
                Ok(Action::Send(iq_result_from(
                    id,
                    root.attribute("to").unwrap_or(&muc_domain),
                    &format!(
                        "<unique xmlns='http://jabber.org/protocol/muc#unique'>{}</unique>",
                        uuid::Uuid::new_v4()
                    ),
                )))
            }
            ("query", "http://jabber.org/protocol/muc#owner", "get") => {
                self.muc_owner_get(id, root).await
            }
            ("query", "http://jabber.org/protocol/muc#owner", "set") => {
                self.muc_owner_set(id, root, child).await
            }
            ("query", "http://jabber.org/protocol/muc#admin", "get") => {
                self.muc_admin_get(id, root, child).await
            }
            ("query", "http://jabber.org/protocol/muc#admin", "set") => {
                self.muc_admin_set(id, root, child).await
            }
            ("moderate", "urn:xmpp:message-moderate:1", "set") => {
                self.muc_moderate(id, root, child).await
            }
            ("query", "http://jabber.org/protocol/disco#info", "get") => {
                self.disco_info(id, root.attribute("to"), child).await
            }
            ("query", "http://jabber.org/protocol/disco#items", "get") => {
                self.disco_items(id, root.attribute("to"), child).await
            }
            ("ping", "urn:xmpp:ping", "get") => Ok(Action::Send(iq_result(id, ""))),
            ("time", "urn:xmpp:time", "get") => {
                let now = chrono::Utc::now();
                let payload = format!(
                    "<time xmlns='urn:xmpp:time'><tzo>+00:00</tzo><utc>{}</utc></time>",
                    now.format("%Y-%m-%dT%H:%M:%SZ")
                );
                Ok(Action::Send(iq_result(id, &payload)))
            }
            ("query", "jabber:iq:version", "get") => Ok(Action::Send(iq_result(
                id,
                &format!(
                    "<query xmlns='jabber:iq:version'><name>{}</name><version>{}</version><os>{}</os></query>",
                    crate::state::xml_escape(&self.state.config.server_name),
                    env!("CARGO_PKG_VERSION"),
                    xmpp_version_os()
                ),
            ))),
            ("services", "urn:xmpp:extdisco:2", "get") => self.external_services(id, root, child),
            ("credentials", "urn:xmpp:extdisco:2", "get") => {
                self.external_credentials(id, root, child)
            }
            ("vCard", "vcard-temp", "get") => self.vcard_get(id, root).await,
            ("vCard", "vcard-temp", "set") => self.vcard_set(id, root, child, raw).await,
            ("enable", "urn:xmpp:push:0", "set") => self.enable_push(id, root, child, raw).await,
            ("disable", "urn:xmpp:push:0", "set") => self.disable_push(id, root, child).await,
            ("request", "urn:xmpp:http:upload:0", "get") => {
                self.http_upload_slot(id, root.attribute("to"), child).await
            }
            // XEP-0363 defines slot allocation as an IQ-get. The upload
            // service is known and implemented, so using IQ-set is a
            // malformed request rather than an unknown feature.
            ("request", "urn:xmpp:http:upload:0", _) => Ok(Action::Send(iq_error_from(
                id,
                &self.upload_domain(),
                "bad-request",
            ))),
            ("query", "urn:xmpp:mam:2", "set") => self.mam(id, child, root.attribute("to")).await,
            ("query", "urn:xmpp:mam:2", "get") => {
                self.mam_query_form(id, root.attribute("to"), child).await
            }
            ("metadata", "urn:xmpp:mam:2", "get") => {
                self.mam_metadata(id, root.attribute("to"), child).await
            }
            ("prefs", "urn:xmpp:mam:2", "get") => {
                self.mam_preferences_get(id, root.attribute("to"), child)
                    .await
            }
            ("prefs", "urn:xmpp:mam:2", "set") => {
                self.mam_preferences_set(id, root.attribute("to"), child)
                    .await
            }
            ("enable", "urn:xmpp:carbons:2", "set") => self.set_carbons(id, root, child, true),
            ("disable", "urn:xmpp:carbons:2", "set") => self.set_carbons(id, root, child, false),
            ("blocklist", "urn:xmpp:blocking", "get") => self.blocklist(id, root, child).await,
            ("block", "urn:xmpp:blocking", "set") => self.block(id, root, child).await,
            ("unblock", "urn:xmpp:blocking", "set") => self.unblock(id, root, child).await,
            ("pubsub", "http://jabber.org/protocol/pubsub", "set") => {
                if root
                    .attribute("to")
                    .is_some_and(|to| is_service_jid(to, &self.pubsub_domain()))
                {
                    self.pubsub_iq_set(id, child, root.attribute("to").unwrap_or(""))
                        .await
                } else {
                    let result = self.pep_publish(id, root, child, raw).await;
                    map_pubsub_capacity_result(id, result)
                }
            }
            ("pubsub", "http://jabber.org/protocol/pubsub", "get") => {
                if root
                    .attribute("to")
                    .is_some_and(|to| is_service_jid(to, &self.pubsub_domain()))
                {
                    self.pubsub_iq_get(id, child).await
                } else {
                    self.pep_get(id, root, child).await
                }
            }
            ("pubsub", "http://jabber.org/protocol/pubsub#owner", "set")
                if root
                    .attribute("to")
                    .is_some_and(|to| is_service_jid(to, &self.pubsub_domain())) =>
            {
                self.pubsub_owner_set(id, child).await
            }
            ("pubsub", "http://jabber.org/protocol/pubsub#owner", "set") => {
                let result = self.pep_owner_set(id, root, child).await;
                map_pubsub_capacity_result(id, result)
            }
            ("pubsub", "http://jabber.org/protocol/pubsub#owner", "get")
                if root
                    .attribute("to")
                    .is_some_and(|to| is_service_jid(to, &self.pubsub_domain())) =>
            {
                self.pubsub_owner_get(id, child).await
            }
            ("pubsub", "http://jabber.org/protocol/pubsub#owner", "get") => {
                self.pep_owner_get(id, root, child).await
            }
            ("query", "jabber:iq:private", "get") => {
                self.private_get(id, root.attribute("to"), child).await
            }
            ("query", "jabber:iq:private", "set") => {
                self.private_set(id, root.attribute("to"), child, raw).await
            }
            _ => {
                tracing::debug!(
                    element = child.tag_name().name(),
                    namespace = ns,
                    iq_type = kind,
                    iq_id = id,
                    "unsupported IQ"
                );
                Ok(Action::Send(iq_error(id, "feature-not-implemented")))
            }
        }
    }
}

fn is_service_jid(value: &str, service_domain: &str) -> bool {
    crate::jid::CanonicalJid::parse(value).is_ok_and(|jid| {
        jid.localpart().is_none()
            && jid.resourcepart().is_none()
            && jid.domainpart() == service_domain
    })
}

pub(crate) fn is_caps_disco_get(root: Node<'_, '_>) -> bool {
    root.tag_name().name() == "iq"
        && root.attribute("type") == Some("get")
        && root.children().find(Node::is_element).is_some_and(|child| {
            child.tag_name().name() == "query"
                && child.tag_name().namespace() == Some("http://jabber.org/protocol/disco#info")
        })
}

fn full_jid_iq_visible(same_account: bool, subscribed: bool, directed: bool) -> bool {
    same_account || subscribed || directed
}

fn missing_full_jid_iq_needs_error(kind: &str) -> bool {
    matches!(kind, "get" | "set")
}

fn is_websocket_open(xml: &str) -> bool {
    let Ok(document) = Document::parse(xml) else {
        return false;
    };
    let root = document.root_element();
    root.tag_name().name() == "open"
        && root.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-framing")
}

fn is_stream_close(xml: &str) -> bool {
    xml.strip_prefix("</stream:stream")
        .and_then(|suffix| suffix.strip_suffix('>'))
        .is_some_and(|trailing| trailing.trim().is_empty())
}

fn tls_failure() -> String {
    "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>".to_owned()
}

fn authoritative_client_stanza(xml: &str, root: Node<'_, '_>, full_jid: &str) -> String {
    let subscription_presence = root.tag_name().name() == "presence"
        && matches!(
            root.attribute("type"),
            Some("subscribe" | "subscribed" | "unsubscribe" | "unsubscribed")
        );
    let from = if subscription_presence {
        bare_jid(full_jid)
    } else {
        full_jid
    };
    set_from(xml, from)
}

fn pre_auth_registration_iq(root: Node<'_, '_>) -> bool {
    if root.tag_name().name() != "iq" || !matches!(root.attribute("type"), Some("get" | "set")) {
        return false;
    }
    let mut children = root.children().filter(|child| child.is_element());
    let Some(child) = children.next() else {
        return false;
    };
    children.next().is_none()
        && matches!(
            (child.tag_name().name(), child.tag_name().namespace()),
            ("query", Some("jabber:iq:register"))
                | ("register", Some(crate::xmpp::protocol::ibr::IBR2_NS))
        )
}

fn resource_binding_iq(root: Node<'_, '_>) -> bool {
    if root.tag_name().name() != "iq" || root.attribute("type") != Some("set") {
        return false;
    }
    let mut children = root.children().filter(|child| child.is_element());
    let Some(child) = children.next() else {
        return false;
    };
    children.next().is_none()
        && child.tag_name().name() == "bind"
        && child.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-bind")
}

fn valid_bind_payload(bind: Node<'_, '_>) -> bool {
    if bind.attributes().len() != 0
        || bind.children().any(|child| {
            child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return false;
    }
    let children = bind
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    match children.as_slice() {
        [] => true,
        [resource] => {
            resource.tag_name().name() == "resource"
                && resource.tag_name().namespace() == bind.tag_name().namespace()
                && resource.attributes().len() == 0
                && !resource.children().any(|child| child.is_element())
                && resource.text().is_some_and(|text| !text.is_empty())
        }
        _ => false,
    }
}

fn valid_empty_iq_payload(payload: Node<'_, '_>) -> bool {
    payload.attributes().len() == 0
        && !payload.children().any(|child| child.is_element())
        && payload.text().is_none_or(|text| text.trim().is_empty())
}

fn valid_client_stanza_namespace(root: Node<'_, '_>, websocket: bool, raw: &str) -> bool {
    match root.tag_name().namespace() {
        Some("jabber:client") => true,
        // In a TCP XML stream the default `jabber:client` namespace is
        // inherited from the open stream element, which is deliberately not
        // present in the standalone frame passed to roxmltree.
        None => !websocket && !root_resets_default_namespace(raw),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        authoritative_client_stanza, full_jid_iq_visible, is_caps_disco_get, is_stream_close,
        missing_full_jid_iq_needs_error, pre_auth_registration_iq, resource_binding_iq,
        tls_failure, valid_bind_payload, valid_client_stanza_namespace, valid_empty_iq_payload,
        xmpp_version_os,
    };
    use crate::xmpp::stanza_validation::validate_client_stanza;
    use roxmltree::Document;

    fn with_root(xml: &str, check: impl FnOnce(roxmltree::Node<'_, '_>)) {
        let document = Document::parse(xml).expect("test stanza must be XML");
        check(document.root_element());
    }

    #[test]
    fn version_response_reports_the_compilation_target_os() {
        let expected = match std::env::consts::OS {
            "linux" => "Linux",
            "windows" => "Windows",
            "macos" => "macOS",
            other => other,
        };
        assert_eq!(xmpp_version_os(), expected);
    }

    #[test]
    fn websocket_stanzas_require_the_client_namespace() {
        with_root("<message/>", |root| {
            assert!(!valid_client_stanza_namespace(root, true, "<message/>"));
            assert!(valid_client_stanza_namespace(root, false, "<message/>"));
        });
        with_root("<message xmlns='jabber:client'/>", |root| {
            assert!(valid_client_stanza_namespace(
                root,
                true,
                "<message xmlns='jabber:client'/>"
            ));
        });
        with_root("<message xmlns='urn:evil'/>", |root| {
            assert!(!valid_client_stanza_namespace(
                root,
                false,
                "<message xmlns='urn:evil'/>"
            ));
        });
        with_root("<message xmlns=''/>", |root| {
            assert!(!valid_client_stanza_namespace(
                root,
                false,
                "<message xmlns=''/>"
            ));
        });
    }

    #[test]
    fn tcp_stream_close_accepts_only_xml_whitespace_before_the_delimiter() {
        assert!(is_stream_close("</stream:stream>"));
        assert!(is_stream_close("</stream:stream \r\n>"));
        assert!(!is_stream_close("</stream:stream bogus>"));
        assert!(!is_stream_close("</stream:streams>"));
    }

    #[test]
    fn starttls_failure_uses_the_terminal_rfc6120_shape() {
        let failure = tls_failure();
        assert_eq!(
            failure,
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
        );
        assert!(!failure.contains("unexpected-request"));
    }

    #[test]
    fn c2s_sender_is_always_server_authoritative() {
        with_root(
            "<message from='mallory@example.test/Other'><body>Hello</body></message>",
            |root| {
                let stamped = authoritative_client_stanza(
                    "<message from='mallory@example.test/Other'><body>Hello</body></message>",
                    root,
                    "alice@example.test/Phone",
                );
                with_root(&stamped, |stamped_root| {
                    assert_eq!(
                        stamped_root.attribute("from"),
                        Some("alice@example.test/Phone")
                    );
                });
            },
        );
        with_root(
            "<presence type='subscribe' to='bob@example.test'/>",
            |root| {
                let stamped = authoritative_client_stanza(
                    "<presence type='subscribe' to='bob@example.test'/>",
                    root,
                    "alice@example.test/Phone",
                );
                with_root(&stamped, |stamped_root| {
                    assert_eq!(stamped_root.attribute("from"), Some("alice@example.test"));
                });
            },
        );
    }

    #[test]
    fn unentitled_full_jid_caps_disco_is_hidden() {
        with_root(
            "<iq type='get' id='caps' to='bob@example.test/Phone'><query xmlns='http://jabber.org/protocol/disco#info' node='client#hash'/></iq>",
            |root| assert!(is_caps_disco_get(root)),
        );
        assert!(!full_jid_iq_visible(false, false, false));
        assert!(full_jid_iq_visible(true, false, false));
        assert!(full_jid_iq_visible(false, true, false));
        assert!(full_jid_iq_visible(false, false, true));
    }

    #[test]
    fn full_jid_jingle_is_subject_to_the_same_presence_leak_gate() {
        with_root(
            "<iq type='set' id='info' to='alice@example.test/Phone'><jingle xmlns='urn:xmpp:jingle:1' action='session-info' sid='s'><ringing xmlns='urn:xmpp:jingle:apps:rtp:info:1'/></jingle></iq>",
            |root| assert!(!is_caps_disco_get(root)),
        );
        assert!(!full_jid_iq_visible(false, false, false));
    }

    #[test]
    fn missing_full_jid_iq_never_creates_a_result_or_error_loop() {
        assert!(missing_full_jid_iq_needs_error("get"));
        assert!(missing_full_jid_iq_needs_error("set"));
        assert!(!missing_full_jid_iq_needs_error("result"));
        assert!(!missing_full_jid_iq_needs_error("error"));
    }

    #[test]
    fn iq_type_id_and_payload_cardinality_are_strict() {
        for valid in [
            "<iq type='get' id='g'><ping/></iq>",
            "<iq type='set' id='s'><query/></iq>",
            "<iq type='result' id='r'/>",
            "<iq type='result' id='r2'><query/></iq>",
            "<iq type='error' id='e'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
            "<iq type='error' id='e2'><query/><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
        ] {
            with_root(valid, |root| {
                assert_eq!(validate_client_stanza(root), Ok(()))
            });
        }
        for invalid in [
            "<iq id='missing-type'><ping/></iq>",
            "<iq type='get'><ping/></iq>",
            "<iq type='get' id='empty'/>",
            "<iq type='set' id='many'><a/><b/></iq>",
            "<iq type='result' id='many'><a/><b/></iq>",
            "<iq type='error' id='missing-error'><query/></iq>",
            "<iq type='error' id='duplicate-error'><error/><error/></iq>",
            "<iq type='error' id='malformed-error'><error/></iq>",
            "<iq type='invented' id='bad'><query/></iq>",
        ] {
            with_root(invalid, |root| {
                assert_eq!(validate_client_stanza(root), Err("bad-request"))
            });
        }
    }

    #[test]
    fn stanza_types_ids_and_jids_are_bounded_and_validated() {
        with_root(
            "<message type='chat' to='Alice@Example.test/Phone'/>",
            |root| {
                assert_eq!(validate_client_stanza(root), Ok(()));
            },
        );
        for valid in [
            "<presence xml:lang='en'><priority> 1 </priority><show>away</show><status>Busy</status><status xml:lang='ja'>多忙</status></presence>",
            "<message xmlns:x='urn:example:extension' x:trace='ok'><body>Hello</body><body xml:lang='fr'>Salut</body><thread parent='older'>newer</thread></message>",
            "<presence type='error' to='alice@example.test'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'>Offline</text></error></presence>",
            "<message type='error'><error type='cancel'><gone xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'>xmpp:new@example.test</gone></error></message>",
            "<message type='error'><error type='cancel'><future-condition xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
        ] {
            with_root(valid, |root| {
                assert_eq!(validate_client_stanza(root), Ok(()))
            });
        }
        for invalid in [
            "<message type='invented'/>",
            "<presence type='available'/>",
            "<presence type='invented'/>",
            "<presence><priority>128</priority></presence>",
            "<presence><priority>1</priority><priority>2</priority></presence>",
            "<presence><show>online</show></presence>",
            "<presence type='unavailable'><priority>1</priority></presence>",
            "<presence type='subscribe'><show>away</show></presence>",
            "<presence type='subscribe'/>",
            "<presence type='probe'/>",
            "<presence type='error'/>",
            "<presence type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>",
            "<message><body>one</body><body>two</body></message>",
            "<message><body><b>nested</b></body></message>",
            "<message invented='value'/>",
            "<message xml:lang='en--US'/>",
            "<message><body xml:lang='not_a_tag'>bad</body></message>",
            "<message type='error'><error type='cancel'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
            "<message type='error'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'>must be empty</bad-request></error></message>",
            "<message to='alice@bad domain'/>",
            "<message id=''/>",
        ] {
            with_root(invalid, |root| {
                assert!(validate_client_stanza(root).is_err())
            });
        }
    }

    #[test]
    fn explicit_stream_namespace_cannot_bypass_core_child_validation() {
        for invalid in [
            "<message><body xmlns='jabber:client'><nested/></body></message>",
            "<message><body xml:lang='en'/><body xmlns='jabber:client' xml:lang='EN'/></message>",
        ] {
            with_root(invalid, |root| {
                assert_eq!(validate_client_stanza(root), Err("bad-request"))
            });
        }
    }

    #[test]
    fn negotiation_phase_helpers_allow_only_registration_and_binding() {
        for allowed in [
            "<iq type='get' id='r'><query xmlns='jabber:iq:register'/></iq>",
            "<iq type='set' id='r'><register xmlns='urn:xmpp:register:0'/></iq>",
        ] {
            with_root(allowed, |root| assert!(pre_auth_registration_iq(root)));
        }
        for denied in [
            "<message><body>pre-auth</body></message>",
            "<iq type='get' id='d'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>",
            "<iq type='result' id='r'><query xmlns='jabber:iq:register'/></iq>",
        ] {
            with_root(denied, |root| assert!(!pre_auth_registration_iq(root)));
        }

        with_root(
            "<iq type='set' id='b'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>Phone</resource></bind></iq>",
            |root| assert!(resource_binding_iq(root)),
        );
        for denied in [
            "<iq type='get' id='b'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq>",
            "<iq type='set' id='x'><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>",
        ] {
            with_root(denied, |root| assert!(!resource_binding_iq(root)));
        }

        for valid in [
            "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>",
            "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>Phone</resource></bind>",
        ] {
            with_root(valid, |root| assert!(valid_bind_payload(root)));
        }
        for invalid in [
            "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind' extra='x'/>",
            "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource/><resource>two</resource></bind>",
            "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource><nested/></resource></bind>",
            "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>a@example.test/r</jid></bind>",
        ] {
            with_root(invalid, |root| assert!(!valid_bind_payload(root)));
        }
        with_root(
            "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>",
            |root| assert!(valid_empty_iq_payload(root)),
        );
        with_root(
            "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'><extra/></session>",
            |root| assert!(!valid_empty_iq_payload(root)),
        );
    }
}
