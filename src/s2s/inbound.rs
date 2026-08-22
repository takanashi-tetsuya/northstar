use crate::{
    db,
    state::{attr_escape, bare_jid, jid_domain, localpart, AppState},
    xmpp::xml_util::*,
};
use anyhow::{Context, Result};
use roxmltree::Document;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;

use super::*;

pub async fn serve(
    state: Arc<AppState>,
    mut outbound: mpsc::Receiver<FederationEnvelope>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    if !state.config.federation_enabled {
        tracing::warn!("server-to-server federation is disabled by policy");
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                envelope = outbound.recv() => {
                    if envelope.is_none() {
                        return Ok(());
                    }
                }
            }
        }
    }
    let listener = TcpListener::bind(state.config.s2s_bind)
        .await
        .with_context(|| format!("could not bind S2S listener to {}", state.config.s2s_bind))?;
    let acceptor = TlsAcceptor::from(s2s_server_config(&state)?);
    tracing::info!(address = %state.config.s2s_bind, "XMPP S2S listener ready");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                state.metrics.federation_inbound_connections_total.fetch_add(1, Ordering::Relaxed);
                let state = Arc::clone(&state);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Err(error) = inbound_connection(stream, state, acceptor).await {
                        tracing::debug!(%peer, ?error, "inbound federation stream closed");
                    }
                });
            }
            envelope = outbound.recv() => {
                let Some(envelope) = envelope else { return Ok(()) };
                let sender = get_or_create_outbound(&state, &envelope.target_domain);
                if sender.try_send(envelope.clone()).is_err() {
                    tracing::warn!(domain = %envelope.target_domain, "failed to queue federation envelope");
                    bounce_delivery_failure(&state, &envelope);
                }
            }
        }
    }
}

pub(crate) async fn inbound_connection(
    mut stream: TcpStream,
    state: Arc<AppState>,
    acceptor: TlsAcceptor,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let mut buffer = String::new();
    let opening = timed_read_frame(&mut stream, &mut buffer).await?;
    let claimed_domain = stream_attribute(&opening, "from").unwrap_or_default();
    let target = stream_attribute(&opening, "to").unwrap_or_default();
    if !target.eq_ignore_ascii_case(&state.config.domain)
        || !state.config.federation_domain_allowed(&claimed_domain)
    {
        send_stream_error(&mut stream, "host-unknown").await?;
        anyhow::bail!("federation domain rejected by policy");
    }
    write_xml(
        &mut stream,
        &server_open(
            &state.config.domain,
            &claimed_domain,
            &stream_id().to_string(),
        ),
    )
    .await?;
    write_xml(
        &mut stream,
        "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>",
    )
    .await?;
    let starttls = timed_read_frame(&mut stream, &mut buffer).await?;
    if !starttls.starts_with("<starttls") {
        send_stream_error(&mut stream, "policy-violation").await?;
        anyhow::bail!("remote server did not negotiate STARTTLS");
    }
    write_xml(
        &mut stream,
        "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
    )
    .await?;
    let mut secure = tokio::time::timeout(IO_TIMEOUT, acceptor.accept(stream))
        .await
        .context("inbound S2S TLS handshake timed out")??;
    let peer_certificates = secure
        .get_ref()
        .1
        .peer_certificates()
        .map(|certificates| certificates.to_vec())
        .unwrap_or_default();
    buffer.clear();
    let opening = timed_read_frame(&mut secure, &mut buffer).await?;
    let asserted_domain = stream_attribute(&opening, "from").unwrap_or_default();
    let target = stream_attribute(&opening, "to").unwrap_or_default();
    if !asserted_domain.eq_ignore_ascii_case(&claimed_domain)
        || !target.eq_ignore_ascii_case(&state.config.domain)
    {
        anyhow::bail!("S2S stream identity changed after TLS");
    }
    write_xml(
        &mut secure,
        &server_open(
            &state.config.domain,
            &asserted_domain,
            &stream_id().to_string(),
        ),
    )
    .await?;
    write_xml(
        &mut secure,
        "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>",
    )
    .await?;
    let authentication = timed_read_frame(&mut secure, &mut buffer).await?;
    let auth_document = Document::parse(&authentication).context("invalid S2S SASL stanza")?;
    let auth_element = auth_document.root_element();
    if auth_element.tag_name().name() != "auth"
        || auth_element.attribute("mechanism") != Some("EXTERNAL")
    {
        write_xml(
            &mut secure,
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure>",
        )
        .await?;
        anyhow::bail!("remote server did not use SASL EXTERNAL");
    }
    let authorization = decode_external(auth_element.text().unwrap_or_default())?;
    let authenticated_domain = if authorization.is_empty() {
        asserted_domain.clone()
    } else {
        authorization.to_ascii_lowercase()
    };
    if authenticated_domain != asserted_domain
        || !verify_peer_domain(&state, &peer_certificates, &authenticated_domain)?
    {
        write_xml(
            &mut secure,
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>",
        )
        .await?;
        anyhow::bail!("S2S certificate does not authorize the asserted domain");
    }
    write_xml(
        &mut secure,
        "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>",
    )
    .await?;
    buffer.clear();
    let opening = timed_read_frame(&mut secure, &mut buffer).await?;
    if stream_attribute(&opening, "from").as_deref() != Some(authenticated_domain.as_str())
        || stream_attribute(&opening, "to").as_deref() != Some(state.config.domain.as_str())
    {
        anyhow::bail!("invalid post-SASL S2S stream identity");
    }
    write_xml(
        &mut secure,
        &server_open(
            &state.config.domain,
            &authenticated_domain,
            &stream_id().to_string(),
        ),
    )
    .await?;
    write_xml(&mut secure, "<stream:features/>").await?;

    loop {
        let frame = timed_read_frame(&mut secure, &mut buffer).await?;
        if frame.starts_with("</stream:stream") {
            write_xml(&mut secure, "</stream:stream>").await?;
            return Ok(());
        }
        if let Some(reply) = route_inbound(&state, &authenticated_domain, &frame).await? {
            write_xml(&mut secure, &server_namespace(&reply)).await?;
        }
    }
}

pub(crate) async fn route_inbound(
    state: &AppState,
    authenticated_domain: &str,
    raw: &str,
) -> Result<Option<String>> {
    let client_raw = client_namespace(raw);
    let document = Document::parse(&client_raw).context("invalid federated stanza")?;
    let root = document.root_element();
    let from = root.attribute("from").unwrap_or_default();
    let to = root.attribute("to").unwrap_or_default();
    if jid_domain(from).is_none_or(|domain| !domain.eq_ignore_ascii_case(authenticated_domain))
        || jid_domain(to).is_none_or(|domain| !domain.eq_ignore_ascii_case(&state.config.domain))
    {
        return Ok(Some(s2s_stanza_error(root, "auth", "not-authorized")));
    }
    match root.tag_name().name() {
        "message" => route_inbound_message(state, root, &client_raw, from, to).await,
        "iq" => route_inbound_iq(state, root, &client_raw, from, to).await,
        "presence" => route_inbound_presence(state, root, &client_raw, from, to).await,
        _ => Ok(Some(s2s_stanza_error(
            root,
            "cancel",
            "unsupported-stanza-type",
        ))),
    }
}

pub(crate) async fn route_inbound_presence(
    state: &AppState,
    root: roxmltree::Node<'_, '_>,
    raw: &str,
    from: &str,
    to: &str,
) -> Result<Option<String>> {
    let Some(recipient) = db::find_user(&state.pool, &localpart(to).to_ascii_lowercase()).await?
    else {
        return Ok(None);
    };
    if db::is_blocked(&state.pool, recipient.id, from).await? {
        return Ok(None);
    }
    let kind = root.attribute("type").unwrap_or("available");
    if kind == "subscribe" {
        db::add_federated_presence_pending(&state.pool, recipient.id, bare_jid(from)).await?;
    }
    if matches!(kind, "subscribed" | "unsubscribe" | "unsubscribed") {
        let contact = bare_jid(from);
        let existing = db::roster_item(&state.pool, recipient.id, contact).await?;
        let subscription = existing
            .as_ref()
            .map(|item| item.2.as_str())
            .unwrap_or("none");
        let ask = existing.as_ref().and_then(|item| item.3.as_deref());
        let (subscription, ask) = match kind {
            "subscribed" => (add_subscription(subscription, "to"), None),
            "unsubscribe" => (remove_subscription(subscription, "from"), ask),
            "unsubscribed" => (remove_subscription(subscription, "to"), None),
            _ => unreachable!(),
        };
        db::update_subscription(&state.pool, recipient.id, contact, &subscription, ask).await?;
        let push = format!(
            "<iq xmlns='jabber:client' type='set' id='remote-roster-{}'><query xmlns='jabber:iq:roster'><item jid='{}' subscription='{}'{}/></query></iq>",
            stream_id(),
            attr_escape(contact),
            attr_escape(&subscription),
            ask.map(|value| format!(" ask='{}'", attr_escape(value)))
                .unwrap_or_default()
        );
        for target in state.sessions_for(to) {
            let _ = target.sender.try_send(push.clone());
        }
    }
    for target in state.sessions_for(to) {
        let _ = target.sender.try_send(raw.to_owned());
    }
    Ok(None)
}

pub(crate) async fn route_inbound_iq(
    state: &AppState,
    root: roxmltree::Node<'_, '_>,
    raw: &str,
    from: &str,
    to: &str,
) -> Result<Option<String>> {
    let kind = root.attribute("type").unwrap_or("get");
    if matches!(kind, "result" | "error") {
        for target in state.sessions_for(to) {
            let _ = target.sender.try_send(raw.to_owned());
        }
        return Ok(None);
    }
    let id = root.attribute("id").unwrap_or_default();
    let Some(child) = root.children().find(|node| node.is_element()) else {
        return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
    };
    let namespace = child.tag_name().namespace().unwrap_or_default();
    match (child.tag_name().name(), namespace, kind) {
        ("ping", "urn:xmpp:ping", "get") => Ok(Some(s2s_iq_result(id, to, from, ""))),
        ("vCard", "vcard-temp", "get") => {
            let Some(owner) =
                db::find_user(&state.pool, &localpart(to).to_ascii_lowercase()).await?
            else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            let payload = db::vcard(&state.pool, owner.id)
                .await?
                .unwrap_or_else(|| "<vCard xmlns='vcard-temp'/>".to_owned());
            Ok(Some(s2s_iq_result(id, to, from, &payload)))
        }
        ("pubsub", "http://jabber.org/protocol/pubsub", "get") => {
            let Some(items) = child
                .children()
                .find(|node| node.is_element() && node.tag_name().name() == "items")
            else {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            };
            let Some(node) = items.attribute("node") else {
                return Ok(Some(s2s_iq_error(id, to, from, "bad-request")));
            };
            let Some(owner) =
                db::find_user(&state.pool, &localpart(to).to_ascii_lowercase()).await?
            else {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            };
            let requested_id = items
                .children()
                .find(|node| node.is_element() && node.tag_name().name() == "item")
                .and_then(|node| node.attribute("id"));
            let stored = db::pep_items(&state.pool, owner.id, node, requested_id, 100).await?;
            if stored.is_empty() {
                return Ok(Some(s2s_iq_error(id, to, from, "item-not-found")));
            }
            let mut payload = format!(
                "<pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='{}'>",
                attr_escape(node)
            );
            for (_, item) in stored {
                payload.push_str(&item);
            }
            payload.push_str("</items></pubsub>");
            Ok(Some(s2s_iq_result(id, to, from, &payload)))
        }
        ("query", "http://jabber.org/protocol/disco#info", "get") => {
            let payload = "<query xmlns='http://jabber.org/protocol/disco#info'><identity category='server' type='im' name='Northstar XMPP Server'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='http://jabber.org/protocol/pubsub'/><feature var='http://jabber.org/protocol/pubsub#pep'/><feature var='urn:xmpp:ping'/><feature var='vcard-temp'/><feature var='urn:xmpp:omemo:2'/><feature var='urn:xmpp:push:0'/></query>";
            Ok(Some(s2s_iq_result(id, to, from, payload)))
        }
        _ => {
            let targets = state.sessions_for(to);
            if targets.is_empty() {
                return Ok(Some(s2s_iq_error(id, to, from, "service-unavailable")));
            }
            for target in targets {
                let _ = target.sender.try_send(raw.to_owned());
            }
            Ok(None)
        }
    }
}

pub(crate) async fn route_inbound_message(
    state: &AppState,
    root: roxmltree::Node<'_, '_>,
    raw: &str,
    from: &str,
    to: &str,
) -> Result<Option<String>> {
    let Some(recipient) = db::find_user(&state.pool, &localpart(to).to_ascii_lowercase()).await?
    else {
        return Ok(Some(s2s_stanza_error(
            root,
            "cancel",
            "service-unavailable",
        )));
    };
    if db::is_blocked(&state.pool, recipient.id, from).await? {
        return Ok(Some(s2s_stanza_error(
            root,
            "cancel",
            "service-unavailable",
        )));
    }
    let encrypted = is_encrypted(root);
    let persistence_allowed = !has_no_store_hint(root);
    let archive = if encrypted {
        encrypted_archive_stanza(raw)
    } else {
        raw.to_owned()
    };
    if persistence_allowed && (encrypted || !state.config.require_encrypted_archive) {
        db::archive_message(
            &state.pool,
            recipient.id,
            bare_jid(from),
            &archive,
            encrypted,
            root.attribute("id"),
        )
        .await?;
    }
    let mut targets = state.session_entries_for(to);
    if !to.contains('/') {
        targets.retain(|(_, session)| {
            session.available.load(Ordering::Relaxed)
                && session.priority.load(Ordering::Relaxed) >= 0
        });
        targets.sort_by(|(left_jid, left), (right_jid, right)| {
            right
                .priority
                .load(Ordering::Relaxed)
                .cmp(&left.priority.load(Ordering::Relaxed))
                .then_with(|| left_jid.cmp(right_jid))
        });
    }
    if targets
        .iter()
        .any(|(_, target)| target.sender.try_send(raw.to_owned()).is_ok())
    {
        state
            .metrics
            .messages_routed_total
            .fetch_add(1, Ordering::Relaxed);
        return Ok(None);
    }
    if persistence_allowed && (encrypted || !state.config.require_encrypted_archive) {
        db::store_offline(&state.pool, recipient.id, from, &archive, encrypted).await?;
        return Ok(None);
    }
    Ok(Some(s2s_stanza_error(root, "wait", "service-unavailable")))
}
