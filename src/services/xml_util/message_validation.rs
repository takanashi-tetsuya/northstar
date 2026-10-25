//! Validates message extension wire shapes and their bounded metadata before routing and storage.

use super::*;

/// Validate the server-visible XEP-0449 v0.2.0 marker. Sticker media is
/// carried by XEP-0447, while sticker-pack payloads remain ordinary bounded
/// PubSub items. Encrypted markers are intentionally opaque to the server.
pub(super) fn validate_sticker(root: Node<'_, '_>) -> Result<(), &'static str> {
    const STICKERS: &str = "urn:xmpp:stickers:0";
    let stickers = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "sticker"
                && node.tag_name().namespace() == Some(STICKERS)
        })
        .collect::<Vec<_>>();
    if stickers.is_empty() {
        return Ok(());
    }
    if stickers.len() != 1 {
        return Err("bad-request");
    }

    let sticker = stickers[0];
    if sticker.children().any(|child| child.is_element())
        || has_non_whitespace_text(sticker)
        || sticker.attributes().any(|attribute| {
            attribute.namespace().is_some() || !matches!(attribute.name(), "pack" | "jid" | "node")
        })
    {
        return Err("bad-request");
    }

    let pack = sticker.attribute("pack");
    let jid = sticker.attribute("jid");
    let node = sticker.attribute("node");
    for value in [pack, node].into_iter().flatten() {
        if value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control) {
            return Err("bad-request");
        }
    }
    if jid.is_some() != node.is_some() || (jid.is_some() && pack.is_none()) {
        return Err("bad-request");
    }
    if jid.is_some_and(|value| northstar_xmpp_types::jid::CanonicalJid::parse_bare(value).is_err())
    {
        return Err("jid-malformed");
    }

    // Section 4.1 defines the marker as metadata for a stateless file share,
    // not as a free-standing chat signal. A single share keeps the association
    // unambiguous and mirrors the one-file wire shape in the specification.
    let shares = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "file-sharing"
                && node.tag_name().namespace() == Some("urn:xmpp:sfs:0")
        })
        .count();
    if shares != 1 {
        return Err("bad-request");
    }
    Ok(())
}

/// Validate a plaintext, server-visible XEP-0434 v0.6.0 trust message. A
/// trust message encrypted through XEP-0420/OMEMO is ciphertext at this
/// boundary and deliberately remains opaque. Signature verification and the
/// XEP-0450 policy decision belong to endpoints, not the routing server.
pub(super) fn validate_trust_message(root: Node<'_, '_>) -> Result<(), &'static str> {
    const TRUST_MESSAGES: &str = "urn:xmpp:tm:1";
    const MAX_TRUST_OWNERS: usize = 1_024;
    const MAX_TRUST_ENTRIES_PER_OWNER: usize = 1_024;
    const MAX_TRUST_ENTRIES: usize = 8_192;
    const MAX_KEY_IDENTIFIER_BYTES: usize = 64 * 1024;

    let messages = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "trust-message"
                && node.tag_name().namespace() == Some(TRUST_MESSAGES)
        })
        .collect::<Vec<_>>();
    if messages.is_empty() {
        return Ok(());
    }
    if messages.len() != 1 {
        return Err("bad-request");
    }
    let message = messages[0];
    if message.range().len() > 2 * 1024 * 1024 {
        return Err("resource-constraint");
    }
    if has_non_whitespace_text(message)
        || message.attributes().any(|attribute| {
            attribute.namespace().is_some() || !matches!(attribute.name(), "usage" | "encryption")
        })
    {
        return Err("bad-request");
    }
    for required in ["usage", "encryption"] {
        let value = message.attribute(required).ok_or("bad-request")?;
        if value.is_empty()
            || value.len() > 1_024
            || value
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err("bad-request");
        }
    }

    let owners = message
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    if owners.is_empty() {
        return Err("bad-request");
    }
    if owners.len() > MAX_TRUST_OWNERS {
        return Err("resource-constraint");
    }
    let mut owner_jids = HashSet::new();
    let mut total_entries = 0usize;
    for owner in owners {
        if owner.tag_name().name() != "key-owner"
            || owner.tag_name().namespace() != Some(TRUST_MESSAGES)
            || has_non_whitespace_text(owner)
            || owner
                .attributes()
                .any(|attribute| attribute.namespace().is_some() || attribute.name() != "jid")
        {
            return Err("bad-request");
        }
        let owner_jid = owner
            .attribute("jid")
            .ok_or("bad-request")
            .and_then(|value| {
                northstar_xmpp_types::jid::CanonicalJid::parse_bare(value)
                    .map_err(|_| "jid-malformed")
            })?;
        if !owner_jids.insert(owner_jid.to_string()) {
            return Err("bad-request");
        }

        let actions = owner
            .children()
            .filter(|node| node.is_element())
            .collect::<Vec<_>>();
        if actions.is_empty() {
            return Err("bad-request");
        }
        if actions.len() > MAX_TRUST_ENTRIES_PER_OWNER {
            return Err("resource-constraint");
        }
        total_entries = total_entries
            .checked_add(actions.len())
            .ok_or("resource-constraint")?;
        if total_entries > MAX_TRUST_ENTRIES {
            return Err("resource-constraint");
        }

        let mut key_identifiers = HashSet::new();
        for action in actions {
            if action.tag_name().namespace() != Some(TRUST_MESSAGES)
                || !matches!(action.tag_name().name(), "trust" | "distrust")
                || action.attributes().len() != 0
                || action.children().any(|node| node.is_element())
            {
                return Err("bad-request");
            }
            let encoded = action.text().unwrap_or_default();
            if encoded.len()
                > MAX_KEY_IDENTIFIER_BYTES
                    .saturating_mul(2)
                    .saturating_add(16)
            {
                return Err("resource-constraint");
            }
            if !valid_omemo_base64(encoded, MAX_KEY_IDENTIFIER_BYTES) {
                return Err("bad-request");
            }
            let compact = encoded
                .chars()
                .filter(|character| !character.is_ascii_whitespace())
                .collect::<String>();
            if !key_identifiers.insert(compact) {
                return Err("bad-request");
            }
        }
    }
    Ok(())
}

/// Validate the server-visible OMEMO 2 transport envelope without inspecting
/// or attempting to decrypt its SCE payload. This shared C2S/S2S boundary
/// keeps malformed recipient maps out of durable MAM/offline storage and
/// prevents a purported encrypted stanza from carrying a plaintext fallback.
pub(super) fn validate_omemo2_envelope(root: Node<'_, '_>) -> Result<(), &'static str> {
    if root.children().any(|node| {
        node.is_element()
            && node.tag_name().name() == "envelope"
            && node.tag_name().namespace() == Some(SCE)
    }) {
        // XEP-0420 forbids an unencrypted envelope as a direct stanza child.
        return Err("not-allowed");
    }

    let encrypted = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "encrypted"
                && node.tag_name().namespace() == Some(OMEMO2)
        })
        .collect::<Vec<_>>();
    if encrypted.is_empty() {
        return Ok(());
    }
    if encrypted.len() != 1 {
        return Err("bad-request");
    }
    let encrypted = encrypted[0];
    if encrypted.range().len() > MAX_OMEMO2_ENCRYPTED_BYTES {
        return Err("resource-constraint");
    }
    if encrypted.attributes().len() != 0 || has_non_whitespace_text(encrypted) {
        return Err("bad-request");
    }

    // OMEMO 2 uses SCE. A plaintext body/subject/thread, attachment or OOB URL
    // next to the ciphertext is a downgrade/leak, not a fallback.
    if root.children().any(|node| is_omemo2_plaintext_leak(&node)) {
        return Err("not-acceptable");
    }

    let children = encrypted
        .children()
        .filter(Node::is_element)
        .collect::<Vec<_>>();
    if children.iter().any(|node| {
        node.tag_name().namespace() != Some(OMEMO2)
            || !matches!(node.tag_name().name(), "header" | "payload")
    }) {
        return Err("bad-request");
    }
    let headers = children
        .iter()
        .filter(|node| node.tag_name().name() == "header")
        .copied()
        .collect::<Vec<_>>();
    let payloads = children
        .iter()
        .filter(|node| node.tag_name().name() == "payload")
        .copied()
        .collect::<Vec<_>>();
    if headers.len() != 1
        || payloads.len() > 1
        || children.first().map(|node| node.tag_name().name()) != Some("header")
        || payloads
            .first()
            .is_some_and(|_| children.get(1).map(|node| node.tag_name().name()) != Some("payload"))
    {
        return Err("bad-request");
    }

    let header = headers[0];
    if header
        .attributes()
        .any(|attribute| attribute.namespace().is_some() || attribute.name() != "sid")
        || header
            .attribute("sid")
            .and_then(parse_omemo_positive_i31)
            .is_none()
        || has_non_whitespace_text(header)
    {
        return Err("bad-request");
    }

    let groups = header
        .children()
        .filter(Node::is_element)
        .collect::<Vec<_>>();
    if groups.is_empty() || groups.len() > MAX_OMEMO2_KEY_GROUPS {
        return Err("resource-constraint");
    }
    let mut recipient_jids = HashSet::new();
    let mut total_keys = 0usize;
    for group in groups {
        if group.tag_name().name() != "keys"
            || group.tag_name().namespace() != Some(OMEMO2)
            || group
                .attributes()
                .any(|attribute| attribute.namespace().is_some() || attribute.name() != "jid")
            || has_non_whitespace_text(group)
        {
            return Err("bad-request");
        }
        let recipient = group
            .attribute("jid")
            .ok_or("bad-request")
            .and_then(|jid| {
                northstar_xmpp_types::jid::CanonicalJid::parse_bare(jid)
                    .map_err(|_| "jid-malformed")
            })?;
        if recipient.localpart().is_none() || !recipient_jids.insert(recipient.to_string()) {
            return Err("bad-request");
        }

        let keys = group
            .children()
            .filter(Node::is_element)
            .collect::<Vec<_>>();
        if keys.is_empty() || keys.len() > MAX_OMEMO2_KEYS_PER_GROUP {
            return Err("resource-constraint");
        }
        total_keys = total_keys
            .checked_add(keys.len())
            .ok_or("resource-constraint")?;
        if total_keys > MAX_OMEMO2_TOTAL_KEYS {
            return Err("resource-constraint");
        }
        let mut device_ids = HashSet::new();
        for key in keys {
            if key.tag_name().name() != "key"
                || key.tag_name().namespace() != Some(OMEMO2)
                || key.children().any(|node| node.is_element())
                || key.attributes().any(|attribute| {
                    attribute.namespace().is_some() || !matches!(attribute.name(), "rid" | "kex")
                })
            {
                return Err("bad-request");
            }
            let rid = key
                .attribute("rid")
                .and_then(parse_omemo_positive_i31)
                .ok_or("bad-request")?;
            if !device_ids.insert(rid)
                || key
                    .attribute("kex")
                    .is_some_and(|value| !matches!(value, "true" | "false" | "1" | "0"))
                || !valid_omemo_base64(key.text().unwrap_or_default(), MAX_OMEMO2_KEY_BYTES)
            {
                return Err("bad-request");
            }
        }
    }

    if let Some(payload) = payloads.first() {
        if payload.attributes().len() != 0
            || payload.children().any(|node| node.is_element())
            || !valid_omemo_base64(payload.text().unwrap_or_default(), MAX_OMEMO2_PAYLOAD_BYTES)
        {
            return Err("bad-request");
        }
        let store = root
            .children()
            .filter(|node| {
                node.is_element() && node.tag_name().namespace() == Some("urn:xmpp:hints")
            })
            .filter(|node| node.tag_name().name() == "store")
            .count();
        if store != 1 {
            // XEP-0420 requires this structural hint because an SCE payload
            // has no plaintext body. Other XEP-0334 hints are an independent
            // storage-policy decision: in particular, `no-store` may override
            // persistence while an already authenticated live route still
            // carries the ciphertext.
            return Err("not-acceptable");
        }
    }

    if root.children().any(|node| {
        node.is_element()
            && node.tag_name().name() == "encryption"
            && node.tag_name().namespace() == Some("urn:xmpp:eme:0")
            && node.attribute("namespace") != Some(OMEMO2)
    }) {
        return Err("bad-request");
    }
    Ok(())
}

pub(super) fn is_omemo2_plaintext_leak(node: &Node<'_, '_>) -> bool {
    if !node.is_element() {
        return false;
    }
    let namespace = node.tag_name().namespace().unwrap_or_default();
    let name = node.tag_name().name();
    (matches!(namespace, "" | "jabber:client") && matches!(name, "body" | "subject" | "thread"))
        || (namespace == "jabber:x:oob" && name == "x")
        || (namespace == "urn:xmpp:sfs:0" && name == "file-sharing")
        || (namespace == OMEMO2 && name == "opt-out")
}

pub(super) fn has_non_whitespace_text(node: Node<'_, '_>) -> bool {
    node.children()
        .filter(Node::is_text)
        .any(|child| child.text().is_some_and(|text| !text.trim().is_empty()))
}

pub(super) fn parse_omemo_positive_i31(value: &str) -> Option<u32> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|value| *value <= i32::MAX as u32)
}

pub(super) fn valid_omemo_base64(value: &str, max_decoded: usize) -> bool {
    if value.is_empty() || value.len() > max_decoded.saturating_mul(2).saturating_add(16) {
        return false;
    }
    let compact = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    !compact.is_empty()
        && BASE64
            .decode(compact)
            .is_ok_and(|decoded| !decoded.is_empty() && decoded.len() <= max_decoded)
}

pub(super) fn validate_stanza_ids(root: Node<'_, '_>) -> Result<(), &'static str> {
    northstar_xep_0359::parse_message(root)
        .map(|_| ())
        .map_err(|error| match error {
            northstar_xep_0359::SidError::InvalidIssuer(_) => "jid-malformed",
            _ => "bad-request",
        })
}

pub(super) fn validate_processing_hints(root: Node<'_, '_>) -> Result<(), &'static str> {
    message_storage_policy(root).map(|_| ())
}

pub(super) fn validate_private_carbon_marker(root: Node<'_, '_>) -> Result<(), &'static str> {
    let markers = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "private"
                && node.tag_name().namespace() == Some("urn:xmpp:carbons:2")
        })
        .collect::<Vec<_>>();
    if markers.len() > 1 {
        return Err("bad-request");
    }
    if markers.first().is_some_and(|marker| {
        marker.attributes().len() != 0
            || marker.children().any(|child| child.is_element())
            || marker.text().is_some_and(|text| !text.trim().is_empty())
    }) {
        return Err("bad-request");
    }
    Ok(())
}

pub(super) fn valid_message_reference(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        !value.is_empty()
            && value.len() <= 1_024
            && !value.chars().any(|character| character.is_control())
    })
}

pub(super) fn validate_chat_states(root: Node<'_, '_>) -> Result<(), &'static str> {
    northstar_xep_0085::parse_message(root)
        .map(|_| ())
        .map_err(|_| "bad-request")
}

pub(super) fn validate_explicit_encryption(root: Node<'_, '_>) -> Result<(), &'static str> {
    northstar_xep_0380::parse_message(root)
        .map(|_| ())
        .map_err(|_| "bad-request")
}

pub(super) fn validate_fallbacks(root: Node<'_, '_>) -> Result<(), &'static str> {
    let message_texts = |name: &str| {
        root.children()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().name() == name
                    && matches!(node.tag_name().namespace(), None | Some("jabber:client"))
            })
            .map(|node| node.text().unwrap_or_default().chars().count())
            .collect::<Vec<_>>()
    };

    for fallback in root.children().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "fallback"
            && node.tag_name().namespace() == Some("urn:xmpp:fallback:0")
    }) {
        if fallback
            .attributes()
            .any(|attribute| attribute.namespace().is_some() || attribute.name() != "for")
        {
            return Err("bad-request");
        }
        let namespace = fallback.attribute("for").ok_or("bad-request")?;
        if namespace.is_empty()
            || namespace.len() > 1_024
            || namespace.chars().any(char::is_control)
            || fallback.text().is_some_and(|text| !text.trim().is_empty())
        {
            return Err("bad-request");
        }

        let mut body_seen = false;
        for region in fallback.children().filter(|child| child.is_element()) {
            let name = region.tag_name().name();
            if region.tag_name().namespace() != Some("urn:xmpp:fallback:0")
                || !matches!(name, "subject" | "body")
                || (name == "subject" && body_seen)
                || region.children().any(|child| child.is_element())
                || region.text().is_some_and(|text| !text.trim().is_empty())
                || region.attributes().any(|attribute| {
                    attribute.namespace().is_some() || !matches!(attribute.name(), "start" | "end")
                })
            {
                return Err("bad-request");
            }
            body_seen |= name == "body";

            let (start, end) = match (region.attribute("start"), region.attribute("end")) {
                (None, None) => continue,
                (Some(start), Some(end)) => (
                    start.parse::<u32>().map_err(|_| "bad-request")? as usize,
                    end.parse::<u32>().map_err(|_| "bad-request")? as usize,
                ),
                _ => return Err("bad-request"),
            };
            let lengths = message_texts(name);
            if start > end || lengths.is_empty() || lengths.into_iter().any(|length| end > length) {
                return Err("bad-request");
            }
        }
    }
    Ok(())
}

pub(super) fn validate_correction(root: Node<'_, '_>) -> Result<(), &'static str> {
    let Some(_) = northstar_xep_0308::parse_message(root).map_err(|_| "bad-request")? else {
        return Ok(());
    };
    // A correction resends the complete logical content. A naked control is
    // ambiguous archive spam; encrypted replacements remain inside E2EE.
    if !root.children().any(|node| {
        node.is_element()
            && ((matches!(node.tag_name().name(), "body" | "subject")
                && matches!(node.tag_name().namespace(), None | Some("jabber:client")))
                || is_encryption_node(node))
    }) {
        return Err("bad-request");
    }
    if root.children().any(is_non_messaging_correction_payload) {
        return Err("not-allowed");
    }
    Ok(())
}

pub(super) fn is_non_messaging_correction_payload(node: Node<'_, '_>) -> bool {
    if !node.is_element() {
        return false;
    }
    matches!(
        (node.tag_name().namespace(), node.tag_name().name()),
        (Some("jabber:x:roster"), "x")
            | (Some("http://jabber.org/protocol/pubsub#event"), "event")
            | (Some("urn:xmpp:jingle-message:0"), _)
            | (Some("urn:xmpp:call-invites:0"), _)
            | (Some("urn:xmpp:chat-markers:0"), "displayed")
            | (Some("urn:xmpp:receipts"), "received")
            | (Some("urn:xmpp:reactions:0"), "reactions")
            | (Some("urn:xmpp:message-retract:1"), "retract" | "retracted")
    )
}

pub(super) fn validate_displayed_marker(root: Node<'_, '_>) -> Result<(), &'static str> {
    let marker = northstar_xep_0333::parse_message(root).map_err(|_| "bad-request")?;
    if matches!(marker, Some(northstar_xep_0333::ChatMarker::Markable))
        && !valid_message_reference(root.attribute("id"))
    {
        return Err("bad-request");
    }
    Ok(())
}

pub(super) fn validate_no_client_tombstone(root: Node<'_, '_>) -> Result<(), &'static str> {
    if root.children().any(|node| {
        node.is_element()
            && node.tag_name().name() == "retracted"
            && node.tag_name().namespace() == Some("urn:xmpp:message-retract:1")
    }) {
        // `<retracted/>` is an archive-service tombstone representation. A
        // live endpoint requests retraction with `<retract/>` instead.
        return Err("not-allowed");
    }
    Ok(())
}

pub(super) fn validate_reactions(root: Node<'_, '_>) -> Result<(), &'static str> {
    northstar_xep_0444::parse_message(root)
        .map(|_| ())
        .map_err(|_| "not-acceptable")
}

pub(super) fn validate_reply(root: Node<'_, '_>) -> Result<(), &'static str> {
    if let Some(reply) = northstar_xep_0461::parse_message(root).map_err(|_| "bad-request")? {
        // Canonical JID parsing is a server identity policy, deliberately kept
        // outside the capability-free wire crate.
        if northstar_xmpp_types::jid::CanonicalJid::parse(reply.to()).is_err() {
            return Err("bad-request");
        }
    }
    Ok(())
}

pub(super) fn validate_file_sharing(root: Node<'_, '_>) -> Result<(), &'static str> {
    let shares = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "file-sharing"
                && node.tag_name().namespace() == Some("urn:xmpp:sfs:0")
        })
        .collect::<Vec<_>>();
    if shares.len() > 16 {
        return Err("resource-constraint");
    }
    let multiple = shares.len() > 1;
    let mut ids = HashSet::new();
    for share in shares {
        if share
            .attributes()
            .any(|attribute| !matches!(attribute.name(), "id" | "disposition"))
            || share
                .attribute("disposition")
                .is_some_and(|value| !matches!(value, "attachment" | "inline"))
        {
            return Err("bad-request");
        }
        if multiple {
            let id = share
                .attribute("id")
                .filter(|id| valid_message_reference(Some(id)));
            if id.is_none() || !ids.insert(id.unwrap()) {
                return Err("bad-request");
            }
        }
        if share.range().len() > 262_144
            || share.descendants().filter(|node| node.is_element()).count() > 256
            || share
                .children()
                .filter(|node| node.is_text())
                .any(|node| node.text().is_some_and(|text| !text.trim().is_empty()))
        {
            return Err("resource-constraint");
        }
        let file_nodes = share
            .children()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().name() == "file"
                    && node.tag_name().namespace() == Some("urn:xmpp:file:metadata:0")
            })
            .collect::<Vec<_>>();
        let sources = share
            .children()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().name() == "sources"
                    && node.tag_name().namespace() == Some("urn:xmpp:sfs:0")
            })
            .count();
        if file_nodes.len() != 1 || sources > 1 {
            return Err("bad-request");
        }
        validate_file_metadata(file_nodes[0])?;
    }
    Ok(())
}

pub(super) fn validate_file_metadata(file: Node<'_, '_>) -> Result<(), &'static str> {
    if file.attributes().len() != 0
        || file.range().len() > 131_072
        || file.descendants().filter(|node| node.is_element()).count() > 128
        || file
            .children()
            .filter(|node| node.is_text())
            .any(|node| node.text().is_some_and(|text| !text.trim().is_empty()))
    {
        return Err("resource-constraint");
    }

    let mut singletons = HashSet::new();
    let mut descriptions = HashSet::new();
    let mut hash_count = 0usize;
    let mut thumbnail_count = 0usize;
    for child in file.children().filter(|node| node.is_element()) {
        let namespace = child.tag_name().namespace().unwrap_or_default();
        let name = child.tag_name().name();
        match (namespace, name) {
            ("urn:xmpp:file:metadata:0", "date") => {
                validate_file_scalar(child, 64)?;
                if !singletons.insert(name)
                    || chrono::DateTime::parse_from_rfc3339(child.text().unwrap_or_default())
                        .is_err()
                {
                    return Err("bad-request");
                }
            }
            ("urn:xmpp:file:metadata:0", "media-type") => {
                validate_file_scalar(child, 255)?;
                let value = child.text().unwrap_or_default();
                if !singletons.insert(name)
                    || value.split_once('/').is_none_or(|(top, sub)| {
                        top.is_empty()
                            || sub.is_empty()
                            || value.chars().any(|character| {
                                character.is_control() || character.is_whitespace()
                            })
                    })
                {
                    return Err("bad-request");
                }
            }
            ("urn:xmpp:file:metadata:0", "name") => {
                validate_file_scalar(child, 1_024)?;
                let value = child.text().unwrap_or_default();
                if !singletons.insert(name)
                    || value.is_empty()
                    || value.chars().any(char::is_control)
                {
                    return Err("bad-request");
                }
            }
            ("urn:xmpp:file:metadata:0", "size")
            | ("urn:xmpp:file:metadata:0", "width")
            | ("urn:xmpp:file:metadata:0", "height")
            | ("urn:xmpp:file:metadata:0", "length") => {
                validate_file_scalar(child, 32)?;
                if !singletons.insert(name)
                    || child.text().unwrap_or_default().parse::<u64>().is_err()
                {
                    return Err("bad-request");
                }
            }
            ("urn:xmpp:file:metadata:0", "desc") => {
                if child.children().any(|nested| nested.is_element())
                    || child.text().is_some_and(|text| {
                        text.len() > 8_192 || text.chars().any(char::is_control)
                    })
                {
                    return Err("bad-request");
                }
                let language = child
                    .attribute(("http://www.w3.org/XML/1998/namespace", "lang"))
                    .unwrap_or_default();
                if child.attributes().any(|attribute| {
                    attribute.namespace() != Some("http://www.w3.org/XML/1998/namespace")
                        || attribute.name() != "lang"
                }) || !descriptions.insert(language)
                    || (!language.is_empty() && !valid_language_tag(language))
                {
                    return Err("bad-request");
                }
            }
            ("urn:xmpp:hashes:2", "hash") => {
                hash_count += 1;
                let algorithm = child.attribute("algo").unwrap_or_default();
                let encoded = child.text().unwrap_or_default();
                if hash_count > 32
                    || child.children().any(|nested| nested.is_element())
                    || algorithm.is_empty()
                    || algorithm.len() > 64
                    || algorithm
                        .chars()
                        .any(|character| !character.is_ascii_alphanumeric() && character != '-')
                    || child
                        .attributes()
                        .any(|attribute| attribute.name() != "algo")
                    || encoded.is_empty()
                    || encoded.len() > 1_024
                    || encoded.chars().any(|character| {
                        !character.is_ascii_alphanumeric()
                            && !matches!(character, '+' | '/' | '=' | '-' | '_')
                    })
                {
                    return Err("bad-request");
                }
            }
            ("urn:xmpp:thumbs:1", "thumbnail") => {
                thumbnail_count += 1;
                if thumbnail_count > 16
                    || child.range().len() > 8_192
                    || child.descendants().filter(|node| node.is_element()).count() > 16
                {
                    return Err("resource-constraint");
                }
                // XEP-0264 has several transport profiles. Keep thumbnails
                // opaque for clients, but reject unbounded or control-bearing
                // metadata rather than claiming to render it.
                if child.attributes().any(|attribute| {
                    attribute.value().len() > 4_096
                        || attribute.value().chars().any(char::is_control)
                }) {
                    return Err("bad-request");
                }
            }
            _ => {
                // XEP-0446 is a client data format and intentionally
                // extensible. Preserve unknown metadata transparently while
                // enforcing an aggregate resource ceiling.
                if child.range().len() > 65_536
                    || child.descendants().filter(|node| node.is_element()).count() > 64
                    || child.attributes().any(|attribute| {
                        attribute.value().len() > 4_096
                            || attribute.value().chars().any(char::is_control)
                    })
                {
                    return Err("resource-constraint");
                }
            }
        }
    }
    Ok(())
}

pub(super) fn validate_file_scalar(node: Node<'_, '_>, limit: usize) -> Result<(), &'static str> {
    if node.attributes().len() != 0
        || node.children().any(|child| child.is_element())
        || node
            .text()
            .is_none_or(|text| text.is_empty() || text.len() > limit)
    {
        return Err("bad-request");
    }
    Ok(())
}
