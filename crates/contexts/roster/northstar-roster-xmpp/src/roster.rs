//! The RFC 6121 roster: get and set, and the stanzas of roster pushes.

use anyhow::Result;
use northstar_roster_application::{
    BeginRosterSyncError, RosterGetCommand, RosterRemovalRoute, RosterRemoveCommand,
    RosterRepository, RosterService, RosterSyncPermit, RosterUpsertCommand, S2sOutboxPolicy,
};
use northstar_roster_core::{
    LocalRosterContact, PresenceAccount, RosterAuthorization, RosterChange, RosterReadSnapshot,
};
use northstar_xml_builder::stanza::{iq_error, iq_result_from};
use northstar_xml_builder::XmlElement;
use roxmltree::Node;
use std::collections::HashSet;

/// What a client session provides to the roster handlers.
pub trait RosterSession: crate::SessionIdentity {
    /// The roster service, over the repository the composition root binds.
    fn roster_service(&self) -> &RosterService<impl RosterRepository<Error = anyhow::Error>>;
    /// The session's bound full JID, or `None` before resource binding.
    fn roster_full_jid(&self) -> Option<&str>;
    /// Starts the session's initial roster synchronization.
    fn roster_begin_sync(
        &self,
        annotations_requested: bool,
    ) -> std::result::Result<RosterSyncPermit, BeginRosterSyncError>;
    /// Abandons a synchronization that will not complete.
    fn roster_fail_sync(&self, permit: RosterSyncPermit);
    /// Cancels the session's connection.
    fn roster_disconnect(&self);
    /// Whether `domain` is a service this server hosts (rooms, uploads, PubSub).
    fn roster_is_hosted_domain(&self, domain: &str) -> bool;
    /// The durable federation outbox policy.
    fn roster_outbox_policy(&self) -> S2sOutboxPolicy;
    /// Wakes the durable federation outbox.
    fn roster_wake_outbox(&self);
    /// Delivers a subscription presence `stanza` of a roster removal to the available
    /// resources of `recipient`, on this node and on the others.
    fn roster_deliver_removal_presence(
        &self,
        owner: &PresenceAccount,
        recipient: &LocalRosterContact,
        target_bare: &str,
        stanza: &str,
    ) -> impl std::future::Future<Output = ()> + Send;
    /// Delivers a committed roster change to the interested resources of `owner`.
    fn roster_push_change(
        &self,
        owner_id: uuid::Uuid,
        owner: &str,
        change: &RosterChange,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// The answer to a roster get.
pub enum RosterGetOutcome {
    /// Only this stanza is sent.
    Reply(String),
    /// This reply is sent, and the session then flushes the synchronization after the transport.
    Synchronize {
        /// The reply stanza.
        response: String,
        /// The synchronization this get started.
        permit: RosterSyncPermit,
        /// The roster version of the reply.
        snapshot_version: i64,
        /// The pushes that bring a cached roster up to the snapshot.
        initial_delta: Vec<String>,
        /// The full JID the pushes go to.
        target: String,
    },
}

const MIX_ROSTER_NS: &str = "urn:xmpp:mix:roster:0";

/// Answers an RFC 6121 roster get IQ request.
pub async fn roster_get<S: RosterSession>(
    session: &S,
    id: &str,
    iq: Node<'_, '_>,
    query: Node<'_, '_>,
) -> Result<RosterGetOutcome> {
    let Some(user) = session.session_account() else {
        return Ok(RosterGetOutcome::Reply(iq_error(id, "not-authorized")));
    };
    if let Some(condition) = roster_target_error(
        iq.attribute("to"),
        &user.username,
        session.session_local_domain(),
        false,
    ) {
        return Ok(RosterGetOutcome::Reply(iq_error(id, condition)));
    }
    let annotations_requested = match validate_roster_get(query) {
        Ok(requested) => requested,
        Err(condition) => return Ok(RosterGetOutcome::Reply(iq_error(id, condition))),
    };
    let permit = match session.roster_begin_sync(annotations_requested) {
        Ok(permit) => permit,
        Err(BeginRosterSyncError::AlreadySynchronizing) => {
            return Ok(RosterGetOutcome::Reply(iq_error(id, "resource-constraint")));
        }
        Err(BeginRosterSyncError::Failed) => {
            session.roster_disconnect();
            return Ok(RosterGetOutcome::Reply(iq_error(id, "resource-constraint")));
        }
    };
    let requested_version = query
        .attribute("ver")
        .and_then(|version| version.parse::<i64>().ok());
    let snapshot = match session
        .roster_service()
        .execute_roster_get(RosterGetCommand {
            owner_id: user.id,
            expected_auth_generation: user.auth_generation,
            requested_version,
            annotations_requested,
        })
        .await
    {
        Ok(RosterAuthorization::Authorized(snapshot)) => snapshot,
        Ok(RosterAuthorization::Unauthorized) => {
            session.roster_fail_sync(permit);
            session.roster_disconnect();
            return Ok(RosterGetOutcome::Reply(iq_error(id, "not-authorized")));
        }
        Err(error) => {
            session.roster_fail_sync(permit);
            session.roster_disconnect();
            return Err(error);
        }
    };
    let RosterReadSnapshot {
        version: current_version,
        items,
        changes,
        mix_participants,
    } = snapshot;
    let owner_jid = format!("{}@{}", user.username, session.session_local_domain());
    // A version-only empty result cannot convey newly requested MIX
    // annotations for cached items, so an opt-in request receives a full
    // roster snapshot. Unannotated requests keep normal XEP-0237 deltas.
    let target = session.roster_full_jid().unwrap_or_default().to_owned();
    let (response, initial_delta) = if let Some(changes) = changes {
        let pushes = changes
            .into_iter()
            .map(|change| {
                let item = roster_change_item_element(&change, None);
                roster_push_xml(&owner_jid, &target, change.version, item)
            })
            .collect::<Vec<_>>();
        (iq_result_from(id, &owner_jid, ""), pushes)
    } else {
        let mut query =
            XmlElement::namespaced("query", "jabber:iq:roster").attr("ver", current_version);
        for change in items {
            query.push_child(roster_item_element(
                &change.contact_jid,
                change.display_name.as_deref(),
                change.subscription.as_deref().unwrap_or("none"),
                change.ask.as_deref(),
                change.approved,
                &change.groups,
                mix_participants
                    .get(&change.contact_jid)
                    .map(String::as_str),
            ));
        }
        let payload = query.finish();
        (iq_result_from(id, &owner_jid, &payload), Vec::new())
    };

    Ok(RosterGetOutcome::Synchronize {
        response,
        permit,
        snapshot_version: current_version,
        initial_delta,
        target,
    })
}

/// Answers an RFC 6121 roster set IQ request.
pub async fn roster_set<S: RosterSession>(
    session: &S,
    id: &str,
    iq: Node<'_, '_>,
    query: Node<'_, '_>,
) -> Result<String> {
    let Some(user) = session.session_account() else {
        return Ok(iq_error(id, "not-authorized"));
    };
    if let Some(condition) = roster_target_error(
        iq.attribute("to"),
        &user.username,
        session.session_local_domain(),
        true,
    ) {
        return Ok(iq_error(id, condition));
    }
    if query.attributes().len() != 0 || has_non_whitespace_text(query) {
        return Ok(iq_error(id, "bad-request"));
    }
    let elements = query
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    if elements.len() != 1
        || elements[0].tag_name().name() != "item"
        || elements[0].tag_name().namespace() != Some("jabber:iq:roster")
    {
        return Ok(iq_error(id, "bad-request"));
    }
    let parsed = match parse_roster_set_item(elements[0]) {
        Ok(parsed) => parsed,
        Err(condition) => return Ok(iq_error(id, condition)),
    };
    if parsed.remove {
        let owner_jid = format!("{}@{}", user.username, session.session_local_domain());
        let contact_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(&parsed.contact)?;
        let hosted_service = session.roster_is_hosted_domain(contact_jid.domainpart());
        let unsubscribe = roster_removal_presence(&owner_jid, &parsed.contact, "unsubscribe");
        let unsubscribed = roster_removal_presence(&owner_jid, &parsed.contact, "unsubscribed");
        let remote = contact_jid.domainpart() != session.session_local_domain() && !hosted_service;
        let route = if remote {
            let policy = session.roster_outbox_policy();
            RosterRemovalRoute::Remote {
                target_domain: contact_jid.domainpart(),
                unsubscribe_stanza: &unsubscribe,
                unsubscribed_stanza: &unsubscribed,
                bounce_to: Some(&owner_jid),
                policy,
            }
        } else {
            RosterRemovalRoute::Local {
                owner_jid: &owner_jid,
                contact_username: (contact_jid.domainpart() == session.session_local_domain())
                    .then(|| contact_jid.localpart())
                    .flatten(),
            }
        };
        let removal = match session
            .roster_service()
            .execute_roster_remove(RosterRemoveCommand {
                owner_id: user.id,
                expected_auth_generation: user.auth_generation,
                jid: &parsed.contact,
                route,
            })
            .await?
        {
            RosterAuthorization::Authorized(Some(removal)) => removal,
            RosterAuthorization::Authorized(None) => {
                return Ok(iq_error(id, "item-not-found"));
            }
            RosterAuthorization::Unauthorized => {
                session.roster_disconnect();
                return Ok(iq_error(id, "not-authorized"));
            }
        };

        if remote && (removal.send_unsubscribe || removal.send_unsubscribed) {
            // Both cancellation rows committed with the roster removal;
            // this wake is only an edge trigger and restart recovery is
            // provided by the periodic durable-outbox poll.
            session.roster_wake_outbox();
        }
        if let Some(contact) = removal.local_contact.as_ref() {
            let target_jid = format!("{}@{}", contact.username, session.session_local_domain());
            // RFC 6121 subscription notifications precede the roster
            // state they caused. Preserve that order for every local and
            // clustered interested resource.
            if removal.send_unsubscribe {
                session
                    .roster_deliver_removal_presence(&user, contact, &target_jid, &unsubscribe)
                    .await;
            }
            if removal.send_unsubscribed {
                session
                    .roster_deliver_removal_presence(&user, contact, &target_jid, &unsubscribed)
                    .await;
            }
            if let Some(change) = removal.contact_change.as_ref() {
                session
                    .roster_push_change(contact.id, &contact.username, change)
                    .await?;
            }
        }
        session
            .roster_push_change(user.id, &user.username, &removal.owner_change)
            .await?;
    } else {
        let change = match session
            .roster_service()
            .execute_roster_upsert(RosterUpsertCommand {
                owner_id: user.id,
                expected_auth_generation: user.auth_generation,
                jid: parsed.contact,
                name: parsed.name,
                groups: parsed.groups,
            })
            .await?
        {
            RosterAuthorization::Authorized(change) => change,
            RosterAuthorization::Unauthorized => {
                session.roster_disconnect();
                return Ok(iq_error(id, "not-authorized"));
            }
        };
        session
            .roster_push_change(user.id, &user.username, &change)
            .await?;
    }
    let owner_jid = format!("{}@{}", user.username, session.session_local_domain());
    Ok(iq_result_from(id, &owner_jid, ""))
}

/// Renders an RFC 6121 roster item or deletion element from a committed change.
pub fn roster_change_item_element(
    change: &RosterChange,
    participant_id: Option<&str>,
) -> XmlElement {
    if change.removed {
        return removed_roster_item_element(&change.contact_jid);
    }
    roster_item_element(
        &change.contact_jid,
        change.display_name.as_deref(),
        change.subscription.as_deref().unwrap_or("none"),
        change.ask.as_deref(),
        change.approved,
        &change.groups,
        participant_id,
    )
}

/// Renders an RFC 6121 roster push IQ stanza.
pub fn roster_push_xml(from: &str, to: &str, version: i64, item: XmlElement) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "set")
        .attr("from", from)
        .attr("to", to)
        .attr("id", format!("roster-{}", stream_id()))
        .child(
            XmlElement::namespaced("query", "jabber:iq:roster")
                .attr("ver", version)
                .child(item),
        )
        .finish()
}

#[cfg(test)]
pub(crate) fn roster_item_xml(
    jid: &str,
    name: Option<&str>,
    subscription: &str,
    ask: Option<&str>,
    approved: bool,
    groups: &[String],
    participant_id: Option<&str>,
) -> String {
    roster_item_element(
        jid,
        name,
        subscription,
        ask,
        approved,
        groups,
        participant_id,
    )
    .finish()
}

fn roster_item_element(
    jid: &str,
    name: Option<&str>,
    subscription: &str,
    ask: Option<&str>,
    approved: bool,
    groups: &[String],
    participant_id: Option<&str>,
) -> XmlElement {
    let mut item = XmlElement::new("item")
        .attr("jid", jid)
        .attr("subscription", subscription)
        .optional_attr("name", name)
        .optional_attr("ask", ask);
    if approved {
        item = item.attr("approved", "true");
    }
    for group in groups {
        item.push_child(XmlElement::new("group").text(group.clone()));
    }
    if let Some(participant_id) = participant_id {
        item.push_child(
            XmlElement::namespaced("channel", MIX_ROSTER_NS).attr("participant-id", participant_id),
        );
    }
    item
}

fn removed_roster_item_element(jid: &str) -> XmlElement {
    XmlElement::new("item")
        .attr("jid", jid)
        .attr("subscription", "remove")
}

fn roster_removal_presence(from: &str, to: &str, kind: &str) -> String {
    XmlElement::namespaced("presence", "jabber:client")
        .attr("from", from)
        .attr("to", to)
        .attr("type", kind)
        .attr("id", uuid::Uuid::new_v4())
        .finish()
}

fn roster_target_allowed(target: Option<&str>, username: &str, domain: &str) -> bool {
    target.is_none_or(|target| {
        northstar_xmpp_types::jid::CanonicalJid::parse_bare(target).is_ok_and(|jid| {
            jid.localpart() == Some(username)
                && jid.domainpart() == domain
                && jid.resourcepart().is_none()
        })
    })
}

fn roster_target_error(
    target: Option<&str>,
    username: &str,
    domain: &str,
    write: bool,
) -> Option<&'static str> {
    (!roster_target_allowed(target, username, domain)).then_some(if write {
        "forbidden"
    } else {
        "service-unavailable"
    })
}

fn validate_roster_get(query: Node<'_, '_>) -> std::result::Result<bool, &'static str> {
    if query
        .attributes()
        .any(|attribute| attribute.namespace().is_some() || attribute.name() != "ver")
        || has_non_whitespace_text(query)
    {
        return Err("bad-request");
    }
    let children = query
        .children()
        .filter(Node::is_element)
        .collect::<Vec<_>>();
    if children.is_empty() {
        return Ok(false);
    }
    if children.len() != 1
        || children[0].tag_name().name() != "annotate"
        || children[0].tag_name().namespace() != Some(MIX_ROSTER_NS)
        || children[0].attributes().len() != 0
        || children[0].children().any(|node| node.is_element())
        || has_non_whitespace_text(children[0])
    {
        return Err("bad-request");
    }
    Ok(true)
}

fn has_non_whitespace_text(node: Node<'_, '_>) -> bool {
    node.children()
        .filter(|child| child.is_text())
        .filter_map(|child| child.text())
        .any(|text| !text.trim().is_empty())
}

fn stream_id() -> u128 {
    uuid::Uuid::new_v4().as_u128()
}

fn valid_bare_jid(value: &str) -> bool {
    northstar_xmpp_types::jid::CanonicalJid::parse_bare(value).is_ok()
}

struct ParsedRosterSetItem {
    contact: String,
    name: Option<String>,
    groups: Vec<String>,
    remove: bool,
}

fn parse_roster_set_item(
    item: Node<'_, '_>,
) -> std::result::Result<ParsedRosterSetItem, &'static str> {
    if item.attributes().any(|attribute| {
        attribute.namespace().is_some()
            || !matches!(attribute.name(), "jid" | "name" | "subscription")
    }) || has_non_whitespace_text(item)
    {
        return Err("bad-request");
    }
    let jid = item.attribute("jid").ok_or("jid-malformed")?;
    if !valid_bare_jid(jid) {
        return Err("jid-malformed");
    }
    let contact = northstar_xmpp_types::jid::canonicalize_bare(jid)
        .expect("valid_bare_jid and canonicalize_bare use the same parser");
    let name = item.attribute("name");
    if name.is_some_and(|name| name.chars().count() > 128 || name.len() > 1_024) {
        return Err("not-acceptable");
    }
    let groups = parse_roster_groups(item)?;
    // RFC 6121 requires ignoring all client-supplied subscription values
    // except the special deletion token.
    let remove = item.attribute("subscription") == Some("remove");
    if remove && (name.is_some() || !groups.is_empty()) {
        return Err("bad-request");
    }
    Ok(ParsedRosterSetItem {
        contact,
        name: name.map(str::to_owned),
        groups,
        remove,
    })
}

fn parse_roster_groups(item: Node<'_, '_>) -> std::result::Result<Vec<String>, &'static str> {
    let mut seen = HashSet::new();
    let mut groups = Vec::new();
    let mut group_bytes = 0usize;
    for child in item.children().filter(|node| node.is_element()) {
        if child.tag_name().name() != "group"
            || child.tag_name().namespace() != Some("jabber:iq:roster")
            || child.attributes().len() != 0
            || child.children().any(|node| node.is_element())
        {
            return Err("bad-request");
        }
        let group = child.text().unwrap_or_default().to_owned();
        if group.trim().is_empty() || group.len() > 1_024 {
            return Err("not-acceptable");
        }
        if !seen.insert(group.clone()) {
            return Err("bad-request");
        }
        group_bytes = group_bytes.saturating_add(group.len());
        if groups.len() >= 64 || group_bytes > 16_384 {
            return Err("resource-constraint");
        }
        groups.push(group);
    }
    Ok(groups)
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn mix_roster_annotation_is_opt_in_and_carries_stable_id() {
        let plain = roster_item_xml("c@mix.example.test", None, "none", None, false, &[], None);
        assert_eq!(
            plain,
            "<item jid='c@mix.example.test' subscription='none'/>"
        );

        let annotated = roster_item_xml(
            "c@mix.example.test",
            Some("Channel"),
            "none",
            None,
            false,
            &[],
            Some("opaque-id"),
        );
        assert!(annotated.contains("urn:xmpp:mix:roster:0"));
        assert!(annotated.contains("participant-id='opaque-id'"));
        assert!(annotated.contains("name='Channel'"));
    }

    #[test]
    fn mix_roster_annotation_escapes_untrusted_values() {
        let item = roster_item_xml(
            "c@mix.example.test",
            Some("A&B"),
            "none",
            None,
            true,
            &["A <group>".to_owned()],
            Some("opaque'id"),
        );
        assert!(item.contains("name='A&amp;B'"));
        assert!(item.contains("participant-id='opaque&apos;id'"));
        assert!(item.contains("approved='true'"));
        assert!(item.contains("<group>A &lt;group&gt;</group>"));
    }

    #[test]
    fn roster_groups_and_client_owned_fields_follow_rfc_6121() {
        let document = Document::parse(
            "<item xmlns='jabber:iq:roster' jid='a@example.test' subscription='both'><group>Friends</group><group>仕事</group></item>",
        )
        .unwrap();
        let parsed = parse_roster_set_item(document.root_element()).unwrap();
        assert_eq!(parsed.groups, ["Friends".to_owned(), "仕事".to_owned()]);
        assert!(!parsed.remove, "non-remove subscription must be ignored");

        let duplicate = Document::parse(
            "<item xmlns='jabber:iq:roster' jid='a@example.test'><group>Friends</group><group>Friends</group></item>",
        )
        .unwrap();
        assert_eq!(
            parse_roster_set_item(duplicate.root_element()).err(),
            Some("bad-request")
        );

        let empty =
            Document::parse("<item xmlns='jabber:iq:roster' jid='a@example.test'><group/></item>")
                .unwrap();
        assert_eq!(
            parse_roster_set_item(empty.root_element()).err(),
            Some("not-acceptable")
        );
        let whitespace = Document::parse(
            "<item xmlns='jabber:iq:roster' jid='a@example.test'><group>   </group></item>",
        )
        .unwrap();
        assert_eq!(
            parse_roster_set_item(whitespace.root_element()).err(),
            Some("not-acceptable")
        );

        let long_name = format!(
            "<item xmlns='jabber:iq:roster' jid='a@example.test' name='{}'/>",
            "x".repeat(129)
        );
        let long_name = Document::parse(&long_name).unwrap();
        assert_eq!(
            parse_roster_set_item(long_name.root_element()).err(),
            Some("not-acceptable")
        );

        let long_group = format!(
            "<item xmlns='jabber:iq:roster' jid='a@example.test'><group>{}</group></item>",
            "x".repeat(1_025)
        );
        let long_group = Document::parse(&long_group).unwrap();
        assert_eq!(
            parse_roster_set_item(long_group.root_element()).err(),
            Some("not-acceptable")
        );

        let invalid = Document::parse(
            "<item xmlns='jabber:iq:roster' jid='a@example.test'><group><b/></group></item>",
        )
        .unwrap();
        assert_eq!(
            parse_roster_set_item(invalid.root_element()).err(),
            Some("bad-request")
        );
    }

    #[test]
    fn roster_targets_and_get_payload_are_strict() {
        assert!(roster_target_allowed(None, "alice", "example.test"));
        assert!(roster_target_allowed(
            Some("Alice@EXAMPLE.test"),
            "alice",
            "example.test"
        ));
        assert!(!roster_target_allowed(
            Some("bob@example.test"),
            "alice",
            "example.test"
        ));
        assert!(!roster_target_allowed(
            Some("alice@example.test/Phone"),
            "alice",
            "example.test"
        ));
        assert_eq!(
            roster_target_error(Some("bob@example.test"), "alice", "example.test", true),
            Some("forbidden")
        );
        assert_eq!(
            roster_target_error(Some("bob@example.test"), "alice", "example.test", false),
            Some("service-unavailable")
        );

        for (xml, expected) in [
            ("<query xmlns='jabber:iq:roster'/>", Ok(false)),
            ("<query xmlns='jabber:iq:roster' ver='opaque'/>", Ok(false)),
            (
                "<query xmlns='jabber:iq:roster'><annotate xmlns='urn:xmpp:mix:roster:0'/></query>",
                Ok(true),
            ),
            (
                "<query xmlns='jabber:iq:roster' extra='x'/>",
                Err("bad-request"),
            ),
            (
                "<query xmlns='jabber:iq:roster'><item jid='bob@example.test'/></query>",
                Err("bad-request"),
            ),
        ] {
            let document = Document::parse(xml).unwrap();
            assert_eq!(validate_roster_get(document.root_element()), expected);
        }
    }

    #[test]
    fn roster_push_uses_the_committed_snapshot_and_exact_target() {
        let change = RosterChange {
            version: 42,
            contact_jid: "bob@example.test".to_owned(),
            display_name: Some("B&B".to_owned()),
            subscription: Some("both".to_owned()),
            ask: None,
            groups: vec!["Friends".to_owned()],
            approved: true,
            removed: false,
        };
        let item = roster_change_item_element(&change, None);
        let push = roster_push_xml("alice@example.test", "alice@example.test/Phone", 42, item);
        assert!(push.contains("from='alice@example.test'"));
        assert!(push.contains("to='alice@example.test/Phone'"));
        assert!(push.contains("ver='42'"));
        assert!(push.contains("name='B&amp;B'"));
        assert!(push.contains("<group>Friends</group>"));
    }

    #[test]
    fn roster_output_round_trips_hostile_runtime_values_without_markup_injection() {
        let jid = "x'&<@example.test";
        let name = "name' /><injected xmlns='urn:evil'/>";
        let group = "<& already &amp; escaped-looking".to_owned();
        let participant = "p' /><injected/>";
        let item = roster_item_xml(
            jid,
            Some(name),
            "none",
            Some("subscribe"),
            true,
            std::slice::from_ref(&group),
            Some(participant),
        );
        let document = Document::parse(&item).unwrap();
        let root = document.root_element();
        assert_eq!(root.attribute("jid"), Some(jid));
        assert_eq!(root.attribute("name"), Some(name));
        assert_eq!(root.children().filter(Node::is_element).count(), 2);
        let group_node = root
            .children()
            .find(|child| child.tag_name().name() == "group")
            .unwrap();
        assert_eq!(group_node.text(), Some(group.as_str()));
        let channel = root
            .children()
            .find(|child| child.tag_name().name() == "channel")
            .unwrap();
        assert_eq!(channel.attribute("participant-id"), Some(participant));
        assert!(document
            .descendants()
            .all(|node| !node.is_element() || node.tag_name().name() != "injected"));
    }
}
