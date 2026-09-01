use super::{Action, ProtocolSession};
use crate::jid::CanonicalJid;
use crate::services::private_storage::{
    LegacyBookmarkSnapshot, PrivateXmlEntry, PrivateXmlWriteOutcome, MAX_BOOKMARK_ITEMS,
};
use crate::services::pubsub::{
    PepAudienceSnapshot, PepBookmarkMutationOutcome, PepQuotas, PubSubAccount,
};
use crate::xmpp::xml_builder::XmlElement;
use crate::xmpp::xml_util::{iq_error, iq_result};
use anyhow::Result;
use roxmltree::Node;
use std::collections::{HashMap, HashSet};

const LEGACY_BOOKMARKS: &str = "storage:bookmarks";
const BOOKMARKS2: &str = "urn:xmpp:bookmarks:1";
const PRIVATE_XML: &str = "jabber:iq:private";
const PRIVATE_XML_MAX_ITEM_BYTES: usize = 512 * 1024;
const PRIVATE_XML_MAX_REQUEST_BYTES: usize = 1024 * 1024;

impl ProtocolSession {
    pub(crate) async fn private_get(
        &mut self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = self.authenticated.as_ref() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };

        if !private_target_is_self(to, &user.username, &self.state.config.domain) {
            return Ok(Action::Send(iq_error(id, "forbidden")));
        }

        if query.attributes().len() != 0
            || query.children().any(|child| {
                child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
            })
        {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }
        let children = query
            .children()
            .filter(|child| child.is_element())
            .collect::<Vec<_>>();
        if children.is_empty() {
            return Ok(Action::Send(private_bad_format(id)));
        }
        let Some(namespace) = children[0]
            .tag_name()
            .namespace()
            .filter(|namespace| !namespace.is_empty() && *namespace != PRIVATE_XML)
        else {
            return Ok(Action::Send(iq_error(id, "not-acceptable")));
        };
        if children.iter().any(|child| {
            child.tag_name().namespace() != Some(namespace)
                || child.tag_name().name().len() > 255
                || namespace.len() > 1024
        }) {
            // A get may name multiple elements, but XEP-0049 forbids querying
            // more than one namespace in the same IQ.
            return Ok(Action::Send(iq_error(id, "bad-request")));
        }

        let mut response = XmlElement::namespaced("query", PRIVATE_XML);
        for child in children {
            let name = child.tag_name().name();
            let xml_data = if name == "storage" && namespace == LEGACY_BOOKMARKS {
                let snapshot = self
                    .state
                    .private_storage_service()
                    .legacy_bookmark_snapshot(user.id)
                    .await?;
                modern_bookmarks_as_legacy(snapshot)?
            } else {
                self.state
                    .private_storage_service()
                    .get(user.id, name, namespace)
                    .await?
            };
            if let Some(data) = xml_data {
                response.push_validated_fragment(&data)?;
            } else {
                response.push_child(XmlElement::dynamic(name)?.attr("xmlns", namespace));
            }
        }

        Ok(Action::Send(iq_result(id, &response.finish())))
    }

    pub(crate) async fn private_set(
        &mut self,
        id: &str,
        to: Option<&str>,
        query: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        let Some(user) = self.authenticated.as_ref() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };

        if !private_target_is_self(to, &user.username, &self.state.config.domain) {
            return Ok(Action::Send(iq_error(id, "forbidden")));
        }

        // XEP-0049 permits an IQ-set to contain multiple elements as long as
        // they are all qualified by the same namespace.  The previous
        // exactly-one check made the batch path below unreachable.
        let children = match private_children(query) {
            Ok(children) => children,
            Err(()) => return Ok(Action::Send(iq_error(id, "not-acceptable"))),
        };
        let Some(namespace) = children[0]
            .tag_name()
            .namespace()
            .filter(|namespace| !namespace.is_empty() && *namespace != PRIVATE_XML)
        else {
            return Ok(Action::Send(iq_error(id, "not-acceptable")));
        };
        let mut seen_names = HashSet::new();
        let mut request_bytes = 0_usize;
        for child in &children {
            let name = child.tag_name().name();
            let ns = child.tag_name().namespace();
            let xml_data = &raw[child.range()];
            request_bytes = request_bytes.saturating_add(xml_data.len());
            if ns != Some(namespace)
                || name.len() > 255
                || namespace.len() > 1024
                || xml_data.len() > PRIVATE_XML_MAX_ITEM_BYTES
                || !seen_names.insert(name)
            {
                return Ok(Action::Send(iq_error(id, "not-acceptable")));
            }
        }
        if request_bytes > PRIVATE_XML_MAX_REQUEST_BYTES {
            return Ok(Action::Send(iq_error(id, "resource-constraint")));
        }

        if children.len() == 1
            && children[0].tag_name().name() == "storage"
            && namespace == LEGACY_BOOKMARKS
        {
            let mut items = match legacy_bookmarks_as_modern(children[0]) {
                Ok(items) => items,
                Err(condition) => return Ok(Action::Send(iq_error(id, condition))),
            };
            let private_xml = &raw[children[0].range()];
            let previous_items = self
                .state
                .private_storage_service()
                .prepare_legacy_bookmark_write(user.id, &mut items)
                .await?;
            let previous = previous_items.iter().cloned().collect::<HashMap<_, _>>();
            let event = bookmark_event_delta(&items, &previous)?;
            let (max_private_bytes, max_nodes, max_storage_bytes) = self
                .state
                .private_storage_service()
                .legacy_bookmark_limits();
            let owner = PubSubAccount {
                id: user.id,
                username: user.username.clone(),
                auth_generation: user.auth_generation,
            };
            let audience_state = std::sync::Arc::clone(&self.state);
            let publisher_full_jid = self.full_jid.clone();
            match self
                .state
                .pubsub_service()
                .commit_legacy_bookmarks(
                    &owner,
                    self.connection_id,
                    private_xml,
                    &mut items,
                    &previous_items,
                    max_private_bytes,
                    PepQuotas {
                        max_nodes,
                        max_storage_bytes,
                    },
                    &move |audience: &PepAudienceSnapshot| {
                        if event.is_empty() {
                            return Ok(Vec::new());
                        }
                        ProtocolSession::prepare_pep_audience_messages(
                            audience_state.as_ref(),
                            publisher_full_jid.as_deref(),
                            BOOKMARKS2,
                            &event,
                            audience,
                        )
                    },
                )
                .await?
            {
                PepBookmarkMutationOutcome::Stored => {}
                PepBookmarkMutationOutcome::ConcurrentChange => {
                    return Ok(Action::Send(iq_error(id, "conflict")));
                }
                PepBookmarkMutationOutcome::ResourceConstraint => {
                    return Ok(Action::Send(iq_error(id, "resource-constraint")));
                }
                PepBookmarkMutationOutcome::Forbidden => {
                    return Ok(Action::Send(iq_error(id, "forbidden")));
                }
            }
            return Ok(Action::Send(iq_result(id, "")));
        }

        let entries = children
            .iter()
            .map(|child| PrivateXmlEntry {
                element_name: child.tag_name().name(),
                element_ns: namespace,
                xml_data: &raw[child.range()],
            })
            .collect::<Vec<_>>();
        if self
            .state
            .private_storage_service()
            .set_batch(user.id, &entries)
            .await?
            == PrivateXmlWriteOutcome::QuotaExceeded
        {
            return Ok(Action::Send(iq_error(id, "resource-constraint")));
        }

        Ok(Action::Send(iq_result(id, "")))
    }
}

fn bookmark_event_delta(
    current: &[(String, String)],
    previous: &HashMap<String, String>,
) -> Result<String> {
    let current_ids = current
        .iter()
        .map(|(item_id, _)| item_id.as_str())
        .collect::<HashSet<_>>();
    let mut event = XmlElement::new("northstar-event-fragment");
    for (_, payload) in current
        .iter()
        .filter(|(item_id, payload)| previous.get(item_id) != Some(payload))
    {
        event.push_validated_fragment(payload)?;
    }
    let mut removed = previous
        .keys()
        .filter(|item_id| !current_ids.contains(item_id.as_str()))
        .collect::<Vec<_>>();
    removed.sort();
    for item_id in removed {
        event.push_child(XmlElement::new("retract").attr("id", item_id));
    }
    Ok(event.finish_children())
}

fn private_bad_format(id: &str) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "error")
        .attr("id", id)
        .child(
            XmlElement::new("error")
                .attr("type", "modify")
                .child(XmlElement::namespaced(
                    "bad-format",
                    "urn:ietf:params:xml:ns:xmpp-stanzas",
                )),
        )
        .finish()
}

fn private_children<'a, 'input>(
    query: Node<'a, 'input>,
) -> std::result::Result<Vec<Node<'a, 'input>>, ()> {
    if query.attributes().len() != 0
        || query.children().any(|child| {
            child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
        || query
            .children()
            .filter(|child| child.is_element())
            .any(|child| {
                child
                    .tag_name()
                    .namespace()
                    .is_none_or(|namespace| namespace.is_empty() || namespace == PRIVATE_XML)
            })
    {
        return Err(());
    }
    let children = query
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    (!children.is_empty()).then_some(children).ok_or(())
}

fn private_target_is_self(to: Option<&str>, username: &str, domain: &str) -> bool {
    let Some(to) = to else {
        return true;
    };
    let Ok(target) = CanonicalJid::parse_bare(to) else {
        return false;
    };
    target
        .localpart()
        .is_some_and(|localpart| localpart == username)
        && target.domainpart() == domain
}

fn legacy_bookmarks_as_modern(
    storage: Node<'_, '_>,
) -> std::result::Result<Vec<(String, String)>, &'static str> {
    if storage.attributes().len() != 0
        || storage.children().any(|child| {
            child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
        })
    {
        return Err("bad-request");
    }
    let mut seen = HashSet::new();
    let mut items = Vec::new();
    for conference in storage.children().filter(|node| node.is_element()) {
        if conference.tag_name().namespace() != Some(LEGACY_BOOKMARKS) {
            return Err("bad-request");
        }
        if conference.tag_name().name() != "conference" {
            // XEP-0048 also permits URL bookmarks. XEP-0402 intentionally
            // does not, so retain them only in Private XML storage.
            if conference.tag_name().name() == "url" {
                validate_legacy_url_bookmark(conference)?;
                continue;
            }
            return Err("bad-request");
        }
        if conference
            .attributes()
            .any(|attribute| !matches!(attribute.name(), "autojoin" | "jid" | "name"))
            || conference.children().any(|child| {
                child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty())
            })
        {
            return Err("bad-request");
        }
        let jid = conference.attribute("jid").unwrap_or_default();
        let canonical_jid = CanonicalJid::parse_bare(jid).map_err(|_| "jid-malformed")?;
        if canonical_jid.localpart().is_none() || !seen.insert(canonical_jid.to_string()) {
            return Err("jid-malformed");
        }
        let jid = canonical_jid.to_string();
        let autojoin = match conference.attribute("autojoin") {
            None => None,
            Some(value @ ("0" | "1" | "false" | "true")) => Some(value),
            Some(_) => return Err("bad-request"),
        };
        let mut modern_conference = XmlElement::namespaced("conference", BOOKMARKS2)
            .optional_attr("name", conference.attribute("name"))
            .optional_attr("autojoin", autojoin);
        let mut previous_child = 0_u8;
        let mut values = HashMap::new();
        for child in conference.children().filter(|child| child.is_element()) {
            if child.tag_name().namespace() != Some(LEGACY_BOOKMARKS)
                || child.attributes().len() != 0
                || child.children().any(|nested| nested.is_element())
            {
                return Err("bad-request");
            }
            let order = match child.tag_name().name() {
                "nick" => 1,
                "password" => 2,
                _ => return Err("bad-request"),
            };
            if order <= previous_child {
                return Err("bad-request");
            }
            previous_child = order;
            values.insert(child.tag_name().name(), child.text().unwrap_or_default());
        }
        for child_name in ["nick", "password"] {
            if let Some(value) = values.get(child_name) {
                let child = match child_name {
                    "nick" => XmlElement::new("nick"),
                    "password" => XmlElement::new("password"),
                    _ => unreachable!("fixed bookmark child name"),
                };
                modern_conference.push_child(child.text(*value));
            }
        }
        let modern = XmlElement::new("item")
            .attr("id", &jid)
            .child(modern_conference)
            .finish();
        items.push((jid, modern));
        if items.len() > MAX_BOOKMARK_ITEMS {
            return Err("resource-constraint");
        }
    }
    Ok(items)
}

fn modern_bookmarks_as_legacy(snapshot: LegacyBookmarkSnapshot) -> Result<Option<String>> {
    if !snapshot.modern_node_exists {
        return Ok(snapshot.private_xml);
    }
    let mut legacy = XmlElement::namespaced("storage", LEGACY_BOOKMARKS);
    for (item_id, item_xml) in snapshot.modern_items {
        let wrapped = match XmlElement::namespaced("pubsub", "http://jabber.org/protocol/pubsub")
            .validated_fragment(&item_xml)
        {
            Ok(wrapper) => wrapper.finish(),
            Err(error) => {
                tracing::warn!(item_id, ?error, "ignored malformed stored bookmark item");
                continue;
            }
        };
        let Ok(document) = roxmltree::Document::parse(&wrapped) else {
            tracing::warn!(item_id, "ignored malformed stored bookmark item");
            continue;
        };
        let Some(conference) = document.descendants().find(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(BOOKMARKS2)
                && node.tag_name().name() == "conference"
        }) else {
            continue;
        };
        let mut legacy_conference = XmlElement::new("conference")
            .attr("jid", &item_id)
            .optional_attr("name", conference.attribute("name"))
            .optional_attr("autojoin", conference.attribute("autojoin"));
        for child_name in ["nick", "password"] {
            if let Some(value) = conference
                .children()
                .find(|child| {
                    child.is_element()
                        && child.tag_name().namespace() == Some(BOOKMARKS2)
                        && child.tag_name().name() == child_name
                })
                .and_then(|child| child.text())
            {
                let child = match child_name {
                    "nick" => XmlElement::new("nick"),
                    "password" => XmlElement::new("password"),
                    _ => unreachable!("fixed bookmark child name"),
                };
                legacy_conference.push_child(child.text(value));
            }
        }
        legacy.push_child(legacy_conference);
    }
    // XEP-0402 intentionally has no URL-bookmark representation.  Preserve
    // those entries from the legacy Private XML document while projecting
    // conference bookmarks from the authoritative Bookmarks 2 node.
    if let Some(storage) = snapshot.private_xml.as_deref() {
        legacy.push_validated_fragment(&legacy_url_bookmarks(storage))?;
    }
    Ok(Some(legacy.finish()))
}

fn validate_legacy_url_bookmark(url: Node<'_, '_>) -> std::result::Result<(), &'static str> {
    if url
        .attributes()
        .any(|attribute| !matches!(attribute.name(), "name" | "url"))
        || url.children().any(|child| child.is_element())
        || url.text().is_some_and(|text| !text.trim().is_empty())
    {
        return Err("bad-request");
    }
    let value = url.attribute("url").ok_or("bad-request")?;
    let lower = value.to_ascii_lowercase();
    let remainder = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
        .ok_or("bad-request")?;
    if remainder.is_empty()
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err("bad-request");
    }
    Ok(())
}

fn legacy_url_bookmarks(storage: &str) -> String {
    let Ok(document) = roxmltree::Document::parse(storage) else {
        return String::new();
    };
    let root = document.root_element();
    if root.tag_name().name() != "storage" || root.tag_name().namespace() != Some(LEGACY_BOOKMARKS)
    {
        return String::new();
    }
    root.children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() == "url"
                && child.tag_name().namespace() == Some(LEGACY_BOOKMARKS)
                && validate_legacy_url_bookmark(*child).is_ok()
        })
        .map(|child| {
            XmlElement::new("url")
                .optional_attr("name", child.attribute("name"))
                .attr(
                    "url",
                    child
                        .attribute("url")
                        .expect("validated URL has url attribute"),
                )
                .finish()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn legacy_bookmarks_convert_without_leaking_url_entries() {
        let document = Document::parse("<storage xmlns='storage:bookmarks'><conference jid='room@conference.example' name='Room' autojoin='true'><nick>Alice &amp; Bob</nick><password>&lt;secret&gt;</password></conference><url name='Home' url='https://example.test'/></storage>").unwrap();
        let converted = legacy_bookmarks_as_modern(document.root_element()).unwrap();
        assert_eq!(converted.len(), 1);
        assert_eq!(converted[0].0, "room@conference.example");
        assert!(converted[0].1.contains("Alice &amp; Bob"));
        assert!(converted[0].1.contains("&lt;secret&gt;"));
        assert!(!converted[0].1.contains("https://example.test"));
    }

    #[test]
    fn legacy_bookmarks_reject_duplicates_and_bad_autojoin() {
        for xml in [
            "<storage xmlns='storage:bookmarks'><conference jid='room@conference.example'/><conference jid='ROOM@conference.example'/></storage>",
            "<storage xmlns='storage:bookmarks'><conference jid='room@conference.example' autojoin='yes'/></storage>",
            "<storage xmlns='storage:bookmarks'><conference jid='not-a-jid'/></storage>",
            "<storage xmlns='storage:bookmarks'><conference jid='room@conference.example'><nick>a</nick><nick>b</nick></conference></storage>",
            "<storage xmlns='storage:bookmarks'><conference jid='room@conference.example'><password>secret</password><nick>late</nick></conference></storage>",
            "<storage xmlns='storage:bookmarks'><conference jid='room@conference.example' unexpected='1'/></storage>",
            "<storage xmlns='storage:bookmarks'><url url='ftp://example.test/file'/></storage>",
            "<storage xmlns='storage:bookmarks'><url/></storage>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(legacy_bookmarks_as_modern(document.root_element()).is_err());
        }
    }

    #[test]
    fn private_xml_requires_exact_namespaced_children() {
        let document = Document::parse(
            "<query xmlns='jabber:iq:private'><prefs xmlns='urn:example:prefs'/></query>",
        )
        .unwrap();
        assert!(private_children(document.root_element()).is_ok());
        let batch = Document::parse(
            "<query xmlns='jabber:iq:private'><one xmlns='urn:example:prefs'/><two xmlns='urn:example:prefs'/></query>",
        )
        .unwrap();
        assert_eq!(private_children(batch.root_element()).unwrap().len(), 2);
        for xml in [
            "<query xmlns='jabber:iq:private'/>",
            "<query xmlns='jabber:iq:private'><prefs/></query>",
            "<query xmlns='jabber:iq:private'>non-whitespace<prefs xmlns='urn:example:prefs'/></query>",
            "<query xmlns='jabber:iq:private' unexpected='true'><prefs xmlns='urn:example:prefs'/></query>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(private_children(document.root_element()).is_err());
        }
    }

    #[test]
    fn private_bad_format_uses_the_historical_stanza_condition_namespace() {
        let error = private_bad_format("get-empty");
        assert!(error.contains("<bad-format xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"));
        assert!(!error.contains("<not-acceptable"));
        assert!(!error.contains("<bad-format xmlns='jabber:iq:private'"));
    }

    #[test]
    fn legacy_url_projection_preserves_only_valid_http_bookmarks() {
        let projected = legacy_url_bookmarks(
            "<storage xmlns='storage:bookmarks'><conference jid='room@conference.example'/><url name='Docs &amp; Help' url='HTTPS://example.test/docs'/><url url='ftp://example.test/file'/></storage>",
        );
        assert_eq!(
            projected,
            "<url name='Docs &amp; Help' url='HTTPS://example.test/docs'/>"
        );
    }

    #[test]
    fn bookmark_compatibility_suppresses_unchanged_events() {
        let current = vec![(
            "room@conference.example".to_owned(),
            "<item id='room@conference.example'><conference xmlns='urn:xmpp:bookmarks:1' autojoin='true'></conference></item>".to_owned(),
        )];
        let identical = HashMap::from([(current[0].0.clone(), current[0].1.clone())]);
        assert!(bookmark_event_delta(&current, &identical)
            .unwrap()
            .is_empty());

        let removed = bookmark_event_delta(&[], &identical).unwrap();
        assert_eq!(removed, "<retract id='room@conference.example'/>");
    }

    #[test]
    fn private_xml_target_is_strictly_the_authenticated_bare_jid() {
        assert!(private_target_is_self(None, "alice", "example.test"));
        assert!(private_target_is_self(
            Some("alice@EXAMPLE.test"),
            "alice",
            "example.test"
        ));
        assert!(!private_target_is_self(
            Some("alice@example.test/Phone"),
            "alice",
            "example.test"
        ));
        assert!(!private_target_is_self(
            Some("bob@example.test"),
            "alice",
            "example.test"
        ));
        assert!(!private_target_is_self(
            Some("alice@remote.test"),
            "alice",
            "example.test"
        ));
    }
}
