//! Dependency-light XML parsing shared by the MAM and PubSub protocol paths.
//!
//! This module deliberately owns only syntactic parsing and bounded protocol
//! values. Database access, authorization and stanza rendering remain in the
//! protocol/application layers. Keeping this boundary free of `AppState`
//! makes the exact production parser reusable by deterministic tests and the
//! parser-robustness harness without maintaining a second XML interpretation.

use roxmltree::Node;
use std::collections::{BTreeSet, HashSet};
use uuid::Uuid;

pub(crate) const MAM_NS: &str = "urn:xmpp:mam:2";
pub(crate) const RSM_NS: &str = "http://jabber.org/protocol/rsm";
const XDATA_NS: &str = "jabber:x:data";
pub(crate) const PUBSUB_NS: &str = "http://jabber.org/protocol/pubsub";
pub(crate) const PUBSUB_OWNER_NS: &str = "http://jabber.org/protocol/pubsub#owner";

pub(crate) const MAX_MAM_RESULTS: i64 = 100;
const MAX_MAM_IDS: usize = 100;
// OFFSET paging is inherently more expensive than keyset paging. XEP-0059
// makes index retrieval optional; callers can continue with the opaque ids in
// the returned page after this production bound.
const MAX_MAM_RSM_INDEX: i64 = 1_000_000;
const MAX_PUBSUB_ITEM_ID_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MamRsmPage {
    First,
    Last,
    Before(Uuid),
    After(Uuid),
    Index(i64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedMamQuery<T> {
    pub(crate) with_jid: Option<String>,
    pub(crate) start: Option<T>,
    pub(crate) end: Option<T>,
    pub(crate) before_id: Option<Uuid>,
    pub(crate) after_id: Option<Uuid>,
    pub(crate) ids: Vec<Uuid>,
    pub(crate) page: MamRsmPage,
    pub(crate) max: i64,
    pub(crate) query_id: Option<String>,
    pub(crate) flip_page: bool,
}

pub(crate) fn attributes_are(node: Node<'_, '_>, allowed: &[&str]) -> bool {
    node.attributes().all(|attribute| {
        attribute.namespace().is_none()
            && allowed.iter().any(|allowed| attribute.name() == *allowed)
    })
}

pub(crate) fn structural_text_is_empty(node: Node<'_, '_>) -> bool {
    node.children()
        .filter(|child| child.is_text())
        .all(|child| child.text().unwrap_or_default().trim().is_empty())
}

fn field_values<'a>(field: Node<'a, '_>) -> Result<Vec<&'a str>, &'static str> {
    if !attributes_are(field, &["var", "type"]) || !structural_text_is_empty(field) {
        return Err("bad-request");
    }
    let mut values = Vec::new();
    for child in field.children().filter(|child| child.is_element()) {
        if child.tag_name().namespace() != Some(XDATA_NS)
            || child.tag_name().name() != "value"
            || !attributes_are(child, &[])
            || child.children().any(|nested| nested.is_element())
        {
            return Err("bad-request");
        }
        values.push(child.text().unwrap_or_default());
    }
    Ok(values)
}

fn one_value<'a>(values: &[&'a str]) -> Result<&'a str, &'static str> {
    match values {
        [value] => Ok(*value),
        _ => Err("bad-request"),
    }
}

fn parse_archive_id(value: &str) -> Result<Uuid, &'static str> {
    Uuid::parse_str(value).map_err(|_| "item-not-found")
}

#[allow(clippy::too_many_arguments)]
fn parse_mam_form<T, CanonicalizeJid, ParseTimestamp>(
    form: Node<'_, '_>,
    with_jid: &mut Option<String>,
    start: &mut Option<T>,
    end: &mut Option<T>,
    before_id: &mut Option<Uuid>,
    after_id: &mut Option<Uuid>,
    ids: &mut Vec<Uuid>,
    canonicalize_jid: &mut CanonicalizeJid,
    parse_timestamp: &mut ParseTimestamp,
) -> Result<(), &'static str>
where
    CanonicalizeJid: FnMut(&str) -> Result<String, &'static str>,
    ParseTimestamp: FnMut(&str) -> Result<T, &'static str>,
{
    if form.tag_name().namespace() != Some(XDATA_NS)
        || form.tag_name().name() != "x"
        || !attributes_are(form, &["type"])
        || form.attribute("type") != Some("submit")
        || !structural_text_is_empty(form)
    {
        return Err("bad-request");
    }
    let mut seen = HashSet::new();
    let mut form_type_seen = false;
    for field in form.children().filter(|child| child.is_element()) {
        if field.tag_name().namespace() != Some(XDATA_NS) || field.tag_name().name() != "field" {
            return Err("bad-request");
        }
        let name = field.attribute("var").ok_or("bad-request")?;
        if !seen.insert(name.to_owned()) {
            return Err("bad-request");
        }
        let values = field_values(field)?;
        match name {
            "FORM_TYPE" => {
                if field.attribute("type").is_some_and(|kind| kind != "hidden")
                    || one_value(&values)? != MAM_NS
                {
                    return Err("bad-request");
                }
                form_type_seen = true;
            }
            "with" => {
                if field
                    .attribute("type")
                    .is_some_and(|kind| kind != "jid-single")
                {
                    return Err("bad-request");
                }
                *with_jid = Some(canonicalize_jid(one_value(&values)?)?);
            }
            "start" | "end" => {
                if field
                    .attribute("type")
                    .is_some_and(|kind| kind != "text-single")
                {
                    return Err("bad-request");
                }
                let timestamp = parse_timestamp(one_value(&values)?)?;
                if name == "start" {
                    *start = Some(timestamp);
                } else {
                    *end = Some(timestamp);
                }
            }
            "before-id" | "after-id" => {
                if field
                    .attribute("type")
                    .is_some_and(|kind| kind != "text-single")
                {
                    return Err("bad-request");
                }
                let archive_id = parse_archive_id(one_value(&values)?)?;
                if name == "before-id" {
                    *before_id = Some(archive_id);
                } else {
                    *after_id = Some(archive_id);
                }
            }
            "ids" => {
                if field
                    .attribute("type")
                    .is_some_and(|kind| kind != "list-multi")
                    || values.is_empty()
                    || values.len() > MAX_MAM_IDS
                {
                    return Err(if values.len() > MAX_MAM_IDS {
                        "resource-constraint"
                    } else {
                        "bad-request"
                    });
                }
                let mut unique = HashSet::new();
                for value in values {
                    let archive_id = parse_archive_id(value)?;
                    if !unique.insert(archive_id) {
                        return Err("bad-request");
                    }
                    ids.push(archive_id);
                }
            }
            _ => return Err("feature-not-implemented"),
        }
    }
    if !form_type_seen {
        return Err("bad-request");
    }
    Ok(())
}

fn parse_mam_rsm(set: Node<'_, '_>) -> Result<(MamRsmPage, i64), &'static str> {
    if !attributes_are(set, &[]) || !structural_text_is_empty(set) {
        return Err("bad-request");
    }
    let mut max = MAX_MAM_RESULTS;
    let mut before = None;
    let mut after = None;
    let mut index = None;
    let mut seen = HashSet::new();
    for child in set.children().filter(|child| child.is_element()) {
        if child.tag_name().namespace() != Some(RSM_NS)
            || !matches!(
                child.tag_name().name(),
                "max" | "before" | "after" | "index"
            )
            || !seen.insert(child.tag_name().name())
            || !attributes_are(child, &[])
            || child.children().any(|nested| nested.is_element())
        {
            return Err("bad-request");
        }
        let value = child.text().unwrap_or_default();
        match child.tag_name().name() {
            "max" => {
                max = value.parse::<i64>().map_err(|_| "bad-request")?;
                if max < 0 {
                    return Err("bad-request");
                }
                max = max.min(MAX_MAM_RESULTS);
            }
            "before" => before = Some(value),
            "after" => after = Some(value),
            "index" => {
                let parsed = value.parse::<i64>().map_err(|_| "bad-request")?;
                if parsed < 0 {
                    return Err("bad-request");
                }
                if parsed > MAX_MAM_RSM_INDEX {
                    return Err("resource-constraint");
                }
                index = Some(parsed);
            }
            _ => unreachable!("RSM element allow-list was checked above"),
        }
    }
    if usize::from(before.is_some()) + usize::from(after.is_some()) + usize::from(index.is_some())
        > 1
    {
        return Err("bad-request");
    }
    let page = match (before, after, index) {
        (Some(""), None, None) => MamRsmPage::Last,
        (Some(value), None, None) => MamRsmPage::Before(parse_archive_id(value)?),
        (None, Some(""), None) => return Err("bad-request"),
        (None, Some(value), None) => MamRsmPage::After(parse_archive_id(value)?),
        (None, None, Some(index)) => MamRsmPage::Index(index),
        (None, None, None) => MamRsmPage::First,
        _ => unreachable!("ambiguous RSM controls rejected above"),
    };
    Ok((page, max))
}

/// Parse the production XEP-0313 query grammar.
///
/// JID preparation and timestamp conversion are supplied by the protocol
/// caller so this module stays dependency-light. They execute at the exact
/// point where the corresponding field occurs, preserving the former error
/// precedence when a malformed form contains more than one invalid value.
pub(crate) fn parse_mam_query<T, CanonicalizeJid, ParseTimestamp>(
    query: Node<'_, '_>,
    mut canonicalize_jid: CanonicalizeJid,
    mut parse_timestamp: ParseTimestamp,
) -> Result<ParsedMamQuery<T>, &'static str>
where
    T: PartialOrd,
    CanonicalizeJid: FnMut(&str) -> Result<String, &'static str>,
    ParseTimestamp: FnMut(&str) -> Result<T, &'static str>,
{
    if query.tag_name().namespace() != Some(MAM_NS)
        || query.tag_name().name() != "query"
        || !attributes_are(query, &["queryid"])
        || !structural_text_is_empty(query)
    {
        return Err(if query.attribute("node").is_some() {
            "feature-not-implemented"
        } else {
            "bad-request"
        });
    }
    let query_id = query
        .attribute("queryid")
        .map(str::to_owned)
        .filter(|value| value.len() <= 1_024 && !value.chars().any(char::is_control));
    if query.attribute("queryid").is_some() && query_id.is_none() {
        return Err("bad-request");
    }
    let mut form = None;
    let mut rsm = None;
    let mut flip_page = false;
    for child in query.children().filter(|child| child.is_element()) {
        match (child.tag_name().name(), child.tag_name().namespace()) {
            ("x", Some(XDATA_NS)) if form.is_none() => form = Some(child),
            ("set", Some(RSM_NS)) if rsm.is_none() => rsm = Some(child),
            ("flip-page", Some(MAM_NS)) if !flip_page => {
                if !attributes_are(child, &[])
                    || child.children().any(|nested| nested.is_element())
                    || !structural_text_is_empty(child)
                {
                    return Err("bad-request");
                }
                flip_page = true;
            }
            ("x", Some(XDATA_NS)) | ("set", Some(RSM_NS)) | ("flip-page", Some(MAM_NS)) => {
                return Err("bad-request");
            }
            _ => return Err("feature-not-implemented"),
        }
    }

    let mut with_jid = None;
    let mut start = None;
    let mut end = None;
    let mut before_id = None;
    let mut after_id = None;
    let mut ids = Vec::new();
    if let Some(form) = form {
        parse_mam_form(
            form,
            &mut with_jid,
            &mut start,
            &mut end,
            &mut before_id,
            &mut after_id,
            &mut ids,
            &mut canonicalize_jid,
            &mut parse_timestamp,
        )?;
    }
    if matches!((&start, &end), (Some(start), Some(end)) if start > end) {
        return Err("bad-request");
    }
    let (page, max) = rsm
        .map(parse_mam_rsm)
        .transpose()?
        .unwrap_or((MamRsmPage::First, MAX_MAM_RESULTS));
    Ok(ParsedMamQuery {
        with_jid,
        start,
        end,
        before_id,
        after_id,
        ids,
        page,
        max,
        query_id,
        flip_page,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PubSubNamespace {
    Entity,
    Owner,
}

#[derive(Debug)]
pub(crate) struct ParsedPubSubEnvelope<'a, 'input> {
    pub(crate) namespace: PubSubNamespace,
    pub(crate) operations: Vec<Node<'a, 'input>>,
}

fn has_only_whitespace_text(node: Node<'_, '_>) -> bool {
    node.children()
        .filter(|child| child.is_text())
        .all(|child| child.text().is_none_or(|text| text.trim().is_empty()))
}

/// Parse the common XEP-0060 request envelope before authorization or storage
/// is consulted. The returned operation nodes are still interpreted by the
/// entity/owner handlers because their legal combinations depend on IQ kind.
pub(crate) fn parse_pubsub_envelope<'a, 'input>(
    child: Node<'a, 'input>,
    kind: &str,
) -> Result<ParsedPubSubEnvelope<'a, 'input>, &'static str> {
    let namespace = child.tag_name().namespace().unwrap_or_default();
    if child.tag_name().name() != "pubsub" {
        return Err("feature-not-implemented");
    }
    if !has_only_whitespace_text(child) {
        return Err("bad-request");
    }
    let operations = child
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    if operations.is_empty() {
        return Err("bad-request");
    }
    let rsm_count = operations
        .iter()
        .filter(|operation| {
            operation.tag_name().name() == "set" && operation.tag_name().namespace() == Some(RSM_NS)
        })
        .count();
    if rsm_count > 1
        || operations.iter().any(|operation| {
            operation.tag_name().namespace() != Some(namespace)
                && !(kind == "get"
                    && namespace == PUBSUB_NS
                    && operation.tag_name().name() == "set"
                    && operation.tag_name().namespace() == Some(RSM_NS))
        })
    {
        return Err("bad-request");
    }
    let namespace = match (namespace, kind) {
        (PUBSUB_NS, "get" | "set") => PubSubNamespace::Entity,
        (PUBSUB_OWNER_NS, "get" | "set") => PubSubNamespace::Owner,
        _ => return Err("feature-not-implemented"),
    };
    Ok(ParsedPubSubEnvelope {
        namespace,
        operations,
    })
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PubSubRsmRequest {
    pub(crate) max: Option<usize>,
    pub(crate) after: Option<String>,
    /// `Some(None)` represents the empty `<before/>` final-page request.
    pub(crate) before: Option<Option<String>>,
}

pub(crate) fn valid_pubsub_item_id(item_id: &str) -> bool {
    !item_id.is_empty()
        && item_id.len() <= MAX_PUBSUB_ITEM_ID_BYTES
        && !item_id.chars().any(char::is_control)
}

pub(crate) fn parse_pubsub_rsm(set: Node<'_, '_>) -> Result<PubSubRsmRequest, &'static str> {
    if set.tag_name().name() != "set"
        || set.tag_name().namespace() != Some(RSM_NS)
        || set.attributes().len() != 0
        || set
            .children()
            .filter(|child| child.is_text())
            .any(|child| child.text().is_some_and(|text| !text.trim().is_empty()))
    {
        return Err("bad-request");
    }
    let mut result = PubSubRsmRequest::default();
    let mut seen = BTreeSet::new();
    for child in set.children().filter(|child| child.is_element()) {
        if child.tag_name().namespace() != Some(RSM_NS)
            || child.attributes().len() != 0
            || child.children().any(|nested| nested.is_element())
            || !seen.insert(child.tag_name().name())
        {
            return Err("bad-request");
        }
        let text = child
            .children()
            .filter(|content| content.is_text())
            .map(|content| content.text().unwrap_or_default())
            .collect::<String>();
        match child.tag_name().name() {
            "max" => {
                result.max = Some(
                    text.parse::<usize>()
                        .ok()
                        .filter(|max| *max <= 1_000)
                        .ok_or("bad-request")?,
                );
            }
            "after" if valid_pubsub_item_id(&text) => result.after = Some(text),
            "before" if text.is_empty() => result.before = Some(None),
            "before" if valid_pubsub_item_id(&text) => result.before = Some(Some(text)),
            _ => return Err("bad-request"),
        }
    }
    if result.after.is_some() && result.before.is_some() {
        return Err("bad-request");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    fn parse_mam(xml: &str) -> Result<ParsedMamQuery<i64>, &'static str> {
        let document = Document::parse(xml).expect("valid deterministic XML fixture");
        parse_mam_query(
            document.root_element(),
            |jid| {
                if jid.contains('@') && jid.trim() == jid {
                    Ok(jid.to_ascii_lowercase())
                } else {
                    Err("jid-malformed")
                }
            },
            |timestamp| timestamp.parse::<i64>().map_err(|_| "bad-request"),
        )
    }

    #[test]
    fn mam_parser_preserves_extended_filters_and_bounds() {
        let parsed = parse_mam(
            "<query xmlns='urn:xmpp:mam:2' queryid='q'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mam:2</value></field><field var='with'><value>A@Example.test</value></field><field var='start'><value>10</value></field><field var='end'><value>20</value></field><field var='ids' type='list-multi'><value>de305d54-75b4-431b-adb2-eb6b9e546013</value></field></x><set xmlns='http://jabber.org/protocol/rsm'><max>500</max><before/></set><flip-page/></query>",
        )
        .unwrap();
        assert_eq!(parsed.with_jid.as_deref(), Some("a@example.test"));
        assert_eq!((parsed.start, parsed.end), (Some(10), Some(20)));
        assert_eq!(parsed.ids.len(), 1);
        assert_eq!(parsed.page, MamRsmPage::Last);
        assert_eq!(parsed.max, MAX_MAM_RESULTS);
        assert_eq!(parsed.query_id.as_deref(), Some("q"));
        assert!(parsed.flip_page);
    }

    #[test]
    fn mam_parser_keeps_error_conditions_and_validation_order() {
        assert_eq!(
            parse_mam("<query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><index>1000001</index></set></query>"),
            Err("resource-constraint")
        );
        assert_eq!(
            parse_mam("<query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='with'><value> malformed </value></field><field var='start'><value>not-a-time</value></field></x></query>"),
            Err("jid-malformed")
        );
        assert_eq!(
            parse_mam("<query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='start'><value>20</value></field><field var='end'><value>10</value></field></x></query>"),
            Err("bad-request")
        );
    }

    #[test]
    fn pubsub_envelope_accepts_entity_get_with_one_rsm_control() {
        let document = Document::parse(
            "<pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='n'/><set xmlns='http://jabber.org/protocol/rsm'><max>10</max></set></pubsub>",
        )
        .unwrap();
        let parsed = parse_pubsub_envelope(document.root_element(), "get").unwrap();
        assert_eq!(parsed.namespace, PubSubNamespace::Entity);
        assert_eq!(parsed.operations.len(), 2);
        assert_eq!(
            parse_pubsub_rsm(parsed.operations[1]).unwrap().max,
            Some(10)
        );
    }

    #[test]
    fn pubsub_envelope_and_rsm_reject_ambiguous_structures() {
        for xml in [
            "<pubsub xmlns='http://jabber.org/protocol/pubsub'/>",
            "<pubsub xmlns='http://jabber.org/protocol/pubsub'><items/><set xmlns='http://jabber.org/protocol/rsm'/><set xmlns='http://jabber.org/protocol/rsm'/></pubsub>",
            "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'><configure/><items xmlns='http://jabber.org/protocol/pubsub'/></pubsub>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert_eq!(
                parse_pubsub_envelope(document.root_element(), "get").unwrap_err(),
                "bad-request",
                "{xml}"
            );
        }

        for xml in [
            "<set xmlns='http://jabber.org/protocol/rsm'><max>1001</max></set>",
            "<set xmlns='http://jabber.org/protocol/rsm'><after>a</after><before>b</before></set>",
            "<set xmlns='http://jabber.org/protocol/rsm'><max>1</max><max>2</max></set>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert_eq!(
                parse_pubsub_rsm(document.root_element()),
                Err("bad-request")
            );
        }
    }
}
