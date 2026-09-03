//! Strict, deterministic XML parsers for XEP-0313 requests, forms, preferences, and responses.

use crate::constants::{
    MAX_ARCHIVE_ID_BYTES, MAX_MAM_IDS, MAX_MAM_RESULTS, MAX_MAM_RSM_INDEX, MAX_PREFS_JIDS,
    MAX_QUERY_ID_BYTES, XMLNS_DATA, XMLNS_DELAY, XMLNS_FORWARD, XMLNS_MAM, XMLNS_RSM,
};
use crate::error::MamError;
use crate::prefs::{DefaultPolicy, MamPreferences};
use crate::query::{ArchiveId, MamFilter, MamQuery, MamRsmPage, UtcTimestamp};
use crate::result_fin::{MamFin, MamMetadata, MamMetadataBoundary, MamResult};
use crate::xml::{attributes_are, structural_text_is_empty};
use northstar_xep_0059::{
    parse_rsm_element_with_bounds, parse_rsm_response_element_with_bounds, BeforeCursor, RsmBounds,
    RsmError,
};
use northstar_xmpp_types::{canonicalize, CanonicalJid};
use roxmltree::Node;
use std::collections::HashSet;
use std::str::FromStr;

/// Check if a MAM node is a strictly empty query/metadata/prefs GET command.
pub fn is_empty_mam_command(node: Node<'_, '_>, name: &str) -> bool {
    node.tag_name().namespace() == Some(XMLNS_MAM)
        && node.tag_name().name() == name
        && attributes_are(node, &[])
        && structural_text_is_empty(node)
        && !node.children().any(|child| child.is_element())
}

/// Parse an incoming XEP-0313 MAM `<query>` element into a validated [`MamQuery`].
pub fn parse_mam_query(query: Node<'_, '_>) -> Result<MamQuery, MamError> {
    if query.tag_name().namespace() != Some(XMLNS_MAM) || query.tag_name().name() != "query" {
        return Err(MamError::BadRequest(
            "expected <query xmlns='urn:xmpp:mam:2'/> element",
        ));
    }
    if query.attribute("node").is_some() {
        return Err(MamError::FeatureNotImplemented(
            "node attribute on MAM query is not supported",
        ));
    }
    if !attributes_are(query, &["queryid"]) || !structural_text_is_empty(query) {
        return Err(MamError::BadRequest(
            "unexpected attributes or text on MAM query",
        ));
    }

    let query_id = if let Some(qid) = query.attribute("queryid") {
        if qid.len() > MAX_QUERY_ID_BYTES || qid.chars().any(char::is_control) {
            return Err(MamError::BadRequest("invalid queryid attribute"));
        }
        Some(qid.to_owned())
    } else {
        None
    };

    let mut form_node = None;
    let mut rsm_node = None;
    let mut flip_page = false;

    for child in query.children().filter(|child| child.is_element()) {
        match (child.tag_name().name(), child.tag_name().namespace()) {
            ("x", Some(XMLNS_DATA)) if form_node.is_none() => form_node = Some(child),
            ("set", Some(XMLNS_RSM)) if rsm_node.is_none() => rsm_node = Some(child),
            ("flip-page", Some(XMLNS_MAM)) if !flip_page => {
                if !attributes_are(child, &[])
                    || child.children().any(|nested| nested.is_element())
                    || !structural_text_is_empty(child)
                {
                    return Err(MamError::BadRequest("malformed flip-page element"));
                }
                flip_page = true;
            }
            ("x", Some(XMLNS_DATA)) | ("set", Some(XMLNS_RSM)) | ("flip-page", Some(XMLNS_MAM)) => {
                return Err(MamError::BadRequest("duplicate child element in MAM query"));
            }
            _ => {
                return Err(MamError::FeatureNotImplemented(
                    "unsupported child element in MAM query",
                ))
            }
        }
    }

    let filter = if let Some(form) = form_node {
        parse_mam_form(form)?
    } else {
        MamFilter::default()
    };

    let (page, max) = if let Some(rsm) = rsm_node {
        parse_mam_rsm(rsm)?
    } else {
        (MamRsmPage::First, MAX_MAM_RESULTS)
    };

    let result = MamQuery {
        filter,
        page,
        max,
        query_id,
        flip_page,
    };
    result.validate()?;
    Ok(result)
}

fn field_values<'a>(field: Node<'a, '_>) -> Result<Vec<&'a str>, MamError> {
    if !attributes_are(field, &["var", "type"]) || !structural_text_is_empty(field) {
        return Err(MamError::BadRequest(
            "invalid field attributes or structural text",
        ));
    }
    let mut values = Vec::new();
    for child in field.children().filter(|child| child.is_element()) {
        if child.tag_name().namespace() != Some(XMLNS_DATA)
            || child.tag_name().name() != "value"
            || !attributes_are(child, &[])
            || child.children().any(|nested| nested.is_element())
        {
            return Err(MamError::BadRequest("invalid field value element"));
        }
        values.push(child.text().unwrap_or_default());
    }
    Ok(values)
}

fn one_value<'a>(values: &[&'a str]) -> Result<&'a str, MamError> {
    match values {
        [value] => Ok(*value),
        _ => Err(MamError::BadRequest("expected single value in field")),
    }
}

fn parse_mam_form(form: Node<'_, '_>) -> Result<MamFilter, MamError> {
    if form.tag_name().namespace() != Some(XMLNS_DATA)
        || form.tag_name().name() != "x"
        || !attributes_are(form, &["type"])
        || form.attribute("type") != Some("submit")
        || !structural_text_is_empty(form)
    {
        return Err(MamError::BadRequest(
            "invalid data form envelope in MAM query",
        ));
    }

    let mut seen = HashSet::new();
    let mut form_type_seen = false;
    let mut filter = MamFilter::default();

    for field in form.children().filter(|child| child.is_element()) {
        if field.tag_name().namespace() != Some(XMLNS_DATA) || field.tag_name().name() != "field" {
            return Err(MamError::BadRequest(
                "unexpected non-field element in data form",
            ));
        }
        let var = field
            .attribute("var")
            .ok_or(MamError::BadRequest("missing var on field"))?;
        if !seen.insert(var.to_owned()) {
            return Err(MamError::BadRequest("duplicate field in data form"));
        }

        let values = field_values(field)?;
        match var {
            "FORM_TYPE" => {
                if field.attribute("type").is_some_and(|kind| kind != "hidden")
                    || one_value(&values)? != XMLNS_MAM
                {
                    return Err(MamError::BadRequest("invalid FORM_TYPE in MAM submit form"));
                }
                form_type_seen = true;
            }
            "with" => {
                if field
                    .attribute("type")
                    .is_some_and(|kind| kind != "jid-single")
                {
                    return Err(MamError::BadRequest("invalid type attribute on with field"));
                }
                let raw_jid = one_value(&values)?;
                let canon = CanonicalJid::parse(raw_jid)
                    .map_err(|_| MamError::JidMalformed("invalid JID in with filter"))?;
                filter.with_jid = Some(canon);
            }
            "start" | "end" => {
                if field
                    .attribute("type")
                    .is_some_and(|kind| kind != "text-single")
                {
                    return Err(MamError::BadRequest(
                        "invalid type attribute on timestamp field",
                    ));
                }
                let raw_time = one_value(&values)?;
                let ts = UtcTimestamp::parse(raw_time)?;
                if var == "start" {
                    filter.start = Some(ts);
                } else {
                    filter.end = Some(ts);
                }
            }
            "before-id" | "after-id" => {
                if field
                    .attribute("type")
                    .is_some_and(|kind| kind != "text-single")
                {
                    return Err(MamError::BadRequest(
                        "invalid type attribute on ID boundary field",
                    ));
                }
                let raw_id = one_value(&values)?;
                let archive_id = ArchiveId::parse(raw_id)?;
                if var == "before-id" {
                    filter.before_id = Some(archive_id);
                } else {
                    filter.after_id = Some(archive_id);
                }
            }
            "ids" => {
                if field
                    .attribute("type")
                    .is_some_and(|kind| kind != "list-multi")
                    || values.is_empty()
                {
                    return Err(MamError::BadRequest("invalid type or empty ids filter"));
                }
                if values.len() > MAX_MAM_IDS {
                    return Err(MamError::ResourceConstraint(
                        "too many IDs requested in filter",
                    ));
                }
                let mut unique = HashSet::new();
                for val in values {
                    let id = ArchiveId::parse(val)?;
                    if !unique.insert(id.clone()) {
                        return Err(MamError::BadRequest("duplicate ID in ids filter"));
                    }
                    filter.ids.push(id);
                }
            }
            _ => {
                return Err(MamError::FeatureNotImplemented(
                    "unrecognized field var in MAM submit form",
                ))
            }
        }
    }

    if !form_type_seen {
        return Err(MamError::BadRequest("missing FORM_TYPE in submit form"));
    }

    filter.validate()?;
    Ok(filter)
}

fn parse_mam_rsm(set: Node<'_, '_>) -> Result<(MamRsmPage, u32), MamError> {
    // XEP-0059 owns XML validation and mutually-exclusive cursor semantics.
    // MAM adds UUID cursor validation and its own result-count policy.
    let bounds = RsmBounds::new(usize::MAX, MAX_ARCHIVE_ID_BYTES, MAX_MAM_RSM_INDEX);
    let request = parse_rsm_element_with_bounds(set, &bounds).map_err(map_rsm_request_error)?;
    let max = request.max.map_or(MAX_MAM_RESULTS, |value| {
        u32::try_from(value)
            .unwrap_or(u32::MAX)
            .min(MAX_MAM_RESULTS)
    });
    let page = match (request.before, request.after, request.index) {
        (Some(BeforeCursor::LastPage), None, None) => MamRsmPage::Last,
        (Some(BeforeCursor::Item(value)), None, None) => {
            MamRsmPage::Before(ArchiveId::parse(&value)?)
        }
        (None, Some(value), None) => MamRsmPage::After(ArchiveId::parse(&value)?),
        (None, None, Some(index)) => MamRsmPage::Index(index),
        (None, None, None) => MamRsmPage::First,
        _ => return Err(MamError::BadRequest("conflicting RSM pagination controls")),
    };
    Ok((page, max))
}

fn map_rsm_request_error(error: RsmError) -> MamError {
    match error {
        RsmError::IndexLimitExceeded { .. } => {
            MamError::ResourceConstraint("RSM index exceeds maximum limit")
        }
        RsmError::EmptyCursor("after") => MamError::BadRequest("empty after tag in RSM"),
        RsmError::InvalidMax(value) if value.starts_with('-') => {
            MamError::BadRequest("negative max in RSM")
        }
        RsmError::InvalidIndex(value) if value.starts_with('-') => {
            MamError::BadRequest("negative index in RSM")
        }
        RsmError::InvalidMax(_) => MamError::BadRequest("invalid max in RSM"),
        RsmError::InvalidIndex(_) => MamError::BadRequest("invalid index in RSM"),
        RsmError::MutuallyExclusiveCursors(_) => {
            MamError::BadRequest("conflicting RSM pagination controls")
        }
        _ => MamError::BadRequest("invalid RSM set"),
    }
}

/// Parse a `<prefs xmlns='urn:xmpp:mam:2'>` element into a validated [`MamPreferences`].
pub fn parse_mam_preferences(prefs: Node<'_, '_>) -> Result<MamPreferences, MamError> {
    if prefs.tag_name().namespace() != Some(XMLNS_MAM)
        || prefs.tag_name().name() != "prefs"
        || !attributes_are(prefs, &["default"])
        || !structural_text_is_empty(prefs)
    {
        return Err(MamError::BadRequest("invalid prefs element envelope"));
    }

    let default_str = prefs
        .attribute("default")
        .ok_or(MamError::BadRequest("missing default attribute on prefs"))?;
    let default_policy = DefaultPolicy::from_str(default_str)?;

    let mut always = Vec::new();
    let mut never = Vec::new();
    let mut all_jids = HashSet::new();
    let mut containers_seen = HashSet::new();

    for container in prefs.children().filter(|node| node.is_element()) {
        let name = container.tag_name().name();
        if container.tag_name().namespace() != Some(XMLNS_MAM)
            || !matches!(name, "always" | "never")
            || !containers_seen.insert(name)
            || !attributes_are(container, &[])
            || !structural_text_is_empty(container)
        {
            return Err(MamError::BadRequest("invalid container inside prefs"));
        }

        let destination = if name == "always" {
            &mut always
        } else {
            &mut never
        };

        for child in container.children().filter(|node| node.is_element()) {
            if child.tag_name().namespace() != Some(XMLNS_MAM)
                || child.tag_name().name() != "jid"
                || !attributes_are(child, &[])
                || child.children().any(|nested| nested.is_element())
            {
                return Err(MamError::BadRequest(
                    "invalid jid element in prefs container",
                ));
            }

            let text = child.text().unwrap_or_default();
            let canon = canonicalize(text)
                .map_err(|_| MamError::JidMalformed("malformed JID in preferences"))?;
            if !all_jids.insert(canon.clone()) {
                return Err(MamError::BadRequest("duplicate JID in preferences"));
            }
            destination.push(canon);

            if all_jids.len() > MAX_PREFS_JIDS {
                return Err(MamError::ResourceConstraint(
                    "preferences exceed 500 JIDs limit",
                ));
            }
        }
    }

    Ok(MamPreferences {
        default_policy,
        always,
        never,
    })
}

/// Parse a `<metadata xmlns='urn:xmpp:mam:2'>` element into [`MamMetadata`].
pub fn parse_metadata_response(metadata: Node<'_, '_>) -> Result<MamMetadata, MamError> {
    if metadata.tag_name().namespace() != Some(XMLNS_MAM)
        || metadata.tag_name().name() != "metadata"
    {
        return Err(MamError::BadRequest(
            "expected <metadata xmlns='urn:xmpp:mam:2'/>",
        ));
    }

    let mut start = None;
    let mut end = None;

    for child in metadata.children().filter(|c| c.is_element()) {
        if child.tag_name().namespace() != Some(XMLNS_MAM) {
            return Err(MamError::BadRequest(
                "unexpected namespace in metadata child",
            ));
        }
        let id_str = child
            .attribute("id")
            .ok_or(MamError::BadRequest("missing id in metadata boundary"))?;
        let ts_str = child.attribute("timestamp").ok_or(MamError::BadRequest(
            "missing timestamp in metadata boundary",
        ))?;
        let id = ArchiveId::parse(id_str)?;
        let timestamp = UtcTimestamp::parse(ts_str)?;

        match child.tag_name().name() {
            "start" => start = Some(MamMetadataBoundary { id, timestamp }),
            "end" => end = Some(MamMetadataBoundary { id, timestamp }),
            _ => return Err(MamError::BadRequest("unknown tag in metadata")),
        }
    }

    Ok(MamMetadata { start, end })
}

/// Parse a `<fin xmlns='urn:xmpp:mam:2'>` element into a [`MamFin`].
pub fn parse_fin_element(fin: Node<'_, '_>) -> Result<MamFin, MamError> {
    if fin.tag_name().namespace() != Some(XMLNS_MAM) || fin.tag_name().name() != "fin" {
        return Err(MamError::BadRequest(
            "expected <fin xmlns='urn:xmpp:mam:2'/>",
        ));
    }

    let complete = fin
        .attribute("complete")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let stable = fin
        .attribute("stable")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true);

    let rsm_sets = fin
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() == "set"
                && child.tag_name().namespace() == Some(XMLNS_RSM)
        })
        .collect::<Vec<_>>();
    if rsm_sets.len() > 1 {
        return Err(MamError::BadRequest("duplicate RSM set in fin"));
    }
    let response = rsm_sets
        .first()
        .map(|set| {
            parse_rsm_response_element_with_bounds(
                *set,
                &RsmBounds::new(usize::MAX, MAX_ARCHIVE_ID_BYTES, MAX_MAM_RSM_INDEX),
            )
            .map_err(|_| MamError::BadRequest("invalid RSM set in fin"))
        })
        .transpose()?;
    let first = response
        .as_ref()
        .and_then(|response| response.first.as_ref())
        .map(|first| ArchiveId::parse(&first.value).map(|archive_id| (archive_id, first.index)))
        .transpose()?;
    let last = response
        .as_ref()
        .and_then(|response| response.last.as_deref())
        .map(ArchiveId::parse)
        .transpose()?;
    let count = response.and_then(|response| response.count);

    Ok(MamFin {
        complete,
        stable,
        first,
        last,
        count,
    })
}

/// Parse a `<result xmlns='urn:xmpp:mam:2'>` element into a [`MamResult`].
pub fn parse_result_element(result: Node<'_, '_>) -> Result<MamResult, MamError> {
    if result.tag_name().namespace() != Some(XMLNS_MAM) || result.tag_name().name() != "result" {
        return Err(MamError::BadRequest(
            "expected <result xmlns='urn:xmpp:mam:2'/>",
        ));
    }

    let id_str = result
        .attribute("id")
        .ok_or(MamError::BadRequest("missing id attribute on result"))?;
    let id = ArchiveId::parse(id_str)?;
    let query_id = result.attribute("queryid").map(str::to_owned);

    let forwarded = result
        .children()
        .find(|c| {
            c.is_element()
                && c.tag_name().name() == "forwarded"
                && c.tag_name().namespace() == Some(XMLNS_FORWARD)
        })
        .ok_or(MamError::BadRequest("missing forwarded wrapper in result"))?;

    let delay = forwarded
        .children()
        .find(|c| {
            c.is_element()
                && c.tag_name().name() == "delay"
                && c.tag_name().namespace() == Some(XMLNS_DELAY)
        })
        .ok_or(MamError::BadRequest(
            "missing delay element in forwarded result",
        ))?;

    let stamp_str = delay
        .attribute("stamp")
        .ok_or(MamError::BadRequest("missing stamp attribute on delay"))?;
    let delay_stamp = UtcTimestamp::parse(stamp_str)?;

    let inner_stanza = forwarded
        .children()
        .find(|c| {
            c.is_element()
                && !(c.tag_name().name() == "delay"
                    && c.tag_name().namespace() == Some(XMLNS_DELAY))
        })
        .ok_or(MamError::BadRequest(
            "missing inner stanza in forwarded payload",
        ))?;

    let raw_document_text = inner_stanza.document().input_text();
    let forwarded_stanza = raw_document_text[inner_stanza.range()].to_owned();

    Ok(MamResult {
        id,
        query_id,
        delay_stamp,
        forwarded_stanza,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    fn parse(xml: &str) -> Result<MamQuery, MamError> {
        let doc = Document::parse(xml).unwrap();
        parse_mam_query(doc.root_element())
    }

    #[test]
    fn parses_extended_query_with_rsm_and_flip() {
        let xml = "<query xmlns='urn:xmpp:mam:2' queryid='q1'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mam:2</value></field><field var='with'><value>Alice@Example.test/Phone</value></field><field var='ids'><value>de305d54-75b4-431b-adb2-eb6b9e546013</value></field></x><set xmlns='http://jabber.org/protocol/rsm'><max>20</max><before/></set><flip-page/></query>";
        let query = parse(xml).unwrap();
        assert_eq!(
            query.filter.with_jid.as_ref().map(|j| j.to_string()),
            Some("alice@example.test/Phone".to_owned())
        );
        assert_eq!(query.filter.ids.len(), 1);
        assert_eq!(query.page, MamRsmPage::Last);
        assert_eq!(query.max, 20);
        assert!(query.flip_page);
        assert_eq!(query.query_id.as_deref(), Some("q1"));
    }

    #[test]
    fn query_without_rsm_starts_at_oldest_item() {
        let query = parse("<query xmlns='urn:xmpp:mam:2'/>").unwrap();
        assert_eq!(query.page, MamRsmPage::First);
        assert_eq!(query.max, MAX_MAM_RESULTS);
    }

    #[test]
    fn rejects_malformed_queries() {
        for (xml, expected) in [
            (
                "<query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='unknown'><value>x</value></field></x></query>",
                MamError::FeatureNotImplemented("unrecognized field var in MAM submit form"),
            ),
            (
                "<query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><before/><after>x</after></set></query>",
                MamError::BadRequest("conflicting RSM pagination controls"),
            ),
            (
                "<query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><max>-1</max></set></query>",
                MamError::BadRequest("negative max in RSM"),
            ),
            (
                "<query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><index>1000001</index></set></query>",
                MamError::ResourceConstraint("RSM index exceeds maximum limit"),
            ),
            (
                "<query xmlns='urn:xmpp:mam:2'><flip-page/><flip-page/></query>",
                MamError::BadRequest("duplicate child element in MAM query"),
            ),
            (
                "<query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='with'><value>a@example.test</value></field></x></query>",
                MamError::BadRequest("missing FORM_TYPE in submit form"),
            ),
            (
                "<query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mam:2</value></field><field var='with'><value> alice@example.test </value></field></x></query>",
                MamError::JidMalformed("invalid JID in with filter"),
            ),
        ] {
            assert_eq!(parse(xml), Err(expected), "{xml}");
        }
    }

    #[test]
    fn parses_preferences_correctly() {
        let doc = Document::parse("<prefs xmlns='urn:xmpp:mam:2' default='roster'><always><jid>A@Example.test/Phone</jid></always><never><jid>b@example.test</jid></never></prefs>").unwrap();
        let prefs = parse_mam_preferences(doc.root_element()).unwrap();
        assert_eq!(prefs.default_policy, DefaultPolicy::Roster);
        assert_eq!(prefs.always, vec!["a@example.test/Phone"]);
        assert_eq!(prefs.never, vec!["b@example.test"]);
    }
}
