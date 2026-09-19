//! Safe XML builders for MAM queries, extended forms, results, fin responses, and metadata.

use crate::constants::{XMLNS_CLIENT, XMLNS_DELAY, XMLNS_FORWARD, XMLNS_MAM, XMLNS_SID};
use crate::error::MamError;
use crate::prefs::MamPreferences;
use crate::result_fin::{MamFin, MamMetadata, MamResult};
use crate::xml::XmlElement;
use northstar_xep_0059::{build_rsm_set, RsmFirstItem, RsmResponse};
use northstar_xmpp_types::canonicalize;
use roxmltree::Document;

/// Return the canonical static XEP-0313 extended query data form XML string.
pub fn build_extended_form() -> &'static str {
    "<query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='form'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mam:2</value></field><field var='with' type='jid-single'/><field var='start' type='text-single'/><field var='end' type='text-single'/><field var='before-id' type='text-single'/><field var='after-id' type='text-single'/><field var='ids' type='list-multi'><validate xmlns='http://jabber.org/protocol/xdata-validate' datatype='xs:string'><open/></validate></field></x></query>"
}

/// Build a `<metadata xmlns='urn:xmpp:mam:2'>` XML response string from [`MamMetadata`].
pub fn build_metadata(metadata: &MamMetadata) -> String {
    let mut root = XmlElement::namespaced("metadata", XMLNS_MAM);
    if let Some(start) = &metadata.start {
        root.push_child(
            XmlElement::new("start")
                .attr("id", start.id.as_str())
                .attr("timestamp", start.timestamp.to_rfc3339_millis()),
        );
    }
    if let Some(end) = &metadata.end {
        root.push_child(
            XmlElement::new("end")
                .attr("id", end.id.as_str())
                .attr("timestamp", end.timestamp.to_rfc3339_millis()),
        );
    }
    root.finish()
}

/// Build a `<prefs xmlns='urn:xmpp:mam:2'>` XML response string from [`MamPreferences`].
///
/// Both `<always>` and `<never>` list containers are always emitted even when empty.
pub fn build_preferences(prefs: &MamPreferences) -> String {
    let mut always_el = XmlElement::new("always");
    for jid in &prefs.always {
        always_el.push_child(XmlElement::new("jid").text(jid));
    }

    let mut never_el = XmlElement::new("never");
    for jid in &prefs.never {
        never_el.push_child(XmlElement::new("jid").text(jid));
    }

    XmlElement::namespaced("prefs", XMLNS_MAM)
        .attr("default", prefs.default_policy.as_str())
        .child(always_el)
        .child(never_el)
        .finish()
}

/// Build a standalone `<forwarded xmlns='urn:xmpp:forward:0'>` element containing `<delay>` and an archived stanza.
pub fn build_forwarded(stamp: &str, archived_stanza: &str) -> Result<XmlElement, MamError> {
    let mut forwarded = XmlElement::namespaced("forwarded", XMLNS_FORWARD)
        .child(XmlElement::namespaced("delay", XMLNS_DELAY).attr("stamp", stamp));
    forwarded
        .push_validated_fragment(archived_stanza)
        .map_err(|_| MamError::XmlMalformed("archived stanza is malformed XML".to_owned()))?;
    Ok(forwarded)
}

/// Build a `<result xmlns='urn:xmpp:mam:2'>` element containing `<forwarded>` from parts.
pub fn build_result_payload(
    archive_id: &str,
    query_id: Option<&str>,
    delay_stamp: &str,
    archived_stanza: &str,
) -> Result<String, MamError> {
    let forwarded = build_forwarded(delay_stamp, archived_stanza)?;
    let result = XmlElement::namespaced("result", XMLNS_MAM)
        .attr("id", archive_id)
        .optional_attr("queryid", query_id)
        .child(forwarded);
    Ok(result.finish())
}

/// Build a complete `<message xmlns='jabber:client'>` containing a MAM `<result>` payload.
pub fn build_result_message(
    message_id: &str,
    to: &str,
    from: Option<&str>,
    archive_id: &str,
    query_id: Option<&str>,
    delay_stamp: &str,
    archived_stanza: &str,
) -> Result<String, MamError> {
    let forwarded = build_forwarded(delay_stamp, archived_stanza)?;
    let result = XmlElement::namespaced("result", XMLNS_MAM)
        .attr("id", archive_id)
        .optional_attr("queryid", query_id)
        .child(forwarded);

    let message = XmlElement::namespaced("message", XMLNS_CLIENT)
        .attr("id", message_id)
        .attr("to", to)
        .optional_attr("from", from)
        .child(result);
    Ok(message.finish())
}

/// Build a `<result>` payload from a typed [`MamResult`].
pub fn build_result(result: &MamResult) -> Result<String, MamError> {
    build_result_payload(
        result.id.as_str(),
        result.query_id.as_deref(),
        &result.delay_stamp.to_rfc3339_millis(),
        &result.forwarded_stanza,
    )
}

/// Build a `<fin xmlns='urn:xmpp:mam:2'>` XML response string.
pub fn build_fin(
    complete: bool,
    stable: bool,
    first: Option<(&str, Option<u64>)>,
    last: Option<&str>,
    count: Option<u64>,
) -> String {
    let mut xml = String::from("<fin xmlns='urn:xmpp:mam:2' complete='");
    xml.push_str(if complete { "true" } else { "false" });
    xml.push_str("' stable='");
    xml.push_str(if stable { "true" } else { "false" });
    if first.is_none() && last.is_none() && count.is_none() {
        xml.push_str("'/>");
        return xml;
    }
    xml.push_str("'>");
    let response = RsmResponse {
        first: first.map(|(value, index)| RsmFirstItem {
            value: value.to_owned(),
            index,
        }),
        last: last.map(str::to_owned),
        count,
        index: None,
    };
    xml.push_str(&build_rsm_set(&response));
    xml.push_str("</fin>");
    xml
}

/// Build a `<fin>` XML string from a typed [`MamFin`].
pub fn build_fin_from_model(fin: &MamFin) -> String {
    build_fin(
        fin.complete,
        fin.stable,
        fin.first.as_ref().map(|(id, idx)| (id.as_str(), *idx)),
        fin.last.as_ref().map(|id| id.as_str()),
        fin.count,
    )
}

/// Reassert the queried account's immutable archive UID at the personal MAM output boundary.
///
/// Removes any existing `<stanza-id xmlns='urn:xmpp:sid:0'>` claiming the same authority (`account_bare_jid`)
/// and appends the authoritative `<stanza-id>` element while preserving foreign server IDs.
pub fn reassert_archive_stanza_id(
    stanza: &str,
    account_bare_jid: &str,
    archive_id: &str,
) -> Result<String, MamError> {
    let document = Document::parse(stanza)
        .map_err(|e| MamError::XmlMalformed(format!("malformed stanza XML: {e}")))?;
    let canonical_by = canonicalize(account_bare_jid)
        .map_err(|_| MamError::JidMalformed("malformed account bare JID"))?;

    let mut ranges = document
        .root_element()
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "stanza-id"
                && node.tag_name().namespace() == Some(XMLNS_SID)
                && node
                    .attribute("by")
                    .is_some_and(|value| canonicalize(value).is_ok_and(|v| v == canonical_by))
        })
        .map(|node| node.range())
        .collect::<Vec<_>>();

    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut cleaned = stanza.to_owned();
    for range in ranges {
        cleaned.replace_range(range, "");
    }

    let new_stanza_id = XmlElement::new("stanza-id")
        .attr("xmlns", XMLNS_SID)
        .attr("id", archive_id)
        .attr("by", &canonical_by)
        .finish();

    let root_doc = Document::parse(&cleaned)
        .map_err(|e| MamError::XmlMalformed(format!("malformed cleaned XML: {e}")))?;
    let root_node = root_doc.root_element();
    let root_str = &cleaned[root_node.range()];

    // Insert new_stanza_id into root element
    if let Some(slash_pos) = root_str.find("/>") {
        // Self-closing root tag
        let mut result = cleaned.clone();
        let close_tag = format!("</{}>", root_node.tag_name().name());
        result.replace_range(
            root_node.range().start + slash_pos..root_node.range().start + slash_pos + 2,
            &format!(">{new_stanza_id}{close_tag}"),
        );
        Ok(result)
    } else if let Some(closing_pos) = root_str.rfind("</") {
        let mut result = cleaned.clone();
        result.insert_str(root_node.range().start + closing_pos, &new_stanza_id);
        Ok(result)
    } else {
        Err(MamError::XmlMalformed(
            "root element lacks valid XML closing".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prefs::DefaultPolicy;
    use crate::query::{ArchiveId, UtcTimestamp};

    #[test]
    fn builds_preferences_xml_and_always_emits_both_containers() {
        let prefs = MamPreferences::default();
        let xml = build_preferences(&prefs);
        assert_eq!(
            xml,
            "<prefs xmlns='urn:xmpp:mam:2' default='always'><always/><never/></prefs>"
        );

        let custom = MamPreferences::new(
            DefaultPolicy::Roster,
            vec!["alice@example.test".to_owned()],
            vec!["bob@example.test".to_owned()],
        )
        .unwrap();
        let custom_xml = build_preferences(&custom);
        assert_eq!(
            custom_xml,
            "<prefs xmlns='urn:xmpp:mam:2' default='roster'><always><jid>alice@example.test</jid></always><never><jid>bob@example.test</jid></never></prefs>"
        );
    }

    #[test]
    fn builds_metadata_xml() {
        let metadata = MamMetadata {
            start: Some(crate::result_fin::MamMetadataBoundary {
                id: ArchiveId::parse("de305d54-75b4-431b-adb2-eb6b9e546013").unwrap(),
                timestamp: UtcTimestamp::parse("2026-09-02T15:25:08.123Z").unwrap(),
            }),
            end: None,
        };
        let xml = build_metadata(&metadata);
        assert_eq!(
            xml,
            "<metadata xmlns='urn:xmpp:mam:2'><start id='de305d54-75b4-431b-adb2-eb6b9e546013' timestamp='2026-09-02T15:25:08.123Z'/></metadata>"
        );
    }

    #[test]
    fn builds_fin_xml() {
        let fin_xml = build_fin(
            true,
            true,
            Some(("first-id", Some(0))),
            Some("last-id"),
            Some(42),
        );
        assert_eq!(
            fin_xml,
            "<fin xmlns='urn:xmpp:mam:2' complete='true' stable='true'><set xmlns='http://jabber.org/protocol/rsm'><first index='0'>first-id</first><last>last-id</last><count>42</count></set></fin>"
        );
    }

    #[test]
    fn reasserts_stanza_id_cleanly() {
        let raw = "<message xmlns='jabber:client'><stanza-id xmlns='urn:xmpp:sid:0' id='forged' by='Alice@Example.test'/><stanza-id xmlns='urn:xmpp:sid:0' id='remote-id' by='remote.test'/><body/></message>";
        let rendered = reassert_archive_stanza_id(
            raw,
            "alice@example.test",
            "de305d54-75b4-431b-adb2-eb6b9e546013",
        )
        .unwrap();
        assert!(!rendered.contains("forged"));
        assert!(rendered.contains("remote-id"));
        assert!(rendered.contains("de305d54-75b4-431b-adb2-eb6b9e546013"));
    }
}
