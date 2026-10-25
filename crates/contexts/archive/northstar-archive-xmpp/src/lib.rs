//! XMPP adapter of the archive context: XEP-0313 queries, metadata and preferences from client sessions.

#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use northstar_archive_application::{
    ArchiveBoundary, ArchiveRow, MamArchiveQuery, MamMetadataCommand, MamMetadataResult,
    MamPreferences, MamPreferencesGetCommand, MamPreferencesSetCommand, MamPreferencesWriter,
    MamQueryCommand, MamQueryRepository, MamQueryResult, MamQueryScope, MamRoomAccess,
    MamRoomAccessOutcome, MamRsmPage, MamService,
};
#[cfg(test)]
use northstar_xep_0313::MAX_MAM_RESULTS;
use northstar_xep_0313::{
    build_extended_form, is_empty_mam_command, parse_mam_preferences as parse_xep_mam_preferences,
    parse_mam_query as parse_xep_mam_query, MamError, MamRsmPage as ParsedMamRsmPage, UtcTimestamp,
    XMLNS_MAM as MAM_NS, XMLNS_RSM as RSM_NS,
};
use northstar_xep_0359::add_stanza_id;
use northstar_xml_builder::stanza::{iq_error, iq_result, iq_result_from};
use northstar_xml_builder::XmlElement;
use roxmltree::Node;
use uuid::Uuid;

/// The stanzas a MAM request is answered with.
pub enum MamReply {
    /// A single reply stanza.
    Send(String),
    /// The result messages followed by the final IQ, in order.
    SendMany(Vec<String>),
}

/// What a client session provides to the XEP-0313 handlers.
pub trait MamSession: Sync {
    /// The authenticated account's user id and username, or `None` before authentication.
    fn mam_account(&self) -> Option<(uuid::Uuid, &str)>;
    /// The session's bound full JID, or `None` before resource binding.
    fn mam_full_jid(&self) -> Option<&str>;
    /// The server's local domain.
    fn mam_local_domain(&self) -> &str;
    /// The domain of the local MUC service.
    fn mam_muc_domain(&self) -> String;
    /// Whether the session currently occupies the room with this bare JID.
    fn mam_joined_room(&self, room_bare_jid: &str) -> bool;
    /// The archive application service, over the repository the composition root binds.
    fn mam_service(
        &self,
    ) -> &MamService<
        impl MamQueryRepository<Error = anyhow::Error> + MamPreferencesWriter<Error = anyhow::Error>,
    >;
    /// One archived room message as this viewer receives it: the room's occupant id for the sender
    /// and the sender's real JID only where the room reveals it.
    fn mam_room_stanza(&self, access: &MamRoomAccess, item: &ArchiveRow) -> String;
}

#[derive(Clone, Debug)]
pub struct ParsedMamQuery {
    pub query: MamArchiveQuery,
    pub query_id: Option<String>,
    pub flip_page: bool,
}

struct MamRoomTarget {
    localpart: String,
    bare_jid: String,
}

/// Reassert the queried account's immutable archive UID at the MAM output
/// boundary.  Besides repairing legacy/tombstoned rows that predate identity
/// preservation, `add_stanza_id` removes any same-authority claim before
/// adding the trusted value while retaining other authorities' provenance.
fn personal_mam_stanza(item: &ArchiveRow, account_bare_jid: &str) -> String {
    add_stanza_id(&item.stanza, account_bare_jid, item.id)
}

fn empty_mam_command(node: Node<'_, '_>, name: &str) -> bool {
    is_empty_mam_command(node, name)
}

fn mam_error_condition(error: &MamError) -> &'static str {
    error.as_stanza_error_condition()
}

fn archive_id_to_uuid(
    id: &northstar_xep_0313::ArchiveId,
) -> std::result::Result<Uuid, &'static str> {
    Uuid::parse_str(id.as_str()).map_err(|_| "item-not-found")
}

fn mam_timestamp_to_chrono(
    timestamp: UtcTimestamp,
) -> std::result::Result<DateTime<Utc>, &'static str> {
    let seconds = timestamp.epoch_nanos().div_euclid(1_000_000_000);
    let nanoseconds = timestamp.epoch_nanos().rem_euclid(1_000_000_000) as u32;
    let seconds = i64::try_from(seconds).map_err(|_| "bad-request")?;
    DateTime::from_timestamp(seconds, nanoseconds).ok_or("bad-request")
}

/// Parses a MAM query element into the archive query, the query id and the flip-page flag.
pub fn parse_mam_query(query: Node<'_, '_>) -> std::result::Result<ParsedMamQuery, &'static str> {
    let parsed = parse_xep_mam_query(query).map_err(|error| mam_error_condition(&error))?;
    let filter = parsed.filter;
    Ok(ParsedMamQuery {
        query: MamArchiveQuery {
            with_jid: filter.with_jid.map(|jid| jid.to_string()),
            start: filter.start.map(mam_timestamp_to_chrono).transpose()?,
            end: filter.end.map(mam_timestamp_to_chrono).transpose()?,
            before_id: filter
                .before_id
                .as_ref()
                .map(archive_id_to_uuid)
                .transpose()?,
            after_id: filter
                .after_id
                .as_ref()
                .map(archive_id_to_uuid)
                .transpose()?,
            ids: filter
                .ids
                .iter()
                .map(archive_id_to_uuid)
                .collect::<std::result::Result<Vec<_>, _>>()?,
            page: match parsed.page {
                ParsedMamRsmPage::First => MamRsmPage::First,
                ParsedMamRsmPage::Last => MamRsmPage::Last,
                ParsedMamRsmPage::Before(id) => MamRsmPage::Before(archive_id_to_uuid(&id)?),
                ParsedMamRsmPage::After(id) => MamRsmPage::After(archive_id_to_uuid(&id)?),
                ParsedMamRsmPage::Index(index) => {
                    MamRsmPage::Index(i64::try_from(index).map_err(|_| "resource-constraint")?)
                }
            },
            max: i64::from(parsed.max),
        },
        query_id: parsed.query_id,
        flip_page: parsed.flip_page,
    })
}

fn owns_archive_target<S: MamSession>(session: &S, to: Option<&str>) -> bool {
    let Some(full_jid) = session.mam_full_jid() else {
        return false;
    };
    let Some(to) = to else {
        return true;
    };
    let Ok(target) = northstar_xmpp_types::jid::CanonicalJid::parse(to) else {
        return false;
    };
    let Ok(owner) = northstar_xmpp_types::jid::CanonicalJid::parse(full_jid) else {
        return false;
    };
    (target.localpart().is_none()
        && target.resourcepart().is_none()
        && target.domainpart() == session.mam_local_domain())
        || (target.resourcepart().is_none() && target.bare() == owner.bare())
}

/// The source of a MAM result stream is the archive entity that was
/// queried.  In particular, an IQ explicitly addressed to the account's
/// bare JID must not produce source-less result messages: XEP-0313 clients
/// are required to correlate both the archive JID and `queryid` to avoid
/// result injection.  An omitted `to` retains normal C2S implicit-server
/// reply semantics for compatibility.
fn personal_archive_reply_from(to: Option<&str>) -> Option<String> {
    to.and_then(|to| northstar_xmpp_types::jid::CanonicalJid::parse(to).ok())
        .map(|target| target.to_string())
}

fn mam_room_target<S: MamSession>(
    session: &S,
    id: &str,
    to: Option<&str>,
) -> Result<Option<MamRoomTarget>, MamReply> {
    let Some(to) = to else {
        return Ok(None);
    };
    let Ok(target) = northstar_xmpp_types::jid::CanonicalJid::parse(to) else {
        return Err(MamReply::Send(iq_error(id, "jid-malformed")));
    };
    if target.domainpart() != session.mam_muc_domain() {
        return Ok(None);
    }
    if target.resourcepart().is_some() || target.localpart().is_none() {
        return Err(MamReply::Send(iq_error(id, "item-not-found")));
    }
    Ok(Some(MamRoomTarget {
        localpart: target
            .localpart()
            .expect("room localpart checked above")
            .to_owned(),
        bare_jid: target.bare(),
    }))
}

async fn mam_room_access<S: MamSession>(
    session: &S,
    id: &str,
    to: Option<&str>,
) -> anyhow::Result<Result<Option<MamRoomAccess>, MamReply>> {
    let target = match mam_room_target(session, id, to) {
        Ok(Some(target)) => target,
        Ok(None) => return Ok(Ok(None)),
        Err(action) => return Ok(Err(action)),
    };
    let Some((user_id, _)) = session.mam_account() else {
        return Ok(Err(MamReply::Send(iq_error(id, "not-authorized"))));
    };
    let outcome = session
        .mam_service()
        .authorize_room(
            &target.localpart,
            user_id,
            session.mam_joined_room(&target.bare_jid),
        )
        .await?;
    match outcome {
        MamRoomAccessOutcome::Allowed(access) => Ok(Ok(Some(access))),
        MamRoomAccessOutcome::Missing => Ok(Err(MamReply::Send(iq_error(id, "item-not-found")))),
        MamRoomAccessOutcome::Forbidden => Ok(Err(MamReply::Send(iq_error(id, "forbidden")))),
    }
}

/// Answers a MAM preferences retrieval request.
pub async fn mam_preferences_get<S: MamSession>(
    session: &S,
    id: &str,
    to: Option<&str>,
    prefs: roxmltree::Node<'_, '_>,
) -> anyhow::Result<MamReply> {
    let Some((user_id, _)) = session.mam_account() else {
        return Ok(MamReply::Send(iq_error(id, "not-authorized")));
    };
    if !owns_archive_target(session, to) {
        return Ok(MamReply::Send(iq_error(id, "forbidden")));
    }
    if !empty_mam_command(prefs, "prefs") {
        return Ok(MamReply::Send(iq_error(id, "bad-request")));
    }
    let preferences = session
        .mam_service()
        .execute_mam_preferences_get(MamPreferencesGetCommand { owner_id: user_id })
        .await?;
    let payload = mam_preferences_xml(&preferences);
    Ok(MamReply::Send(
        personal_archive_reply_from(to)
            .map(|from| iq_result_from(id, &from, &payload))
            .unwrap_or_else(|| iq_result(id, &payload)),
    ))
}

/// Answers a MAM preferences update request.
pub async fn mam_preferences_set<S: MamSession>(
    session: &S,
    id: &str,
    to: Option<&str>,
    prefs: roxmltree::Node<'_, '_>,
) -> anyhow::Result<MamReply> {
    let Some((user_id, _)) = session.mam_account() else {
        return Ok(MamReply::Send(iq_error(id, "not-authorized")));
    };
    if !owns_archive_target(session, to) {
        return Ok(MamReply::Send(iq_error(id, "forbidden")));
    }
    let preferences = match parse_mam_preferences(prefs) {
        Ok(preferences) => preferences,
        Err(condition) => return Ok(MamReply::Send(iq_error(id, condition))),
    };
    session
        .mam_service()
        .execute_mam_preferences_set(MamPreferencesSetCommand {
            owner_id: user_id,
            preferences: preferences.clone(),
        })
        .await?;
    let payload = mam_preferences_xml(&preferences);
    Ok(MamReply::Send(
        personal_archive_reply_from(to)
            .map(|from| iq_result_from(id, &from, &payload))
            .unwrap_or_else(|| iq_result(id, &payload)),
    ))
}

/// Answers a MAM query form retrieval request.
pub async fn mam_query_form<S: MamSession>(
    session: &S,
    id: &str,
    to: Option<&str>,
    query: roxmltree::Node<'_, '_>,
) -> anyhow::Result<MamReply> {
    let room = match mam_room_access(session, id, to).await? {
        Ok(room) => room,
        Err(action) => return Ok(action),
    };
    if room.is_none() && !owns_archive_target(session, to) {
        return Ok(MamReply::Send(iq_error(id, "forbidden")));
    }
    if !empty_mam_command(query, "query") {
        return Ok(MamReply::Send(iq_error(id, "bad-request")));
    }
    Ok(MamReply::Send(if let Some(access) = room {
        let room_jid = format!("{}@{}", access.localpart(), session.mam_muc_domain());
        iq_result_from(id, &room_jid, build_extended_form())
    } else if let Some(from) = personal_archive_reply_from(to) {
        iq_result_from(id, &from, build_extended_form())
    } else {
        iq_result(id, build_extended_form())
    }))
}

/// Answers a MAM archive metadata request.
pub async fn mam_metadata<S: MamSession>(
    session: &S,
    id: &str,
    to: Option<&str>,
    metadata: roxmltree::Node<'_, '_>,
) -> anyhow::Result<MamReply> {
    let target = match mam_room_target(session, id, to) {
        Ok(target) => target,
        Err(action) => return Ok(action),
    };
    if target.is_none() && !owns_archive_target(session, to) {
        return Ok(MamReply::Send(iq_error(id, "forbidden")));
    }
    if !empty_mam_command(metadata, "metadata") {
        return Ok(MamReply::Send(iq_error(id, "bad-request")));
    }
    let Some((user_id, _)) = session.mam_account() else {
        return Ok(MamReply::Send(iq_error(id, "not-authorized")));
    };
    let scope = if let Some(target) = target {
        MamQueryScope::Room {
            localpart: target.localpart,
            viewer_id: user_id,
            currently_joined: session.mam_joined_room(&target.bare_jid),
        }
    } else {
        MamQueryScope::Personal { owner_id: user_id }
    };
    let (room, boundaries) = match session
        .mam_service()
        .execute_mam_metadata(MamMetadataCommand { scope })
        .await?
    {
        MamMetadataResult::Boundaries { room, start, end } => (room, (start, end)),
        MamMetadataResult::ItemNotFound => {
            return Ok(MamReply::Send(iq_error(id, "item-not-found")));
        }
        MamMetadataResult::Forbidden => {
            return Ok(MamReply::Send(iq_error(id, "forbidden")));
        }
    };
    let boundary = |name: &str, value: ArchiveBoundary| {
        let element = match name {
            "start" => XmlElement::new("start"),
            "end" => XmlElement::new("end"),
            _ => unreachable!("fixed MAM metadata boundary"),
        };
        element.attr("id", value.id).attr(
            "timestamp",
            value
                .created_at
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        )
    };
    let mut metadata = XmlElement::namespaced("metadata", MAM_NS);
    if let Some(start) = boundaries.0 {
        metadata.push_child(boundary("start", start));
    }
    if let Some(end) = boundaries.1 {
        metadata.push_child(boundary("end", end));
    }
    let payload = metadata.finish();
    Ok(MamReply::Send(if let Some(access) = room {
        let room_jid = format!("{}@{}", access.localpart(), session.mam_muc_domain());
        iq_result_from(id, &room_jid, &payload)
    } else if let Some(from) = personal_archive_reply_from(to) {
        iq_result_from(id, &from, &payload)
    } else {
        iq_result(id, &payload)
    }))
}

/// Answers a MAM archive query request.
pub async fn mam_query<S: MamSession>(
    session: &S,
    id: &str,
    query: roxmltree::Node<'_, '_>,
    to: Option<&str>,
) -> anyhow::Result<MamReply> {
    let Some((user_id, username)) = session.mam_account() else {
        return Ok(MamReply::Send(iq_error(id, "not-authorized")));
    };
    let parsed = match parse_mam_query(query) {
        Ok(parsed) => parsed,
        Err(condition) => return Ok(MamReply::Send(iq_error(id, condition))),
    };
    let target = match mam_room_target(session, id, to) {
        Ok(target) => target,
        Err(action) => return Ok(action),
    };
    if target.is_none() && !owns_archive_target(session, to) {
        return Ok(MamReply::Send(iq_error(id, "forbidden")));
    }
    let scope = if let Some(target) = target {
        MamQueryScope::Room {
            localpart: target.localpart,
            viewer_id: user_id,
            currently_joined: session.mam_joined_room(&target.bare_jid),
        }
    } else {
        MamQueryScope::Personal { owner_id: user_id }
    };
    let (room, page) = match session
        .mam_service()
        .execute_mam_query(MamQueryCommand {
            scope,
            query: parsed.query,
        })
        .await?
    {
        MamQueryResult::Page { room, page } => (room, page),
        MamQueryResult::ItemNotFound | MamQueryResult::ValidationFailed(_) => {
            return Ok(MamReply::Send(iq_error(id, "item-not-found")));
        }
        MamQueryResult::Forbidden => {
            return Ok(MamReply::Send(iq_error(id, "forbidden")));
        }
    };

    let archive_from = room
        .as_ref()
        .map(|access| format!("{}@{}", access.localpart(), session.mam_muc_domain()))
        .or_else(|| personal_archive_reply_from(to));
    let personal_archive_by = format!("{}@{}", username, session.mam_local_domain());
    let mut replies = Vec::with_capacity(page.rows.len() + 1);
    let rows: Box<dyn Iterator<Item = &ArchiveRow>> = if parsed.flip_page {
        Box::new(page.rows.iter().rev())
    } else {
        Box::new(page.rows.iter())
    };
    for item in rows {
        let archived_stanza = if let Some(access) = &room {
            session.mam_room_stanza(access, item)
        } else {
            personal_mam_stanza(item, &personal_archive_by)
        };
        let forwarded = XmlElement::namespaced("forwarded", "urn:xmpp:forward:0")
            .child(
                XmlElement::namespaced("delay", "urn:xmpp:delay").attr(
                    "stamp",
                    item.created_at
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                ),
            )
            .validated_fragment(&archived_stanza)?;
        let result = XmlElement::namespaced("result", MAM_NS)
            .attr("id", item.id)
            .optional_attr("queryid", parsed.query_id.as_deref())
            .child(forwarded);
        replies.push(
            XmlElement::namespaced("message", "jabber:client")
                .attr("id", Uuid::new_v4())
                .attr("to", session.mam_full_jid().unwrap_or_default())
                .optional_attr("from", archive_from.as_deref())
                .child(result)
                .finish(),
        );
    }

    let mut set = XmlElement::namespaced("set", RSM_NS);
    if let (Some(first), Some(last)) = (page.rows.first(), page.rows.last()) {
        set.push_child(
            XmlElement::new("first")
                .attr("index", page.first_index)
                .text(first.id.to_string()),
        );
        set.push_child(XmlElement::new("last").text(last.id.to_string()));
    }
    set.push_child(XmlElement::new("count").text(page.total.to_string()));
    let fin = XmlElement::namespaced("fin", MAM_NS)
        .attr("complete", page.complete)
        .attr("stable", "true")
        .child(set)
        .finish();
    replies.push(if let Some(from) = archive_from.as_deref() {
        iq_result_from(id, from, &fin)
    } else {
        iq_result(id, &fin)
    });
    Ok(MamReply::SendMany(replies))
}

fn parse_mam_preferences(prefs: Node<'_, '_>) -> std::result::Result<MamPreferences, &'static str> {
    let parsed = parse_xep_mam_preferences(prefs).map_err(|error| mam_error_condition(&error))?;
    Ok(MamPreferences {
        default_policy: parsed.default_policy.as_str().to_owned(),
        always: parsed.always,
        never: parsed.never,
    })
}

fn mam_preferences_xml(preferences: &MamPreferences) -> String {
    let list = |name: &str, values: &[String]| {
        let mut list = match name {
            "always" => XmlElement::new("always"),
            "never" => XmlElement::new("never"),
            _ => unreachable!("fixed MAM preference list"),
        };
        for jid in values {
            list.push_child(XmlElement::new("jid").text(jid.clone()));
        }
        list
    };
    XmlElement::namespaced("prefs", MAM_NS)
        .attr("default", &preferences.default_policy)
        .child(list("always", &preferences.always))
        .child(list("never", &preferences.never))
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    fn parse(xml: &str) -> std::result::Result<ParsedMamQuery, &'static str> {
        let document = Document::parse(xml).unwrap();
        parse_mam_query(document.root_element())
    }

    #[test]
    fn parses_extended_filters_rsm_and_flip() {
        let parsed = parse("<query xmlns='urn:xmpp:mam:2' queryid='q1'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mam:2</value></field><field var='with'><value>Alice@Example.test/Phone</value></field><field var='ids'><value>de305d54-75b4-431b-adb2-eb6b9e546013</value></field></x><set xmlns='http://jabber.org/protocol/rsm'><max>20</max><before/></set><flip-page/></query>").unwrap();
        assert_eq!(
            parsed.query.with_jid.as_deref(),
            Some("alice@example.test/Phone")
        );
        assert_eq!(parsed.query.ids.len(), 1);
        assert_eq!(parsed.query.page, MamRsmPage::Last);
        assert_eq!(parsed.query.max, 20);
        assert!(parsed.flip_page);

        let indexed = parse("<query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><max>20</max><index>371</index></set></query>").unwrap();
        assert_eq!(indexed.query.page, MamRsmPage::Index(371));
    }

    #[test]
    fn query_without_rsm_starts_at_the_oldest_item() {
        let parsed = parse("<query xmlns='urn:xmpp:mam:2'/>").unwrap();
        assert_eq!(parsed.query.page, MamRsmPage::First);
        assert_eq!(parsed.query.max, i64::from(MAX_MAM_RESULTS));
    }

    #[test]
    fn personal_mam_reasserts_the_account_archive_uid_as_stanza_id() {
        let id = Uuid::parse_str("de305d54-75b4-431b-adb2-eb6b9e546013").unwrap();
        let expected_id = id.to_string();
        for stanza in [
            "<message xmlns='jabber:client'><retracted xmlns='urn:xmpp:message-retract:1' id='action'/><stanza-id xmlns='urn:xmpp:sid:0' id='remote-id' by='remote.test'/></message>",
            "<message xmlns='jabber:client'><retracted xmlns='urn:xmpp:message-retract:1' id='action'/><stanza-id xmlns='urn:xmpp:sid:0' id='forged-local' by='Alice@Example.test'/><stanza-id xmlns='urn:xmpp:sid:0' id='remote-id' by='remote.test'/></message>",
        ] {
            let item = ArchiveRow {
                id,
                peer_jid: "bob@example.test".to_owned(),
                stanza: stanza.to_owned(),
                encrypted: false,
                stanza_id: Some("client-id".to_owned()),
                created_at: Utc::now(),
            };

            let rendered = personal_mam_stanza(&item, "alice@example.test");
            let document = Document::parse(&rendered).unwrap();
            let stanza_ids = document
                .root_element()
                .children()
                .filter(|node| {
                    node.is_element()
                        && node.tag_name().namespace() == Some("urn:xmpp:sid:0")
                        && node.tag_name().name() == "stanza-id"
                })
                .collect::<Vec<_>>();
            let account_ids = stanza_ids
                .iter()
                .filter(|node| {
                    node.attribute("by").is_some_and(|by| {
                        northstar_xmpp_types::jid::canonicalize(by).ok().as_deref()
                            == Some("alice@example.test")
                    })
                })
                .collect::<Vec<_>>();

            assert_eq!(account_ids.len(), 1, "{rendered}");
            assert_eq!(account_ids[0].attribute("id"), Some(expected_id.as_str()));
            assert!(stanza_ids.iter().any(|node| {
                node.attribute("id") == Some("remote-id")
                    && node.attribute("by") == Some("remote.test")
            }));
            assert!(!rendered.contains("forged-local"));
        }
    }

    #[test]
    fn rejects_unknown_duplicate_and_malformed_query_controls() {
        for (xml, condition) in [
            (
                "<query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field><field var='unknown'><value>x</value></field></x></query>",
                "feature-not-implemented",
            ),
            (
                "<query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><before/><after>x</after></set></query>",
                "bad-request",
            ),
            (
                "<query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><max>-1</max></set></query>",
                "bad-request",
            ),
            (
                "<query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><before/><index>0</index></set></query>",
                "bad-request",
            ),
            (
                "<query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><index>-1</index></set></query>",
                "bad-request",
            ),
            (
                "<query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><index>1000001</index></set></query>",
                "resource-constraint",
            ),
            (
                "<query xmlns='urn:xmpp:mam:2'><flip-page/><flip-page/></query>",
                "bad-request",
            ),
            (
                "<query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='with'><value>a@example.test</value></field></x></query>",
                "bad-request",
            ),
        ] {
            assert_eq!(parse(xml).unwrap_err(), condition, "{xml}");
        }
    }

    #[test]
    fn invalid_opaque_archive_ids_are_item_not_found() {
        assert_eq!(
            parse("<query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><after>not-a-server-id</after></set></query>").unwrap_err(),
            "item-not-found"
        );
    }

    #[test]
    fn preferences_are_canonical_disjoint_and_always_emit_lists() {
        let document = Document::parse("<prefs xmlns='urn:xmpp:mam:2' default='roster'><always><jid>A@Example.test/Phone</jid></always><never><jid>b@example.test</jid></never></prefs>").unwrap();
        let parsed = parse_mam_preferences(document.root_element()).unwrap();
        assert_eq!(parsed.always, ["a@example.test/Phone"]);
        assert_eq!(parsed.never, ["b@example.test"]);
        assert_eq!(
            mam_preferences_xml(&MamPreferences::default()),
            "<prefs xmlns='urn:xmpp:mam:2' default='always'><always/><never/></prefs>"
        );

        let duplicate = Document::parse("<prefs xmlns='urn:xmpp:mam:2' default='always'><always><jid>A@example.test</jid></always><never><jid>a@EXAMPLE.test</jid></never></prefs>").unwrap();
        assert_eq!(
            parse_mam_preferences(duplicate.root_element()).unwrap_err(),
            "bad-request"
        );

        let whitespace = Document::parse("<prefs xmlns='urn:xmpp:mam:2' default='always'><always><jid> a@example.test </jid></always></prefs>").unwrap();
        assert_eq!(
            parse_mam_preferences(whitespace.root_element()).unwrap_err(),
            "jid-malformed"
        );
    }

    #[test]
    fn mam_get_commands_are_strictly_empty() {
        for (xml, name, valid) in [
            ("<query xmlns='urn:xmpp:mam:2'/>", "query", true),
            ("<metadata xmlns='urn:xmpp:mam:2'/>", "metadata", true),
            ("<prefs xmlns='urn:xmpp:mam:2'/>", "prefs", true),
            (
                "<metadata xmlns='urn:xmpp:mam:2'><start/></metadata>",
                "metadata",
                false,
            ),
            (
                "<prefs xmlns='urn:xmpp:mam:2' default='always'/>",
                "prefs",
                false,
            ),
            (
                "<query xmlns='urn:xmpp:mam:2'>payload</query>",
                "query",
                false,
            ),
        ] {
            let document = Document::parse(xml).unwrap();
            assert_eq!(
                empty_mam_command(document.root_element(), name),
                valid,
                "{xml}"
            );
        }
    }

    #[test]
    fn with_filter_does_not_trim_ambiguous_jid_text() {
        assert_eq!(
            parse("<query xmlns='urn:xmpp:mam:2'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mam:2</value></field><field var='with'><value> alice@example.test </value></field></x></query>")
                .unwrap_err(),
            "jid-malformed"
        );
    }
}
