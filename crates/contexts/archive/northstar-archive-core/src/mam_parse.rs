//! Parses a XEP-0313 query element into the archive query.

use crate::{MamArchiveQuery, MamRsmPage};
use chrono::{DateTime, Utc};
use northstar_xep_0313::{
    parse_mam_query as parse_xep_mam_query, MamError, MamRsmPage as ParsedMamRsmPage, UtcTimestamp,
};
use roxmltree::Node;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct ParsedMamQuery {
    pub query: MamArchiveQuery,
    pub query_id: Option<String>,
    pub flip_page: bool,
}

pub fn mam_error_condition(error: &MamError) -> &'static str {
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
