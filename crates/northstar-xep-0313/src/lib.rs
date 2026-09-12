#![forbid(unsafe_code)]

//! Pure, capability-free XEP-0313 Message Archive Management (MAM) protocol types, wire parsers, and XML builders.
//!
//! This crate contains transport-neutral domain models and pure validation logic for XEP-0313 MAM.
//! It deliberately has no dependencies on PostgreSQL (`sqlx`, `PgPool`), Redis, async runtimes (`tokio`),
//! networking/sockets, filesystem, environment access, logging, clocks, or server state (`AppState`).

pub mod builder;
pub mod constants;
pub mod error;
pub mod parser;
pub mod prefs;
pub mod query;
pub mod result_fin;
pub mod xml;

pub use builder::{
    build_extended_form, build_fin, build_fin_from_model, build_forwarded, build_metadata,
    build_preferences, build_result, build_result_message, build_result_payload,
    reassert_archive_stanza_id,
};
pub use constants::{
    DESCRIPTOR, DISCO_FEATURE_MAM, DISCO_FEATURE_MAM_EXTENDED, MAX_ARCHIVE_ID_BYTES, MAX_MAM_IDS,
    MAX_MAM_RESULTS, MAX_MAM_RSM_INDEX, MAX_PREFS_JIDS, MAX_QUERY_ID_BYTES, XEP_ID, XMLNS_CLIENT,
    XMLNS_DATA, XMLNS_DELAY, XMLNS_FORWARD, XMLNS_MAM, XMLNS_RSM, XMLNS_SID, XMLNS_XDATA_VALIDATE,
};
pub use error::MamError;
pub use parser::{
    is_empty_mam_command, parse_fin_element, parse_mam_preferences, parse_mam_query,
    parse_metadata_response, parse_result_element,
};
pub use prefs::{
    evaluate_preference, evaluate_preference_with_canonical, DefaultPolicy, MamPreferences,
};
pub use query::{ArchiveId, MamFilter, MamQuery, MamRsmPage, UtcTimestamp};
pub use result_fin::{MamFin, MamMetadata, MamMetadataBoundary, MamResult};
pub use xml::{
    attr_escape, escape_xml_attr, escape_xml_text, validate_qname, xml_escape, XmlElement,
};
