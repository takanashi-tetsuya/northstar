#![forbid(unsafe_code)]

//! Capability-free XEP-0059 Result Set Management wire models, validation, builders, and pagination helpers.
//!
//! This crate implements the core Result Set Management (RSM) protocol specified in
//! [XEP-0059: Result Set Management](https://xmpp.org/extensions/xep-0059.html).
//!
//! It is strictly capability-free: it has no database, network, clock, async runtime,
//! filesystem, or server state dependencies.

pub mod bounds;
pub mod builder;
pub mod constants;
pub mod error;
pub mod models;
pub mod paginate;
pub mod parser;
pub mod xml;

pub use bounds::RsmBounds;
pub use builder::{
    build_mam_fin, build_mam_fin_element, build_rsm_request, build_rsm_request_element,
    build_rsm_set, build_rsm_set_element, build_rsm_set_raw,
};
pub use constants::{
    DEFAULT_MAX_CURSOR_BYTES, DEFAULT_MAX_INDEX, DEFAULT_MAX_PAGE_SIZE, DESCRIPTOR, NAMESPACE,
    NS_RSM, XEP_ID,
};
pub use error::RsmError;
pub use models::{BeforeCursor, PagingDirective, RsmFin, RsmFirstItem, RsmRequest, RsmResponse};
pub use paginate::{
    paginate_items, paginate_items_with_bounds, paginate_slice, paginate_slice_with_bounds,
};
pub use parser::{
    parse_rsm_element, parse_rsm_element_with_bounds, parse_rsm_from_parent,
    parse_rsm_from_parent_with_bounds, parse_rsm_response_element,
    parse_rsm_response_element_with_bounds, parse_rsm_response_str,
    parse_rsm_response_str_with_bounds, parse_rsm_str, parse_rsm_str_with_bounds,
};
pub use xml::{escape_xml_attr, escape_xml_text, XmlElement};
