#![forbid(unsafe_code)]

//! Capability-free XEP-0115 Entity Capabilities library for Northstar.
//!
//! This crate provides pure domain models, deterministic canonicalization,
//! cryptographic hash verification, and strict XML wire parsing/building for
//! XEP-0115 (Entity Capabilities v1.5).
//!
//! # Architecture & Boundary Guarantees
//!
//! - **No Caches or Global State**: Pure calculation and verification only. No cache storage, no DashMap, no LRU.
//! - **No Networking or IO**: No async runtimes, no Tokio, no database pools, no HTTP, no outbound queries.
//! - **No Clock Dependency**: Pure input-to-output validation without wall-clock timestamps.
//! - **Separate from XEP-0390**: XEP-0390 Entity Capabilities 2 is kept separate to avoid mixing canonicalization rules.

pub mod canonical;
pub mod constants;
pub mod error;
pub mod hash;
pub mod model;
pub mod wire;

// Common re-exports
pub use canonical::{generate_canonical_form_string, generate_canonical_verification_string};
pub use constants::{
    CAPS_NS, DATA_NS, DESCRIPTOR, DISCO_INFO_NS, MAX_CATEGORY_LEN, MAX_DISCO_CHILDREN,
    MAX_DISCO_PAYLOAD_BYTES, MAX_EXT_LEN, MAX_FEATURES, MAX_FEATURE_LEN, MAX_FIELD_VALUES,
    MAX_FIELD_VALUE_LEN, MAX_FIELD_VAR_LEN, MAX_FORMS, MAX_FORM_FIELDS, MAX_FORM_TYPE_LEN,
    MAX_HASH_LEN, MAX_IDENTITIES, MAX_LANG_LEN, MAX_NAME_LEN, MAX_NODE_LEN, MAX_TYPE_LEN,
    MAX_VER_LEN, XEP_ID, XML_NS,
};
pub use error::CapsError;
pub use hash::{compute_verification_string_and_ver, verify_caps_advertisement, CapsHashAlgorithm};
pub use model::{
    CapsAdvertisement, CapsKey, CapsScope, CapsValidationResult, DiscoInfo, DiscoInfoBuilder,
    ExtendedForm, Feature, FormField, Identity,
};
pub use wire::{
    build_caps_element, build_disco_info_query, build_disco_info_request, parse_caps_element,
    parse_caps_from_presence, parse_caps_xml, parse_disco_info_element, parse_disco_info_xml,
    validate_disco_node_attribute,
};
