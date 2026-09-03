//! Compatibility facade for transport-neutral XML stream framing.
//!
//! The incremental parser, restricted-XML policy and structural limits are
//! owned by `northstar-xml-framing`. Transport adapters keep this module path
//! while the implementation remains single-sourced and independently tested.

pub use northstar_xml_framing::{
    is_xml_whitespace, resource_limit, stream_error_condition, take_frame, XmlEntityFramer,
};
