//! Configurable bounds and validation limits for XEP-0059 operations.

use crate::constants::{DEFAULT_MAX_CURSOR_BYTES, DEFAULT_MAX_INDEX, DEFAULT_MAX_PAGE_SIZE};
use crate::error::RsmError;

/// Operational bounds for XEP-0059 Result Set Management requests.
///
/// Different subsystems (e.g. MAM, PubSub, Service Discovery) enforce different
/// page size and index constraints while sharing canonical RSM parsing semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsmBounds {
    /// Maximum allowed page size in <max> requests.
    pub max_page_size: usize,
    /// Maximum allowed byte length for opaque cursor strings (<after> and <before>).
    pub max_cursor_bytes: usize,
    /// Maximum allowed zero-based index for <index> requests.
    pub max_index: u64,
}

impl Default for RsmBounds {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl RsmBounds {
    /// Default standard bounds for general RSM operations (1,000 items, 1 KiB cursor, 1,000,000 max index).
    pub const DEFAULT: Self = Self {
        max_page_size: DEFAULT_MAX_PAGE_SIZE,
        max_cursor_bytes: DEFAULT_MAX_CURSOR_BYTES,
        max_index: DEFAULT_MAX_INDEX,
    };

    /// Strict bounds commonly configured for MAM (Message Archive Management) queries (100 items limit).
    pub const MAM: Self = Self {
        max_page_size: 100,
        max_cursor_bytes: DEFAULT_MAX_CURSOR_BYTES,
        max_index: DEFAULT_MAX_INDEX,
    };

    /// Strict bounds commonly configured for Service Discovery (100 items limit).
    pub const DISCOVERY: Self = Self {
        max_page_size: 100,
        max_cursor_bytes: DEFAULT_MAX_CURSOR_BYTES,
        max_index: DEFAULT_MAX_INDEX,
    };

    /// Standard bounds configured for Publish-Subscribe item retrieval (1,000 items limit).
    pub const PUBSUB: Self = Self {
        max_page_size: DEFAULT_MAX_PAGE_SIZE,
        max_cursor_bytes: DEFAULT_MAX_CURSOR_BYTES,
        max_index: DEFAULT_MAX_INDEX,
    };

    /// Construct a new custom [RsmBounds] specification.
    pub const fn new(max_page_size: usize, max_cursor_bytes: usize, max_index: u64) -> Self {
        Self {
            max_page_size,
            max_cursor_bytes,
            max_index,
        }
    }

    /// Return a copy of these bounds with an updated max_page_size.
    pub const fn with_max_page_size(mut self, max_page_size: usize) -> Self {
        self.max_page_size = max_page_size;
        self
    }

    /// Return a copy of these bounds with an updated max_cursor_bytes.
    pub const fn with_max_cursor_bytes(mut self, max_cursor_bytes: usize) -> Self {
        self.max_cursor_bytes = max_cursor_bytes;
        self
    }

    /// Return a copy of these bounds with an updated max_index.
    pub const fn with_max_index(mut self, max_index: u64) -> Self {
        self.max_index = max_index;
        self
    }

    /// Validate that a cursor string is non-empty, within byte limit, and free of control characters.
    pub fn validate_cursor(&self, cursor: &str, tag_name: &'static str) -> Result<(), RsmError> {
        if cursor.is_empty() {
            return Err(RsmError::EmptyCursor(tag_name));
        }
        if cursor.len() > self.max_cursor_bytes {
            return Err(RsmError::CursorLengthExceeded {
                length: cursor.len(),
                limit: self.max_cursor_bytes,
            });
        }
        if cursor.chars().any(char::is_control) {
            return Err(RsmError::InvalidCursor(
                cursor.to_owned(),
                "cursor contains control characters",
            ));
        }
        Ok(())
    }

    /// Validate that a requested <max> value does not exceed configured page size limits.
    pub fn validate_max(&self, max: usize) -> Result<(), RsmError> {
        if max > self.max_page_size {
            return Err(RsmError::MaxPageSizeExceeded {
                requested: max,
                limit: self.max_page_size,
            });
        }
        Ok(())
    }

    /// Validate that a requested <index> does not exceed configured index limits.
    pub fn validate_index(&self, index: u64) -> Result<(), RsmError> {
        if index > self.max_index {
            return Err(RsmError::IndexLimitExceeded {
                requested: index,
                limit: self.max_index,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_bounds_construction_and_mutation() {
        let b = RsmBounds::new(50, 256, 10_000)
            .with_max_page_size(60)
            .with_max_cursor_bytes(512)
            .with_max_index(20_000);

        assert_eq!(b.max_page_size, 60);
        assert_eq!(b.max_cursor_bytes, 512);
        assert_eq!(b.max_index, 20_000);
        assert!(b.validate_max(60).is_ok());
        assert!(b.validate_max(61).is_err());
        assert!(b.validate_index(20_000).is_ok());
        assert!(b.validate_index(20_001).is_err());
        assert!(b.validate_cursor("valid-cursor", "after").is_ok());
        assert!(b.validate_cursor("", "after").is_err());
    }
}
