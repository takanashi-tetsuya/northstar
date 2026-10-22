//! Typed models for XEP-0059 Result Set Management requests, responses, and cursors.

use crate::bounds::RsmBounds;
use crate::error::RsmError;

/// Target for `<before>` pagination cursor.
///
/// XEP-0059 defines two distinct semantics for `<before>`:
/// 1. An empty element (`<before/>` or `<before></before>`) requests the *last page* of results.
/// 2. An element with text (`<before>id</before>`) requests the page of results *preceding* `id`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BeforeCursor {
    /// Empty `<before/>` requesting the final page of results.
    LastPage,
    /// `<before>id</before>` requesting the page before the specified item ID.
    Item(String),
}

impl BeforeCursor {
    /// Returns `true` if this cursor represents an empty `<before/>` requesting the last page.
    pub fn is_last_page(&self) -> bool {
        matches!(self, Self::LastPage)
    }

    /// Returns the target item ID if this cursor references a specific item before which to page.
    pub fn item_id(&self) -> Option<&str> {
        match self {
            Self::LastPage => None,
            Self::Item(id) => Some(id.as_str()),
        }
    }

    /// Convert from the legacy `Option<Option<String>>` representation.
    ///
    /// - `None` -> `None` (no before cursor)
    /// - `Some(None)` -> `Some(BeforeCursor::LastPage)`
    /// - `Some(Some(id))` -> `Some(BeforeCursor::Item(id))`
    pub fn from_raw(raw: Option<Option<String>>) -> Option<Self> {
        match raw {
            None => None,
            Some(None) => Some(Self::LastPage),
            Some(Some(id)) if id.is_empty() => Some(Self::LastPage),
            Some(Some(id)) => Some(Self::Item(id)),
        }
    }

    /// Convert into the legacy `Option<Option<String>>` representation.
    pub fn to_raw(&self) -> Option<Option<String>> {
        match self {
            Self::LastPage => Some(None),
            Self::Item(id) => Some(Some(id.clone())),
        }
    }
}

/// Unified, mutually exclusive paging directive derived from an [`RsmRequest`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PagingDirective {
    /// First page of results (default when no cursor/index is specified).
    First,
    /// Last page of results (`<before/>`).
    Last,
    /// Page strictly after the specified cursor item ID (`<after>id</after>`).
    After(String),
    /// Page strictly before the specified cursor item ID (`<before>id</before>`).
    Before(String),
    /// Page beginning at the specified zero-based item index (`<index>n</index>`).
    Index(u64),
}

/// A validated XEP-0059 Result Set Management request payload.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsmRequest {
    /// Maximum number of items requested (`<max>`). If `Some(0)`, queries set size without returning items.
    pub max: Option<usize>,
    /// Request the page of results following this item ID (`<after>id</after>`).
    pub after: Option<String>,
    /// Request the page of results preceding this item ID or the last page (`<before>...</before>`).
    pub before: Option<BeforeCursor>,
    /// Request the page of results starting at this zero-based offset index (`<index>n</index>`).
    pub index: Option<u64>,
}

impl RsmRequest {
    /// Create a new empty [`RsmRequest`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of items requested.
    pub fn with_max(mut self, max: usize) -> Self {
        self.max = Some(max);
        self
    }

    /// Set an `<after>id</after>` cursor.
    pub fn with_after(mut self, after: impl Into<String>) -> Self {
        self.after = Some(after.into());
        self.before = None;
        self.index = None;
        self
    }

    /// Set a `<before>id</before>` cursor.
    pub fn with_before_item(mut self, before_id: impl Into<String>) -> Self {
        self.before = Some(BeforeCursor::Item(before_id.into()));
        self.after = None;
        self.index = None;
        self
    }

    /// Set an empty `<before/>` cursor requesting the last page.
    pub fn with_before_last_page(mut self) -> Self {
        self.before = Some(BeforeCursor::LastPage);
        self.after = None;
        self.index = None;
        self
    }

    /// Set an `<index>n</index>` offset.
    pub fn with_index(mut self, index: u64) -> Self {
        self.index = Some(index);
        self.after = None;
        self.before = None;
        self
    }

    /// Returns `true` if this is a size-only request (`<max>0</max>`), per XEP-0059 §2.7.
    pub fn is_count_only(&self) -> bool {
        self.max == Some(0)
    }

    /// Extract the canonical paging directive from this request.
    pub fn paging_directive(&self) -> PagingDirective {
        if let Some(ref after) = self.after {
            PagingDirective::After(after.clone())
        } else if let Some(ref before) = self.before {
            match before {
                BeforeCursor::LastPage => PagingDirective::Last,
                BeforeCursor::Item(id) => PagingDirective::Before(id.clone()),
            }
        } else if let Some(index) = self.index {
            PagingDirective::Index(index)
        } else {
            PagingDirective::First
        }
    }

    /// Get raw `Option<Option<&str>>` representation of the `before` field for legacy compatibility.
    pub fn raw_before(&self) -> Option<Option<&str>> {
        match &self.before {
            None => None,
            Some(BeforeCursor::LastPage) => Some(None),
            Some(BeforeCursor::Item(id)) => Some(Some(id.as_str())),
        }
    }

    /// Set `before` field from legacy `Option<Option<String>>`.
    pub fn set_raw_before(&mut self, before: Option<Option<String>>) {
        self.before = BeforeCursor::from_raw(before);
    }

    /// Validate this request against the given operational bounds.
    pub fn validate(&self, bounds: &RsmBounds) -> Result<(), RsmError> {
        let mut count = 0;
        if self.after.is_some() {
            count += 1;
        }
        if self.before.is_some() {
            count += 1;
        }
        if self.index.is_some() {
            count += 1;
        }
        if count > 1 {
            return Err(RsmError::MutuallyExclusiveCursors(
                "request must specify at most one of after, before, or index",
            ));
        }

        if let Some(max) = self.max {
            bounds.validate_max(max)?;
        }
        if let Some(ref after) = self.after {
            bounds.validate_cursor(after, "after")?;
        }
        if let Some(BeforeCursor::Item(ref id)) = self.before {
            bounds.validate_cursor(id, "before")?;
        }
        if let Some(index) = self.index {
            bounds.validate_index(index)?;
        }

        Ok(())
    }
}

/// Metadata describing the first item in a returned result page (`<first [index='...']>id</first>`).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsmFirstItem {
    /// Item identifier of the first element in the page.
    pub value: String,
    /// Optional zero-based index of this item in the complete result set.
    pub index: Option<u64>,
}

impl RsmFirstItem {
    /// Construct a new [`RsmFirstItem`] without an index attribute.
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            index: None,
        }
    }

    /// Construct a new [`RsmFirstItem`] with a zero-based index attribute.
    pub fn with_index(value: impl Into<String>, index: u64) -> Self {
        Self {
            value: value.into(),
            index: Some(index),
        }
    }

    /// Get the item ID.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Get the optional zero-based index.
    pub fn index(&self) -> Option<u64> {
        self.index
    }
}

impl From<String> for RsmFirstItem {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for RsmFirstItem {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<(u64, String)> for RsmFirstItem {
    fn from((index, value): (u64, String)) -> Self {
        Self::with_index(value, index)
    }
}

impl From<(u64, &str)> for RsmFirstItem {
    fn from((index, value): (u64, &str)) -> Self {
        Self::with_index(value, index)
    }
}

impl From<(usize, String)> for RsmFirstItem {
    fn from((index, value): (usize, String)) -> Self {
        Self::with_index(value, index as u64)
    }
}

impl From<(usize, &str)> for RsmFirstItem {
    fn from((index, value): (usize, &str)) -> Self {
        Self::with_index(value, index as u64)
    }
}

/// Metadata describing a returned page of results in a `<set xmlns='http://jabber.org/protocol/rsm'>` response.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsmResponse {
    /// First item in the page, with optional index (`<first index='...'>id</first>`).
    pub first: Option<RsmFirstItem>,
    /// Last item in the page (`<last>id</last>`).
    pub last: Option<String>,
    /// Total number of items in the full result set (`<count>total</count>`).
    pub count: Option<u64>,
    /// Approximate or actual zero-based index returned in `<index>` tag (if used).
    pub index: Option<u64>,
}

impl RsmResponse {
    /// Create a new empty [`RsmResponse`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty result set response with count (per XEP-0059 §2.6 and §2.7).
    pub fn empty(count: u64) -> Self {
        Self {
            first: None,
            last: None,
            count: Some(count),
            index: None,
        }
    }

    /// Set the first item in the page.
    pub fn with_first(mut self, first: impl Into<RsmFirstItem>) -> Self {
        self.first = Some(first.into());
        self
    }

    /// Set the last item in the page.
    pub fn with_last(mut self, last: impl Into<String>) -> Self {
        self.last = Some(last.into());
        self
    }

    /// Set the total item count.
    pub fn with_count(mut self, count: u64) -> Self {
        self.count = Some(count);
        self
    }

    /// Set the index.
    pub fn with_index(mut self, index: u64) -> Self {
        self.index = Some(index);
        self
    }

    /// Return the first item value, if present.
    pub fn first_value(&self) -> Option<&str> {
        self.first.as_ref().map(|f| f.value.as_str())
    }

    /// Return the zero-based index of the first item, if present.
    pub fn first_index(&self) -> Option<u64> {
        self.first.as_ref().and_then(|f| f.index)
    }

    /// Return the last item value, if present.
    pub fn last_value(&self) -> Option<&str> {
        self.last.as_deref()
    }

    /// Return the total count, if present.
    pub fn count_value(&self) -> Option<u64> {
        self.count
    }

    /// Returns `true` if this response represents an empty page (no `first` and no `last`).
    pub fn is_empty_page(&self) -> bool {
        self.first.is_none() && self.last.is_none()
    }
}

/// Structured fin stanza metadata (e.g. for MAM XEP-0313 / MIX MAM) enclosing an RSM set.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RsmFin {
    /// Whether the archive result set was complete.
    pub complete: bool,
    /// Whether the archive snapshot was stable.
    pub stable: bool,
    /// The enclosed RSM response metadata.
    pub rsm: Option<RsmResponse>,
}

impl RsmFin {
    /// Construct a new [`RsmFin`] metadata descriptor.
    pub fn new(complete: bool, stable: bool) -> Self {
        Self {
            complete,
            stable,
            rsm: None,
        }
    }

    /// Construct a new [`RsmFin`] with enclosed RSM metadata.
    pub fn with_rsm(complete: bool, stable: bool, rsm: RsmResponse) -> Self {
        Self {
            complete,
            stable,
            rsm: Some(rsm),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn before_cursor_conversions() {
        assert_eq!(BeforeCursor::from_raw(None), None);
        assert_eq!(
            BeforeCursor::from_raw(Some(None)),
            Some(BeforeCursor::LastPage)
        );
        assert_eq!(
            BeforeCursor::from_raw(Some(Some("".to_string()))),
            Some(BeforeCursor::LastPage)
        );
        assert_eq!(
            BeforeCursor::from_raw(Some(Some("item-1".to_string()))),
            Some(BeforeCursor::Item("item-1".to_string()))
        );

        assert_eq!(BeforeCursor::LastPage.to_raw(), Some(None));
        assert_eq!(
            BeforeCursor::Item("item-1".to_string()).to_raw(),
            Some(Some("item-1".to_string()))
        );
    }

    #[test]
    fn paging_directive_derivation() {
        let req1 = RsmRequest::new();
        assert_eq!(req1.paging_directive(), PagingDirective::First);

        let req2 = RsmRequest::new().with_after("id-1");
        assert_eq!(
            req2.paging_directive(),
            PagingDirective::After("id-1".into())
        );

        let req3 = RsmRequest::new().with_before_last_page();
        assert_eq!(req3.paging_directive(), PagingDirective::Last);

        let req4 = RsmRequest::new().with_before_item("id-2");
        assert_eq!(
            req4.paging_directive(),
            PagingDirective::Before("id-2".into())
        );

        let req5 = RsmRequest::new().with_index(100);
        assert_eq!(req5.paging_directive(), PagingDirective::Index(100));
    }

    #[test]
    fn first_item_conversions_and_accessors() {
        let f1: RsmFirstItem = "item-1".into();
        assert_eq!(f1.value(), "item-1");
        assert_eq!(f1.index(), None);

        let f2: RsmFirstItem = (5u64, "item-5").into();
        assert_eq!(f2.value(), "item-5");
        assert_eq!(f2.index(), Some(5));

        let f3: RsmFirstItem = (10usize, "item-10".to_string()).into();
        assert_eq!(f3.value(), "item-10");
        assert_eq!(f3.index(), Some(10));
    }

    #[test]
    fn fin_structure_construction() {
        let fin = RsmFin::with_rsm(true, false, RsmResponse::empty(0));
        assert!(fin.complete);
        assert!(!fin.stable);
        assert!(fin.rsm.is_some());
    }
}
