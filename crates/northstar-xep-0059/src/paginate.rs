//! Pure, deterministic pagination helpers over ordered in-memory slices.

use crate::bounds::RsmBounds;
use crate::error::RsmError;
use crate::models::{BeforeCursor, RsmFirstItem, RsmRequest, RsmResponse};

/// Pure deterministic pagination over an ordered slice, returning a slice sub-borrow and response metadata.
pub fn paginate_slice<'a, T, FId>(
    items: &'a [T],
    request: &RsmRequest,
    fallback_max: usize,
    get_id: FId,
) -> Result<(&'a [T], RsmResponse), RsmError>
where
    FId: Fn(&T) -> &str,
{
    paginate_slice_with_bounds(items, request, &RsmBounds::DEFAULT, fallback_max, get_id)
}

/// Pure deterministic pagination over an ordered slice with custom bounds.
pub fn paginate_slice_with_bounds<'a, T, FId>(
    items: &'a [T],
    request: &RsmRequest,
    bounds: &RsmBounds,
    fallback_max: usize,
    get_id: FId,
) -> Result<(&'a [T], RsmResponse), RsmError>
where
    FId: Fn(&T) -> &str,
{
    request.validate(bounds)?;

    let total = items.len();
    let max = request
        .max
        .unwrap_or(fallback_max)
        .min(bounds.max_page_size);

    // If max is 0 (size request per XEP-0059 §2.7), return empty slice with total count.
    if max == 0 {
        return Ok((
            &items[0..0],
            RsmResponse {
                first: None,
                last: None,
                count: Some(total as u64),
                index: None,
            },
        ));
    }

    let cursor_index = |cursor: &str| -> Result<usize, RsmError> {
        items
            .iter()
            .position(|item| get_id(item) == cursor)
            .ok_or_else(|| RsmError::ItemNotFound(cursor.to_owned()))
    };

    let (start, end) = if let Some(ref after) = request.after {
        let pos = cursor_index(after)?;
        let start = (pos + 1).min(total);
        let end = start.saturating_add(max).min(total);
        (start, end)
    } else if let Some(ref before) = request.before {
        let end = match before {
            BeforeCursor::LastPage => total,
            BeforeCursor::Item(cursor) => cursor_index(cursor)?,
        };
        let start = end.saturating_sub(max);
        (start, end)
    } else if let Some(index) = request.index {
        let start = (index as usize).min(total);
        let end = start.saturating_add(max).min(total);
        (start, end)
    } else {
        let start = 0;
        let end = max.min(total);
        (start, end)
    };

    let page = &items[start..end];

    let first = page.first().map(|item| RsmFirstItem {
        value: get_id(item).to_owned(),
        index: Some(start as u64),
    });
    let last = page.last().map(|item| get_id(item).to_owned());

    Ok((
        page,
        RsmResponse {
            first,
            last,
            count: Some(total as u64),
            index: None,
        },
    ))
}

/// Pure deterministic pagination returning cloned items and response metadata.
pub fn paginate_items<T: Clone, FId>(
    items: &[T],
    request: &RsmRequest,
    fallback_max: usize,
    get_id: FId,
) -> Result<(Vec<T>, RsmResponse), RsmError>
where
    FId: Fn(&T) -> &str,
{
    let (slice, resp) = paginate_slice(items, request, fallback_max, get_id)?;
    Ok((slice.to_vec(), resp))
}

/// Pure deterministic pagination returning cloned items with custom bounds.
pub fn paginate_items_with_bounds<T: Clone, FId>(
    items: &[T],
    request: &RsmRequest,
    bounds: &RsmBounds,
    fallback_max: usize,
    get_id: FId,
) -> Result<(Vec<T>, RsmResponse), RsmError>
where
    FId: Fn(&T) -> &str,
{
    let (slice, resp) = paginate_slice_with_bounds(items, request, bounds, fallback_max, get_id)?;
    Ok((slice.to_vec(), resp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paginate_with_custom_bounds() {
        let items = vec!["a", "b", "c"];
        let req = RsmRequest::new().with_max(5);
        let bounds = RsmBounds::new(2, 100, 1000);

        // When max (5) > bounds max_page_size (2), request.validate fails
        assert!(paginate_items_with_bounds(&items, &req, &bounds, 10, |s| *s).is_err());
    }
}
