//! In-memory page planning for authorized PubSub item and disco queries.

/// The wire layer validates the RSM controls before constructing this query.
/// The existing PubSub list endpoints use cursor and limit controls only.
pub struct PubSubListPageQuery<'a> {
    pub max: Option<usize>,
    pub after: Option<&'a str>,
    /// `Some(None)` requests the final page.
    pub before: Option<Option<&'a str>>,
}

pub struct PubSubListPage<T> {
    pub items: Vec<T>,
    pub first: Option<(usize, String)>,
    pub last: Option<String>,
    pub total: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PubSubListPageError {
    MissingCursor,
}

/// Page a previously authorized, ordered result set without another read.
/// No database transaction or audience calculation takes place here.
pub fn page_pubsub_list<T>(
    items: Vec<T>,
    query: PubSubListPageQuery<'_>,
    fallback_max: usize,
    id: impl Fn(&T) -> &str,
) -> Result<PubSubListPage<T>, PubSubListPageError> {
    let total = items.len();
    let max = query.max.unwrap_or(fallback_max).min(1_000);
    let cursor_index = |cursor: &str| {
        items
            .iter()
            .position(|item| id(item) == cursor)
            .ok_or(PubSubListPageError::MissingCursor)
    };
    let (start, end) = if let Some(after) = query.after {
        let start = cursor_index(after)?.saturating_add(1).min(total);
        (start, start.saturating_add(max).min(total))
    } else if let Some(before) = query.before {
        let end = match before {
            Some(before) => cursor_index(before)?,
            None => total,
        };
        (end.saturating_sub(max), end)
    } else {
        (0, max.min(total))
    };
    let page = items
        .into_iter()
        .skip(start)
        .take(end - start)
        .collect::<Vec<_>>();
    Ok(PubSubListPage {
        first: page.first().map(|item| (start, id(item).to_owned())),
        last: page.last().map(|item| id(item).to_owned()),
        items: page,
        total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(
        query: PubSubListPageQuery<'_>,
    ) -> Result<PubSubListPage<&'static str>, PubSubListPageError> {
        page_pubsub_list(vec!["alpha", "beta", "gamma", "delta"], query, 2, |item| {
            item
        })
    }

    #[test]
    fn forward_and_reverse_cursors_preserve_order_and_first_index() {
        let forward = page(PubSubListPageQuery {
            max: Some(1),
            after: Some("alpha"),
            before: None,
        })
        .unwrap();
        assert_eq!(forward.items, ["beta"]);
        assert_eq!(forward.first, Some((1, "beta".to_owned())));
        assert_eq!(forward.last.as_deref(), Some("beta"));
        assert_eq!(forward.total, 4);

        let reverse = page(PubSubListPageQuery {
            max: Some(2),
            after: None,
            before: Some(Some("delta")),
        })
        .unwrap();
        assert_eq!(reverse.items, ["beta", "gamma"]);
        assert_eq!(reverse.first, Some((1, "beta".to_owned())));
    }

    #[test]
    fn final_zero_and_missing_cursor_have_distinct_results() {
        let last = page(PubSubListPageQuery {
            max: Some(2),
            after: None,
            before: Some(None),
        })
        .unwrap();
        assert_eq!(last.items, ["gamma", "delta"]);
        let zero = page(PubSubListPageQuery {
            max: Some(0),
            after: None,
            before: None,
        })
        .unwrap();
        assert!(zero.items.is_empty());
        assert_eq!(zero.total, 4);
        assert!(zero.first.is_none());
        assert_eq!(
            page(PubSubListPageQuery {
                max: None,
                after: Some("missing"),
                before: None,
            })
            .err(),
            Some(PubSubListPageError::MissingCursor)
        );
    }

    #[test]
    fn caller_limit_is_capped_at_one_thousand() {
        let items = (0..1_001).collect::<Vec<_>>();
        let page = page_pubsub_list(
            items,
            PubSubListPageQuery {
                max: Some(usize::MAX),
                after: None,
                before: None,
            },
            usize::MAX,
            |item| if *item == 0 { "zero" } else { "other" },
        )
        .unwrap();
        assert_eq!(page.items.len(), 1_000);
        assert_eq!(page.total, 1_001);
    }
}
