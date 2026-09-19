use northstar_xep_0059::{paginate_items, paginate_slice, RsmError, RsmRequest};

#[test]
fn paginates_first_page() {
    let items = vec!["item-1", "item-2", "item-3", "item-4", "item-5"];
    let req = RsmRequest::new().with_max(2);

    let (page, resp) = paginate_items(&items, &req, 10, |s| *s).unwrap();
    assert_eq!(page, vec!["item-1", "item-2"]);
    assert_eq!(resp.first_value(), Some("item-1"));
    assert_eq!(resp.first_index(), Some(0));
    assert_eq!(resp.last_value(), Some("item-2"));
    assert_eq!(resp.count_value(), Some(5));
}

#[test]
fn paginates_forward_after_cursor() {
    let items = vec!["item-1", "item-2", "item-3", "item-4", "item-5"];
    let req = RsmRequest::new().with_max(2).with_after("item-2");

    let (page, resp) = paginate_items(&items, &req, 10, |s| *s).unwrap();
    assert_eq!(page, vec!["item-3", "item-4"]);
    assert_eq!(resp.first_value(), Some("item-3"));
    assert_eq!(resp.first_index(), Some(2));
    assert_eq!(resp.last_value(), Some("item-4"));
    assert_eq!(resp.count_value(), Some(5));

    // After last item
    let req_end = RsmRequest::new().with_max(2).with_after("item-5");
    let (page_end, resp_end) = paginate_items(&items, &req_end, 10, |s| *s).unwrap();
    assert!(page_end.is_empty());
    assert_eq!(resp_end.first, None);
    assert_eq!(resp_end.last, None);
    assert_eq!(resp_end.count_value(), Some(5));
}

#[test]
fn paginates_backward_before_cursor() {
    let items = vec!["item-1", "item-2", "item-3", "item-4", "item-5"];
    let req = RsmRequest::new().with_max(2).with_before_item("item-4");

    let (page, resp) = paginate_items(&items, &req, 10, |s| *s).unwrap();
    assert_eq!(page, vec!["item-2", "item-3"]);
    assert_eq!(resp.first_value(), Some("item-2"));
    assert_eq!(resp.first_index(), Some(1));
    assert_eq!(resp.last_value(), Some("item-3"));
    assert_eq!(resp.count_value(), Some(5));

    // Before first item
    let req_start = RsmRequest::new().with_max(2).with_before_item("item-1");
    let (page_start, resp_start) = paginate_items(&items, &req_start, 10, |s| *s).unwrap();
    assert!(page_start.is_empty());
    assert_eq!(resp_start.first, None);
    assert_eq!(resp_start.last, None);
    assert_eq!(resp_start.count_value(), Some(5));
}

#[test]
fn paginates_last_page_empty_before() {
    let items = vec!["item-1", "item-2", "item-3", "item-4", "item-5"];
    let req = RsmRequest::new().with_max(2).with_before_last_page();

    let (page, resp) = paginate_items(&items, &req, 10, |s| *s).unwrap();
    assert_eq!(page, vec!["item-4", "item-5"]);
    assert_eq!(resp.first_value(), Some("item-4"));
    assert_eq!(resp.first_index(), Some(3));
    assert_eq!(resp.last_value(), Some("item-5"));
    assert_eq!(resp.count_value(), Some(5));

    // Last page when page size > total items
    let req_large = RsmRequest::new().with_max(10).with_before_last_page();
    let (page_large, resp_large) = paginate_items(&items, &req_large, 10, |s| *s).unwrap();
    assert_eq!(
        page_large,
        vec!["item-1", "item-2", "item-3", "item-4", "item-5"]
    );
    assert_eq!(resp_large.first_value(), Some("item-1"));
    assert_eq!(resp_large.first_index(), Some(0));
    assert_eq!(resp_large.last_value(), Some("item-5"));
    assert_eq!(resp_large.count_value(), Some(5));
}

#[test]
fn paginates_indexed_offset() {
    let items = vec!["item-1", "item-2", "item-3", "item-4", "item-5"];
    let req = RsmRequest::new().with_max(2).with_index(2);

    let (page, resp) = paginate_items(&items, &req, 10, |s| *s).unwrap();
    assert_eq!(page, vec!["item-3", "item-4"]);
    assert_eq!(resp.first_value(), Some("item-3"));
    assert_eq!(resp.first_index(), Some(2));
    assert_eq!(resp.last_value(), Some("item-4"));
    assert_eq!(resp.count_value(), Some(5));

    // Index beyond total
    let req_beyond = RsmRequest::new().with_max(2).with_index(100);
    let (page_beyond, resp_beyond) = paginate_items(&items, &req_beyond, 10, |s| *s).unwrap();
    assert!(page_beyond.is_empty());
    assert_eq!(resp_beyond.first, None);
    assert_eq!(resp_beyond.last, None);
    assert_eq!(resp_beyond.count_value(), Some(5));
}

#[test]
fn paginates_size_only_max_zero() {
    let items = vec!["item-1", "item-2", "item-3"];
    let req = RsmRequest::new().with_max(0);

    let (page, resp) = paginate_items(&items, &req, 10, |s| *s).unwrap();
    assert!(page.is_empty());
    assert_eq!(resp.first, None);
    assert_eq!(resp.last, None);
    assert_eq!(resp.count_value(), Some(3));
}

#[test]
fn paginates_empty_slice() {
    let items: Vec<&str> = vec![];
    let req = RsmRequest::new().with_max(10);

    let (page, resp) = paginate_items(&items, &req, 10, |s| *s).unwrap();
    assert!(page.is_empty());
    assert_eq!(resp.first, None);
    assert_eq!(resp.last, None);
    assert_eq!(resp.count_value(), Some(0));
}

#[test]
fn paginates_cursor_not_found_returns_item_not_found_error() {
    let items = vec!["item-1", "item-2"];
    let req = RsmRequest::new().with_after("non-existent");

    let err = paginate_items(&items, &req, 10, |s| *s).unwrap_err();
    assert_eq!(err, RsmError::ItemNotFound("non-existent".to_owned()));
    assert!(err.is_item_not_found());
    assert_eq!(err.to_xmpp_error_condition(), "item-not-found");
}

#[test]
fn paginate_slice_zero_copy_borrow() {
    #[derive(Debug, PartialEq)]
    struct NonCloneableItem {
        id: String,
        val: u32,
    }

    let items = vec![
        NonCloneableItem {
            id: "a".into(),
            val: 1,
        },
        NonCloneableItem {
            id: "b".into(),
            val: 2,
        },
        NonCloneableItem {
            id: "c".into(),
            val: 3,
        },
    ];
    let req = RsmRequest::new().with_max(2).with_after("a");

    let (slice, resp) = paginate_slice(&items, &req, 10, |item| &item.id).unwrap();
    assert_eq!(slice.len(), 2);
    assert_eq!(slice[0].id, "b");
    assert_eq!(slice[1].id, "c");
    assert_eq!(resp.first_value(), Some("b"));
    assert_eq!(resp.last_value(), Some("c"));
}
