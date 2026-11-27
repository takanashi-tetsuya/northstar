use super::*;
use std::{cell::RefCell, future::ready};

#[tokio::test]
async fn retry_only_the_known_unaccepted_remainder() {
    use ExactPresenceAcceptance::*;
    let calls = RefCell::new(Vec::new());
    let result = publish_remaining(vec![1, 2, 3, 4], |target| {
        let mut calls = calls.borrow_mut();
        let first = !calls.contains(&target);
        calls.push(target);
        ready((
            target,
            Ok(match (target, first) {
                (2, true) => Retry,
                (3, _) => Gone,
                (4, _) => Unknown,
                _ => Accepted,
            }),
        ))
    })
    .await;
    assert!(result.is_err());
    assert_eq!(calls.into_inner(), [1, 2, 3, 4, 2]);
}
