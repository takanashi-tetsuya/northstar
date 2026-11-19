use super::*;
// Parser-only regressions. These construct no frame, port, runtime owner,
// application or writer and do not alias the ignored saved-case workload.
fn error<T: for<'de> Deserialize<'de>>(input: &str) -> String {
    match serde_json::from_str::<T>(input) {
        Ok(_) => panic!("invalid input was accepted"),
        Err(error) => error.to_string(),
    }
}
#[test]
fn empty_tagged_variants_reject_unknown_and_duplicate_keys() {
    assert!(error::<RecipientOwner>(r#"{"kind":"None","extra":1}"#).starts_with("unknown field"));
    assert!(error::<Drive>(r#"{"kind":"Complete","extra":1}"#).starts_with("unknown field"));
    assert!(
        error::<Transaction>(r#"{"kind":"AccountUnavailable","extra":1}"#)
            .starts_with("unknown field")
    );
    assert!(
        error::<Completion>(r#"{"kind":"ErrorAfterReceipt","extra":1}"#)
            .starts_with("unknown field")
    );
    assert!(error::<BoshRecording>(r#"{"kind":"Disabled","extra":1}"#).starts_with("unknown field"));
    assert!(
        error::<RecipientOwner>(r#"{"kind":"None","kind":"None"}"#).starts_with("duplicate field")
    );
    assert!(serde_json::from_str::<RecipientOwner>(r#"{"kind":"None"}"#).is_ok());
    assert!(serde_json::from_str::<Drive>(r#"{"kind":"Complete"}"#).is_ok());
}
#[test]
fn named_objects_reject_root_and_nested_positional_arrays() {
    assert!(serde_json::from_str::<Case>("[]").is_err());
    assert!(serde_json::from_str::<Original>(
        r#"["00000000-0000-0000-0000-000000000001","x","a","b","c"]"#
    )
    .is_err());
    assert!(serde_json::from_str::<NativeSpec>(r#"{"connection_id":"00000000-0000-0000-0000-000000000003","fence":[],"write":{"chunk_limit":2,"fail_after_accepted_bytes":null,"flush":"Ok"},"ack":{"commit":"Complete","disposition":"Deleted"}}"#).is_err());
    assert!(serde_json::from_str::<RecipientOwner>(
        r#"{"kind":"Native","frame_id":"00000000-0000-0000-0000-000000000001","native":[]}"#
    )
    .is_err());
}
#[test]
fn required_nullable_keeps_null_distinct_from_missing_and_preserves_nested_errors() {
    assert!(serde_json::from_str::<WriteScript>(
        r#"{"chunk_limit":2,"fail_after_accepted_bytes":null,"flush":"Ok"}"#
    )
    .is_ok());
    assert!(error::<WriteScript>(r#"{"chunk_limit":2,"flush":"Ok"}"#).contains("missing field"));
    assert!(error::<Nullable<WriteScript>>(
        r#"{"chunk_limit":2,"chunk_limit":3,"fail_after_accepted_bytes":null,"flush":"Ok"}"#
    )
    .starts_with("duplicate field"));
    assert!(error::<Nullable<WriteScript>>(
        r#"{"chunk_limit":2,"fail_after_accepted_bytes":null,"flush":"Ok","extra":0}"#
    )
    .starts_with("unknown field"));
    assert!(serde_json::from_str::<Nullable<WriteScript>>("[]").is_err());
    assert!(serde_json::from_str::<WriteScript>(
        r#"{"chunk_limit":2,"fail_after_accepted_bytes":false,"flush":"Ok"}"#
    )
    .is_err());
}
#[test]
fn simple_enums_reject_object_forms_at_nested_boundaries() {
    assert!(serde_json::from_str::<Mode>(r#"{"Live":null}"#).is_err());
    assert!(serde_json::from_str::<CommitCut>(r#"{"Complete":null}"#).is_err());
    assert!(serde_json::from_str::<Queue>(r#"{"Empty":null}"#).is_err());
    assert!(serde_json::from_str::<Rearm>(r#"{"Return":null}"#).is_err());
    assert!(serde_json::from_str::<Flush>(r#"{"Ok":null}"#).is_err());
    assert!(serde_json::from_str::<NativeDisposition>(r#"{"Deleted":null}"#).is_err());
    assert!(serde_json::from_str::<Responder>(r#"{"Open":null}"#).is_err());
    assert!(serde_json::from_str::<WriteScript>(
        r#"{"chunk_limit":2,"fail_after_accepted_bytes":null,"flush":{"Ok":null}}"#
    )
    .is_err());
    assert!(
        serde_json::from_str::<Completion>(r#"{"kind":"Return","mode":{"Live":null}}"#).is_err()
    );
    assert!(serde_json::from_str::<NativeAck>(
        r#"{"commit":{"Complete":null},"disposition":"Deleted"}"#
    )
    .is_err());
    assert!(serde_json::from_str::<Mode>(r#""Live""#).is_ok());
    assert!(serde_json::from_str::<CommitCut>(r#""Complete""#).is_ok());
}

#[test]
fn canonical_primitives_reject_uuid_aliases_nonintegers_and_bad_hex() {
    assert!(serde_json::from_str::<Id>(r#""00000000000000000000000000000001""#).is_err());
    assert!(serde_json::from_str::<Id>(r#""00000000-0000-0000-0000-00000000000A""#).is_err());
    for input in [
        r#"{"chunk_limit":2.0,"fail_after_accepted_bytes":null,"flush":"Ok"}"#,
        r#"{"chunk_limit":true,"fail_after_accepted_bytes":null,"flush":"Ok"}"#,
        r#"{"chunk_limit":-1,"fail_after_accepted_bytes":null,"flush":"Ok"}"#,
    ] {
        assert!(serde_json::from_str::<WriteScript>(input).is_err());
    }
    assert_eq!(unhex("00af").unwrap(), vec![0, 175]);
    for value in ["0", "AF", "0g"] {
        assert!(unhex(value).is_err());
    }
}
