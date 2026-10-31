use super::*;

#[test]
fn muc_operation_jids_must_be_canonical_bare_room_keys() {
    assert!(validate_operation_payload(
        "admin.muc_destroy",
        1,
        &json!({
            "room_jid": "room@conference.example.test",
            "alternate_jid": "alternate@conference.example.test"
        }),
    )
    .is_ok());
    assert!(validate_operation_identity_keys(
        "admin.muc_destroy",
        Some("room@conference.example.test"),
        &json!({"room_jid":"room@conference.example.test"}),
    )
    .is_ok());
    assert!(validate_operation_identity_keys(
        "admin.muc_destroy",
        Some("Room@conference.example.test"),
        &json!({"room_jid":"room@conference.example.test"}),
    )
    .is_err());
    for payload in [
        json!({"room_jid":"Room@conference.example.test"}),
        json!({"room_jid":"room@BÜCHER.example"}),
        json!({"room_jid":"room@conference.example.test/Phone"}),
        json!({"room_jid":"conference.example.test"}),
        json!({
            "room_jid":"room@conference.example.test",
            "alternate_jid":"Alternate@conference.example.test"
        }),
        json!({
            "room_jid":"room@conference.example.test",
            "alternate_jid":"alternate@conference.example.test/Phone"
        }),
    ] {
        assert!(validate_operation_payload("admin.muc_destroy", 1, &payload).is_err());
    }
}
