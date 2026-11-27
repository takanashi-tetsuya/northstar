use super::{exact_iq_request, EXACT_MESSAGE_DELIVERY_VERSION};

#[test]
fn exact_iq_admission_requires_the_address_and_rejects_response_checks() {
    let target = "bob@example.test/Phone";
    let envelope = serde_json::json!({
        "protocol_version": EXACT_MESSAGE_DELIVERY_VERSION,
        "exact_iq_check_only": true,
    });
    let get = roxmltree::Document::parse(
        "<iq type='get' from='alice@remote.test' to='bob@example.test/Phone'/>",
    )
    .unwrap();
    assert_eq!(
        exact_iq_request(&envelope, target, Some(&get)),
        Some((true, true))
    );
    assert_eq!(
        exact_iq_request(&envelope, "bob@example.test/Tablet", Some(&get)),
        None
    );
    let result = roxmltree::Document::parse(
        "<iq type='result' from='alice@remote.test' to='bob@example.test/Phone'/>",
    )
    .unwrap();
    assert_eq!(exact_iq_request(&envelope, target, Some(&result)), None);
}
