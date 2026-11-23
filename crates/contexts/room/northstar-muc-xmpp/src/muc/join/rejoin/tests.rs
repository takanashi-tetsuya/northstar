use super::*;

#[test]
fn malformed_explicit_rejoin_history_fails_preflight() {
    let document = roxmltree::Document::parse(
        "<presence><x xmlns='http://jabber.org/protocol/muc'><history maxstanzas='-1'/></x></presence>",
    ).unwrap();
    let root = document.root_element();
    assert!(matches!(
        preflight_rejoin_history(root, true, || northstar_time::DateTime::from_timestamp(
            0, 0
        )
        .unwrap()),
        Err(MalformedMucStanza)
    ));
    assert!(matches!(
        preflight_rejoin_history(root, false, || panic!("not a same-nick rejoin")),
        Ok(None)
    ));
}
