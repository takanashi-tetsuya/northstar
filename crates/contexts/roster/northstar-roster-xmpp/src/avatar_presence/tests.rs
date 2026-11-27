use northstar_xml_builder::rewrite::project_presence_avatar;

#[test]
fn replay_renders_the_current_hash_and_omits_it_on_read_error() {
    let cached = "<presence id='old'><show>away</show><x xmlns='vcard-temp:x:update'><photo>old-hash</photo></x></presence>";
    let fresh = project_presence_avatar(cached, Some(Some("new-hash"))).unwrap();
    assert!(fresh.contains("<photo>new-hash</photo>"));
    assert!(!fresh.contains("old-hash"));
    let failed = project_presence_avatar(cached, None).unwrap();
    assert_eq!(failed, "<presence id='old'><show>away</show></presence>");
}

#[test]
fn explicit_opt_out_survives_both_authoritative_hashes_and_read_errors() {
    let opted_out = "<presence><x xmlns='vcard-temp:x:update'><photo/></x></presence>";
    for hash in [Some(Some("new-hash")), Some(None), None] {
        assert_eq!(
            project_presence_avatar(opted_out, hash).as_deref(),
            Some(opted_out)
        );
    }
}

#[test]
fn a_comment_cannot_hide_a_stale_hash_after_empty_text() {
    let cached = "<presence><x xmlns='vcard-temp:x:update'><photo> <!-- split -->old-hash</photo></x></presence>";
    // The opt-out check must not accept this photo, and the fragment
    // validator rejects comments, so the cache is not eligible for replay.
    assert_eq!(project_presence_avatar(cached, None), None);
    assert_eq!(
        project_presence_avatar(cached, Some(Some("new-hash"))),
        None
    );
}
