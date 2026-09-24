use super::*;

#[test]
fn test_inject_vcard_avatar_hash() {
    let raw = "<presence from='a' to='b'><x xmlns='vcard-temp:x:update'><photo>forged</photo></x></presence>";
    let doc = roxmltree::Document::parse(raw).unwrap();
    let replaced = inject_vcard_avatar_hash(raw, doc.root_element(), Some("real"));
    assert!(replaced.contains("<photo>real</photo>"));
    assert!(!replaced.contains("forged"));
}

#[test]
fn explicit_empty_photo_is_not_overwritten() {
    let raw = "<presence><x xmlns='vcard-temp:x:update'><photo/></x></presence>";
    let doc = roxmltree::Document::parse(raw).unwrap();
    assert_eq!(
        inject_vcard_avatar_hash(raw, doc.root_element(), Some("stored")),
        raw
    );

    let ambiguous =
        "<presence><x xmlns='vcard-temp:x:update'><photo/><photo>forged</photo></x></presence>";
    let doc = roxmltree::Document::parse(ambiguous).unwrap();
    let replaced = inject_vcard_avatar_hash(ambiguous, doc.root_element(), Some("stored"));
    assert_eq!(replaced.matches("vcard-temp:x:update").count(), 1);
    assert!(replaced.contains("<photo>stored</photo>"));
    assert!(!replaced.contains("forged"));

    let duplicate = "<presence><x xmlns='vcard-temp:x:update'><photo/></x><x xmlns='vcard-temp:x:update'><photo>forged</photo></x></presence>";
    let doc = roxmltree::Document::parse(duplicate).unwrap();
    let replaced = inject_vcard_avatar_hash(duplicate, doc.root_element(), Some("stored"));
    assert_eq!(replaced.matches("vcard-temp:x:update").count(), 1);
    assert!(!replaced.contains("forged"));
}

#[test]
fn avatar_hash_is_text_and_prefixed_empty_presence_is_expanded_safely() {
    let raw = "<c:presence xmlns:c='jabber:client'/>";
    let document = roxmltree::Document::parse(raw).unwrap();
    let attack = "hash</photo><injected xmlns='urn:evil'/>";
    let replaced = inject_vcard_avatar_hash(raw, document.root_element(), Some(attack));
    let document = roxmltree::Document::parse(&replaced).unwrap();
    let root = document.root_element();
    assert_eq!(root.tag_name().namespace(), Some("jabber:client"));
    assert!(document
        .descendants()
        .all(|node| !node.is_element() || node.tag_name().name() != "injected"));
    let photo = document
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "photo")
        .unwrap();
    assert_eq!(photo.tag_name().namespace(), Some("vcard-temp:x:update"));
    assert_eq!(photo.text(), Some(attack));
}
