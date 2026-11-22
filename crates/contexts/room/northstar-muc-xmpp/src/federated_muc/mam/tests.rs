use super::*;
use northstar_archive_core::MamMucRowMetadata;
use northstar_time::DateTime;
use roxmltree::{Document, Node};

const FIXTURES: &str =
    include_str!("../../../../northstar-room-core/src/stanza/mam_projection/fixtures.xml");
const ROOM: &str = "room@conference.local.test";
const RECIPIENT: &str = "viewer@remote.test/Phone";

fn fixture(fixtures: &Document<'_>, name: &str) -> (MamRoomAccess, FederatedMamStreamRow) {
    let defaults = fixtures.root_element();
    let case = defaults
        .children()
        .find(|node| node.attribute("name") == Some(name))
        .unwrap();
    let value = |name| {
        case.attribute(name)
            .or_else(|| defaults.attribute(name))
            .unwrap()
    };
    let access = MamRoomAccess::new(
        "room".to_owned(),
        vec![value("secret-byte").parse::<u8>().unwrap(); value("secret-length").parse().unwrap()],
        case.attribute("reveal") == Some("true"),
    );
    let row = FederatedMamStreamRow {
        id: Uuid::parse_str(value("id")).unwrap(),
        peer_jid: value("sender").to_owned(),
        stanza: case
            .first_element_child()
            .unwrap()
            .text()
            .unwrap()
            .to_owned(),
        created_at: DateTime::from_timestamp(1_767_225_600, 0).unwrap(),
        encrypted: case.attribute("encrypted") == Some("true"),
        muc: Some(MamMucRowMetadata {
            nick: value("nick").to_owned(),
            message_kind: value("kind").to_owned(),
            retracted: case.attribute("retracted") == Some("true"),
        }),
    };
    (access, row)
}

fn render(page: &FederatedMamStreamPage, flip: bool) -> anyhow::Result<Vec<String>> {
    render_federated_mam_stream(
        page,
        ROOM,
        RECIPIENT,
        "i",
        Some("q"),
        flip,
        Uuid::from_u128(9),
    )
}

#[test]
fn federated_mam_wraps_canonical_projection() {
    let fixtures = Document::parse(FIXTURES).unwrap();
    for name in [
        "discussion-hidden",
        "discussion-disclosed",
        "moderation-action",
    ] {
        let (access, row) = fixture(&fixtures, name);
        let uid = row.id().to_string();
        let page = FederatedMamStreamPage::new(access, vec![row], 1, 0, true);
        let replies = render(&page, false).unwrap();
        assert_eq!(replies, render(&page, false).unwrap());
        assert_eq!(replies.len(), 2);
        let message = Document::parse(&replies[0]).unwrap();
        let outer = message.root_element();
        assert_eq!(outer.attribute("to"), Some(RECIPIENT));
        assert_eq!(outer.attribute("from"), Some(ROOM));
        let result = outer.first_element_child().unwrap();
        assert!(result.has_tag_name((XMLNS_MAM, "result")));
        assert_eq!(result.attribute("id"), Some(uid.as_str()));
        assert_eq!(result.attribute("queryid"), Some("q"));
        let forwarded = result.first_element_child().unwrap();
        assert!(forwarded.has_tag_name(("urn:xmpp:forward:0", "forwarded")));
        let delay = forwarded.first_element_child().unwrap();
        assert!(delay.has_tag_name(("urn:xmpp:delay", "delay")));
        assert_eq!(delay.attribute("stamp"), Some("2026-01-01T00:00:00.000Z"));
        let inner = forwarded
            .children()
            .find(|node| node.has_tag_name(("jabber:client", "message")))
            .unwrap();
        let sid = inner
            .children()
            .find(|node| node.has_tag_name(("urn:xmpp:sid:0", "stanza-id")))
            .unwrap();
        assert_eq!(sid.attribute("id"), Some(uid.as_str()));
        let case = fixtures
            .root_element()
            .children()
            .find(|node| node.attribute("name") == Some(name))
            .unwrap();
        let expected = case
            .children()
            .find(|node| node.has_tag_name("expected"))
            .unwrap()
            .first_element_child()
            .unwrap();
        assert_eq!(&replies[0][inner.range()], &FIXTURES[expected.range()]);
        let terminal = Document::parse(&replies[1]).unwrap();
        let iq = terminal.root_element();
        assert_eq!(iq.attribute("id"), Some("i"));
        assert_eq!(iq.attribute("to"), Some(RECIPIENT));
        let fin = iq.first_element_child().unwrap();
        assert!(fin.has_tag_name((XMLNS_MAM, "fin")));
        assert_eq!(fin.attribute("stable"), Some("true"));
        assert_eq!(fin.attribute("complete"), Some("true"));
    }
}

#[test]
fn federated_mam_flip_preserves_rsm_and_fin() {
    let fixtures = Document::parse(FIXTURES).unwrap();
    let (access, first) = fixture(&fixtures, "discussion-hidden");
    let (_, last) = fixture(&fixtures, "author-action");
    let first_id = first.id().to_string();
    let last_id = last.id().to_string();
    let page = FederatedMamStreamPage::new(access.clone(), vec![first, last], 12, 5, false);
    let forward = render(&page, false).unwrap();
    let flipped = render(&page, true).unwrap();
    for (payload, id) in forward[..2]
        .iter()
        .zip([&first_id, &last_id])
        .chain(flipped[..2].iter().zip([&last_id, &first_id]))
    {
        let result = Document::parse(payload).unwrap();
        assert_eq!(
            result
                .root_element()
                .first_element_child()
                .unwrap()
                .attribute("id"),
            Some(id.as_str())
        );
    }
    assert_eq!(forward[2], flipped[2]);
    let document = Document::parse(&flipped[2]).unwrap();
    let fin = document.root_element().first_element_child().unwrap();
    assert_eq!(fin.attribute("complete"), Some("false"));
    let rsm = fin.first_element_child().unwrap();
    assert!(rsm.has_tag_name((XMLNS_RSM, "set")));
    let fields: Vec<_> = rsm.children().filter(Node::is_element).collect();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0].attribute("index"), Some("5"));
    for (field, name, text) in [
        (fields[0], "first", first_id.as_str()),
        (fields[1], "last", last_id.as_str()),
        (fields[2], "count", "12"),
    ] {
        assert!(field.has_tag_name((XMLNS_RSM, name)));
        assert_eq!(field.text(), Some(text));
    }
    let empty = render(
        &FederatedMamStreamPage::new(access, vec![], 0, 0, true),
        true,
    )
    .unwrap();
    assert_eq!(empty.len(), 1);
    let document = Document::parse(&empty[0]).unwrap();
    let fin = document.root_element().first_element_child().unwrap();
    assert!(fin.has_tag_name((XMLNS_MAM, "fin")));
    let rsm = fin.first_element_child().unwrap();
    let count = rsm.first_element_child().unwrap();
    assert!(count.has_tag_name((XMLNS_RSM, "count")));
    assert_eq!(count.text(), Some("0"));
    assert_eq!(rsm.children().filter(Node::is_element).count(), 1);
}

#[test]
fn federated_mam_bad_row_returns_no_stream() {
    let fixtures = Document::parse(FIXTURES).unwrap();
    let (access, good) = fixture(&fixtures, "discussion-hidden");
    let (_, mut bad) = fixture(&fixtures, "malformed");
    bad.id = Uuid::from_u128(2);
    let page = FederatedMamStreamPage::new(access, vec![good, bad], 2, 0, true);
    let error = render(&page, false).unwrap_err();
    assert_eq!(
        error.downcast_ref::<MucMamProjectionError>(),
        Some(&MucMamProjectionError::Xml)
    );
}
