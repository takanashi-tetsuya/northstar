use super::*;
use northstar_archive_core::MamMucRowMetadata;
use roxmltree::Document;

const FIXTURES: &str =
    include_str!("../../../room/northstar-room-core/src/stanza/mam_projection/fixtures.xml");

#[test]
fn local_room_mam_uses_authorized_projection() {
    let fixtures = Document::parse(FIXTURES).unwrap();
    let defaults = fixtures.root_element();
    let room_jid = defaults.attribute("room").unwrap();
    let secret = vec![
        defaults
            .attribute("secret-byte")
            .unwrap()
            .parse::<u8>()
            .unwrap();
        32
    ];
    for name in ["discussion-hidden", "discussion-disclosed"] {
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
            secret.clone(),
            case.attribute("reveal") == Some("true"),
        );
        let row = ArchiveRow {
            id: Uuid::parse_str(value("id")).unwrap(),
            peer_jid: value("sender").to_owned(),
            stanza: case
                .first_element_child()
                .unwrap()
                .text()
                .unwrap()
                .to_owned(),
            encrypted: false,
            stanza_id: None,
            created_at: Utc::now(),
            muc: Some(MamMucRowMetadata {
                nick: value("nick").to_owned(),
                message_kind: value("kind").to_owned(),
                retracted: false,
            }),
        };
        let projection = || MamPageProjection {
            id: "i",
            recipient: "viewer@local.test/Phone",
            archive_from: Some(room_jid),
            personal_archive_by: "viewer@local.test",
            room: Some(&access),
            query_id: Some("q"),
            flip_page: false,
        };
        let mut page = ArchivePage {
            rows: vec![row.clone()],
            total: 1,
            first_index: 0,
            complete: true,
        };
        let MamReply::SendMany(replies) = render_mam_page(&page, projection()).unwrap() else {
            panic!("expected one result and fin");
        };
        assert_eq!(replies.len(), 2);
        let result_doc = Document::parse(&replies[0]).unwrap();
        let result = result_doc.root_element().first_element_child().unwrap();
        assert_eq!(result.attribute("id"), Some(value("id")));
        let inner = result
            .first_element_child()
            .unwrap()
            .children()
            .find(|node| node.has_tag_name(("jabber:client", "message")))
            .unwrap();
        let expected = case
            .children()
            .find(|node| node.has_tag_name("expected"))
            .unwrap()
            .first_element_child()
            .unwrap();
        assert_eq!(&replies[0][inner.range()], &FIXTURES[expected.range()]);

        let mut corrupt = row;
        corrupt.id = Uuid::new_v4();
        corrupt.stanza = "<message><body>".to_owned();
        page.rows.push(corrupt);
        page.total = 2;
        let MamReply::Send(error) = render_mam_page(&page, projection()).unwrap() else {
            panic!("a good row followed by a bad one must not deliver a prefix or fin");
        };
        let error = Document::parse(&error).unwrap();
        let iq = error.root_element();
        assert_eq!(iq.attribute("id"), Some("i"));
        assert_eq!(iq.attribute("from"), Some(room_jid));
        assert_eq!(iq.attribute("type"), Some("error"));
        let condition = iq.first_element_child().unwrap();
        assert_eq!(condition.attribute("type"), Some("wait"));
        assert!(condition.first_element_child().unwrap().has_tag_name((
            "urn:ietf:params:xml:ns:xmpp-stanzas",
            "internal-server-error"
        )));
    }
}
