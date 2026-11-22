use super::*;

fn fixture() -> Document<'static> {
    Document::parse(include_str!("fixtures.xml")).unwrap()
}

fn project(case: Node<'_, '_>) -> Result<String, MucMamProjectionError> {
    let defaults = case.parent().unwrap();
    let value = |name| {
        case.attribute(name)
            .or_else(|| defaults.attribute(name))
            .unwrap()
    };
    let secret =
        vec![value("secret-byte").parse::<u8>().unwrap(); value("secret-length").parse().unwrap()];
    project_muc_mam_message(
        value("room"),
        &secret,
        case.attribute("reveal") == Some("true"),
        MucMamStoredRow {
            id: Uuid::parse_str(value("id")).unwrap(),
            stanza: case
                .children()
                .find(|node| node.has_tag_name("stored"))
                .unwrap()
                .text()
                .unwrap(),
            sender_jid: value("sender"),
            nick: value("nick"),
            message_kind: value("kind"),
            encrypted: case.attribute("encrypted") == Some("true"),
            retracted: case.attribute("retracted") == Some("true"),
        },
    )
}

fn assert_tree(actual: Node<'_, '_>, expected: Node<'_, '_>) {
    assert_eq!(
        actual.tag_name().namespace(),
        expected.tag_name().namespace()
    );
    assert_eq!(actual.tag_name().name(), expected.tag_name().name());
    assert_eq!(actual.attributes().len(), expected.attributes().len());
    for attribute in expected.attributes() {
        let value = if let Some(namespace) = attribute.namespace() {
            actual.attribute((namespace, attribute.name()))
        } else {
            actual.attribute(attribute.name())
        };
        assert_eq!(value, Some(attribute.value()), "{}", attribute.name());
    }
    let significant = |child: &Node<'_, '_>| {
        child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty())
    };
    let actual_children: Vec<_> = actual.children().filter(significant).collect();
    let expected_children: Vec<_> = expected.children().filter(significant).collect();
    assert_eq!(actual_children.len(), expected_children.len());
    for (actual, expected) in actual_children.into_iter().zip(expected_children) {
        if expected.is_element() {
            assert!(actual.is_element());
            assert_tree(actual, expected);
        } else {
            assert!(actual.is_text());
            assert_eq!(actual.text(), expected.text());
        }
    }
}

#[test]
fn canonical_muc_mam_projection_matches_fixtures() {
    let fixtures = fixture();
    for case in fixtures.root_element().children().filter(Node::is_element) {
        if case.attribute("error").is_some() {
            continue;
        }
        let output = project(case)
            .unwrap_or_else(|error| panic!("{}: {error}", case.attribute("name").unwrap()));
        let actual = Document::parse(&output).unwrap();
        let expected = case
            .children()
            .find(|node| node.has_tag_name("expected"))
            .unwrap();
        assert_tree(
            actual.root_element(),
            expected.first_element_child().unwrap(),
        );
    }
}

#[test]
fn stored_identity_claims_never_survive_projection() {
    let fixtures = fixture();
    let case = fixtures
        .root_element()
        .children()
        .find(|node| node.attribute("name") == Some("poisoned"))
        .unwrap();
    let output = project(case).unwrap();
    assert!(!output.contains("forged"));
    let document = Document::parse(&output).unwrap();
    let root = document.root_element();
    assert_eq!(
        root.attribute("from"),
        Some("room@conference.local.test/Alice")
    );
    assert_eq!(root.attribute("id"), Some(""));
    assert!(root.attributes().all(|attr| attr.name() != "to"));
    assert!(root
        .descendants()
        .filter(Node::is_element)
        .all(|node| !matches!(
            node.tag_name().namespace(),
            Some(MUC_USER | "urn:northstar:muc:sender:0" | RETRACT | MODERATE)
        )));
    for claim in [(SID, "stanza-id"), (OCCUPANT, "occupant-id")] {
        assert_eq!(
            root.children()
                .filter(|node| node.has_tag_name(claim))
                .count(),
            1
        );
    }
}

#[test]
fn muc_mam_projection_rejects_corrupt_rows() {
    let fixtures = fixture();
    for case in fixtures.root_element().children().filter(Node::is_element) {
        if let Some(category) = case.attribute("error") {
            let error = project(case).unwrap_err();
            assert_eq!(
                format!("{error:?}"),
                category,
                "{}",
                case.attribute("name").unwrap()
            );
        }
    }
}
