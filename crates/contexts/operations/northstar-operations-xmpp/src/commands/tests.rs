use super::*;
use roxmltree::Document;

#[test]
fn uses_the_registered_xep_0133_nodes() {
    assert!(is_command(ONLINE_COUNT));
    assert!(is_command(ONLINE_LIST));
    assert!(is_command(REGISTERED_COUNT));
    assert!(is_command(REGISTERED_LIST));
    assert!(is_command(ADD_USER));
    assert!(is_command(EDIT_ADMIN));
    assert!(!is_command(
        "http://jabber.org/protocol/admin#get-user-password"
    ));
    assert!(!is_command(
        "http://jabber.org/protocol/admin#get-online-users"
    ));
}

#[test]
fn command_bearers_are_opaque_fixed_size_values() {
    assert!(valid_command_bearer(&"A1".repeat(32)));
    assert!(!valid_command_bearer(&"A1".repeat(31)));
    assert!(!valid_command_bearer(&format!("{}-", "A".repeat(63))));
}

#[test]
fn command_target_digest_is_field_order_independent_but_value_order_sensitive() {
    let first = Submission {
        fields: HashMap::from([
            (
                "accountjids".to_owned(),
                vec!["a@example.test".to_owned(), "b@example.test".to_owned()],
            ),
            ("confirm".to_owned(), vec!["1".to_owned()]),
        ]),
    };
    let reordered_fields = Submission {
        fields: HashMap::from([
            ("confirm".to_owned(), vec!["1".to_owned()]),
            (
                "accountjids".to_owned(),
                vec!["a@example.test".to_owned(), "b@example.test".to_owned()],
            ),
        ]),
    };
    let reordered_values = Submission {
        fields: HashMap::from([
            ("confirm".to_owned(), vec!["1".to_owned()]),
            (
                "accountjids".to_owned(),
                vec!["b@example.test".to_owned(), "a@example.test".to_owned()],
            ),
        ]),
    };
    assert_eq!(
        command_target_digest(DELETE_USER, &first),
        command_target_digest(DELETE_USER, &reordered_fields)
    );
    assert_ne!(
        command_target_digest(DELETE_USER, &first),
        command_target_digest(DELETE_USER, &reordered_values)
    );
    assert_ne!(
        command_target_digest(DELETE_USER, &first),
        command_target_digest(DISABLE_USER, &first)
    );
}

#[test]
fn parses_a_bounded_list_submission_and_rejects_duplicate_fields() {
    let good_xml = format!(
        "<command xmlns='{COMMANDS_NS}'><x xmlns='{DATA_NS}' type='submit'><field var='FORM_TYPE'><value>{ADMIN_FORM_TYPE}</value></field><field var='max_items'><value>150</value></field><field var='start'><value>25</value></field></x></command>"
    );
    let good = Document::parse(&good_xml).unwrap();
    let parsed = parse_submission(good.root_element(), REGISTERED_LIST).unwrap();
    assert_eq!(parsed.one("max_items"), Ok("150"));
    assert_eq!(parsed.one("start"), Ok("25"));

    let duplicate_xml = format!(
        "<command xmlns='{COMMANDS_NS}'><x xmlns='{DATA_NS}' type='submit'><field var='FORM_TYPE'><value>{ADMIN_FORM_TYPE}</value></field><field var='max_items'><value>25</value></field><field var='max_items'><value>50</value></field><field var='start'><value>0</value></field></x></command>"
    );
    let duplicate = Document::parse(&duplicate_xml).unwrap();
    assert_eq!(
        parse_submission(duplicate.root_element(), REGISTERED_LIST),
        Err(())
    );
}

#[test]
fn rejects_wrong_form_namespaces_unknown_fields_and_oversized_lists() {
    for xml in [
        format!(
            "<command xmlns='{COMMANDS_NS}'><x xmlns='urn:wrong' type='submit'/></command>"
        ),
        format!(
            "<command xmlns='{COMMANDS_NS}'><x xmlns='{DATA_NS}' type='submit'><field var='FORM_TYPE'><value>{ADMIN_FORM_TYPE}</value></field><field var='unknown'><value>1</value></field><field var='max_items'><value>25</value></field><field var='start'><value>0</value></field></x></command>"
        ),
        format!(
            "<command xmlns='{COMMANDS_NS}'><x xmlns='{DATA_NS}' type='submit'><field var='FORM_TYPE'><value>{ADMIN_FORM_TYPE}</value></field><field var='max_items'><value>201</value></field><field var='start'><value>0</value></field></x></command>"
        ),
    ] {
        let document = Document::parse(&xml).unwrap();
        let parsed = parse_submission(document.root_element(), REGISTERED_LIST);
        if let Ok(parsed) = parsed {
            assert!(
                parsed
                    .one("max_items")
                    .ok()
                    .and_then(|value| value.parse::<usize>().ok())
                    .is_none_or(|value| !(1..=MAX_LIST_ITEMS).contains(&value))
            );
        }
    }
}

#[test]
fn command_errors_use_xep_0050_error_types_and_escape_input() {
    let error = command_error(
        "id'1",
        "example.test",
        "node&x",
        "bad-request",
        "modify",
        Some("bad-sessionid"),
    );
    assert!(error.contains("type='modify'"));
    assert!(error.contains("<bad-sessionid xmlns='http://jabber.org/protocol/commands'/"));
    assert!(error.contains("id='id&apos;1'"));
    assert!(error.contains("node='node&amp;x'"));
    Document::parse(&error).unwrap();
}

#[test]
fn command_output_builder_contains_hostile_runtime_values() {
    let hostile = "x'&<injected xmlns='urn:evil'/>\r\n🙂";
    let result = command_result(hostile, hostile, hostile, hostile, hostile, "");
    let document = Document::parse(&result).unwrap();
    let iq = document.root_element();
    let command = iq.children().find(|child| child.is_element()).unwrap();
    assert_eq!(iq.attribute("id"), Some(hostile));
    assert_eq!(iq.attribute("from"), Some(hostile));
    assert_eq!(command.attribute("node"), Some(hostile));
    assert_eq!(command.attribute("sessionid"), Some(hostile));
    assert_eq!(command.attribute("status"), Some(hostile));
    assert_eq!(
        document
            .descendants()
            .filter(|node| node.is_element() && node.tag_name().name() == "injected")
            .count(),
        0
    );

    let field = field(
        "runtime",
        "text-single",
        hostile,
        true,
        &[hostile.to_owned()],
    );
    let field_xml = field.finish();
    let document = Document::parse(&field_xml).unwrap();
    let field = document.root_element();
    assert_eq!(field.attribute("label"), Some(hostile));
    assert_eq!(
        field
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "value")
            .and_then(|node| node.text()),
        Some(hostile)
    );
}

#[test]
fn malformed_cached_command_payload_fails_closed_without_panicking() {
    let result = command_result(
        "request-id",
        "example.test",
        REGISTERED_LIST,
        "session-id",
        "completed",
        "<x><broken></x>",
    );
    let document = Document::parse(&result).unwrap();
    let iq = document.root_element();
    assert_eq!(iq.attribute("type"), Some("error"));
    assert!(document.descendants().any(|node| {
        node.is_element()
            && node.tag_name().name() == "internal-server-error"
            && node.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
    }));
}
