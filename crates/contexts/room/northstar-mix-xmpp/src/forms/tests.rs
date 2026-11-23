use super::*;

#[test]
fn preference_patch_leaves_omissions_to_the_command() {
    let fields = [
        ("FORM_TYPE".to_owned(), vec![ANON_NS.to_owned()]),
        ("Presence".to_owned(), vec!["not share".to_owned()]),
    ]
    .into();
    assert_eq!(
        parse_preference_patch(&fields).unwrap(),
        PreferencePatch {
            share_presence: Some(false),
            ..PreferencePatch::default()
        }
    );
    let joined = parse_preference_submission(&fields, None).unwrap();
    assert_eq!(
        preference_result_form(&joined),
        concat!(
            "<x xmlns='jabber:x:data' type='result'>",
            "<field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mix:anon:0</value></field>",
            "<field var='JID Visibility'><value>default</value></field>",
            "<field var='Private Messages'><value>allow</value></field>",
            "<field var='vCard'><value>block</value></field>",
            "<field var='Presence'><value>not share</value></field></x>",
        )
    );
}

#[test]
fn preference_patch_preserves_presence_error_precedence() {
    let mut fields = BTreeMap::from([
        ("FORM_TYPE".to_owned(), vec![ANON_NS.to_owned()]),
        ("Presence".to_owned(), vec!["invalid".to_owned()]),
        ("JID Visibility".to_owned(), vec!["invalid".to_owned()]),
    ]);
    assert_eq!(
        parse_preference_patch(&fields).unwrap_err().to_string(),
        "invalid MIX presence preference"
    );
    fields.remove("Presence");
    assert_eq!(
        parse_preference_patch(&fields).unwrap_err().to_string(),
        "invalid MIX participant preference"
    );
}
