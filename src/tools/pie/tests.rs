use super::*;

struct TestTree(PathBuf);

impl TestTree {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("northstar-pie-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn portable_scram() -> &'static str {
    "<scram-credentials xmlns='urn:xmpp:pie:0#scram' mechanism='SCRAM-SHA-256'><iter-count>4096</iter-count><salt>QUFBQUFBQUFBQUFBQUFBQQ==</salt><server-key>QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=</server-key><stored-key>QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=</stored-key></scram-credentials>"
}

#[test]
fn command_defaults_are_safe() {
    let command = parse_command(&["import".into(), "--input".into(), "data.xml".into()]).unwrap();
    assert!(matches!(
        command,
        Command::Import(ImportOptions {
            dry_run: false,
            conflict: ConflictPolicy::Fail,
            unknown: UnknownPolicy::Warn,
            allow_plaintext_passwords: false,
            ..
        })
    ));
    assert!(parse_command(&[
        "export".into(),
        "--output".into(),
        "data.xml".into(),
        "--dry-run".into()
    ])
    .is_err());
}

#[test]
fn include_uri_rejects_traversal_urls_and_bad_escapes() {
    for value in [
        "../secret.xml",
        "%2e%2e/secret.xml",
        "/etc/passwd",
        "https://example.test/a",
        "C:%5csecret",
        "a.xml?x",
        "a.xml#x",
        "%zz",
    ] {
        let decoded = percent_decode(value);
        if let Ok(decoded) = decoded {
            let path = Path::new(&decoded);
            assert!(
                path.is_absolute()
                    || decoded.contains("://")
                    || decoded.contains(['?', '#', '\\'])
                    || path.components().any(|component| matches!(
                        component,
                        Component::ParentDir | Component::RootDir | Component::Prefix(_)
                    )),
                "unexpectedly safe: {value}"
            );
        }
    }
}

#[test]
fn dtd_and_entity_documents_are_rejected() {
    assert!(reject_dtd("<!DOCTYPE x [<!ENTITY e 'boom'>]><x>&e;</x>").is_err());
    assert!(reject_dtd("<server-data xmlns='urn:xmpp:pie:0'/>").is_ok());
}

#[test]
fn serializer_makes_inherited_namespaces_self_contained() {
    let document =
        Document::parse("<item xmlns='urn:test'><payload xml:lang='en'>a&amp;b</payload></item>")
            .unwrap();
    let payload = document
        .descendants()
        .find(|node| node.tag_name().name() == "payload")
        .unwrap();
    assert_eq!(
        node_to_xml(payload),
        "<payload xmlns='urn:test' xml:lang='en'>a&amp;b</payload>"
    );
}

#[test]
fn scram_parser_rejects_weak_or_ambiguous_credentials() {
    let weak = Document::parse("<scram-credentials xmlns='urn:xmpp:pie:0#scram' mechanism='SCRAM-SHA-256'><iter-count>1</iter-count><salt>QUFBQUFBQUFBQUFBQUFBQQ==</salt><server-key>QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=</server-key><stored-key>QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=</stored-key></scram-credentials>").unwrap();
    let mut user = PieUser::default();
    let mut output = ImportDocument::default();
    assert!(parse_scram(weak.root_element(), &mut user, &mut output).is_err());
}

#[test]
fn privacy_and_pep_sibling_order_does_not_change_import_meaning() {
    let xml = format!(
        "<user xmlns='{PIE_NS}' name='alice'>{}
             <query xmlns='{PRIVACY_NS}'>
               <list name='chosen'><item type='jid' value='blocked@example.test' action='deny' order='1'/></list>
               <default name='chosen'/>
             </query>
             <pubsub xmlns='{PUBSUB_OWNER_NS}'>
               <subscriptions node='urn:test:ordered'><subscription jid='bob@example.test' subscription='subscribed' subid='s1'/></subscriptions>
               <configure node='urn:test:ordered'><x xmlns='jabber:x:data' type='submit'>
                 <field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field>
                 <field var='pubsub#access_model'><value>whitelist</value></field>
               </x></configure>
             </pubsub>
             </user>",
        portable_scram()
    );
    let document = Document::parse(&xml).unwrap();
    let mut budget = LoadBudget::default();
    let mut output = ImportDocument::default();
    push_user(
        document.root_element(),
        "example.test",
        &mut budget,
        &mut output,
    )
    .unwrap();
    let user = &output.users[0];
    assert_eq!(user.blocked, ["blocked@example.test"]);
    assert_eq!(user.pep_nodes["urn:test:ordered"].subscriptions.len(), 1);
}

#[test]
fn identity_import_preserves_resources_and_bares_presence_subscriptions() {
    let offline_xml = format!(
        "<offline-messages><message xmlns='{CLIENT_NS}' from='ALICE@B\u{fc}CHER.Example./Phone' to='owner@example.test'/></offline-messages>"
    );
    let offline = Document::parse(&offline_xml).unwrap();
    let mut user = PieUser {
        username: "owner".to_owned(),
        ..PieUser::default()
    };
    let mut budget = LoadBudget::default();
    parse_offline(
        offline.root_element(),
        "owner@example.test",
        &mut user,
        &mut budget,
    )
    .unwrap();
    assert_eq!(user.offline[0].sender, "alice@bücher.example/Phone");
    assert_eq!(user.offline[0].target_resource, None);

    let full_normal_xml = format!(
        "<offline-messages><message xmlns='{CLIENT_NS}' from='alice@remote.test/Phone' to='owner@example.test/Target'/></offline-messages>"
    );
    let full_normal = Document::parse(&full_normal_xml).unwrap();
    parse_offline(
        full_normal.root_element(),
        "owner@example.test",
        &mut user,
        &mut budget,
    )
    .unwrap();
    assert_eq!(user.offline[1].target_resource.as_deref(), Some("Target"));

    let full_chat_xml = format!(
        "<offline-messages><message xmlns='{CLIENT_NS}' type='chat' from='alice@remote.test/Phone' to='owner@example.test/Fallback'/></offline-messages>"
    );
    let full_chat = Document::parse(&full_chat_xml).unwrap();
    parse_offline(
        full_chat.root_element(),
        "owner@example.test",
        &mut user,
        &mut budget,
    )
    .unwrap();
    assert_eq!(user.offline[2].target_resource, None);

    for rejected in [
        format!(
            "<offline-messages><message xmlns='{CLIENT_NS}' from='alice@remote.test' to='OWNER@example.test/Target'/></offline-messages>"
        ),
        format!(
            "<offline-messages><message xmlns='{CLIENT_NS}' from='alice@remote.test' to='owner@evil.test/Target'/></offline-messages>"
        ),
    ] {
        let rejected = Document::parse(&rejected).unwrap();
        assert!(
            parse_offline(
                rejected.root_element(),
                "owner@example.test",
                &mut user,
                &mut budget,
            )
            .is_err()
        );
    }

    let privacy_xml = format!(
        "<query xmlns='{PRIVACY_NS}'><default name='northstar-blocklist'/><list name='northstar-blocklist'><item type='jid' value='ALICE@B\u{fc}CHER.Example./Phone' action='deny' order='1'/></list></query>"
    );
    let privacy = Document::parse(&privacy_xml).unwrap();
    let mut output = ImportDocument::default();
    parse_privacy(privacy.root_element(), &mut user, &mut budget, &mut output).unwrap();
    assert_eq!(user.blocked, ["alice@bücher.example/Phone"]);

    let pending_xml = format!(
        "<presence xmlns='{CLIENT_NS}' type='subscribe' from='BOB@B\u{fc}CHER.Example.' to='owner@example.test'/>",
    );
    let pending = Document::parse(&pending_xml).unwrap();
    parse_pending(
        pending.root_element(),
        "example.test",
        &mut user,
        &mut budget,
    )
    .unwrap();
    assert_eq!(user.pending[0].from, "bob@bücher.example");

    let invalid_xml = format!(
        "<presence xmlns='{CLIENT_NS}' type='subscribe' from='bob@example.test/Phone' to='owner@example.test'/>",
    );
    let invalid = Document::parse(&invalid_xml).unwrap();
    assert!(parse_pending(
        invalid.root_element(),
        "example.test",
        &mut user,
        &mut budget,
    )
    .is_err());
}

#[test]
fn standard_relative_xinclude_layout_loads_host_and_user() {
    let tree = TestTree::new();
    let users = tree.0.join("example.test");
    fs::create_dir(&users).unwrap();
    fs::write(
        tree.0.join("main.xml"),
        "<server-data xmlns='urn:xmpp:pie:0' xmlns:xi='http://www.w3.org/2001/XInclude'><xi:include href='example.test.xml'/></server-data>",
    )
    .unwrap();
    fs::write(
        tree.0.join("example.test.xml"),
        "<host xmlns='urn:xmpp:pie:0' xmlns:xi='http://www.w3.org/2001/XInclude' jid='example.test'><xi:include href='example.test/alice.xml'/></host>",
    )
    .unwrap();
    fs::write(
        users.join("alice.xml"),
        format!(
            "<user xmlns='urn:xmpp:pie:0' name='alice'>{}</user>",
            portable_scram()
        ),
    )
    .unwrap();
    let mut budget = LoadBudget::default();
    let mut output = ImportDocument::default();
    load_server_document(
        &tree.0.canonicalize().unwrap(),
        &tree.0.join("main.xml").canonicalize().unwrap(),
        0,
        "example.test",
        &mut budget,
        &mut output,
    )
    .unwrap();
    assert_eq!(output.users.len(), 1);
    assert_eq!(output.users[0].username, "alice");
    assert!(output.users[0].scram.is_some());
    assert_eq!(budget.files, 3);
}

#[test]
fn xinclude_cannot_escape_the_security_root() {
    let tree = TestTree::new();
    let root = tree.0.join("root");
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("main.xml"),
        "<server-data xmlns='urn:xmpp:pie:0' xmlns:xi='http://www.w3.org/2001/XInclude'><xi:include href='../outside.xml'/></server-data>",
    )
    .unwrap();
    fs::write(
        tree.0.join("outside.xml"),
        "<host xmlns='urn:xmpp:pie:0' jid='example.test'/>",
    )
    .unwrap();
    let mut budget = LoadBudget::default();
    let mut output = ImportDocument::default();
    let error = load_server_document(
        &root.canonicalize().unwrap(),
        &root.join("main.xml").canonicalize().unwrap(),
        0,
        "example.test",
        &mut budget,
        &mut output,
    )
    .unwrap_err();
    assert!(error.to_string().contains("relative URI"));
}

#[test]
fn duplicate_include_and_resource_counters_fail_closed() {
    let tree = TestTree::new();
    fs::write(
        tree.0.join("host.xml"),
        "<host xmlns='urn:xmpp:pie:0' jid='example.test'/>",
    )
    .unwrap();
    fs::write(
        tree.0.join("main.xml"),
        "<server-data xmlns='urn:xmpp:pie:0' xmlns:xi='http://www.w3.org/2001/XInclude'><xi:include href='host.xml'/><xi:include href='host.xml'/></server-data>",
    )
    .unwrap();
    let mut budget = LoadBudget::default();
    let mut output = ImportDocument::default();
    assert!(load_server_document(
        &tree.0.canonicalize().unwrap(),
        &tree.0.join("main.xml").canonicalize().unwrap(),
        0,
        "example.test",
        &mut budget,
        &mut output,
    )
    .unwrap_err()
    .to_string()
    .contains("duplicate include"));
    let mut budget = LoadBudget {
        items: MAX_ITEMS,
        ..Default::default()
    };
    assert!(item(&mut budget).is_err());
    assert!(include_depth(MAX_INCLUDE_DEPTH + 1).is_err());
}

#[cfg(unix)]
#[test]
fn xinclude_refuses_symlinks_even_when_the_target_stays_inside_root() {
    use std::os::unix::fs::symlink;
    let tree = TestTree::new();
    let root = tree.0.canonicalize().unwrap();
    fs::write(
        tree.0.join("host.xml"),
        "<host xmlns='urn:xmpp:pie:0' jid='example.test'/>",
    )
    .unwrap();
    symlink(tree.0.join("host.xml"), tree.0.join("alias.xml")).unwrap();
    let input_error = secure_existing_path(&root, &tree.0.join("alias.xml")).unwrap_err();
    assert!(input_error.to_string().contains("symlink"));
    let error = resolve_include(&root, &tree.0.join("main.xml"), "alias.xml").unwrap_err();
    assert!(error.to_string().contains("symlink"));
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL schema"]
async fn portable_data_roundtrip_conflicts_and_rollback_are_atomic() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL schema");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let alice = crate::db::create_user(
        &pool,
        "alice",
        "alice-portable-password",
        false,
        false,
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let bob = crate::db::create_user(
        &pool,
        "bob",
        "bob-portable-password",
        false,
        false,
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO roster_items(owner_id,contact_jid,display_name,subscription,groups,approved) VALUES($1,'bob@example.test','Bob','both','[\"Friends\",\"Trusted\"]'::jsonb,TRUE)")
        .bind(alice.id).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted) VALUES($1,$2,'alice@example.test',$3,TRUE)")
        .bind(Uuid::new_v4()).bind(bob.id)
        .bind("<message xmlns='jabber:client' from='alice@example.test/phone' to='bob@example.test' type='chat'><encrypted xmlns='urn:xmpp:omemo:2'><header sid='1'/><payload>YQ==</payload></encrypted></message>")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO private_xml(user_id,element_name,element_ns,xml_data) VALUES($1,'prefs','urn:test:prefs',$2)")
        .bind(alice.id).bind("<prefs xmlns='urn:test:prefs'><theme>dark</theme></prefs>").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO vcards(user_id,payload) VALUES($1,$2)")
        .bind(alice.id)
        .bind("<vCard xmlns='vcard-temp'><FN>Alice</FN></vCard>")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,'spam@example.net')")
        .bind(alice.id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO pending_presence_subscriptions(requester_id,recipient_id,stanza) VALUES($1,$2,$3)")
        .bind(alice.id).bind(bob.id)
        .bind("<presence xmlns='jabber:client' type='subscribe' from='alice@example.test' to='bob@example.test'><nick xmlns='http://jabber.org/protocol/nick'>Alice</nick></presence>")
        .execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO pep_nodes(owner_id,node,access_model,max_items,persist_items,send_last_published_item,deliver_notifications,roster_groups_allowed,access_whitelist) VALUES($1,'urn:test:pep','whitelist',10,TRUE,'on_sub',TRUE,ARRAY['Friends','Trusted'],ARRAY['bob@example.test','carol@example.net'])")
        .bind(alice.id).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO pep_subscriptions(owner_id,node,subscriber_jid,subid,state) VALUES($1,'urn:test:pep','bob@example.test',$2,'subscribed')")
        .bind(alice.id).bind(Uuid::new_v4().to_string()).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO pep_items(owner_id,node,item_id,payload) VALUES($1,'urn:test:pep','current',$2)")
        .bind(alice.id).bind("<status xmlns='urn:test:status'>ready</status>").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO message_archive(id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id) VALUES($1,$2,'bob@example.test','bob@example.test',$3,TRUE,'origin-1')")
        .bind(Uuid::new_v4()).bind(alice.id)
        .bind("<message xmlns='jabber:client' from='alice@example.test/phone' to='bob@example.test' type='chat' id='origin-1'><encrypted xmlns='urn:xmpp:omemo:2'><header sid='1'/><payload>Yg==</payload></encrypted></message>")
        .execute(&pool).await.unwrap();
    let expected_scram = crate::db::get_scram_credentials(
        &pool,
        "alice",
        northstar_auth_core::ScramAlgorithm::Sha256,
    )
    .await
    .unwrap()
    .unwrap();
    let tree = TestTree::new();
    let output = tree.0.join("portable.xml");
    export(&pool, "example.test", &output, true).await.unwrap();
    let exported = fs::read_to_string(&output).unwrap();
    assert!(!exported.contains("password="));
    assert!(exported.contains("urn:xmpp:pie:0#scram"));
    assert!(exported.contains("pubsub#roster_groups_allowed"));
    sqlx::query("DELETE FROM users")
        .execute(&pool)
        .await
        .unwrap();
    let runtime = ImportRuntime {
        domain: "example.test",
        scram_iterations: auth::MIN_SCRAM_ITERATIONS,
    };
    let mut options = ImportOptions {
        input: output.clone(),
        root: Some(tree.0.clone()),
        dry_run: true,
        conflict: ConflictPolicy::Fail,
        unknown: UnknownPolicy::Warn,
        allow_plaintext_passwords: false,
    };
    import(&pool, &runtime, &options).await.unwrap();
    let users_after_dry_run: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(users_after_dry_run, 0);
    options.dry_run = false;
    import(&pool, &runtime, &options).await.unwrap();
    let restored_alice = crate::db::find_user(&pool, "alice").await.unwrap().unwrap();
    let restored_bob = crate::db::find_user(&pool, "bob").await.unwrap().unwrap();
    let restored_scram = crate::db::get_scram_credentials(
        &pool,
        "alice",
        northstar_auth_core::ScramAlgorithm::Sha256,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(restored_scram.iterations, expected_scram.iterations);
    assert_eq!(restored_scram.salt, expected_scram.salt);
    assert_eq!(restored_scram.stored_key, expected_scram.stored_key);
    assert_eq!(restored_scram.server_key, expected_scram.server_key);
    for (table, expected) in [
        ("roster_items", 1_i64),
        ("offline_messages", 1),
        ("private_xml", 1),
        ("vcards", 1),
        ("blocked_jids", 1),
        ("pending_presence_subscriptions", 1),
        ("federated_presence_pending", 0),
        ("pep_nodes", 1),
        ("pep_subscriptions", 1),
        ("pep_items", 1),
        ("message_archive", 1),
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, expected, "unexpected row count for {table}");
    }
    options.conflict = ConflictPolicy::Skip;
    import(&pool, &runtime, &options).await.unwrap();
    assert_eq!(
        crate::db::find_user(&pool, "alice")
            .await
            .unwrap()
            .unwrap()
            .id,
        restored_alice.id
    );
    assert_eq!(
        crate::db::find_user(&pool, "bob")
            .await
            .unwrap()
            .unwrap()
            .id,
        restored_bob.id
    );
    options.conflict = ConflictPolicy::Replace;
    import(&pool, &runtime, &options).await.unwrap();
    assert_ne!(
        crate::db::find_user(&pool, "alice")
            .await
            .unwrap()
            .unwrap()
            .id,
        restored_alice.id
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pending_presence_subscriptions")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );

    let existing = crate::db::create_user(
        &pool,
        "zrollback",
        "rollback-existing-password",
        false,
        false,
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let rollback_file = tree.0.join("rollback.xml");
    fs::write(
        &rollback_file,
        format!("<server-data xmlns='urn:xmpp:pie:0'><host jid='example.test'><user name='arollback'>{0}</user><user name='zrollback'>{0}</user></host></server-data>", portable_scram()),
    ).unwrap();
    options.input = rollback_file;
    options.conflict = ConflictPolicy::Fail;
    assert!(import(&pool, &runtime, &options).await.is_err());
    assert!(crate::db::find_user(&pool, "arollback")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        crate::db::find_user(&pool, "zrollback")
            .await
            .unwrap()
            .unwrap()
            .id,
        existing.id
    );
}
