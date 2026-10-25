use super::*;

#[test]
fn blocking_write_keys_are_canonical_without_folding_resources() {
    assert_eq!(
        canonical_blocking_jids(&[
            "A\u{30a}LICE@B\u{fc}CHER.Example./Phone".to_owned(),
            "\u{e5}lice@b\u{fc}cher.example/phone".to_owned(),
            "\u{e5}lice@b\u{fc}cher.example/Phone".to_owned(),
        ])
        .unwrap(),
        [
            "\u{e5}lice@b\u{fc}cher.example/Phone",
            "\u{e5}lice@b\u{fc}cher.example/phone"
        ]
    );
}

#[test]
fn blocking_preserves_opaque_resource_case() {
    assert!(blocked_jid_matches(
        "Alice@Example.test/Phone",
        "alice@example.test/Phone"
    ));
    assert!(!blocked_jid_matches(
        "alice@example.test/Phone",
        "alice@example.test/phone"
    ));
    assert!(blocked_jid_matches(
        "alice@example.test",
        "ALICE@EXAMPLE.TEST/phone"
    ));
    assert!(blocked_jid_matches(
        "example.test",
        "someone@example.test/Phone"
    ));
    assert!(!blocked_jid_matches(
        "example.test",
        "someone@elsewhere.test/Phone"
    ));
    assert!(blocked_jid_matches(
        "example.test/Phone",
        "example.test/Phone"
    ));
    assert!(!blocked_jid_matches(
        "example.test/Phone",
        "someone@example.test/Phone"
    ));
    assert!(blocked_jid_matches(
        "B\u{fc}CHER.Example.",
        "someone@bücher.example/Phone"
    ));
    assert!(!blocked_jid_matches(
        "example.test",
        "someone@example.test/\u{0007}"
    ));
    let candidates = blocking_match_candidates(
        &northstar_xmpp_types::jid::CanonicalJid::parse("Alice@Example.test/Phone").unwrap(),
    );
    assert_eq!(
        candidates,
        [
            "alice@example.test",
            "alice@example.test/Phone",
            "example.test",
            "example.test/Phone"
        ]
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn blocking_is_atomic_bounded_and_indexed_in_postgresql() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("blocking_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE users(
            id UUID PRIMARY KEY,
            username TEXT NOT NULL,
            is_disabled BOOLEAN NOT NULL DEFAULT FALSE
         )",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE blocked_jids( \
           owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, \
           blocked_jid VARCHAR(3071) NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
           PRIMARY KEY(owner_id, blocked_jid))",
    )
    .execute(&pool)
    .await
    .unwrap();
    let owner_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id, username) VALUES($1, 'alice')")
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
    let initial = vec![
        "romeo@example.test/Phone".to_owned(),
        "romeo@example.test".to_owned(),
        "gateway.test/Phone".to_owned(),
        "blocked.test".to_owned(),
        "room@conference.example.test".to_owned(),
    ];
    let mut expected_initial = initial.clone();
    expected_initial.sort_unstable();
    assert_eq!(
        block_jids(&pool, owner_id, &initial).await.unwrap(),
        BlockJidsUpdate::Changed(expected_initial)
    );
    assert_eq!(
        block_jids(&pool, owner_id, &initial).await.unwrap(),
        BlockJidsUpdate::Changed(Vec::new())
    );
    for candidate in [
        "romeo@example.test/Phone",
        "romeo@example.test/Other",
        "gateway.test/Phone",
        "someone@blocked.test/Any",
    ] {
        assert!(
            is_blocked(&pool, owner_id, candidate).await.unwrap(),
            "{candidate}"
        );
    }
    assert!(!is_blocked(&pool, owner_id, "gateway.test/phone")
        .await
        .unwrap());
    assert!(!is_blocked_for_account(
        &pool,
        owner_id,
        "alice@blocked.test",
        "alice@blocked.test/Laptop",
    )
    .await
    .unwrap());
    let blocked_muc = blocked_local_accounts_for_candidates(
        &pool,
        "example.test",
        &[
            "alice@example.test/Laptop".to_owned(),
            "remote@elsewhere.test/Phone".to_owned(),
        ],
        &[
            "room@conference.example.test/Romeo".to_owned(),
            "romeo@example.test/Phone".to_owned(),
        ],
    )
    .await
    .unwrap();
    assert_eq!(
        blocked_muc,
        HashSet::from(["alice@example.test".to_owned()])
    );
    assert_eq!(
        unblock_jids(&pool, owner_id, Some(&["missing.example".to_owned()]),)
            .await
            .unwrap(),
        UnblockJidsUpdate::Changed(Vec::new())
    );

    let current = blocked_jids(&pool, owner_id).await.unwrap().len();
    let fill = (0..MAX_BLOCKED_JIDS_PER_ACCOUNT - current)
        .map(|index| format!("user{index}@quota.test"))
        .collect::<Vec<_>>();
    assert!(matches!(
        block_jids(&pool, owner_id, &fill).await.unwrap(),
        BlockJidsUpdate::Changed(changed) if changed.len() == fill.len()
    ));
    assert_eq!(
        block_jids(&pool, owner_id, &["over-quota.test".to_owned()])
            .await
            .unwrap(),
        BlockJidsUpdate::QuotaExceeded
    );
    assert_eq!(
        blocked_jids(&pool, owner_id).await.unwrap().len(),
        MAX_BLOCKED_JIDS_PER_ACCOUNT
    );

    let concurrent_owner = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id, username) VALUES($1, 'concurrent')")
        .bind(concurrent_owner)
        .execute(&pool)
        .await
        .unwrap();
    let left = (0..600)
        .map(|index| format!("left{index}@quota.test"))
        .collect::<Vec<_>>();
    let right = (0..600)
        .map(|index| format!("right{index}@quota.test"))
        .collect::<Vec<_>>();
    let (left_result, right_result) = tokio::join!(
        block_jids(&pool, concurrent_owner, &left),
        block_jids(&pool, concurrent_owner, &right)
    );
    let results = [left_result.unwrap(), right_result.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, BlockJidsUpdate::QuotaExceeded))
            .count(),
        1
    );
    assert_eq!(
        blocked_jids(&pool, concurrent_owner).await.unwrap().len(),
        600
    );
    assert!(matches!(
        unblock_jids(&pool, owner_id, None).await.unwrap(),
        UnblockJidsUpdate::Changed(changed)
            if changed.len() == MAX_BLOCKED_JIDS_PER_ACCOUNT
    ));
    assert!(blocked_jids(&pool, owner_id).await.unwrap().is_empty());

    sqlx::query("UPDATE users SET is_disabled=TRUE WHERE id=$1")
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        block_jids(&pool, owner_id, &["after-disable.test".to_owned()])
            .await
            .unwrap(),
        BlockJidsUpdate::Unavailable
    );
    assert_eq!(
        unblock_jids(&pool, owner_id, None).await.unwrap(),
        UnblockJidsUpdate::Unavailable
    );

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn local_presence_transitions_are_atomic_and_preserve_pending_stanzas() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("local_presence_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let suffix = Uuid::new_v4().simple().to_string();
    let actor_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let actor_name = format!("roster-a-{}", &suffix[..12]);
    let target_name = format!("roster-b-{}", &suffix[..12]);
    for (id, username) in [(actor_id, &actor_name), (target_id, &target_name)] {
        sqlx::query(
            "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'integration-test')",
        )
        .bind(id)
        .bind(username)
        .execute(&pool)
        .await
        .unwrap();
    }
    let actor_jid = format!("{actor_name}@example.test");
    let target_jid = format!("{target_name}@example.test");
    update_subscription_with_approval(&pool, target_id, &actor_jid, "none", None, Some(true))
        .await
        .unwrap();
    let preapproved = transition_local_presence_subscription(
        &pool,
        actor_id,
        &actor_jid,
        target_id,
        &target_jid,
        "subscribe",
        "<presence type='subscribe'/>",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(preapproved.effect, LocalPresenceEffect::AutoApproved);
    assert_eq!(
        roster_item(&pool, actor_id, &target_jid)
            .await
            .unwrap()
            .unwrap()
            .2,
        "to"
    );
    assert_eq!(
        roster_item(&pool, target_id, &actor_jid)
            .await
            .unwrap()
            .unwrap()
            .2,
        "from"
    );

    transition_local_presence_subscription(
        &pool,
        actor_id,
        &actor_jid,
        target_id,
        &target_jid,
        "unsubscribe",
        "<presence type='unsubscribe'/>",
    )
    .await
    .unwrap();
    let stored = format!(
        "<presence xmlns='jabber:client' from='{actor_jid}' to='{target_jid}' type='subscribe'><nick xmlns='http://jabber.org/protocol/nick'>Alice</nick></presence>"
    );
    let pending = transition_local_presence_subscription(
        &pool,
        actor_id,
        &actor_jid,
        target_id,
        &target_jid,
        "subscribe",
        &stored,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(pending.effect, LocalPresenceEffect::Forward);
    let deliveries = pending_presence_subscriptions(&pool, target_id)
        .await
        .unwrap();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0].stanza.as_deref(), Some(stored.as_str()));

    transition_local_presence_subscription(
        &pool,
        target_id,
        &target_jid,
        actor_id,
        &actor_jid,
        "subscribed",
        "<presence type='subscribed'/>",
    )
    .await
    .unwrap();
    assert!(pending_presence_subscriptions(&pool, target_id)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        roster_item(&pool, actor_id, &target_jid)
            .await
            .unwrap()
            .unwrap()
            .2,
        "to"
    );
    assert_eq!(
        roster_item(&pool, target_id, &actor_jid)
            .await
            .unwrap()
            .unwrap()
            .2,
        "from"
    );

    transition_local_presence_subscription(
        &pool,
        target_id,
        &target_jid,
        actor_id,
        &actor_jid,
        "unsubscribed",
        "<presence type='unsubscribed'/>",
    )
    .await
    .unwrap();
    assert_eq!(
        roster_item(&pool, actor_id, &target_jid)
            .await
            .unwrap()
            .unwrap()
            .2,
        "none"
    );
    assert_eq!(
        roster_item(&pool, target_id, &actor_jid)
            .await
            .unwrap()
            .unwrap()
            .2,
        "none"
    );

    update_subscription(&pool, actor_id, &target_jid, "to", None)
        .await
        .unwrap();
    update_subscription(&pool, target_id, &actor_jid, "from", None)
        .await
        .unwrap();
    let before_version = get_roster_version(&pool, actor_id).await.unwrap();
    let function_name = format!("fail_roster_{}", &suffix[..12]);
    let trigger_name = format!("fail_roster_trigger_{}", &suffix[..12]);
    sqlx::query(&format!(
        "CREATE FUNCTION {function_name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.owner_id = '{target_id}'::uuid THEN RAISE EXCEPTION 'forced second-side failure'; END IF; RETURN NEW; END $$"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger_name} BEFORE INSERT OR UPDATE ON roster_items FOR EACH ROW EXECUTE FUNCTION {function_name}()"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(transition_local_presence_subscription(
        &pool,
        actor_id,
        &actor_jid,
        target_id,
        &target_jid,
        "unsubscribe",
        "<presence type='unsubscribe'/>",
    )
    .await
    .is_err());
    assert_eq!(
        get_roster_version(&pool, actor_id).await.unwrap(),
        before_version
    );
    assert_eq!(
        roster_item(&pool, actor_id, &target_jid)
            .await
            .unwrap()
            .unwrap()
            .2,
        "to"
    );
    sqlx::query(&format!("DROP TRIGGER {trigger_name} ON roster_items"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("DROP FUNCTION {function_name}()"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=ANY($1)")
        .bind(vec![actor_id, target_id])
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn roster_removal_settles_local_mutual_pending_and_federated_state_atomically() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("roster_remove_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let owner_id = Uuid::new_v4();
    let contact_id = Uuid::new_v4();
    let suffix = &Uuid::new_v4().simple().to_string()[..12];
    let owner_name = format!("remove-owner-{suffix}");
    let contact_name = format!("remove-contact-{suffix}");
    for (id, username) in [(owner_id, &owner_name), (contact_id, &contact_name)] {
        sqlx::query(
            "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'integration-test')",
        )
        .bind(id)
        .bind(username)
        .execute(&pool)
        .await
        .unwrap();
    }
    let owner_jid = format!("{owner_name}@example.test");
    let contact_jid = format!("{contact_name}@example.test");
    let local_route = RosterRemovalRoute::Local {
        owner_jid: &owner_jid,
        contact_username: Some(&contact_name),
    };

    // One direction generates exactly one cancellation and updates the
    // reverse roster in the same commit.
    update_subscription(&pool, owner_id, &contact_jid, "to", None)
        .await
        .unwrap();
    update_subscription(&pool, contact_id, &owner_jid, "from", None)
        .await
        .unwrap();
    let one_way = remove_roster_item(&pool, owner_id, &contact_jid, local_route)
        .await
        .unwrap()
        .unwrap();
    assert!(one_way.send_unsubscribe);
    assert!(!one_way.send_unsubscribed);
    assert_eq!(
        one_way
            .contact_change
            .as_ref()
            .and_then(|change| change.subscription.as_deref()),
        Some("none")
    );
    assert!(roster_item(&pool, owner_id, &contact_jid)
        .await
        .unwrap()
        .is_none());

    // Mutual state must produce both RFC 6121 section 2.5.2 stanzas.
    update_subscription(&pool, owner_id, &contact_jid, "both", None)
        .await
        .unwrap();
    update_subscription(&pool, contact_id, &owner_jid, "both", None)
        .await
        .unwrap();
    let mutual = remove_roster_item(&pool, owner_id, &contact_jid, local_route)
        .await
        .unwrap()
        .unwrap();
    assert!(mutual.send_unsubscribe && mutual.send_unsubscribed);
    assert_eq!(
        roster_item(&pool, contact_id, &owner_jid)
            .await
            .unwrap()
            .unwrap()
            .2,
        "none"
    );

    // Opposing pending requests are durable protocol state even though
    // neither side has an established subscription. Removing the owner
    // item cancels both and clears the peer's matching `ask` flag.
    transition_local_presence_subscription(
        &pool,
        owner_id,
        &owner_jid,
        contact_id,
        &contact_jid,
        "subscribe",
        "<presence type='subscribe'/>",
    )
    .await
    .unwrap();
    transition_local_presence_subscription(
        &pool,
        contact_id,
        &contact_jid,
        owner_id,
        &owner_jid,
        "subscribe",
        "<presence type='subscribe'/>",
    )
    .await
    .unwrap();
    let pending_for_owner = pending_presence_subscriptions(&pool, owner_id)
        .await
        .unwrap();
    let pending_for_contact = pending_presence_subscriptions(&pool, contact_id)
        .await
        .unwrap();
    assert_eq!(pending_for_owner[0].requester, contact_name);
    assert_eq!(pending_for_contact[0].requester, owner_name);
    let pending = remove_roster_item(&pool, owner_id, &contact_jid, local_route)
        .await
        .unwrap()
        .unwrap();
    assert!(pending.send_unsubscribe && pending.send_unsubscribed);
    assert!(pending_presence_subscriptions(&pool, owner_id)
        .await
        .unwrap()
        .is_empty());
    assert!(pending_presence_subscriptions(&pool, contact_id)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        roster_item(&pool, contact_id, &owner_jid)
            .await
            .unwrap()
            .unwrap()
            .3,
        None
    );

    let remote = "peer@remote.example";
    update_subscription(&pool, owner_id, remote, "both", Some("subscribe"))
        .await
        .unwrap();
    add_federated_presence_pending_with_stanza(
        &pool,
        owner_id,
        remote,
        Some("<presence xmlns='jabber:server' type='subscribe'/>"),
    )
    .await
    .unwrap();
    let unsubscribe = format!(
        "<presence xmlns='jabber:client' from='{owner_jid}' to='{remote}' type='unsubscribe'/>",
    );
    let unsubscribed = format!(
        "<presence xmlns='jabber:client' from='{owner_jid}' to='{remote}' type='unsubscribed'/>",
    );
    let policy = super::super::S2sOutboxPolicy {
        ttl_seconds: 3600,
        max_rows: 100,
        max_bytes: 1024 * 1024,
        max_per_domain: 100,
    };
    let remote_route = RosterRemovalRoute::Remote {
        target_domain: "remote.example",
        unsubscribe_stanza: &unsubscribe,
        unsubscribed_stanza: &unsubscribed,
        bounce_to: Some(&owner_jid),
        policy,
    };

    // A failure admitting the second outbox row rolls back the first row,
    // roster deletion, pending cleanup and version increment together.
    let function_name = format!("fail_remove_outbox_{suffix}");
    let trigger_name = format!("fail_remove_outbox_trigger_{suffix}");
    sqlx::query(&format!(
        "CREATE FUNCTION {function_name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.stanza LIKE '%type=''unsubscribed''%' THEN RAISE EXCEPTION 'forced second cancellation failure'; END IF; RETURN NEW; END $$"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger_name} BEFORE INSERT ON s2s_outbox FOR EACH ROW EXECUTE FUNCTION {function_name}()"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(remove_roster_item(&pool, owner_id, remote, remote_route)
        .await
        .is_err());
    assert_eq!(
        roster_item(&pool, owner_id, remote)
            .await
            .unwrap()
            .unwrap()
            .2,
        "both"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM s2s_outbox")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        federated_presence_pending(&pool, owner_id)
            .await
            .unwrap()
            .len(),
        1
    );
    sqlx::query(&format!("DROP TRIGGER {trigger_name} ON s2s_outbox"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("DROP FUNCTION {function_name}()"))
        .execute(&pool)
        .await
        .unwrap();

    let federated = remove_roster_item(&pool, owner_id, remote, remote_route)
        .await
        .unwrap()
        .unwrap();
    assert!(federated.send_unsubscribe && federated.send_unsubscribed);
    assert!(federated_presence_pending(&pool, owner_id)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM s2s_outbox")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
    // A lost IQ result and client retry is idempotent: no roster row means
    // no new admission. The two committed rows survive pool teardown,
    // which exercises the same PostgreSQL recovery boundary as restart.
    assert!(remove_roster_item(&pool, owner_id, remote, remote_route)
        .await
        .unwrap()
        .is_none());
    pool.close().await;
    let restart_schema = schema.clone();
    let restarted = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {restart_schema}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM s2s_outbox")
            .fetch_one(&restarted)
            .await
            .unwrap(),
        2
    );
    assert!(roster_item(&restarted, owner_id, remote)
        .await
        .unwrap()
        .is_none());
    restarted.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn roster_versions_and_committed_snapshots_survive_concurrent_writes() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let owner_id = Uuid::new_v4();
    let username = format!("version-{}", &Uuid::new_v4().simple().to_string()[..12]);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
        .bind(owner_id)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();
    let base = get_roster_version(&pool, owner_id).await.unwrap();
    assert!(delete_roster(&pool, owner_id, "missing@example.test")
        .await
        .unwrap()
        .is_none());
    assert_eq!(get_roster_version(&pool, owner_id).await.unwrap(), base);
    let no_groups: Vec<String> = Vec::new();
    let (first, second) = tokio::join!(
        upsert_roster(
            &pool,
            owner_id,
            "one@example.test",
            Some("First snapshot"),
            &no_groups
        ),
        upsert_roster(
            &pool,
            owner_id,
            "two@example.test",
            Some("Second snapshot"),
            &no_groups
        )
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_ne!(first.version, second.version);
    assert_eq!(first.display_name.as_deref(), Some("First snapshot"));
    assert_eq!(second.display_name.as_deref(), Some("Second snapshot"));

    let current = get_roster_version(&pool, owner_id).await.unwrap();
    let snapshot = roster_snapshot(&pool, owner_id).await.unwrap();
    assert_eq!(snapshot.version, current);
    assert_eq!(snapshot.items.len(), 2);
    let delta = roster_changes_since(&pool, owner_id, base, current)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delta.len(), 2);
    assert!(delta
        .windows(2)
        .all(|pair| pair[0].version < pair[1].version));
    assert!(roster_changes_since(&pool, owner_id, current, current)
        .await
        .unwrap()
        .unwrap()
        .is_empty());
    assert!(roster_changes_since(&pool, owner_id, current + 1, current)
        .await
        .unwrap()
        .is_none());

    let a_v2 = upsert_roster(
        &pool,
        owner_id,
        "one@example.test",
        Some("Intermediate A"),
        &no_groups,
    )
    .await
    .unwrap();
    let b_v3 = upsert_roster(
        &pool,
        owner_id,
        "two@example.test",
        Some("Final B"),
        &no_groups,
    )
    .await
    .unwrap();
    let a_v4 = upsert_roster(
        &pool,
        owner_id,
        "one@example.test",
        Some("Final A"),
        &no_groups,
    )
    .await
    .unwrap();
    assert!(a_v2.version < b_v3.version && b_v3.version < a_v4.version);
    let collapsed = roster_changes_since(&pool, owner_id, current, a_v4.version)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(collapsed.len(), 2);
    assert_eq!(collapsed[0].contact_jid, "two@example.test");
    assert_eq!(collapsed[0].version, b_v3.version);
    assert_eq!(collapsed[1].contact_jid, "one@example.test");
    assert_eq!(collapsed[1].version, a_v4.version);
    assert_eq!(collapsed[1].display_name.as_deref(), Some("Final A"));
    let after_b = roster_changes_since(&pool, owner_id, b_v3.version, a_v4.version)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_b, vec![a_v4]);

    sqlx::query("DELETE FROM roster_change_log WHERE owner_id=$1 AND version=$2")
        .bind(owner_id)
        .bind(base + 1)
        .execute(&pool)
        .await
        .unwrap();
    assert!(roster_changes_since(&pool, owner_id, base, current)
        .await
        .unwrap()
        .is_none());
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn remote_transition_and_pending_consumption_are_atomic() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("remote_presence_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let owner_id = Uuid::new_v4();
    let username = format!("remote-{}", &Uuid::new_v4().simple().to_string()[..12]);
    let remote = "sender@remote.example";
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
        .bind(owner_id)
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();
    update_subscription(&pool, owner_id, remote, "none", None)
        .await
        .unwrap();
    add_federated_presence_pending_with_stanza(
        &pool,
        owner_id,
        remote,
        Some("<presence xmlns='jabber:server' type='subscribe'/>"),
    )
    .await
    .unwrap();

    let suffix = Uuid::new_v4().simple().to_string();
    let function_name = format!("fail_pending_delete_{suffix}");
    let trigger_name = format!("fail_pending_delete_trigger_{suffix}");
    sqlx::query(&format!(
        "CREATE FUNCTION {function_name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced pending delete failure'; END $$"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger_name} BEFORE DELETE ON federated_presence_pending FOR EACH ROW EXECUTE FUNCTION {function_name}()"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        transition_remote_presence_subscription(&pool, owner_id, remote, "subscribed")
            .await
            .is_err()
    );
    assert_eq!(
        roster_item(&pool, owner_id, remote)
            .await
            .unwrap()
            .unwrap()
            .2,
        "none"
    );
    assert_eq!(
        federated_presence_pending(&pool, owner_id)
            .await
            .unwrap()
            .len(),
        1
    );
    sqlx::query(&format!(
        "DROP TRIGGER {trigger_name} ON federated_presence_pending"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!("DROP FUNCTION {function_name}()"))
        .execute(&pool)
        .await
        .unwrap();

    let transition = transition_remote_presence_subscription(&pool, owner_id, remote, "subscribed")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(transition.subscription, "from");
    assert_eq!(
        transition
            .change
            .as_ref()
            .and_then(|change| change.subscription.as_deref()),
        Some("from")
    );
    assert!(federated_presence_pending(&pool, owner_id)
        .await
        .unwrap()
        .is_empty());

    // The outbound federation stanza and the roster mutation are one
    // acceptance transaction. A forced outbox failure must leave the
    // previously committed subscription untouched and publish no row.
    let outbox_function = format!("fail_subscription_outbox_{suffix}");
    let outbox_trigger = format!("fail_subscription_outbox_trigger_{suffix}");
    sqlx::query(&format!(
        "CREATE FUNCTION {outbox_function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.stanza LIKE '%atomic-failure-marker%' THEN RAISE EXCEPTION 'forced subscription outbox failure'; END IF; RETURN NEW; END $$"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {outbox_trigger} BEFORE INSERT ON s2s_outbox FOR EACH ROW EXECUTE FUNCTION {outbox_function}()"
    ))
    .execute(&pool)
    .await
    .unwrap();
    let policy = super::super::S2sOutboxPolicy {
        ttl_seconds: 300,
        max_rows: 10_000,
        max_bytes: 64 * 1024 * 1024,
        max_per_domain: 10_000,
    };
    let rejected = "<presence xmlns='jabber:server' from='local@example.test' to='sender@remote.example' type='unsubscribed' id='atomic-failure-marker'/>";
    assert!(transition_remote_presence_subscription_with_outbox(
        &pool,
        owner_id,
        remote,
        "unsubscribed",
        "remote.example",
        rejected,
        Some(&format!("{username}@example.test")),
        policy,
    )
    .await
    .is_err());
    assert_eq!(
        roster_item(&pool, owner_id, remote)
            .await
            .unwrap()
            .unwrap()
            .2,
        "from"
    );
    let rejected_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM s2s_outbox WHERE stanza=$1")
        .bind(rejected)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rejected_count, 0);
    sqlx::query(&format!("DROP TRIGGER {outbox_trigger} ON s2s_outbox"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("DROP FUNCTION {outbox_function}()"))
        .execute(&pool)
        .await
        .unwrap();

    let accepted = rejected.replace("atomic-failure-marker", "atomic-success-marker");
    transition_remote_presence_subscription_with_outbox(
        &pool,
        owner_id,
        remote,
        "unsubscribed",
        "remote.example",
        &accepted,
        Some(&format!("{username}@example.test")),
        policy,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        roster_item(&pool, owner_id, remote)
            .await
            .unwrap()
            .unwrap()
            .2,
        "none"
    );
    let accepted_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM s2s_outbox WHERE stanza=$1")
        .bind(&accepted)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(accepted_count, 1);
    sqlx::query("DELETE FROM s2s_outbox WHERE stanza=$1")
        .bind(&accepted)
        .execute(&pool)
        .await
        .unwrap();

    // RFC 6121 pre-approval is local state only: it MUST NOT send a
    // misleading <subscribed/> until the remote contact asks. A duplicate
    // pre-approval is also a true no-op (no version bump).
    let preapproval = "<presence xmlns='jabber:server' from='local@example.test' to='sender@remote.example' type='subscribed' id='preapproval-must-not-route'/>";
    let before_preapproval = get_roster_version(&pool, owner_id).await.unwrap();
    let transition = transition_remote_presence_subscription_with_outbox(
        &pool,
        owner_id,
        remote,
        "subscribed",
        "remote.example",
        preapproval,
        Some(&format!("{username}@example.test")),
        policy,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!transition.routed);
    assert!(transition.change.is_some());
    let approved: bool = sqlx::query_scalar(
        "SELECT approved FROM roster_items WHERE owner_id=$1 AND contact_jid=$2",
    )
    .bind(owner_id)
    .bind(remote)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(approved);
    let not_routed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM s2s_outbox WHERE stanza=$1")
        .bind(preapproval)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(not_routed, 0);
    let duplicate = transition_remote_presence_subscription_with_outbox(
        &pool,
        owner_id,
        remote,
        "subscribed",
        "remote.example",
        preapproval,
        Some(&format!("{username}@example.test")),
        policy,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!duplicate.routed);
    assert!(duplicate.change.is_none());
    assert_eq!(
        get_roster_version(&pool, owner_id).await.unwrap(),
        before_preapproval + 1
    );

    // The remote request consumes pre-approval and grants `from` in the
    // same transaction; no durable pending request is exposed.
    let inbound = transition_inbound_remote_presence_subscription(
        &pool,
        owner_id,
        "example.test",
        remote,
        "subscribe",
        "<presence xmlns='jabber:client' from='sender@remote.example' to='local@example.test' type='subscribe'/>",
    )
    .await
    .unwrap();
    let AuthorizedInboundRemotePresenceTransition::Transition(authorized) = inbound else {
        panic!("pre-approved inbound subscription was rejected");
    };
    let inbound = authorized.transition;
    assert_eq!(inbound.subscription, "from");
    assert_eq!(inbound.auto_reply, Some("subscribed"));
    assert_eq!(inbound.effect, InboundRemotePresenceEffect::Suppressed);
    assert!(federated_presence_pending(&pool, owner_id)
        .await
        .unwrap()
        .is_empty());
    let approved: bool = sqlx::query_scalar(
        "SELECT approved FROM roster_items WHERE owner_id=$1 AND contact_jid=$2",
    )
    .bind(owner_id)
    .bind(remote)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!approved);

    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn roster_service_snapshot_authorization_and_account_identity_are_fenced() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("roster_service_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();

    let suffix = &Uuid::new_v4().simple().to_string()[..12];
    let owner_id = Uuid::new_v4();
    let contact_id = Uuid::new_v4();
    let owner_name = format!("roster-owner-{suffix}");
    let contact_name = format!("roster-contact-{suffix}");
    for (id, username) in [(owner_id, &owner_name), (contact_id, &contact_name)] {
        sqlx::query(
            "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'integration-test')",
        )
        .bind(id)
        .bind(username)
        .execute(&pool)
        .await
        .unwrap();
    }
    let generation: i64 = sqlx::query_scalar("SELECT auth_generation FROM users WHERE id=$1")
        .bind(owner_id)
        .fetch_one(&pool)
        .await
        .unwrap();

    let remote = "channel@mix.remote.example";
    let first = upsert_roster_authorized(
        &pool,
        owner_id,
        generation,
        remote,
        Some("Channel"),
        &["MIX".to_owned()],
    )
    .await
    .unwrap()
    .unwrap();
    sqlx::query(
        "INSERT INTO mix_pam_memberships(id,user_id,channel_jid,participant_id,state) VALUES($1,$2,$3,$4,'joined')",
    )
    .bind(Uuid::new_v4())
    .bind(owner_id)
    .bind(remote)
    .bind("participant-1")
    .execute(&pool)
    .await
    .unwrap();
    let annotated = roster_read_snapshot(&pool, owner_id, generation, None, true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(annotated.version, first.version);
    assert_eq!(annotated.items.len(), 1);
    assert_eq!(
        annotated.mix_participants.get(remote).map(String::as_str),
        Some("participant-1")
    );

    let second = upsert_roster_authorized(
        &pool,
        owner_id,
        generation,
        remote,
        Some("Renamed"),
        &["Channels".to_owned()],
    )
    .await
    .unwrap()
    .unwrap();
    let delta = roster_read_snapshot(&pool, owner_id, generation, Some(first.version), false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delta.version, second.version);
    assert_eq!(delta.items[0].version, second.version);
    assert_eq!(
        delta.changes.as_ref().unwrap(),
        std::slice::from_ref(&second)
    );

    // Hold the owner lock, queue a stale-session mutation, then advance
    // the credential epoch before releasing it. The waiting mutation must
    // re-evaluate its predicate and commit nothing.
    let mut revocation = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(owner_id)
        .execute(&mut *revocation)
        .await
        .unwrap();
    let waiting_pool = pool.clone();
    let waiting = tokio::spawn(async move {
        upsert_roster_authorized(
            &waiting_pool,
            owner_id,
            generation,
            "stale@remote.example",
            None,
            &[],
        )
        .await
    });
    sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
        .bind(owner_id)
        .execute(&mut *revocation)
        .await
        .unwrap();
    revocation.commit().await.unwrap();
    assert!(waiting.await.unwrap().unwrap().is_none());
    assert!(roster_item(&pool, owner_id, "stale@remote.example")
        .await
        .unwrap()
        .is_none());
    assert!(
        roster_read_snapshot(&pool, owner_id, generation, None, false)
            .await
            .unwrap()
            .is_none()
    );
    let current_generation = generation + 1;

    let contact_jid = format!("{contact_name}@example.test");
    upsert_roster_authorized(&pool, owner_id, current_generation, &contact_jid, None, &[])
        .await
        .unwrap()
        .unwrap();
    let owner_jid = format!("{owner_name}@example.test");
    let removal = remove_roster_item_authorized(
        &pool,
        owner_id,
        current_generation,
        &contact_jid,
        RosterRemovalRoute::Local {
            owner_jid: &owner_jid,
            contact_username: Some(&contact_name),
        },
    )
    .await
    .unwrap();
    let AuthorizedRosterRemoval::Removed(removal) = removal else {
        panic!("authorized local roster removal was rejected");
    };
    assert_eq!(removal.local_contact.as_ref().unwrap().id, contact_id);

    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(contact_id)
        .execute(&pool)
        .await
        .unwrap();
    let replacement_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'integration-test')")
        .bind(replacement_id)
        .bind(&contact_name)
        .execute(&pool)
        .await
        .unwrap();
    assert_ne!(removal.local_contact.unwrap().id, replacement_id);

    sqlx::query("UPDATE users SET is_disabled=TRUE,auth_generation=auth_generation+1 WHERE id=$1")
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(upsert_roster_authorized(
        &pool,
        owner_id,
        current_generation,
        "disabled@remote.example",
        None,
        &[],
    )
    .await
    .unwrap()
    .is_none());

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
