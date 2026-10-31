use super::*;
use northstar_pubsub_application::profile::ProfileService;
use northstar_pubsub_application::profile::VCARD4;

fn profile_service(pool: PgPool, domain: String) -> ProfileService<PostgresProfileRepository> {
    let admission = Arc::new(northstar_pubsub_application::PubSubMutationAdmission::new(
        pool.options().get_max_connections() as usize,
    ));
    ProfileService::with_mutation_admission(PostgresProfileRepository::new(pool, domain), admission)
}
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

struct IsolatedDatabase {
    admin: PgPool,
    pool: PgPool,
    schema: String,
}

impl IsolatedDatabase {
    async fn create(label: &str) -> Self {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("profile_{label}_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
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
        Self {
            admin,
            pool,
            schema,
        }
    }

    async fn finish(self) {
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.admin)
            .await
            .unwrap();
        self.admin.close().await;
    }
}

async fn insert_user(pool: &PgPool, prefix: &str) -> (Uuid, String, i64) {
    let id = Uuid::new_v4();
    let username = format!("{prefix}{}", &id.simple().to_string()[..10]);
    let generation = sqlx::query_scalar::<_, i64>(
        "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')
             RETURNING auth_generation",
    )
    .bind(id)
    .bind(&username)
    .fetch_one(pool)
    .await
    .unwrap();
    (id, username, generation)
}

fn vcard4_item(id: &str, value: &str) -> String {
    format!(
        "<item id='{id}'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'><fn><text>{value}</text></fn></vcard></item>"
    )
}

fn direct_snapshot_deliveries(audience: &ProfileAudienceSnapshot) -> Result<Vec<(String, String)>> {
    Ok(audience
        .roster_jids
        .iter()
        .chain(audience.explicit_jids.iter())
        .map(|jid| {
            (
                jid.clone(),
                format!("<message xmlns='jabber:client' to='{jid}'/>"),
            )
        })
        .collect())
}

#[test]
fn vcard_photo_projection_preserves_non_photo_profile_fields() {
    let existing = "<vCard xmlns='vcard-temp'><FN>Alice &amp; Bob</FN><PHOTO><BINVAL>old</BINVAL></PHOTO><NICKNAME>a</NICKNAME></vCard>";
    let replaced = replace_vcard_temp_photo(existing, Some("image/png"), Some("new"));
    assert!(replaced.contains("<FN>Alice &amp; Bob</FN>"));
    assert!(replaced.contains("<NICKNAME>a</NICKNAME>"));
    assert!(!replaced.contains("old"));
    assert!(replaced.contains("<BINVAL>new</BINVAL>"));
    let cleared = replace_vcard_temp_photo(&replaced, None, None);
    assert!(cleared.contains("<FN>Alice &amp; Bob</FN>"));
    assert!(!cleared.contains("<PHOTO>"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn profile_publish_uses_exact_subscribe_and_block_snapshot() {
    let database = IsolatedDatabase::create("audience").await;
    let (owner_id, _, auth_generation) = insert_user(&database.pool, "owner").await;
    let config = db::default_pep_node_config(VCARD4);
    assert!(matches!(
        db::create_pep_node(&database.pool, owner_id, VCARD4, &config, 10)
            .await
            .unwrap(),
        db::PepCreateOutcome::Created
    ));
    let unsubscribed = format!("unsub{}@remote.test/phone", Uuid::new_v4().simple());
    let blocked = format!("blocked{}@remote.test/tablet", Uuid::new_v4().simple());
    let unsubscribed_record =
        db::subscribe_pep_node(&database.pool, owner_id, VCARD4, &unsubscribed, 100)
            .await
            .unwrap()
            .unwrap();
    db::subscribe_pep_node(&database.pool, owner_id, VCARD4, &blocked, 100)
        .await
        .unwrap()
        .unwrap();

    let service = Arc::new(profile_service(
        database.pool.clone(),
        "example.test".to_owned(),
    ));
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let factory_gate = Arc::clone(&gate);
    let (snapshot_tx, mut snapshot_rx) = tokio::sync::mpsc::unbounded_channel();
    let publish_service = Arc::clone(&service);
    let publish = tokio::spawn(async move {
        let config = db::default_pep_node_config(VCARD4);
        let payload = vcard4_item("profile", "one");
        let items = [("profile", payload.as_str())];
        let factory = move |audience: &ProfileAudienceSnapshot| {
            snapshot_tx
                .send((audience.roster_jids.clone(), audience.explicit_jids.clone()))
                .map_err(|_| anyhow::anyhow!("profile snapshot observer closed"))?;
            let (released, wake) = &*factory_gate;
            let mut released = released.lock().expect("profile gate poisoned");
            while !*released {
                released = wake.wait(released).expect("profile gate poisoned");
            }
            direct_snapshot_deliveries(audience)
        };
        publish_service
            .publish_profile_items(
                ProfilePepWrite {
                    user_id: owner_id,
                    auth_generation,
                    connection_id: Uuid::new_v4(),
                    node: VCARD4,
                    requested: &config.clone().into(),
                    enforce_preconditions: false,
                    items: &items,
                    max_nodes: 10,
                    max_storage_bytes: 1_000_000,
                },
                &factory,
                true,
            )
            .await
    });
    let (_, mut explicit) = tokio::time::timeout(Duration::from_secs(3), snapshot_rx.recv())
        .await
        .expect("publication never reached the audience snapshot")
        .expect("profile snapshot observer closed");
    explicit.sort_unstable();
    let mut expected = vec![unsubscribed.clone(), blocked.clone()];
    expected.sort_unstable();
    assert_eq!(explicit, expected);

    let unsubscribe_pool = database.pool.clone();
    let unsubscribe_jid = unsubscribed.clone();
    let unsubscribe_subid = unsubscribed_record.subid.clone();
    let mut unsubscribe = tokio::spawn(async move {
        db::unsubscribe_pep_node(
            &unsubscribe_pool,
            owner_id,
            VCARD4,
            &unsubscribe_jid,
            Some(&unsubscribe_subid),
        )
        .await
    });
    let block_pool = database.pool.clone();
    let blocked_for_task = blocked.clone();
    let mut block =
        tokio::spawn(
            async move { db::block_jids(&block_pool, owner_id, &[blocked_for_task]).await },
        );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut unsubscribe)
            .await
            .is_err(),
        "unsubscribe bypassed the profile node lock"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut block)
            .await
            .is_err(),
        "block mutation bypassed the profile audience lock"
    );
    {
        let (released, wake) = &*gate;
        *released.lock().expect("profile gate poisoned") = true;
        wake.notify_all();
    }
    assert_eq!(
        publish.await.unwrap().unwrap().status,
        ProfilePublishStatus::Published
    );
    unsubscribe.await.unwrap().unwrap().unwrap();
    assert!(matches!(
        block.await.unwrap().unwrap(),
        db::BlockJidsUpdate::Changed(_)
    ));

    let second_payload = vcard4_item("profile", "two");
    let second_items = [("profile", second_payload.as_str())];
    let (second_tx, mut second_rx) = tokio::sync::mpsc::unbounded_channel();
    let second = service
        .publish_profile_items(
            ProfilePepWrite {
                user_id: owner_id,
                auth_generation,
                connection_id: Uuid::new_v4(),
                node: VCARD4,
                requested: &config.clone().into(),
                enforce_preconditions: false,
                items: &second_items,
                max_nodes: 10,
                max_storage_bytes: 1_000_000,
            },
            &|audience: &ProfileAudienceSnapshot| {
                second_tx
                    .send(audience.explicit_jids.clone())
                    .map_err(|_| anyhow::anyhow!("second observer closed"))?;
                direct_snapshot_deliveries(audience)
            },
            true,
        )
        .await
        .unwrap();
    assert_eq!(second.status, ProfilePublishStatus::Published);
    assert!(second_rx.recv().await.unwrap().is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pep_subscriptions
                  WHERE owner_id=$1 AND node=$2 AND subscriber_jid=$3",
        )
        .bind(owner_id)
        .bind(VCARD4)
        .bind(&blocked)
        .fetch_one(&database.pool)
        .await
        .unwrap(),
        1,
        "blocking filters delivery without silently deleting subscription authority"
    );
    database.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn first_profile_publish_snapshots_roster_privacy_and_rolls_back_atomically() {
    let database = IsolatedDatabase::create("first_publish").await;
    let (owner_id, _, auth_generation) = insert_user(&database.pool, "owner").await;
    let (_, allowed_name, _) = insert_user(&database.pool, "allowed").await;
    let allowed = format!("{allowed_name}@example.test");
    let denied = format!("denied{}@remote.test", Uuid::new_v4().simple());
    for contact in [&allowed, &denied] {
        sqlx::query(
            "INSERT INTO roster_items(owner_id,contact_jid,subscription,groups)
                 VALUES($1,$2,'from','[\"friends\"]'::jsonb)",
        )
        .bind(owner_id)
        .bind(contact)
        .execute(&database.pool)
        .await
        .unwrap();
    }
    let privacy = db::PrivacyList {
        name: "profile-policy".to_owned(),
        items: vec![
            db::PrivacyItem {
                order: 1,
                action: db::PrivacyAction::Deny,
                match_type: Some(db::PrivacyMatchType::Jid),
                match_value: Some(denied.clone()),
                message: true,
                iq: false,
                presence_in: false,
                presence_out: false,
            },
            db::PrivacyItem {
                order: 2,
                action: db::PrivacyAction::Allow,
                match_type: None,
                match_value: None,
                message: false,
                iq: false,
                presence_in: false,
                presence_out: false,
            },
        ],
    };
    assert_eq!(
        db::replace_privacy_list(&database.pool, owner_id, &privacy)
            .await
            .unwrap(),
        db::ReplacePrivacyListOutcome::Stored
    );
    assert!(
        db::set_default_privacy_list(&database.pool, owner_id, Some(&privacy.name))
            .await
            .unwrap()
    );
    sqlx::query(
        "CREATE FUNCTION fail_profile_outbox() RETURNS trigger
             LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced profile outbox failure'; END $$",
    )
    .execute(&database.pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER fail_profile_outbox BEFORE INSERT ON pubsub_event_outbox
             FOR EACH ROW EXECUTE FUNCTION fail_profile_outbox()",
    )
    .execute(&database.pool)
    .await
    .unwrap();

    let service = profile_service(database.pool.clone(), "example.test".to_owned());
    let config = db::default_pep_node_config(VCARD4);
    let payload = vcard4_item("profile", "atomic");
    let items = [("profile", payload.as_str())];
    let (audience_tx, mut audience_rx) = tokio::sync::mpsc::unbounded_channel();
    let failed = service
        .publish_profile_items(
            ProfilePepWrite {
                user_id: owner_id,
                auth_generation,
                connection_id: Uuid::new_v4(),
                node: VCARD4,
                requested: &config.clone().into(),
                enforce_preconditions: false,
                items: &items,
                max_nodes: 10,
                max_storage_bytes: 1_000_000,
            },
            &|audience: &ProfileAudienceSnapshot| {
                audience_tx
                    .send(audience.roster_jids.clone())
                    .map_err(|_| anyhow::anyhow!("first-publish observer closed"))?;
                direct_snapshot_deliveries(audience)
            },
            true,
        )
        .await;
    assert!(failed.is_err());
    assert_eq!(audience_rx.recv().await.unwrap(), vec![allowed.clone()]);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM pep_nodes WHERE owner_id=$1 AND node=$2",
        )
        .bind(owner_id)
        .bind(VCARD4)
        .fetch_one(&database.pool)
        .await
        .unwrap(),
        0
    );
    sqlx::query("DROP TRIGGER fail_profile_outbox ON pubsub_event_outbox")
        .execute(&database.pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION fail_profile_outbox()")
        .execute(&database.pool)
        .await
        .unwrap();

    let result = service
        .publish_profile_items(
            ProfilePepWrite {
                user_id: owner_id,
                auth_generation,
                connection_id: Uuid::new_v4(),
                node: VCARD4,
                requested: &config.clone().into(),
                enforce_preconditions: false,
                items: &items,
                max_nodes: 10,
                max_storage_bytes: 1_000_000,
            },
            &direct_snapshot_deliveries,
            true,
        )
        .await
        .unwrap();
    assert_eq!(result.status, ProfilePublishStatus::Published);
    assert_eq!(
        sqlx::query_scalar::<_, Vec<String>>(
            "SELECT COALESCE(ARRAY_AGG(recipient_jid ORDER BY recipient_jid),ARRAY[]::TEXT[])
                   FROM pubsub_event_outbox WHERE source_node=$1",
        )
        .bind(VCARD4)
        .fetch_one(&database.pool)
        .await
        .unwrap(),
        vec![allowed]
    );
    database.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn legacy_and_metadata_race_never_restores_a_stale_vcard_baseline() {
    let database = IsolatedDatabase::create("legacy_metadata").await;
    let (owner_id, _, auth_generation) = insert_user(&database.pool, "owner").await;
    let service = Arc::new(profile_service(
        database.pool.clone(),
        "example.test".to_owned(),
    ));
    let png = BASE64
        .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
        .unwrap();
    assert!(valid_png_image(&png));
    let hash = sha1_hex(&png);
    let encoded = BASE64.encode(&png);
    let data_item =
        format!("<item id='{hash}'><data xmlns='{AVATAR_DATA}'>{encoded}</data></item>");
    let metadata_item = format!(
        "<item id='{hash}'><metadata xmlns='{AVATAR_METADATA}'><info bytes='{}' id='{hash}' type='image/png'/></metadata></item>",
        png.len()
    );
    let initial = service
        .set_legacy_vcard(
            LegacyVCardWrite {
                user_id: owner_id,
                auth_generation,
                connection_id: Uuid::new_v4(),
                payload: "<vCard xmlns='vcard-temp'><FN>Initial</FN></vCard>",
                avatar_hash: Some(&hash),
                data_item: Some((&hash, &data_item)),
                metadata_item: (&hash, &metadata_item),
                max_nodes: 10,
                max_storage_bytes: 1_000_000,
            },
            &direct_snapshot_deliveries,
        )
        .await
        .unwrap();
    assert_eq!(initial.status, ProfilePublishStatus::Published);

    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let legacy_service = Arc::clone(&service);
    let legacy_barrier = Arc::clone(&barrier);
    let legacy = tokio::spawn(async move {
        legacy_barrier.wait().await;
        legacy_service
            .set_legacy_vcard(
                LegacyVCardWrite {
                    user_id: owner_id,
                    auth_generation,
                    connection_id: Uuid::new_v4(),
                    payload: "<vCard xmlns='vcard-temp'><FN>Legacy Latest</FN></vCard>",
                    avatar_hash: None,
                    data_item: None,
                    metadata_item: (
                        "current",
                        "<item id='current'><metadata xmlns='urn:xmpp:avatar:metadata'/></item>",
                    ),
                    max_nodes: 10,
                    max_storage_bytes: 1_000_000,
                },
                &direct_snapshot_deliveries,
            )
            .await
    });
    let metadata_service = Arc::clone(&service);
    let metadata_barrier = Arc::clone(&barrier);
    let metadata_hash = hash.clone();
    let metadata_xml = metadata_item.clone();
    let metadata = tokio::spawn(async move {
        metadata_barrier.wait().await;
        let config = db::default_pep_node_config(AVATAR_METADATA);
        let items = [(metadata_hash.as_str(), metadata_xml.as_str())];
        metadata_service
            .publish_avatar_metadata(
                ProfilePepWrite {
                    user_id: owner_id,
                    auth_generation,
                    connection_id: Uuid::new_v4(),
                    node: AVATAR_METADATA,
                    requested: &config.clone().into(),
                    enforce_preconditions: false,
                    items: &items,
                    max_nodes: 10,
                    max_storage_bytes: 1_000_000,
                },
                &direct_snapshot_deliveries,
            )
            .await
    });
    barrier.wait().await;
    assert_eq!(
        legacy.await.unwrap().unwrap().status,
        ProfilePublishStatus::Published
    );
    assert_eq!(
        metadata.await.unwrap().unwrap().status,
        ProfilePublishStatus::Published
    );
    let record = db::get_vcard(&database.pool, owner_id).await.unwrap();
    let payload = record.payload_vcard_temp.unwrap();
    assert!(payload.contains("<FN>Legacy Latest</FN>"));
    if record.avatar_hash.is_some() {
        assert!(payload.contains("<PHOTO>"));
    } else {
        assert!(!payload.contains("<PHOTO>"));
    }
    database.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
async fn deleted_account_incarnation_and_corrupt_vcard_fail_closed() {
    let database = IsolatedDatabase::create("identity_decode").await;
    let (old_id, username, auth_generation) = insert_user(&database.pool, "owner").await;
    let mut blocker = database.pool.begin().await.unwrap();
    lock_profile_account(&mut blocker, old_id).await.unwrap();
    let service = Arc::new(profile_service(
        database.pool.clone(),
        "example.test".to_owned(),
    ));
    let stale_service = Arc::clone(&service);
    let stale = tokio::spawn(async move {
        let config = db::default_pep_node_config(VCARD4);
        let payload = vcard4_item("stale", "stale");
        let items = [("stale", payload.as_str())];
        stale_service
            .publish_profile_items(
                ProfilePepWrite {
                    user_id: old_id,
                    auth_generation,
                    connection_id: Uuid::new_v4(),
                    node: VCARD4,
                    requested: &config.clone().into(),
                    enforce_preconditions: false,
                    items: &items,
                    max_nodes: 10,
                    max_storage_bytes: 1_000_000,
                },
                &direct_snapshot_deliveries,
                true,
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(old_id)
        .execute(&database.pool)
        .await
        .unwrap();
    let new_id = Uuid::new_v4();
    let new_generation = sqlx::query_scalar::<_, i64>(
        "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test') RETURNING auth_generation",
    )
        .bind(new_id)
        .bind(&username)
        .fetch_one(&database.pool)
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    assert_eq!(
        stale.await.unwrap().unwrap().status,
        ProfilePublishStatus::Unauthorized
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pep_nodes WHERE owner_id=$1")
            .bind(new_id)
            .fetch_one(&database.pool)
            .await
            .unwrap(),
        0
    );

    assert_eq!(
        service.public_vcard(&username).await.unwrap(),
        PublicVCard::Profile(None)
    );
    assert_eq!(
        service
            .public_vcard("missing-profile-account")
            .await
            .unwrap(),
        PublicVCard::MissingAccount
    );
    sqlx::query("UPDATE users SET is_disabled=TRUE WHERE id=$1")
        .bind(new_id)
        .execute(&database.pool)
        .await
        .unwrap();
    assert_eq!(
        service.public_vcard(&username).await.unwrap(),
        PublicVCard::MissingAccount
    );
    sqlx::query("UPDATE users SET is_disabled=FALSE WHERE id=$1")
        .bind(new_id)
        .execute(&database.pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE vcards ALTER COLUMN payload DROP NOT NULL")
        .execute(&database.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO vcards(user_id,payload) VALUES($1,NULL)")
        .bind(new_id)
        .execute(&database.pool)
        .await
        .unwrap();
    assert!(db::get_vcard(&database.pool, new_id).await.is_err());
    assert!(service.public_vcard(&username).await.is_err());
    let config = db::default_pep_node_config(AVATAR_METADATA).into();
    let items = [(
        "current",
        "<item id='current'><metadata xmlns='urn:xmpp:avatar:metadata'/></item>",
    )];
    assert!(service
        .publish_avatar_metadata(
            ProfilePepWrite {
                user_id: new_id,
                auth_generation: new_generation,
                connection_id: Uuid::new_v4(),
                node: AVATAR_METADATA,
                requested: &config,
                enforce_preconditions: false,
                items: &items,
                max_nodes: 10,
                max_storage_bytes: 1_000_000,
            },
            &direct_snapshot_deliveries,
        )
        .await
        .is_err());
    let still_corrupt: bool =
        sqlx::query_scalar("SELECT payload IS NULL FROM vcards WHERE user_id=$1")
            .bind(new_id)
            .fetch_one(&database.pool)
            .await
            .unwrap();
    assert!(
        still_corrupt,
        "failed publication must not overwrite the damaged row"
    );
    database.finish().await;
}
