//! PostgreSQL tests for personal history identity, MAM reads and offline delivery.

use super::*;
use northstar_archive_application::{
    FederatedMamMetadataCommand, MamAccountOutcome, MamLocalAuthority, MamMetadataCommand,
    MamMetadataResult, MamQueryCommand, MamQueryRepository, MamQueryResult, MamQueryScope,
    MamRoomReadAuthority,
};
use northstar_message_core::{OfflineStoreOutcome, OfflineStorePolicy};
use northstar_muc_xmpp::federated_muc::render_federated_mam_stream;
use std::sync::Arc;
use tokio::sync::Barrier;

fn personal_identity<'a>(
    kind: &'a str,
    actor_scope_raw: &'a str,
    actor_scope: &'a str,
    target_scope: &'a str,
    identity_value: &'a str,
    payload: &str,
) -> PersonalHistoryIdentity<'a> {
    PersonalHistoryIdentity {
        kind,
        actor_scope_raw,
        actor_scope,
        target_scope,
        identity_value,
        payload_authenticators:
            northstar_abuse_application::guard::test_personal_message_content_keyring()
                .authenticators(payload.as_bytes()),
        legacy_payload_digest: Sha256::digest(payload.as_bytes()).into(),
    }
}

fn page_query() -> MamArchiveQuery {
    MamArchiveQuery {
        with_jid: None,
        start: None,
        end: None,
        before_id: None,
        after_id: None,
        ids: Vec::new(),
        page: MamRsmPage::First,
        max: 50,
    }
}

const SNAPSHOT_ROOM_JID: &str = "snapshot-room@conference.local.test";
const SNAPSHOT_MAM_VIEWER: &str = "remote@remote.test/phone";
const HIDE_MAM_ROOM_IDENTITIES: &str = "UPDATE muc_rooms SET non_anonymous=FALSE WHERE id=$1";

fn render_snapshot_mam(
    page: &northstar_archive_application::FederatedMamStreamPage,
) -> Result<Vec<String>> {
    render_federated_mam_stream(
        page,
        SNAPSHOT_ROOM_JID,
        SNAPSHOT_MAM_VIEWER,
        "i",
        Some("q"),
        false,
        Uuid::from_u128(9),
    )
}

async fn snapshot_mam_outbox(pool: &PgPool) -> Vec<(Uuid, String, String)> {
    sqlx::query_as("SELECT id,target_domain,stanza FROM s2s_outbox ORDER BY enqueue_sequence")
        .fetch_all(pool)
        .await
        .unwrap()
}

fn assert_snapshot_mam_pair(entries: &[(Uuid, String, String)], archive_id: Uuid, reveal: bool) {
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|(_, domain, _)| domain == "remote.test"));
    let (outbox_id, _, stored) = &entries[0];
    assert!(!stored.contains("forged"));
    let document = roxmltree::Document::parse(stored).unwrap();
    let outer = document.root_element();
    assert_eq!(outer.tag_name().name(), "message");
    assert_eq!(outer.attribute("from"), Some(SNAPSHOT_ROOM_JID));
    assert_eq!(outer.attribute("to"), Some(SNAPSHOT_MAM_VIEWER));
    let result = outer.first_element_child().unwrap();
    assert!(result.has_tag_name(("urn:xmpp:mam:2", "result")));
    let archive_id = archive_id.to_string();
    assert_eq!(result.attribute("id"), Some(archive_id.as_str()));
    assert_eq!(result.attribute("queryid"), Some("q"));
    let inner = result
        .first_element_child()
        .unwrap()
        .children()
        .find(|node| node.has_tag_name(("jabber:client", "message")))
        .unwrap();
    assert!(inner.attributes().all(|attr| attr.name() != "to"));
    assert_eq!(
        inner.attribute("from"),
        Some("snapshot-room@conference.local.test/Sender")
    );
    for (message, uid) in [(outer, outbox_id.to_string()), (inner, archive_id.clone())] {
        let mut sids = message
            .children()
            .filter(|node| node.has_tag_name(("urn:xmpp:sid:0", "stanza-id")));
        let sid = sids.next().unwrap();
        assert_eq!(sid.attribute("by"), Some(SNAPSHOT_ROOM_JID));
        assert_eq!(sid.attribute("id"), Some(uid.as_str()));
        assert!(sids.next().is_none());
    }
    let identities: Vec<_> = inner
        .descendants()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc#user")
        })
        .collect();
    if reveal {
        assert_eq!(identities.len(), 2);
        assert_eq!(identities[0].tag_name().name(), "x");
        assert_eq!(identities[1].tag_name().name(), "item");
        assert_eq!(
            identities[1].attribute("jid"),
            Some("sender@remote.test/Phone")
        );
    } else {
        assert!(identities.is_empty());
        assert!(!stored.contains("sender@remote.test"));
    }

    let terminal = roxmltree::Document::parse(&entries[1].2).unwrap();
    let iq = terminal.root_element();
    assert_eq!(iq.tag_name().name(), "iq");
    assert_eq!(iq.attribute("type"), Some("result"));
    assert_eq!(iq.attribute("id"), Some("i"));
    assert_eq!(iq.attribute("to"), Some(SNAPSHOT_MAM_VIEWER));
    let fin = iq.first_element_child().unwrap();
    assert!(fin.has_tag_name(("urn:xmpp:mam:2", "fin")));
    assert_eq!(fin.attribute("complete"), Some("true"));
    let rsm = fin.first_element_child().unwrap();
    assert!(rsm.has_tag_name(("http://jabber.org/protocol/rsm", "set")));
    for (name, value) in [
        ("first", archive_id.as_str()),
        ("last", archive_id.as_str()),
        ("count", "1"),
    ] {
        let field = rsm
            .children()
            .find(|node| node.has_tag_name(("http://jabber.org/protocol/rsm", name)))
            .unwrap();
        assert_eq!(field.text(), Some(value));
        if name == "first" {
            assert_eq!(field.attribute("index"), Some("0"));
        }
    }
}

fn maximum_canonical_full_jid(localpart: char, resourcepart: char) -> String {
    // Strict IDNA applies the DNS wire-length limit: three 63-octet
    // labels, two separators, and one 62-octet label make its largest
    // accepted 253-octet domain. Together with maximum local/resource
    // parts this is a 2301-octet canonical full JID. Two such scopes
    // already exceed PostgreSQL's B-tree tuple limit in the former raw
    // composite identity key.
    // Four labels retain three separators.  Their label octets must sum
    // to 250, not 251: 63 + 63 + 63 + 61 + 3 dots is the RFC DNS
    // wire-length boundary of 253 octets.  Keeping the construction
    // exact matters here because this test protects the B-tree identity
    // bound for the largest canonical XMPP domain.
    let domainpart = [63, 63, 63, 61]
        .into_iter()
        .map(|length| "d".repeat(length))
        .collect::<Vec<_>>()
        .join(".");
    assert_eq!(domainpart.len(), 253);
    let jid = format!(
        "{}@{}/{}",
        localpart.to_string().repeat(1023),
        domainpart,
        resourcepart.to_string().repeat(1023)
    );
    assert_eq!(jid.len(), 2301);
    assert_eq!(northstar_xmpp_types::jid::canonicalize(&jid).unwrap(), jid);
    jid
}

#[test]
fn maximum_canonical_full_jid_uses_the_253_octet_dns_boundary() {
    let jid = maximum_canonical_full_jid('a', 'r');
    let (_, domain_and_resource) = jid
        .split_once('@')
        .expect("constructed full JID has a localpart separator");
    let (domain, _) = domain_and_resource
        .split_once('/')
        .expect("constructed full JID has a resource separator");
    assert_eq!(domain.len(), 253);
    assert_eq!(
        domain.split('.').map(str::len).collect::<Vec<_>>(),
        vec![63, 63, 63, 61]
    );
    assert_eq!(jid.len(), 2301);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn personal_message_admission_accepts_maximum_scope_with_bounded_identity_index() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(60))
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("history_identity_test_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .unwrap();
    eprintln!("isolated_schema_created={schema}");
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(60))
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    crate::support::migrate(&pool).await.unwrap();

    let owner_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'maxscope','test')")
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
    let actor_scope = maximum_canonical_full_jid('a', 'r');
    let target_scope = maximum_canonical_full_jid('b', 's');
    let archive_id = Uuid::new_v4();
    let writes = [PersonalArchiveWrite {
        id: archive_id,
        owner_id,
        peer_jid: "peer@remote.test",
        stanza: "<message id='maximum-scope'/>",
        encrypted: false,
        stanza_id: Some("maximum-scope"),
    }];
    let payload = "<message id='maximum-scope'><body>bounded index</body></message>";
    let identity = personal_identity(
        "local-origin",
        &actor_scope,
        &actor_scope,
        &target_scope,
        "maximum-scope-origin",
        payload,
    );
    assert!(matches!(
        admit_personal_history(&pool, Some(&identity), &writes)
            .await
            .unwrap(),
        PersonalHistoryAdmission::Stored(ids) if ids == vec![archive_id]
    ));
    assert!(matches!(
        admit_personal_history(&pool, Some(&identity), &writes)
            .await
            .unwrap(),
        PersonalHistoryAdmission::Replay(ids) if ids == vec![archive_id]
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM personal_message_admissions")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );

    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn mam_policy_and_room_reads_keep_one_authorization_snapshot() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(60))
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("history_identity_test_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .unwrap();
    eprintln!("isolated_schema_created={schema}");
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(60))
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    crate::support::migrate(&pool).await.unwrap();

    let viewer_id = Uuid::new_v4();
    let viewer_account = MamLocalAuthority {
        id: viewer_id,
        username: format!("mam-snapshot-{}", &viewer_id.simple().to_string()[..12]),
        auth_generation: 0,
    };
    let local_viewer = MamRoomReadAuthority {
        full_jid: format!("{}@local.test/phone", viewer_account.username),
        occupancy: None,
    };
    let federated_viewer = MamRoomReadAuthority {
        full_jid: SNAPSHOT_MAM_VIEWER.to_owned(),
        occupancy: None,
    };
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
        .bind(viewer_id)
        .bind(&viewer_account.username)
        .execute(&pool)
        .await
        .unwrap();

    // A sensitive HTTP history read holds the exact account and bearer
    // rows from authorization through the complete MAM projection.  A
    // concurrent logout must therefore serialize after that projection,
    // and the same bearer must be rejected immediately afterwards.
    let bearer = northstar_auth_postgres::users::create_api_session(&pool, viewer_id, 1)
        .await
        .unwrap();
    let archive_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO message_archive(
                 id,owner_id,peer_jid,peer_full_jid,stanza,encrypted)
             VALUES($1,$2,'peer@remote.test','peer@remote.test/device',
                    '<message xmlns=\"jabber:client\" id=\"authorized-history\"/>',FALSE)",
    )
    .bind(archive_id)
    .bind(viewer_id)
    .execute(&pool)
    .await
    .unwrap();
    let mut authorized_history = pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *authorized_history)
        .await
        .unwrap();
    assert!(northstar_auth_postgres::users::authorize_user_in_tx(
        &mut authorized_history,
        viewer_id,
        0,
        &bearer,
    )
    .await
    .unwrap());
    let mut logout = {
        let pool = pool.clone();
        let bearer = bearer.clone();
        tokio::spawn(async move {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("SET LOCAL lock_timeout='5s'")
                .execute(&mut *tx)
                .await
                .unwrap();
            let deleted = northstar_auth_postgres::users::delete_api_session_audited_in_tx(
                &mut tx,
                &bearer,
                Uuid::new_v4(),
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
            deleted
        })
    };
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut logout)
            .await
            .is_err(),
        "logout committed before the authorized history projection finished"
    );
    let page =
        mam_user_archive_page_in_transaction(&mut authorized_history, viewer_id, &page_query())
            .await
            .unwrap()
            .unwrap();
    assert!(page.rows.iter().any(|row| row.id == archive_id));
    authorized_history.commit().await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(5), &mut logout)
        .await
        .expect("logout deadlocked with authorized history")
        .unwrap());
    let mut stale = pool.begin().await.unwrap();
    assert!(!northstar_auth_postgres::users::authorize_user_in_tx(
        &mut stale, viewer_id, 0, &bearer
    )
    .await
    .unwrap());
    stale.rollback().await.unwrap();

    let old_preferences = MamPreferences {
        default_policy: "never".to_owned(),
        always: vec!["peer@remote.test".to_owned()],
        never: Vec::new(),
    };
    let new_preferences = MamPreferences {
        default_policy: "always".to_owned(),
        always: Vec::new(),
        never: vec!["peer@remote.test".to_owned()],
    };
    assert_eq!(
        set_mam_preferences(&pool, &viewer_account, &old_preferences)
            .await
            .unwrap(),
        MamAccountOutcome::Authorized(())
    );
    let mut preference_snapshot = pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *preference_snapshot)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT default_policy FROM mam_preferences WHERE user_id=$1",
        )
        .bind(viewer_id)
        .fetch_one(&mut *preference_snapshot)
        .await
        .unwrap(),
        "never"
    );
    assert_eq!(
        set_mam_preferences(&pool, &viewer_account, &new_preferences)
            .await
            .unwrap(),
        MamAccountOutcome::Authorized(())
    );
    assert_eq!(
        mam_preferences_in_transaction(&mut preference_snapshot, viewer_id)
            .await
            .unwrap(),
        old_preferences,
        "default policy and explicit JIDs must come from one snapshot"
    );
    preference_snapshot.commit().await.unwrap();
    assert_eq!(
        mam_preferences(&pool, &viewer_account).await.unwrap(),
        MamAccountOutcome::Authorized(new_preferences)
    );
    assert!(!archive_allowed(&pool, viewer_id, "peer@remote.test/Phone")
        .await
        .unwrap());

    assert_eq!(
        set_mam_preferences(
            &pool,
            &viewer_account,
            &MamPreferences {
                default_policy: "never".to_owned(),
                always: vec!["peer@remote.test/Phone".to_owned()],
                never: vec!["peer@remote.test".to_owned()],
            },
        )
        .await
        .unwrap(),
        MamAccountOutcome::Authorized(())
    );
    assert!(archive_allowed(&pool, viewer_id, "peer@remote.test/Phone")
        .await
        .unwrap());
    assert!(
        !archive_allowed(&pool, viewer_id, "peer@remote.test/Laptop")
            .await
            .unwrap()
    );
    assert_eq!(
        set_mam_preferences(
            &pool,
            &viewer_account,
            &MamPreferences {
                default_policy: "never".to_owned(),
                always: vec!["peer@remote.test".to_owned()],
                never: vec!["peer@remote.test/Phone".to_owned()],
            },
        )
        .await
        .unwrap(),
        MamAccountOutcome::Authorized(())
    );
    assert!(!archive_allowed(&pool, viewer_id, "peer@remote.test/Phone")
        .await
        .unwrap());
    assert!(archive_allowed(&pool, viewer_id, "peer@remote.test/Laptop")
        .await
        .unwrap());

    assert_eq!(
        set_mam_preferences(
            &pool,
            &viewer_account,
            &MamPreferences {
                default_policy: "roster".to_owned(),
                always: Vec::new(),
                never: Vec::new(),
            },
        )
        .await
        .unwrap(),
        MamAccountOutcome::Authorized(())
    );
    sqlx::query("INSERT INTO roster_items(owner_id,contact_jid) VALUES($1,$2)")
        .bind(viewer_id)
        .bind("peer@remote.test")
        .execute(&pool)
        .await
        .unwrap();
    assert!(archive_allowed(&pool, viewer_id, "peer@remote.test/Phone")
        .await
        .unwrap());
    sqlx::query("DELETE FROM roster_items WHERE owner_id=$1")
        .bind(viewer_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(!archive_allowed(&pool, viewer_id, "peer@remote.test/Phone")
        .await
        .unwrap());

    let room_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO muc_rooms(id,localpart,owner_id,members_only,occupant_id_secret)
             VALUES($1,'snapshot-room',$2,TRUE,$3)",
    )
    .bind(room_id)
    .bind(viewer_id)
    .bind(vec![7_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO muc_affiliations(room_id,user_id,affiliation)
             VALUES($1,$2,'member')",
    )
    .bind(room_id)
    .bind(viewer_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO muc_external_affiliations(room_id,jid,affiliation)
             VALUES($1,'remote@remote.test','member')",
    )
    .bind(room_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE muc_rooms SET occupant_id_secret=NULL WHERE id=$1")
        .bind(room_id)
        .execute(&pool)
        .await
        .unwrap();
    let local_secret =
        match authorize_mam_room(&pool, "snapshot-room", &viewer_account, &local_viewer)
            .await
            .unwrap()
        {
            MamRoomReadOutcome::Allowed { access, .. } => access.occupant_id_secret,
            other => panic!("legacy local room was not authorized: {other:?}"),
        };
    assert_eq!(local_secret.len(), 32);
    sqlx::query("UPDATE muc_rooms SET occupant_id_secret=NULL WHERE id=$1")
        .bind(room_id)
        .execute(&pool)
        .await
        .unwrap();
    let federated_secret =
        match authorize_federated_mam_room(&pool, "snapshot-room", &federated_viewer)
            .await
            .unwrap()
        {
            MamRoomReadOutcome::Allowed { access, .. } => access.occupant_id_secret,
            other => panic!("legacy federated room was not authorized: {other:?}"),
        };
    assert_eq!(federated_secret.len(), 32);
    assert_eq!(
        sqlx::query_scalar::<_, Option<Vec<u8>>>(
            "SELECT occupant_id_secret FROM muc_rooms WHERE id=$1"
        )
        .bind(room_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        Some(federated_secret)
    );
    let message_id = Uuid::new_v4();
    let fixtures = roxmltree::Document::parse(include_str!(
        "../../../../crates/contexts/room/northstar-room-core/src/stanza/mam_projection/fixtures.xml"
    ))
    .unwrap();
    let stored = fixtures
        .root_element()
        .children()
        .find(|node| node.attribute("name") == Some("poisoned"))
        .unwrap()
        .first_element_child()
        .unwrap()
        .text()
        .unwrap();
    sqlx::query(
        "INSERT INTO muc_messages
             (id,room_id,sender_jid,nick,stanza,encrypted,message_kind,actor_scope)
             VALUES($1,$2,'sender@remote.test/Phone','Sender',$3,FALSE,
                    'discussion','sender@remote.test')",
    )
    .bind(message_id)
    .bind(room_id)
    .bind(stored)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(HIDE_MAM_ROOM_IDENTITIES)
        .bind(room_id)
        .execute(&pool)
        .await
        .unwrap();
    let metadata_repository =
        northstar_workflows::mam_repository::PostgresMamRepository::new(pool.clone());
    let federated_metadata = |actor_full_jid: &str| {
        FederatedMamMetadataCommand::from_authenticated_actor(
            "snapshot-room".to_owned(),
            "remote.test",
            actor_full_jid,
            None,
        )
        .unwrap()
    };
    let federated_scope = || MamQueryScope::FederatedRoom {
        localpart: "snapshot-room".to_owned(),
        authority: federated_viewer.clone(),
    };
    let metadata = metadata_repository
        .get_federated_boundaries(federated_metadata("remote@remote.test/phone"))
        .await
        .unwrap();
    assert!(matches!(
        metadata,
        MamMetadataResult::Boundaries {
            room: Some(access),
            start: Some(ArchiveBoundary { id: start, .. }),
            end: Some(ArchiveBoundary { id: end, .. }),
        } if !access.reveal_real_jid() && start == message_id && end == message_id
    ));
    assert!(matches!(
        metadata_repository
            .get_federated_boundaries(federated_metadata("outsider@remote.test/phone"))
            .await
            .unwrap(),
        MamMetadataResult::Forbidden
    ));
    assert!(matches!(
        metadata_repository
            .get_boundaries(MamMetadataCommand {
                scope: federated_scope(),
            })
            .await
            .unwrap(),
        MamMetadataResult::Forbidden
    ));
    assert!(matches!(
        metadata_repository
            .query_archive(MamQueryCommand {
                scope: federated_scope(),
                query: page_query(),
            })
            .await
            .unwrap(),
        MamQueryResult::Forbidden
    ));

    let mut peer_query = page_query();
    peer_query.with_jid = Some("sender@remote.test/Phone".to_owned());
    assert!(matches!(
        mam_room_archive_page_authorized(
            &pool,
            "snapshot-room",
            &viewer_account,
            &local_viewer,
            &peer_query,
        )
        .await
        .unwrap(),
        MamRoomReadOutcome::Forbidden
    ));
    assert!(matches!(
        mam_federated_room_archive_page_authorized(
            &pool,
            "snapshot-room",
            &federated_viewer,
            &peer_query,
        )
        .await
        .unwrap(),
        MamRoomReadOutcome::Forbidden
    ));
    sqlx::query("UPDATE muc_rooms SET non_anonymous=TRUE WHERE id=$1")
        .bind(room_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        mam_room_archive_page_authorized(
            &pool,
            "snapshot-room",
            &viewer_account,
            &local_viewer,
            &peer_query,
        )
        .await
        .unwrap(),
        MamRoomReadOutcome::Allowed {
            value: Some(ArchivePage { total: 1, .. }),
            ..
        }
    ));
    assert!(matches!(
        mam_federated_room_archive_page_authorized(
            &pool,
            "snapshot-room",
            &federated_viewer,
            &peer_query,
        )
        .await
        .unwrap(),
        MamRoomReadOutcome::Allowed {
            value: Some(ArchivePage { total: 1, .. }),
            ..
        }
    ));

    let mut local_snapshot = pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *local_snapshot)
        .await
        .unwrap();
    assert!(mam_account_is_current(&mut local_snapshot, &viewer_account)
        .await
        .unwrap());
    let local_access = match authorize_mam_room_in_transaction(
        &mut local_snapshot,
        "snapshot-room",
        viewer_id,
        &local_viewer,
        false,
    )
    .await
    .unwrap()
    {
        MamRoomReadOutcome::Allowed { access, .. } => access,
        other => panic!("member was not authorized: {other:?}"),
    };
    sqlx::query(
        "UPDATE muc_affiliations SET affiliation='outcast'
              WHERE room_id=$1 AND user_id=$2",
    )
    .bind(room_id)
    .bind(viewer_id)
    .execute(&pool)
    .await
    .unwrap();
    let local_boundaries = archive_boundaries_for_in_transaction(
        &mut local_snapshot,
        MamArchiveSource::Muc(local_access.room_id),
        Some(viewer_id),
    )
    .await
    .unwrap();
    assert_eq!(local_boundaries.0.map(|row| row.id), Some(message_id));
    let local_page = mam_archive_page_for_in_transaction(
        &mut local_snapshot,
        MamArchiveSource::Muc(local_access.room_id),
        Some(viewer_id),
        &page_query(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(local_page.rows[0].id, message_id);
    local_snapshot.commit().await.unwrap();
    assert!(matches!(
        mam_room_archive_page_authorized(
            &pool,
            "snapshot-room",
            &viewer_account,
            &local_viewer,
            &page_query(),
        )
        .await
        .unwrap(),
        MamRoomReadOutcome::Forbidden
    ));

    let mut federated_guard = FederatedMamRoomGuard::acquire(&pool, "snapshot-room")
        .await
        .unwrap()
        .unwrap();
    let federated_room_id = federated_guard.room_id();
    let mut federated_snapshot = federated_guard.begin_snapshot().await.unwrap();
    let (federated_access, federated_page) =
        match mam_federated_room_archive_page_authorized_in_transaction(
            &mut federated_snapshot,
            federated_room_id,
            "snapshot-room",
            &federated_viewer,
            &page_query(),
        )
        .await
        .unwrap()
        {
            MamRoomReadOutcome::Allowed {
                access,
                value: Some(page),
            } => (access, page),
            other => panic!("federated member was not authorized: {other:?}"),
        };
    let writer_pool = pool.clone();
    let mut affiliation_writer = tokio::spawn(async move {
        sqlx::query(
            "UPDATE muc_external_affiliations SET affiliation='outcast'
                  WHERE room_id=$1 AND jid='remote@remote.test'",
        )
        .bind(room_id)
        .execute(&writer_pool)
        .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut affiliation_writer)
            .await
            .is_err(),
        "the federated authority row must stay locked through its durable projection"
    );
    assert_eq!(federated_access.room_id, room_id);
    assert_eq!(federated_page.rows[0].id, message_id);
    federated_snapshot.commit().await.unwrap();
    federated_guard.release().await;
    affiliation_writer.await.unwrap().unwrap();
    assert!(matches!(
        mam_federated_room_archive_page_authorized(
            &pool,
            "snapshot-room",
            &federated_viewer,
            &page_query(),
        )
        .await
        .unwrap(),
        MamRoomReadOutcome::Forbidden
    ));
    assert!(matches!(
        metadata_repository
            .get_federated_boundaries(federated_metadata("remote@remote.test/phone"))
            .await
            .unwrap(),
        MamMetadataResult::Forbidden
    ));

    sqlx::query(
        "UPDATE muc_external_affiliations SET affiliation='member'
              WHERE room_id=$1 AND jid='remote@remote.test'",
    )
    .bind(room_id)
    .execute(&pool)
    .await
    .unwrap();

    // A MUC writer takes namespace 29 before its room row. A waiting MAM
    // read must hold neither that row nor a repeatable-read snapshot: the
    // writer must finish, and the reader must see the new outcast row.
    let race_room_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO muc_rooms(id,localpart,owner_id,members_only,occupant_id_secret)
             VALUES($1,'race-room',$2,FALSE,$3)",
    )
    .bind(race_room_id)
    .bind(viewer_id)
    .bind(vec![9_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    let mut authority_writer = pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::TEXT, 29))")
        .bind(race_room_id.to_string())
        .execute(&mut *authority_writer)
        .await
        .unwrap();
    let writer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *authority_writer)
        .await
        .unwrap();
    let reader_pool = pool.clone();
    let waiting_read = tokio::spawn(async move {
        let authority = MamRoomReadAuthority {
            full_jid: "new@remote.test/phone".to_owned(),
            occupancy: None,
        };
        authorize_federated_mam_room(&reader_pool, "race-room", &authority).await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                         SELECT 1 FROM pg_locks held
                         JOIN pg_locks waiting
                           ON waiting.locktype='advisory'
                          AND waiting.classid=held.classid
                          AND waiting.objid=held.objid
                          AND waiting.objsubid=held.objsubid
                          AND NOT waiting.granted
                        WHERE held.locktype='advisory'
                          AND held.pid=$1 AND held.granted
                     )",
            )
            .bind(writer_pid)
            .fetch_one(&pool)
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("federated MAM read did not wait for the writer's advisory lock");
    tokio::time::timeout(Duration::from_secs(5), async {
        sqlx::query(HIDE_MAM_ROOM_IDENTITIES)
            .bind(race_room_id)
            .execute(&mut *authority_writer)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO muc_external_affiliations(room_id,jid,affiliation)
                 VALUES($1,'new@remote.test','outcast')",
        )
        .bind(race_room_id)
        .execute(&mut *authority_writer)
        .await
        .unwrap();
        authority_writer.commit().await.unwrap();
    })
    .await
    .expect("room writer blocked behind a waiting MAM read");
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), waiting_read)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        MamRoomReadOutcome::Forbidden
    ));

    // Dropping an admitted task must close its locked PostgreSQL session,
    // not hand that session back to the pool with namespace 29 held.
    let mut probe = pool.acquire().await.unwrap();
    let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
    let cancelled_pool = pool.clone();
    let held_read = tokio::spawn(async move {
        let _guard = FederatedMamRoomGuard::acquire(&cancelled_pool, "race-room")
            .await
            .unwrap()
            .unwrap();
        let _ = locked_tx.send(());
        std::future::pending::<()>().await;
    });
    tokio::time::timeout(Duration::from_secs(5), locked_rx)
        .await
        .unwrap()
        .unwrap();
    held_read.abort();
    let _ = held_read.await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let acquired: bool =
                sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended($1::TEXT, 29))")
                    .bind(race_room_id.to_string())
                    .fetch_one(&mut *probe)
                    .await
                    .unwrap();
            if acquired {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancelled MAM task retained a session advisory lock");
    let unlocked: bool =
        sqlx::query_scalar("SELECT pg_advisory_unlock(hashtextextended($1::TEXT, 29))")
            .bind(race_room_id.to_string())
            .fetch_one(&mut *probe)
            .await
            .unwrap();
    assert!(unlocked);
    drop(probe);

    // Rejecting the terminal response rolls back the prefix and must not
    // wake delivery. Exercise the application port as well as the SQL.
    use northstar_archive_application::{
        FederatedMamAdmissionOutcome, FederatedMamOutboxLimits, FederatedMamStreamRequest,
        MamService,
    };
    let (wake, mut receiver) = tokio::sync::mpsc::channel(2);
    let limits = FederatedMamOutboxLimits {
        ttl_seconds: 300,
        max_rows: 1,
        max_bytes: 1024 * 1024,
        max_per_domain: 1,
    };
    let service = MamService::new(
        northstar_workflows::mam_repository::PostgresMamRepository::new(pool.clone()),
        limits,
        wake.clone(),
    );
    let query = page_query();
    let request =
        FederatedMamStreamRequest::new("remote.test", "snapshot-room", &federated_viewer, &query);
    let render = render_snapshot_mam;
    assert_eq!(
        service
            .admit_federated_room_stream(request, render)
            .await
            .unwrap(),
        FederatedMamAdmissionOutcome::OutboxRejected,
    );
    assert!(receiver.try_recv().is_err());
    assert!(service
        .admit_federated_room_stream(request, |_| { anyhow::bail!("injected renderer failure") })
        .await
        .is_err());
    assert!(receiver.try_recv().is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM s2s_outbox")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0,
    );
    assert_eq!(
        service
            .admit_federated_room_stream(
                FederatedMamStreamRequest {
                    localpart: "missing-room",
                    ..request
                },
                |_| panic!("missing room must not reach the renderer"),
            )
            .await
            .unwrap(),
        FederatedMamAdmissionOutcome::Missing
    );
    assert!(receiver.try_recv().is_err());

    let service = Arc::new(MamService::new(
        northstar_workflows::mam_repository::PostgresMamRepository::new(pool.clone()),
        FederatedMamOutboxLimits {
            max_rows: 8,
            max_per_domain: 8,
            ..limits
        },
        wake,
    ));
    let before = super::mam_read_authority_tests::room_mam_evidence(&pool, room_id).await;
    assert_eq!(before.len(), 1);
    assert_eq!(before[0]["stanza"], stored);
    assert!(before[0]["retracted_at"].is_null());
    assert_eq!(before[0]["message_kind"], "discussion");
    let mut terminal_gate = pool.begin().await.unwrap();
    sqlx::query(
        "CREATE FUNCTION pause_mam_fin() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
            IF left(NEW.stanza, 4) = '<iq ' AND position('<fin ' IN NEW.stanza) > 0 THEN
                PERFORM pg_advisory_xact_lock(hashtext(current_schema()), 689);
            END IF;
            RETURN NEW;
         END; $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER pause_mam_fin BEFORE INSERT ON s2s_outbox
         FOR EACH ROW EXECUTE FUNCTION pause_mam_fin()",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext(current_schema()), 689)")
        .execute(&mut *terminal_gate)
        .await
        .unwrap();
    let gate_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *terminal_gate)
        .await
        .unwrap();
    let waiting_stream = {
        let service = Arc::clone(&service);
        let authority = federated_viewer.clone();
        let query = query.clone();
        tokio::spawn(async move {
            service
                .admit_federated_room_stream(
                    FederatedMamStreamRequest::new(
                        "remote.test",
                        "snapshot-room",
                        &authority,
                        &query,
                    ),
                    render_snapshot_mam,
                )
                .await
        })
    };
    let stream_pid = crate::support::blocked_backend(&pool, gate_pid).await;
    let revocation = {
        let pool = pool.clone();
        tokio::spawn(async move {
            sqlx::query(HIDE_MAM_ROOM_IDENTITIES)
                .bind(room_id)
                .execute(&pool)
                .await
                .unwrap()
        })
    };
    crate::support::blocked_backend(&pool, stream_pid).await;
    assert!(snapshot_mam_outbox(&pool).await.is_empty());
    assert!(receiver.try_recv().is_err());
    terminal_gate.commit().await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), waiting_stream)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        FederatedMamAdmissionOutcome::Queued
    );
    receiver
        .try_recv()
        .expect("committed stream wakes delivery");
    assert!(receiver.try_recv().is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM s2s_outbox")
            .fetch_one(&pool)
            .await
            .unwrap(),
        2
    );
    assert_snapshot_mam_pair(&snapshot_mam_outbox(&pool).await, message_id, true);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), revocation)
            .await
            .unwrap()
            .unwrap()
            .rows_affected(),
        1
    );
    drop(receiver);
    assert_eq!(
        service
            .admit_federated_room_stream(request, render)
            .await
            .unwrap(),
        FederatedMamAdmissionOutcome::Queued
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM s2s_outbox")
            .fetch_one(&pool)
            .await
            .unwrap(),
        4,
        "a closed wake channel cannot undo committed delivery"
    );
    assert_snapshot_mam_pair(&snapshot_mam_outbox(&pool).await[2..], message_id, false);
    assert_eq!(
        super::mam_read_authority_tests::room_mam_evidence(&pool, room_id).await,
        before
    );

    // The exact room UUID remains fenced until the authorized projection
    // ends. A destroy plus same-localpart recreation cannot redirect the
    // in-flight read to the replacement room.
    let mut identity_guard = FederatedMamRoomGuard::acquire(&pool, "snapshot-room")
        .await
        .unwrap()
        .unwrap();
    let identity_room_id = identity_guard.room_id();
    let mut identity_fence = identity_guard.begin_snapshot().await.unwrap();
    let access = match mam_federated_room_archive_page_authorized_in_transaction(
        &mut identity_fence,
        identity_room_id,
        "snapshot-room",
        &federated_viewer,
        &page_query(),
    )
    .await
    .unwrap()
    {
        MamRoomReadOutcome::Allowed { access, .. } => access,
        other => panic!("room identity fence was not authorized: {other:?}"),
    };
    assert_eq!(access.room_id, room_id);
    let replacement_id = Uuid::new_v4();
    let replacement_pool = pool.clone();
    let mut replacement = tokio::spawn(async move {
        let mut tx = replacement_pool.begin().await.unwrap();
        sqlx::query(
            "UPDATE muc_rooms
                    SET destroyed_at=clock_timestamp(),destroyed_operation_id=$2
                  WHERE id=$1",
        )
        .bind(room_id)
        .bind(Uuid::new_v4())
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO muc_rooms(id,localpart,owner_id,members_only,occupant_id_secret)
                 VALUES($1,'snapshot-room',$2,TRUE,$3)",
        )
        .bind(replacement_id)
        .bind(viewer_id)
        .bind(vec![8_u8; 32])
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut replacement)
            .await
            .is_err(),
        "destroy/recreate must wait for the exact authorized room snapshot"
    );
    identity_fence.commit().await.unwrap();
    identity_guard.release().await;
    replacement.await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM muc_rooms
                  WHERE localpart='snapshot-room' AND destroyed_at IS NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        replacement_id
    );

    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn mix_source_dedupe_and_mam_visibility_share_one_snapshot_scope() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(60))
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("history_identity_test_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .unwrap();
    // Emitted only after this test has acquired ownership. The outer
    // harness can then recover a schema left by a panic without ever
    // dropping a coincidentally pre-existing namespace.
    eprintln!("isolated_schema_created={schema}");
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(60))
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(statement.as_str()))
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    crate::support::migrate(&pool).await.unwrap();

    let owner_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'mamowner','test')")
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();
    let recipient_owner_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'mamrecipient','test')")
        .bind(recipient_owner_id)
        .execute(&pool)
        .await
        .unwrap();

    let history_barrier = Arc::new(Barrier::new(3));
    let mut history_tasks = Vec::new();
    for _ in 0..2 {
        let pool = pool.clone();
        let history_barrier = Arc::clone(&history_barrier);
        history_tasks.push(tokio::spawn(async move {
                let sender_archive_id = Uuid::new_v4();
                let recipient_archive_id = Uuid::new_v4();
                let writes = [
                    PersonalArchiveWrite {
                        id: sender_archive_id,
                        owner_id,
                        peer_jid: "mamrecipient@local.test/Phone",
                        stanza: "<message id='history-sender'/>",
                        encrypted: false,
                        stanza_id: Some("client-history-id"),
                    },
                    PersonalArchiveWrite {
                        id: recipient_archive_id,
                        owner_id: recipient_owner_id,
                        peer_jid: "mamowner@local.test/Laptop",
                        stanza: "<message id='history-recipient'/>",
                        encrypted: false,
                        stanza_id: Some("client-history-id"),
                    },
                ];
                let identity = personal_identity(
                    "local-origin",
                    "mamowner@local.test",
                    "mamowner@local.test",
                    "mamrecipient@local.test",
                    "origin-atomic-1",
                    "<message id='client-history-id'><origin-id xmlns='urn:xmpp:sid:0' id='origin-atomic-1'/></message>",
                );
                history_barrier.wait().await;
                admit_personal_history(&pool, Some(&identity), &writes)
                    .await
                    .unwrap()
            }));
    }
    history_barrier.wait().await;
    let history_outcomes = futures::future::join_all(history_tasks)
        .await
        .into_iter()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    assert_eq!(
        history_outcomes
            .iter()
            .filter(|outcome| matches!(outcome, PersonalHistoryAdmission::Stored(_)))
            .count(),
        1
    );
    assert_eq!(
        history_outcomes
            .iter()
            .filter(|outcome| matches!(outcome, PersonalHistoryAdmission::Replay(_)))
            .count(),
        1
    );
    let admitted_ids = match &history_outcomes[0] {
        PersonalHistoryAdmission::Stored(ids) | PersonalHistoryAdmission::Replay(ids) => ids,
        PersonalHistoryAdmission::AccountUnavailable => {
            panic!("enabled fixture account unexpectedly unavailable")
        }
    };
    assert!(history_outcomes.iter().all(|outcome| match outcome {
        PersonalHistoryAdmission::Stored(ids) | PersonalHistoryAdmission::Replay(ids) =>
            ids == admitted_ids,
        PersonalHistoryAdmission::AccountUnavailable => false,
    }));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM message_archive WHERE id=ANY($1::UUID[])",
        )
        .bind(admitted_ids)
        .fetch_one(&pool)
        .await
        .unwrap(),
        2
    );
    let conflicting_writes = [PersonalArchiveWrite {
        id: Uuid::new_v4(),
        owner_id,
        peer_jid: "mamrecipient@local.test/Phone",
        stanza: "<message id='forged-history'/>",
        encrypted: false,
        stanza_id: Some("client-history-id"),
    }];
    let conflicting_identity = personal_identity(
        "local-origin",
        "mamowner@local.test",
        "mamowner@local.test",
        "mamrecipient@local.test",
        "origin-atomic-1",
        "<message id='forged-history'/>",
    );
    assert!(
        admit_personal_history(&pool, Some(&conflicting_identity), &conflicting_writes)
            .await
            .unwrap_err()
            .to_string()
            .contains("conflicting personal history identity")
    );

    let rollback_archive_id = Uuid::new_v4();
    let rollback_writes = [
        PersonalArchiveWrite {
            id: rollback_archive_id,
            owner_id,
            peer_jid: "mamrecipient@local.test",
            stanza: "<message id='rollback-a'/>",
            encrypted: false,
            stanza_id: None,
        },
        PersonalArchiveWrite {
            id: Uuid::new_v4(),
            owner_id: Uuid::new_v4(),
            peer_jid: "missing@local.test",
            stanza: "<message id='rollback-b'/>",
            encrypted: false,
            stanza_id: None,
        },
    ];
    let rollback_identity = personal_identity(
        "local-origin",
        "mamowner@local.test",
        "mamowner@local.test",
        "missing@local.test",
        "origin-rollback",
        "<message id='rollback'/>",
    );
    assert_eq!(
            admit_personal_history(&pool, Some(&rollback_identity), &rollback_writes)
                .await
                .unwrap(),
            PersonalHistoryAdmission::AccountUnavailable,
            "the authorization snapshot must reject a missing projection owner before any admission or archive write",
        );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM message_archive WHERE id=$1")
            .bind(rollback_archive_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM personal_message_admissions WHERE identity_value='origin-rollback'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );

    let failed_outbox_archive_id = Uuid::new_v4();
    let failed_outbox_write = [PersonalArchiveWrite {
        id: failed_outbox_archive_id,
        owner_id,
        peer_jid: "remote@remote.test",
        stanza: "<message id='atomic-outbox-failure'/>",
        encrypted: false,
        stanza_id: Some("atomic-outbox-failure"),
    }];
    let rejecting_outbox = PersonalS2sOutboxAdmission {
        local_actor_id: owner_id,
        target_domain: "remote.test",
        stanza: "<message from='mamowner@local.test' to='remote@remote.test'/>",
        bounce_to: Some("mamowner@local.test/Phone"),
        policy: northstar_federation_core::S2sOutboxPolicy {
            ttl_seconds: 300,
            max_rows: 0,
            max_bytes: 1_000_000,
            max_per_domain: 100,
        },
    };
    assert!(
        admit_outbound_personal_history(&pool, None, &failed_outbox_write, &rejecting_outbox,)
            .await
            .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM message_archive WHERE id=$1")
            .bind(failed_outbox_archive_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0,
        "outbox capacity failure must roll back the paired MAM row"
    );

    let accepted_outbox_archive_id = Uuid::new_v4();
    let accepted_outbox_write = [PersonalArchiveWrite {
        id: accepted_outbox_archive_id,
        owner_id,
        peer_jid: "remote@remote.test",
        stanza: "<message id='atomic-outbox-success'/>",
        encrypted: false,
        stanza_id: Some("atomic-outbox-success"),
    }];
    let accepting_outbox = PersonalS2sOutboxAdmission {
        policy: northstar_federation_core::S2sOutboxPolicy {
            max_rows: 100,
            ..rejecting_outbox.policy
        },
        ..rejecting_outbox
    };
    let accepted_outbox_identity = personal_identity(
        "local-origin",
        "mamowner@local.test",
        "mamowner@local.test",
        "remote@remote.test",
        "origin-atomic-outbox-success",
        "<message id='atomic-outbox-success'/>",
    );
    assert!(matches!(
        admit_outbound_personal_history(
            &pool,
            Some(&accepted_outbox_identity),
            &accepted_outbox_write,
            &accepting_outbox,
        )
        .await
        .unwrap(),
        PersonalHistoryAdmission::Stored(_)
    ));
    let replay_outbox_write = [PersonalArchiveWrite {
        id: Uuid::new_v4(),
        ..accepted_outbox_write[0].clone()
    }];
    assert!(matches!(
        admit_outbound_personal_history(
            &pool,
            Some(&accepted_outbox_identity),
            &replay_outbox_write,
            &accepting_outbox,
        )
        .await
        .unwrap(),
        PersonalHistoryAdmission::Replay(_)
    ));
    let conflicting_outbox_identity = personal_identity(
        "local-origin",
        "mamowner@local.test",
        "mamowner@local.test",
        "remote@remote.test",
        "origin-atomic-outbox-success",
        "<message id='changed-outbox-payload'/>",
    );
    assert!(admit_outbound_personal_history(
        &pool,
        Some(&conflicting_outbox_identity),
        &replay_outbox_write,
        &accepting_outbox,
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("conflicting personal history identity"));
    let (paired_archive, paired_outbox): (i64, i64) = (
        sqlx::query_scalar("SELECT COUNT(*) FROM message_archive WHERE id=$1")
            .bind(accepted_outbox_archive_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        sqlx::query_scalar("SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='remote.test'")
            .fetch_one(&pool)
            .await
            .unwrap(),
    );
    assert_eq!((paired_archive, paired_outbox), (1, 1));

    // A plaintext message can deliberately have no MAM projection when
    // REQUIRE_ENCRYPTED_ARCHIVE is enabled. The durable S2S outbox still
    // has to consume its origin-id atomically so retry and conflict
    // semantics do not depend on archive policy.
    let plaintext_outbox = PersonalS2sOutboxAdmission {
            local_actor_id: owner_id,
            target_domain: "plaintext.remote.test",
            stanza: "<message from='mamowner@local.test' to='remote@plaintext.remote.test'><body>plaintext</body></message>",
            bounce_to: Some("mamowner@local.test/Phone"),
            policy: accepting_outbox.policy,
        };
    let plaintext_identity = personal_identity(
        "local-origin",
        "mamowner@local.test",
        "mamowner@local.test",
        "remote@plaintext.remote.test",
        "origin-plaintext-without-mam",
        plaintext_outbox.stanza,
    );
    assert_eq!(
        admit_outbound_personal_history(&pool, Some(&plaintext_identity), &[], &plaintext_outbox,)
            .await
            .unwrap(),
        PersonalHistoryAdmission::Stored(Vec::new())
    );
    assert_eq!(
        admit_outbound_personal_history(&pool, Some(&plaintext_identity), &[], &plaintext_outbox,)
            .await
            .unwrap(),
        PersonalHistoryAdmission::Replay(Vec::new())
    );
    let changed_plaintext_identity = personal_identity(
        "local-origin",
        "mamowner@local.test",
        "mamowner@local.test",
        "remote@plaintext.remote.test",
        "origin-plaintext-without-mam",
        "<message><body>changed plaintext</body></message>",
    );
    assert!(admit_outbound_personal_history(
        &pool,
        Some(&changed_plaintext_identity),
        &[],
        &plaintext_outbox,
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("conflicting personal history identity"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='plaintext.remote.test'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    let plaintext_outbox_id = sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT s2s_outbox_id
               FROM personal_message_admissions
              WHERE identity_kind='local-origin'
                AND identity_value='origin-plaintext-without-mam'",
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .expect("the admission must own its recoverable S2S outbox projection");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM s2s_outbox WHERE id=$1")
            .bind(plaintext_outbox_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );

    // Completing the transient outbox must retain a bounded identity
    // tombstone. Otherwise a socket-write/delete success followed by an
    // exact client replay would enqueue the same logical message again.
    sqlx::query("DELETE FROM s2s_outbox WHERE id=$1")
        .bind(plaintext_outbox_id)
        .execute(&pool)
        .await
        .unwrap();
    let completed_projection = sqlx::query_as::<_, (Option<Uuid>, Option<DateTime<Utc>>)>(
        "SELECT s2s_outbox_id,delivery_completed_at
               FROM personal_message_admissions
              WHERE identity_kind='local-origin'
                AND identity_value='origin-plaintext-without-mam'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(completed_projection.0, None);
    assert!(completed_projection.1.is_some());
    assert_eq!(
        admit_outbound_personal_history(&pool, Some(&plaintext_identity), &[], &plaintext_outbox,)
            .await
            .unwrap(),
        PersonalHistoryAdmission::Replay(Vec::new())
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM s2s_outbox WHERE target_domain='plaintext.remote.test'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        0,
        "a completed origin-id replay must not recreate its S2S outbox"
    );
    assert!(admit_outbound_personal_history(
        &pool,
        Some(&changed_plaintext_identity),
        &[],
        &plaintext_outbox,
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("conflicting personal history identity"));

    let plaintext_c2s_id = Uuid::new_v4();
    let plaintext_c2s = PersonalC2sDeliveryAdmission {
            id: plaintext_c2s_id,
            recipient_id: recipient_owner_id,
            recipient_bare_jid: "mamrecipient@local.test",
            local_actor_id: Some(owner_id),
            sender_jid: "mamowner@local.test/Phone",
            stanza: "<message from='mamowner@local.test/Phone' to='mamrecipient@local.test'><body>local plaintext</body></message>",
            target_full_jid: None,
            encrypted: false,
            policy: OfflineStorePolicy {
                max_messages: 100,
                max_bytes: 1_000_000,
                ttl_days: 30,
                mam_backed: false,
            },
        };
    let plaintext_c2s_identity = personal_identity(
        "local-origin",
        "mamowner@local.test",
        "mamowner@local.test",
        "mamrecipient@local.test",
        "origin-local-plaintext-without-mam",
        plaintext_c2s.stanza,
    );
    assert_eq!(
        admit_personal_history_and_c2s_delivery(
            &pool,
            Some(&plaintext_c2s_identity),
            &[],
            &plaintext_c2s,
        )
        .await
        .unwrap(),
        PersonalHistoryAdmission::Stored(Vec::new())
    );
    assert_eq!(
        admit_personal_history_and_c2s_delivery(
            &pool,
            Some(&plaintext_c2s_identity),
            &[],
            &plaintext_c2s,
        )
        .await
        .unwrap(),
        PersonalHistoryAdmission::Replay(Vec::new())
    );
    let changed_c2s_identity = personal_identity(
        "local-origin",
        "mamowner@local.test",
        "mamowner@local.test",
        "mamrecipient@local.test",
        "origin-local-plaintext-without-mam",
        "<message><body>changed local plaintext</body></message>",
    );
    assert!(admit_personal_history_and_c2s_delivery(
        &pool,
        Some(&changed_c2s_identity),
        &[],
        &plaintext_c2s,
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("conflicting personal history identity"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
            .bind(plaintext_c2s_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    sqlx::query("DELETE FROM message_archive WHERE owner_id=ANY($1::UUID[])")
        .bind(vec![owner_id, recipient_owner_id])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM personal_message_admissions")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM offline_messages WHERE id=$1")
        .bind(plaintext_c2s_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM s2s_outbox")
        .execute(&pool)
        .await
        .unwrap();
    let bob_id = Uuid::new_v4();
    let carol_id = Uuid::new_v4();
    archive_message(
        &pool,
        bob_id,
        owner_id,
        "bob@example.test/Phone",
        "<message id='bob'/>",
        false,
        Some("bob-client"),
    )
    .await
    .unwrap();
    archive_message(
        &pool,
        carol_id,
        owner_id,
        "carol@example.test/Laptop",
        "<message id='carol'/>",
        false,
        Some("carol-client"),
    )
    .await
    .unwrap();

    let mut duplicate_reference = page_query();
    duplicate_reference.ids = vec![bob_id, bob_id];
    let duplicate_page = mam_user_archive_page(&pool, owner_id, &duplicate_reference)
        .await
        .unwrap()
        .expect("a duplicated visible UID remains one valid reference");
    assert_eq!(duplicate_page.total, 1);
    assert_eq!(duplicate_page.rows[0].id, bob_id);

    let mut missing_reference = duplicate_reference;
    missing_reference.ids.push(Uuid::new_v4());
    assert!(mam_user_archive_page(&pool, owner_id, &missing_reference)
        .await
        .unwrap()
        .is_none());

    let other_owner_id = Uuid::new_v4();
    archive_message(
        &pool,
        other_owner_id,
        recipient_owner_id,
        "bob@example.test/Phone",
        "<message id='other-owner'/>",
        false,
        None,
    )
    .await
    .unwrap();
    let mut other_owner_cursor = page_query();
    other_owner_cursor.page = MamRsmPage::After(other_owner_id);
    assert!(mam_user_archive_page(&pool, owner_id, &other_owner_cursor)
        .await
        .unwrap()
        .is_none());
    sqlx::query("DELETE FROM message_archive WHERE id=$1")
        .bind(other_owner_id)
        .execute(&pool)
        .await
        .unwrap();

    let mut wrong_filter_cursor = page_query();
    wrong_filter_cursor.with_jid = Some("bob@example.test".to_owned());
    wrong_filter_cursor.page = MamRsmPage::After(carol_id);
    let filtered_after_other_peer = mam_user_archive_page(&pool, owner_id, &wrong_filter_cursor)
        .await
        .unwrap()
        .expect("the cursor exists in the archive's visible scope");
    assert!(filtered_after_other_peer.rows.is_empty());
    assert_eq!(filtered_after_other_peer.total, 1);
    assert!(filtered_after_other_peer.complete);

    sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,$2)")
        .bind(owner_id)
        .bind("bob@example.test")
        .execute(&pool)
        .await
        .unwrap();
    let mut blocked_cursor = page_query();
    blocked_cursor.page = MamRsmPage::After(bob_id);
    assert!(mam_user_archive_page(&pool, owner_id, &blocked_cursor)
        .await
        .unwrap()
        .is_none());
    let visible = mam_user_archive_page(&pool, owner_id, &page_query())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(visible.total, 1);
    assert_eq!(visible.rows.len(), 1);
    assert_eq!(visible.rows[0].id, carol_id);
    let personal_boundaries = archive_boundaries_visible(&pool, owner_id).await.unwrap();
    assert_eq!(
        personal_boundaries.0.as_ref().map(|row| row.id),
        Some(carol_id)
    );
    assert_eq!(
        personal_boundaries.1.as_ref().map(|row| row.id),
        Some(carol_id)
    );

    let room_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO muc_rooms(id,localpart,owner_id,occupant_id_secret)
             VALUES($1,'visible-room',$2,$3)",
    )
    .bind(room_id)
    .bind(owner_id)
    .bind(vec![5_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    let muc_bob_id = Uuid::new_v4();
    let muc_carol_id = Uuid::new_v4();
    for (id, actor, sender, nick) in [
        (
            muc_bob_id,
            "bob@example.test",
            "bob@example.test/Phone",
            "Bob",
        ),
        (
            muc_carol_id,
            "carol@example.test",
            "carol@example.test/Laptop",
            "Carol",
        ),
    ] {
        sqlx::query(
            "INSERT INTO muc_messages
                 (id,room_id,sender_jid,nick,stanza,encrypted,message_kind,actor_scope)
                 VALUES($1,$2,$3,$4,'<message/>',FALSE,'discussion',$5)",
        )
        .bind(id)
        .bind(room_id)
        .bind(sender)
        .bind(nick)
        .bind(actor)
        .execute(&pool)
        .await
        .unwrap();
    }
    let mut blocked_muc_cursor = page_query();
    blocked_muc_cursor.page = MamRsmPage::After(muc_bob_id);
    assert!(
        mam_muc_archive_page_visible(&pool, room_id, owner_id, &blocked_muc_cursor)
            .await
            .unwrap()
            .is_none()
    );
    let visible_muc = mam_muc_archive_page_visible(&pool, room_id, owner_id, &page_query())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(visible_muc.total, 1);
    assert_eq!(visible_muc.rows[0].id, muc_carol_id);
    let muc_boundaries = muc_archive_boundaries_visible(&pool, room_id, owner_id)
        .await
        .unwrap();
    assert_eq!(
        muc_boundaries.0.as_ref().map(|row| row.id),
        Some(muc_carol_id)
    );
    assert_eq!(
        muc_boundaries.1.as_ref().map(|row| row.id),
        Some(muc_carol_id)
    );

    for (sender, id) in [
        ("bob@example.test/Phone", "blocked-offline"),
        ("carol@example.test/Laptop", "visible-offline"),
    ] {
        assert_eq!(
            store_offline(
                &pool,
                owner_id,
                sender,
                &format!("<message id='{id}'/>"),
                false,
                OfflineStorePolicy {
                    max_messages: 10,
                    max_bytes: 16_384,
                    ttl_days: 30,
                    mam_backed: false,
                },
            )
            .await
            .unwrap(),
            OfflineStoreOutcome::Stored
        );
    }
    let (offline_tx, mut offline_rx) = tokio::sync::mpsc::channel(4);
    let offline_tx = northstar_stream::outbound::OutboundSender::new(offline_tx);
    assert_eq!(
        deliver_offline(&pool, owner_id, 30, &offline_tx, None)
            .await
            .unwrap(),
        1
    );
    drop(offline_tx);
    let delivered = offline_rx.recv().await.unwrap();
    northstar_session_postgres::replay::acknowledge_durable_delivery(
        &pool,
        delivered.c2s_delivery().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(delivered.stanza, "<message id='visible-offline'/>");
    assert!(offline_rx.recv().await.is_none());
    assert_eq!(offline_message_count(&pool, owner_id).await.unwrap(), 0);

    for (id, mam_backed) in [
        ("bind2-mam-duplicate", true),
        ("bind2-temporary-only", false),
    ] {
        assert_eq!(
            store_offline(
                &pool,
                recipient_owner_id,
                "sender@remote.test/Phone",
                &format!("<message id='{id}'/>"),
                false,
                OfflineStorePolicy {
                    max_messages: 10,
                    max_bytes: 16_384,
                    ttl_days: 30,
                    mam_backed,
                },
            )
            .await
            .unwrap(),
            OfflineStoreOutcome::Stored
        );
    }
    let (bind2_tx, mut bind2_rx) = tokio::sync::mpsc::channel(4);
    let bind2_tx = northstar_stream::outbound::OutboundSender::new(bind2_tx);
    assert_eq!(
        deliver_bind2_offline(&pool, recipient_owner_id, 30, &bind2_tx, None)
            .await
            .unwrap(),
        1
    );
    drop(bind2_tx);
    let delivered = bind2_rx.recv().await.unwrap();
    northstar_session_postgres::replay::acknowledge_durable_delivery(
        &pool,
        delivered.c2s_delivery().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(delivered.stanza, "<message id='bind2-temporary-only'/>");
    assert!(bind2_rx.recv().await.is_none());
    assert_eq!(
        offline_message_count(&pool, recipient_owner_id)
            .await
            .unwrap(),
        0
    );

    let source_id = Uuid::new_v4();
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            let archive_id = Uuid::new_v4();
            barrier.wait().await;
            archive_mix_message_once(
                &pool,
                archive_id,
                owner_id,
                "room@mix.remote.test",
                source_id,
                "<message id='remote-reflection'/>",
                true,
                Some("client-origin"),
            )
            .await
            .unwrap()
        }));
    }
    barrier.wait().await;
    let outcomes = futures::future::join_all(tasks)
        .await
        .into_iter()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, SourceArchiveAdmission::Stored(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, SourceArchiveAdmission::Replay(_)))
            .count(),
        1
    );
    let stable_personal_id = match outcomes[0] {
        SourceArchiveAdmission::Stored(id) | SourceArchiveAdmission::Replay(id) => id,
    };
    assert!(outcomes.iter().all(|outcome| match *outcome {
        SourceArchiveAdmission::Stored(id) | SourceArchiveAdmission::Replay(id) =>
            id == stable_personal_id,
    }));
    assert!(archive_mix_message_once(
        &pool,
        Uuid::new_v4(),
        owner_id,
        "room@mix.remote.test",
        source_id,
        "<message id='forged-replay'/>",
        true,
        Some("client-origin"),
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("conflicting MIX source stanza identity"));

    let channel_id = Uuid::new_v4();
    let internal_id = Uuid::new_v4();
    let authoritative_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO mix_channels(id,service_domain,localpart,creator_jid)
             VALUES($1,'mix.local.test','stable','alice@local.test')",
    )
    .bind(channel_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO mix_events(id,channel_id,node,item_id,payload)
             VALUES($1,$2,'urn:xmpp:mix:nodes:messages',$3,'<message/>')",
    )
    .bind(internal_id)
    .bind(channel_id)
    .bind(authoritative_id.to_string())
    .execute(&pool)
    .await
    .unwrap();
    let stored_authority: Uuid =
        sqlx::query_scalar("SELECT authoritative_id FROM mix_events WHERE id=$1")
            .bind(internal_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_authority, authoritative_id);

    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
