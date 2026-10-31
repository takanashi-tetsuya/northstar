//! The privacy context's persistence as the root crate binds it, and the privacy check of a session the session
//! context's tables identify.

use anyhow::Result;
pub use northstar_roster_postgres::privacy::*;
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub async fn privacy_denies_for_sm_session(
    pool: &PgPool,
    session_id: Uuid,
    candidate: &str,
    kind: PrivacyStanzaKind,
) -> Result<Option<bool>> {
    let row = sqlx::query("SELECT * FROM northstar_sm_privacy_state($1)")
        .bind(session_id)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let user_id: Uuid = row.get("user_id");
    let active: Option<String> = row.get("active_privacy_list");
    privacy_denies(pool, user_id, active.as_deref(), candidate, kind)
        .await
        .map(Some)
}

/// Account communication policy with the non-overridable XEP-0191 rule
/// evaluated first.  A privacy-list `allow` can never bypass a block.
#[cfg(test)]
pub async fn communication_denied(
    pool: &PgPool,
    owner_id: Uuid,
    owner_bare_jid: &str,
    active_list: Option<&str>,
    candidate: &str,
    kind: PrivacyStanzaKind,
) -> Result<bool> {
    if super::roster::is_blocked_for_account(pool, owner_id, owner_bare_jid, candidate).await? {
        return Ok(true);
    }
    privacy_denies(pool, owner_id, active_list, candidate, kind).await
}

#[cfg(test)]
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires a random-schema TEST_DATABASE_URL"]
    async fn postgres_privacy_lists_are_bounded_ordered_cascading_and_enforced() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to a disposable random-schema xmpp_test URL");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let owner_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(owner_id)
            .bind(format!("privacy{}", owner_id.simple()))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO roster_items(owner_id,contact_jid,subscription,groups) \
             VALUES($1,'bob@example.test','both','[\"Friends\"]'::jsonb)",
        )
        .bind(owner_id)
        .execute(&pool)
        .await
        .unwrap();

        let list = PrivacyList {
            name: "work".to_owned(),
            items: vec![
                PrivacyItem {
                    order: 10,
                    action: PrivacyAction::Deny,
                    match_type: Some(PrivacyMatchType::Group),
                    match_value: Some("Friends".to_owned()),
                    message: true,
                    iq: false,
                    presence_in: false,
                    presence_out: false,
                },
                PrivacyItem {
                    order: 20,
                    action: PrivacyAction::Deny,
                    match_type: Some(PrivacyMatchType::Subscription),
                    match_value: Some("both".to_owned()),
                    message: false,
                    iq: true,
                    presence_in: false,
                    presence_out: false,
                },
                PrivacyItem {
                    order: 30,
                    action: PrivacyAction::Allow,
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
            replace_privacy_list(&pool, owner_id, &list).await.unwrap(),
            ReplacePrivacyListOutcome::Stored
        );
        assert!(set_default_privacy_list(&pool, owner_id, Some("work"))
            .await
            .unwrap());
        assert!(privacy_denies(
            &pool,
            owner_id,
            None,
            "bob@example.test/Phone",
            PrivacyStanzaKind::Message,
        )
        .await
        .unwrap());
        assert!(privacy_denies(
            &pool,
            owner_id,
            Some("work"),
            "bob@example.test/Phone",
            PrivacyStanzaKind::Iq,
        )
        .await
        .unwrap());
        assert!(!privacy_denies(
            &pool,
            owner_id,
            Some("work"),
            "carol@example.test/Phone",
            PrivacyStanzaKind::Message,
        )
        .await
        .unwrap());
        assert_eq!(
            remove_privacy_list(&pool, owner_id, "work").await.unwrap(),
            RemovePrivacyListOutcome::Conflict
        );

        let allow = PrivacyList {
            name: "allow".to_owned(),
            items: vec![PrivacyItem {
                order: u32::MAX,
                action: PrivacyAction::Allow,
                match_type: None,
                match_value: None,
                message: false,
                iq: false,
                presence_in: false,
                presence_out: false,
            }],
        };
        replace_privacy_list(&pool, owner_id, &allow).await.unwrap();
        let generation: i64 = sqlx::query_scalar("SELECT auth_generation FROM users WHERE id=$1")
            .bind(owner_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        let first_connection = Uuid::new_v4();
        let second_connection = Uuid::new_v4();
        let mut first =
            northstar_auth_postgres::users::lock_auth_generation(&pool, owner_id, generation)
                .await
                .unwrap()
                .unwrap();
        let mut second =
            northstar_auth_postgres::users::lock_auth_generation(&pool, owner_id, generation)
                .await
                .unwrap()
                .unwrap();
        // Both resume transactions hold the account lock before either writes
        // its selection. A lock upgrade would block the first operation here.
        for (transaction, connection) in [
            (&mut first, first_connection),
            (&mut second, second_connection),
        ] {
            sqlx::query("SET LOCAL lock_timeout='1s'")
                .execute(&mut **transaction)
                .await
                .unwrap();
            assert!(set_active_privacy_list_in_transaction(
                transaction,
                owner_id,
                connection,
                Some("allow"),
            )
            .await
            .unwrap());
        }
        second.commit().await.unwrap();
        clear_active_privacy_session(&pool, owner_id, second_connection)
            .await
            .unwrap();

        let removal_pool = pool.clone();
        let removal =
            tokio::spawn(
                async move { remove_privacy_list(&removal_pool, owner_id, "allow").await },
            );
        let waiting = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let blocked: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity
                     WHERE datname=current_database() AND wait_event_type='Lock'
                       AND query='SELECT id FROM users WHERE id=$1 FOR UPDATE')",
                )
                .fetch_one(&pool)
                .await
                .unwrap();
                if blocked {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        first.commit().await.unwrap();
        assert!(
            waiting.is_ok(),
            "list deletion did not wait for the selection transaction"
        );
        assert_eq!(
            removal.await.unwrap().unwrap(),
            RemovePrivacyListOutcome::Conflict
        );
        clear_active_privacy_session(&pool, owner_id, first_connection)
            .await
            .unwrap();
        let active_connection = Uuid::new_v4();
        assert!(
            set_active_privacy_list(&pool, owner_id, active_connection, Some("allow"),)
                .await
                .unwrap()
        );
        assert_eq!(
            remove_privacy_list(&pool, owner_id, "allow").await.unwrap(),
            RemovePrivacyListOutcome::Conflict
        );
        clear_active_privacy_session(&pool, owner_id, active_connection)
            .await
            .unwrap();
        let sm_snapshot = crate::db::SmSessionSnapshot {
            inbound_h: 0,
            outbound_h: 0,
            acked_h: 0,
            available: true,
            carbons: false,
            priority: 0,
            blocklist_requested: false,
            roster_requested: false,
            active_privacy_list: Some("allow".to_owned()),
            privacy_requested: true,
            peer_ip: "192.0.2.44".parse().unwrap(),
            user_agent_id: None,
            joined_rooms: vec![],
            directed_presence: vec![],
            last_presence: None,
            unacked: vec![],
        };
        crate::db::create_sm_session(
            &pool,
            &[7_u8; 32],
            owner_id,
            0,
            &format!("privacy{}@example.test/Phone", owner_id.simple()),
            "Phone",
            "example.test",
            Uuid::new_v4(),
            &sm_snapshot,
            300,
            30,
            8,
            100,
        )
        .await
        .unwrap();
        assert_eq!(
            remove_privacy_list(&pool, owner_id, "allow").await.unwrap(),
            RemovePrivacyListOutcome::Conflict
        );
        sqlx::query("INSERT INTO blocked_jids(owner_id,blocked_jid) VALUES($1,'bob@example.test')")
            .bind(owner_id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(communication_denied(
            &pool,
            owner_id,
            &format!("privacy{}@example.test", owner_id.simple()),
            Some("allow"),
            "bob@example.test/Phone",
            PrivacyStanzaKind::Message,
        )
        .await
        .unwrap());

        // Database constraints independently reject ambiguous evaluation.
        let duplicate = sqlx::query(
            "INSERT INTO privacy_list_items(owner_id,list_name,item_order,action) \
             VALUES($1,'allow',4294967295,'deny')",
        )
        .bind(owner_id)
        .execute(&pool)
        .await;
        assert!(duplicate.is_err());

        set_default_privacy_list(&pool, owner_id, None)
            .await
            .unwrap();
        assert_eq!(
            remove_privacy_list(&pool, owner_id, "work").await.unwrap(),
            RemovePrivacyListOutcome::Removed
        );
        let existing = privacy_overview(&pool, owner_id).await.unwrap().names.len();
        for index in existing..MAX_PRIVACY_LISTS {
            let fill = PrivacyList {
                name: format!("quota-{index:03}"),
                items: allow.items.clone(),
            };
            assert_eq!(
                replace_privacy_list(&pool, owner_id, &fill).await.unwrap(),
                ReplacePrivacyListOutcome::Stored
            );
        }
        let overflow = PrivacyList {
            name: "quota-overflow".to_owned(),
            items: allow.items.clone(),
        };
        assert_eq!(
            replace_privacy_list(&pool, owner_id, &overflow)
                .await
                .unwrap(),
            ReplacePrivacyListOutcome::TooManyLists
        );
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(owner_id)
            .execute(&pool)
            .await
            .unwrap();
        let remaining: i64 = sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM privacy_lists) + \
                    (SELECT COUNT(*) FROM privacy_list_items) + \
                    (SELECT COUNT(*) FROM privacy_default_lists) + \
                    (SELECT COUNT(*) FROM privacy_active_sessions)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(remaining, 0);
    }
}
