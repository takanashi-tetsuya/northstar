use super::ProtocolSession;
use crate::services::retractions::{
    ArchiveWrite, DeliveryProjection, OutboundProjection, OwnerProjection, RetractionCommand,
    RetractionOutcome,
};
use anyhow::Result;
use roxmltree::Node;
use uuid::Uuid;

const NS_RETRACT: &str = "urn:xmpp:message-retract:1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PersonalRetractionCommand {
    pub(crate) target_id: String,
    pub(crate) action_id: String,
    pub(crate) semantic_payload: String,
}

pub(crate) fn personal_retraction_command(
    root: Node<'_, '_>,
) -> std::result::Result<Option<PersonalRetractionCommand>, ()> {
    let mut retracts = root.children().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "retract"
            && node.tag_name().namespace() == Some(NS_RETRACT)
    });
    let Some(retract) = retracts.next() else {
        return Ok(None);
    };
    if retracts.next().is_some()
        || retract.children().any(|node| node.is_element())
        || retract.text().is_some_and(|text| !text.trim().is_empty())
        || retract
            .attributes()
            .any(|attribute| attribute.namespace().is_some() || attribute.name() != "id")
    {
        return Err(());
    }
    let target_id = retract.attribute("id").ok_or(())?;
    let action_id = root.attribute("id").ok_or(())?;
    if [target_id, action_id]
        .into_iter()
        .any(|id| id.is_empty() || id.len() > 1_024 || id.chars().any(char::is_control))
    {
        return Err(());
    }
    if root.children().any(|node| {
        node.is_element()
            && matches!(
                (node.tag_name().namespace(), node.tag_name().name()),
                (Some("urn:xmpp:message-correct:0"), "replace")
                    | (Some("urn:xmpp:reactions:0"), "reactions")
                    | (Some("urn:xmpp:reply:0"), "reply")
                    | (Some("urn:xmpp:chat-markers:0"), _)
                    | (Some("urn:xmpp:receipts"), _)
                    | (Some("http://jabber.org/protocol/chatstates"), _)
                    | (Some("urn:xmpp:jingle-message:0"), _)
                    | (Some("urn:xmpp:call-invites:0"), _)
                    | (Some("urn:xmpp:sfs:0"), "file-sharing")
                    | (Some("http://jabber.org/protocol/pubsub#event"), "event")
                    | (Some("jabber:x:roster"), "x")
                    | (Some("jabber:x:conference"), "x")
            )
    }) {
        return Err(());
    }
    Ok(Some(PersonalRetractionCommand {
        target_id: target_id.to_owned(),
        action_id: action_id.to_owned(),
        semantic_payload: root
            .document()
            .input_text()
            .get(root.range())
            .ok_or(())?
            .to_owned(),
    }))
}

pub(crate) fn retraction_target(root: Node<'_, '_>) -> std::result::Result<Option<String>, ()> {
    personal_retraction_command(root).map(|command| command.map(|command| command.target_id))
}

/// Preserve the visible retraction identity while applying the encrypted-MAM
/// sanitizer. The sanitizer removes plaintext fallback content; this restores
/// only the bounded XEP-0424 target required to replay the action itself.
pub(crate) fn encrypted_retraction_archive(stanza: &str, target_id: &str) -> String {
    crate::xmpp::xml_util::encrypted_retraction_archive_stanza(stanza, target_id)
}

impl ProtocolSession {
    #[expect(
        clippy::too_many_arguments,
        reason = "the XEP-0424 admission keeps both owner projections and the exact durable delivery projection explicit at the protocol boundary"
    )]
    pub(crate) async fn apply_personal_retraction(
        &self,
        sender_id: Uuid,
        sender_jid: &str,
        recipient_id: Option<Uuid>,
        recipient_jid: &str,
        root: Node<'_, '_>,
        action_writes: &[ArchiveWrite<'_>],
        delivery: &DeliveryProjection<'_>,
    ) -> Result<RetractionOutcome> {
        let Some(command) = personal_retraction_command(root).ok().flatten() else {
            anyhow::bail!("personal retraction admission requires a valid command");
        };
        let mut owners = vec![OwnerProjection {
            owner_id: sender_id,
            peer_jid: recipient_jid,
        }];
        if let Some(recipient_id) = recipient_id.filter(|id| *id != sender_id) {
            owners.push(OwnerProjection {
                owner_id: recipient_id,
                peer_jid: sender_jid,
            });
        }
        self.state
            .retraction_service()
            .apply_with_delivery(
                &owners,
                sender_jid,
                &RetractionCommand {
                    target_id: &command.target_id,
                    action_id: &command.action_id,
                    semantic_payload: &command.semantic_payload,
                },
                action_writes,
                Some(delivery),
                None,
            )
            .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the XEP-0424 federation admission keeps archive and outbox authority explicit at the protocol boundary"
    )]
    pub(crate) async fn apply_outbound_personal_retraction(
        &self,
        sender_id: Uuid,
        sender_jid: &str,
        recipient_jid: &str,
        root: Node<'_, '_>,
        action_writes: &[ArchiveWrite<'_>],
        target_domain: &str,
        stanza: &str,
    ) -> Result<RetractionOutcome> {
        let Some(command) = personal_retraction_command(root).ok().flatten() else {
            anyhow::bail!("outbound retraction admission requires a valid retraction command");
        };
        let outbox = OutboundProjection {
            target_domain,
            stanza,
            bounce_to: Some(sender_jid),
            policy: self.state.federation.outbox_policy().into(),
        };
        self.state
            .retraction_service()
            .apply(
                &[OwnerProjection {
                    owner_id: sender_id,
                    peer_jid: recipient_jid,
                }],
                sender_jid,
                &RetractionCommand {
                    target_id: &command.target_id,
                    action_id: &command.action_id,
                    semantic_payload: &command.semantic_payload,
                },
                action_writes,
                Some(&outbox),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::retractions::{retractable_message, tombstone_message, RetractionService};
    use roxmltree::Document;

    async fn apply_personal_retraction_atomic(
        pool: &sqlx::PgPool,
        owners: &[(Uuid, &str)],
        sender_jid: &str,
        command: &PersonalRetractionCommand,
        action_writes: &[ArchiveWrite<'_>],
        outbox: Option<&OutboundProjection<'_>>,
    ) -> Result<RetractionOutcome> {
        let owners = owners
            .iter()
            .map(|(owner_id, peer_jid)| OwnerProjection {
                owner_id: *owner_id,
                peer_jid,
            })
            .collect::<Vec<_>>();
        RetractionService::new(
            pool.clone(),
            crate::abuse::test_personal_retraction_content_keyring(),
            "local.test",
        )
        .apply(
            &owners,
            sender_jid,
            &RetractionCommand {
                target_id: &command.target_id,
                action_id: &command.action_id,
                semantic_payload: &command.semantic_payload,
            },
            action_writes,
            outbox,
        )
        .await
    }

    #[test]
    fn validates_retraction_shape() {
        let document = Document::parse(
            "<message id='action'><retract xmlns='urn:xmpp:message-retract:1' id='original'/></message>",
        )
        .unwrap();
        assert_eq!(
            retraction_target(document.root_element()).unwrap(),
            Some("original".to_owned())
        );
        for xml in [
            "<message><retract xmlns='urn:xmpp:message-retract:1'/></message>",
            "<message><retract xmlns='urn:xmpp:message-retract:1' id='a'/></message>",
            "<message><retract xmlns='urn:xmpp:message-retract:1' id='a'/><retract xmlns='urn:xmpp:message-retract:1' id='b'/></message>",
            "<message><retract xmlns='urn:xmpp:message-retract:1' id='a'><extra/></retract></message>",
            "<message id='action'><retract xmlns='urn:xmpp:message-retract:1' id='a'>not-empty</retract></message>",
            "<message id='action'><retract xmlns='urn:xmpp:message-retract:1' id='a'/><reactions xmlns='urn:xmpp:reactions:0' id='b'/></message>",
            "<message id='action'><body>ambiguous</body><retract xmlns='urn:xmpp:message-retract:1' id='a'/><replace xmlns='urn:xmpp:message-correct:0' id='b'/></message>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(retraction_target(document.root_element()).is_err());
        }

        let longest = "x".repeat(1_024);
        let xml = format!(
            "<message id='{longest}'><retract xmlns='urn:xmpp:message-retract:1' id='{longest}'/></message>"
        );
        let document = Document::parse(&xml).unwrap();
        assert_eq!(
            personal_retraction_command(document.root_element())
                .unwrap()
                .unwrap()
                .target_id
                .len(),
            1_024
        );
        let too_long = "x".repeat(1_025);
        let xml = format!(
            "<message id='action'><retract xmlns='urn:xmpp:message-retract:1' id='{too_long}'/></message>"
        );
        let document = Document::parse(&xml).unwrap();
        assert!(personal_retraction_command(document.root_element()).is_err());
    }

    #[test]
    fn tombstone_drops_original_content_and_escapes_attributes() {
        let document = Document::parse(
            "<message from='a@example.test/device' to='b@example.test' id='m1'><body>secret</body></message>",
        )
        .unwrap();
        let tombstone = tombstone_message(document.root_element(), "retract-1");
        assert!(!tombstone.contains("secret"));
        assert!(tombstone.contains("<retracted xmlns='urn:xmpp:message-retract:1'"));
        assert!(tombstone.contains("id='retract-1'"));
    }

    #[test]
    fn only_user_visible_messages_are_retractable() {
        for xml in [
            "<message from='a@example.test/device'><body>visible</body></message>",
            "<message from='a@example.test/device'><encrypted xmlns='urn:xmpp:omemo:2'/></message>",
            "<message from='a@example.test/device'><file-sharing xmlns='urn:xmpp:sfs:0'/></message>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(retractable_message(document.root_element()), "{xml}");
        }
        for xml in [
            "<message from='a@example.test/device'><received xmlns='urn:xmpp:receipts' id='m1'/></message>",
            "<message from='a@example.test/device'><body>call fallback</body><propose xmlns='urn:xmpp:jingle-message:0' id='call'/></message>",
            "<message from='a@example.test/device'><body>retraction fallback</body><retract xmlns='urn:xmpp:message-retract:1' id='m1'/></message>",
            "<message from='a@example.test/device' type='error'><body>reflected</body></message>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(!retractable_message(document.root_element()), "{xml}");
        }
    }

    #[test]
    fn encrypted_retraction_archive_keeps_only_safe_payload_and_target() {
        let archive = encrypted_retraction_archive(
            "<message from='alice@example.test/Phone' id='action'><body>private fallback</body><encrypted xmlns='urn:xmpp:omemo:2'><header sid='1'/><payload>ciphertext</payload></encrypted><retract xmlns='urn:xmpp:message-retract:1' id='target'/></message>",
            "target",
        );
        assert!(!archive.contains("private fallback"), "{archive}");
        assert!(archive.contains("urn:xmpp:omemo:2"), "{archive}");
        assert!(archive.contains("urn:xmpp:message-retract:1"), "{archive}");
        assert!(archive.contains("id='target'"), "{archive}");
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
    async fn personal_retraction_is_author_scoped_unambiguous_and_atomic() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to the xmpp_test PostgreSQL database");
        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(60))
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("modern_retraction_test_{}", Uuid::new_v4().simple());
        eprintln!("isolated_schema={schema}");
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let connection_schema = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(60))
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

        let sender_id = Uuid::new_v4();
        let recipient_id = Uuid::new_v4();
        for (id, username) in [(sender_id, "alice"), (recipient_id, "bob")] {
            sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test')")
                .bind(id)
                .bind(username)
                .execute(&pool)
                .await
                .unwrap();
        }

        let sender_original_id = Uuid::new_v4();
        let recipient_original_id = Uuid::new_v4();
        for (id, owner_id, peer_jid, peer_full_jid) in [
            (
                sender_original_id,
                sender_id,
                "bob@local.test",
                "bob@local.test/Phone",
            ),
            (
                recipient_original_id,
                recipient_id,
                "alice@local.test",
                "alice@local.test/Laptop",
            ),
        ] {
            sqlx::query(
                "INSERT INTO message_archive
                 (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
                 VALUES($1,$2,$3,$4,$5,FALSE,'target-1')",
            )
            .bind(id)
            .bind(owner_id)
            .bind(peer_jid)
            .bind(peer_full_jid)
            .bind("<message from='alice@local.test/Laptop' to='bob@local.test/Phone' id='target-1'><body>remove me</body></message>")
            .execute(&pool)
            .await
            .unwrap();
        }
        let wrong_peer_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message_archive
             (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
             VALUES($1,$2,'carol@local.test','carol@local.test/Phone',$3,FALSE,'target-1')",
        )
        .bind(wrong_peer_id)
        .bind(sender_id)
        .bind("<message from='alice@local.test/Laptop' to='carol@local.test/Phone' id='target-1'><body>other conversation</body></message>")
        .execute(&pool)
        .await
        .unwrap();

        let action_sender_id = Uuid::new_v4();
        let action_recipient_id = Uuid::new_v4();
        let action_stanza = "<message from='alice@local.test/Laptop' to='bob@local.test/Phone' id='action-1'><retract xmlns='urn:xmpp:message-retract:1' id='target-1'/></message>";
        let writes = [
            ArchiveWrite {
                id: action_sender_id,
                owner_id: sender_id,
                peer_jid: "bob@local.test/Phone",
                stanza: action_stanza,
                encrypted: false,
                stanza_id: Some("action-1"),
            },
            ArchiveWrite {
                id: action_recipient_id,
                owner_id: recipient_id,
                peer_jid: "alice@local.test/Laptop",
                stanza: action_stanza,
                encrypted: false,
                stanza_id: Some("action-1"),
            },
        ];
        apply_personal_retraction_atomic(
            &pool,
            &[
                (sender_id, "bob@local.test/Phone"),
                (recipient_id, "alice@local.test/Laptop"),
            ],
            "alice@local.test/Laptop",
            &PersonalRetractionCommand {
                target_id: "target-1".to_owned(),
                action_id: "action-1".to_owned(),
                semantic_payload: action_stanza.to_owned(),
            },
            &writes,
            None,
        )
        .await
        .unwrap();
        for id in [sender_original_id, recipient_original_id] {
            let stanza: String =
                sqlx::query_scalar("SELECT stanza FROM message_archive WHERE id=$1")
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert!(stanza.contains("<retracted "), "{stanza}");
            assert!(!stanza.contains("remove me"), "{stanza}");
        }
        let wrong_peer: String =
            sqlx::query_scalar("SELECT stanza FROM message_archive WHERE id=$1")
                .bind(wrong_peer_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(wrong_peer.contains("other conversation"));

        let wrong_author_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message_archive
             (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
             VALUES($1,$2,'bob@local.test','bob@local.test/Phone',$3,FALSE,'wrong-author')",
        )
        .bind(wrong_author_id)
        .bind(sender_id)
        .bind("<message from='mallory@local.test/Device' id='wrong-author'><body>not yours</body></message>")
        .execute(&pool)
        .await
        .unwrap();
        apply_personal_retraction_atomic(
            &pool,
            &[(sender_id, "bob@local.test")],
            "alice@local.test/Laptop",
            &PersonalRetractionCommand {
                target_id: "wrong-author".to_owned(),
                action_id: "ignored-action".to_owned(),
                semantic_payload: "<message from='alice@local.test/Laptop' id='ignored-action'><retract xmlns='urn:xmpp:message-retract:1' id='wrong-author'/></message>".to_owned(),
            },
            &[],
            None,
        )
        .await
        .unwrap();
        let wrong_author: String =
            sqlx::query_scalar("SELECT stanza FROM message_archive WHERE id=$1")
                .bind(wrong_author_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(wrong_author.contains("not yours"));

        let ambiguous_ids = [Uuid::new_v4(), Uuid::new_v4()];
        for id in ambiguous_ids {
            sqlx::query(
                "INSERT INTO message_archive
                 (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
                 VALUES($1,$2,'bob@local.test','bob@local.test/Phone',$3,FALSE,'ambiguous')",
            )
            .bind(id)
            .bind(sender_id)
            .bind(format!(
                "<message from='alice@local.test/Laptop' id='ambiguous'><body>{id}</body></message>"
            ))
            .execute(&pool)
            .await
            .unwrap();
        }
        apply_personal_retraction_atomic(
            &pool,
            &[(sender_id, "bob@local.test")],
            "alice@local.test/Laptop",
            &PersonalRetractionCommand {
                target_id: "ambiguous".to_owned(),
                action_id: "ambiguous-action".to_owned(),
                semantic_payload: "<message from='alice@local.test/Laptop' id='ambiguous-action'><retract xmlns='urn:xmpp:message-retract:1' id='ambiguous'/></message>".to_owned(),
            },
            &[],
            None,
        )
        .await
        .unwrap();
        let still_visible: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM message_archive
             WHERE owner_id=$1 AND stanza_id='ambiguous' AND stanza LIKE '%<body>%'",
        )
        .bind(sender_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(still_visible, 2);

        let rollback_target_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message_archive
             (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted,stanza_id)
             VALUES($1,$2,'bob@local.test','bob@local.test/Phone',$3,FALSE,'rollback-target')",
        )
        .bind(rollback_target_id)
        .bind(sender_id)
        .bind("<message from='alice@local.test/Laptop' id='rollback-target'><body>must survive</body></message>")
        .execute(&pool)
        .await
        .unwrap();
        let duplicate_action_id = Uuid::new_v4();
        let rollback_stanza = "<message from='alice@local.test/Laptop' id='rollback-action'><retract xmlns='urn:xmpp:message-retract:1' id='rollback-target'/></message>";
        let failing_writes = [
            ArchiveWrite {
                id: duplicate_action_id,
                owner_id: sender_id,
                peer_jid: "bob@local.test",
                stanza: rollback_stanza,
                encrypted: false,
                stanza_id: Some("rollback-action"),
            },
            ArchiveWrite {
                id: duplicate_action_id,
                owner_id: recipient_id,
                peer_jid: "alice@local.test",
                stanza: rollback_stanza,
                encrypted: false,
                stanza_id: Some("rollback-action"),
            },
        ];
        assert!(apply_personal_retraction_atomic(
            &pool,
            &[(sender_id, "bob@local.test")],
            "alice@local.test/Laptop",
            &PersonalRetractionCommand {
                target_id: "rollback-target".to_owned(),
                action_id: "rollback-action".to_owned(),
                semantic_payload: rollback_stanza.to_owned(),
            },
            &failing_writes,
            None,
        )
        .await
        .is_err());
        let rollback_target: String =
            sqlx::query_scalar("SELECT stanza FROM message_archive WHERE id=$1")
                .bind(rollback_target_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(rollback_target.contains("must survive"));
        let leaked_action: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM message_archive WHERE id=$1")
                .bind(duplicate_action_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(leaked_action, 0);

        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }

    #[test]
    fn personal_retraction_command_parses_valid_xml_and_extracts_fields() {
        let xml = "<message from='alice@example.com' to='bob@example.com' id='act-99'><body>deleted</body><retract xmlns='urn:xmpp:message-retract:1' id='tgt-123'/></message>";
        let doc = Document::parse(xml).unwrap();
        let cmd = personal_retraction_command(doc.root_element())
            .unwrap()
            .unwrap();
        assert_eq!(cmd.target_id, "tgt-123");
        assert_eq!(cmd.action_id, "act-99");
        assert_eq!(cmd.semantic_payload, xml);
    }

    #[test]
    fn personal_retraction_command_rejects_malformed_xml_and_conflicts() {
        // No retract element
        let xml_none = "<message id='act-1'><body>plain message</body></message>";
        let doc_none = Document::parse(xml_none).unwrap();
        assert_eq!(
            personal_retraction_command(doc_none.root_element()).unwrap(),
            None
        );

        // Conflicting replace element
        let xml_replace = "<message id='act-1'><retract xmlns='urn:xmpp:message-retract:1' id='tgt-1'/><replace xmlns='urn:xmpp:message-correct:0' id='tgt-1'/></message>";
        let doc_replace = Document::parse(xml_replace).unwrap();
        assert!(personal_retraction_command(doc_replace.root_element()).is_err());

        // Conflicting reactions element
        let xml_react = "<message id='act-1'><retract xmlns='urn:xmpp:message-retract:1' id='tgt-1'/><reactions xmlns='urn:xmpp:reactions:0' id='tgt-1'/></message>";
        let doc_react = Document::parse(xml_react).unwrap();
        assert!(personal_retraction_command(doc_react.root_element()).is_err());

        // A direct MUC invitation can grant a durable affiliation. It must
        // never share an operation boundary with a personal retraction.
        let xml_invite = "<message id='act-1'><retract xmlns='urn:xmpp:message-retract:1' id='tgt-1'/><x xmlns='jabber:x:conference' jid='room@conference.example.com'/></message>";
        let doc_invite = Document::parse(xml_invite).unwrap();
        assert!(personal_retraction_command(doc_invite.root_element()).is_err());
    }

    #[test]
    fn protocol_retractions_has_zero_db_dto_dependencies() {
        let source = include_str!("retractions.rs");
        let target_archive_dto = format!("db::Personal{}Write", "Archive");
        let target_outbox_dto = format!("db::Personal{}OutboxAdmission", "S2s");
        let db_import = format!("use crate::{};", "db");
        assert!(
            !source.contains(&target_archive_dto),
            "protocol/retractions.rs must not reference db archive DTO"
        );
        assert!(
            !source.contains(&target_outbox_dto),
            "protocol/retractions.rs must not reference db outbox DTO"
        );
        assert!(
            !source.contains(&db_import),
            "protocol/retractions.rs must not import crate db"
        );
    }
}
