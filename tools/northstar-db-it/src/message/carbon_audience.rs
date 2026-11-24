use super::message_repository::drop_isolated_message_pool;
use northstar_message_application::message_carbons::{
    send_received_carbons, send_sent_carbons, CarbonDeliveryPort, CarbonFanout, Direction,
};
use northstar_message_application::messaging::{ExactMessageRoute, MessageService};
use northstar_roster_postgres::{privacy, roster};
use northstar_stream::outbound::OutboundSender;
use northstar_workflows::message_repository::PostgresMessageRepository;
use northstar_xep_0016::{PrivacyAction, PrivacyItem, PrivacyList, PrivacyStanzaKind};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::sync::{mpsc, Notify};
use uuid::Uuid;

const ACCOUNT: &str = "alice@example.test";
const PEER: &str = "bob@example.test";
const ORIGIN: &str = "alice@example.test/Phone";
const SIBLING: &str = "alice@example.test/Tablet";
const ACTIVE: &str = "on-this-device";

struct Port {
    service: MessageService<PostgresMessageRepository>,
    account_id: Uuid,
    connection_id: Uuid,
    sender: OutboundSender,
    queue_waiting: Notify,
}

impl CarbonDeliveryPort for Port {
    type Session = ();

    fn enabled(&self) -> bool {
        true
    }

    fn sessions(&self, bare: &str) -> Vec<(String, ())> {
        assert_eq!(bare, ACCOUNT);
        vec![(SIBLING.to_owned(), ())]
    }

    fn carbon_enabled(&self, _: &()) -> bool {
        true
    }

    fn in_muc_scope(&self, _: &(), _: &str, _: &str) -> bool {
        false
    }

    fn wrap(&self, direction: Direction, from: &str, to: &str, forwarded: &str) -> Option<String> {
        northstar_message_core::validation::carbon_message(direction.as_str(), from, to, forwarded)
    }

    async fn privacy_allows(
        &self,
        _: &(),
        peer: &str,
        kind: PrivacyStanzaKind,
    ) -> anyhow::Result<bool> {
        self.service
            .privacy_allows_session(
                self.account_id,
                self.connection_id,
                Some(ACTIVE),
                peer,
                kind,
            )
            .await
    }

    async fn enqueue(&self, _: &(), stanza: String) -> bool {
        self.sender.send(stanza).await.is_ok()
    }

    async fn enqueue_captured(
        &self,
        _: Option<&ExactMessageRoute>,
        _: &(),
        stanza: String,
        request: CarbonFanout<'_>,
        peer: &str,
    ) -> anyhow::Result<bool> {
        assert_eq!(peer.split('/').next(), Some(PEER));
        assert!(
            self.privacy_allows(&(), peer, PrivacyStanzaKind::Message)
                .await?
        );
        Ok(self
            .sender
            .send_if_current(
                stanza,
                || {
                    self.queue_waiting.notify_one();
                    true
                },
                async {
                    self.service
                        .allows_carbon(
                            request.bare,
                            self.account_id,
                            self.connection_id,
                            Some(ACTIVE),
                            peer,
                        )
                        .await
                        .unwrap()
                },
            )
            .await?)
    }

    fn delivery_failed(&self) {
        panic!("unexpected Carbon failure")
    }

    fn target_timed_out(&self) {
        panic!("unexpected Carbon timeout")
    }
}

async fn isolated_pool() -> (PgPool, PgPool, String) {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("carbon_audience_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .unwrap();
    eprintln!("isolated_schema_created={schema}");
    let connection_schema = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(4)
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
    (admin, pool, schema)
}

async fn replace_active_list(pool: &PgPool, owner: Uuid, action: PrivacyAction) {
    privacy::replace_privacy_list(
        pool,
        owner,
        &PrivacyList {
            name: ACTIVE.into(),
            items: vec![PrivacyItem {
                order: 1,
                action,
                match_type: None,
                match_value: None,
                message: true,
                iq: false,
                presence_in: false,
                presence_out: false,
            }],
        },
    )
    .await
    .unwrap();
}

async fn assert_refused_in_both_directions(block: bool) {
    let (admin, pool, schema) = isolated_pool().await;
    let account = northstar_auth_postgres::users::create_user(
        &pool,
        "alice",
        "test password for carbon policy",
        false,
        true,
        4096,
        false,
    )
    .await
    .unwrap();
    let service = MessageService::new(
        PostgresMessageRepository::new(
            pool.clone(),
            northstar_abuse_application::guard::test_personal_message_content_keyring(),
            "example.test",
            100,
            8_000_000,
            30,
        ),
        false,
    );
    for direction in [Direction::Sent, Direction::Received] {
        replace_active_list(&pool, account.id, PrivacyAction::Allow).await;
        let connection_id = Uuid::new_v4();
        assert!(
            privacy::set_active_privacy_list(&pool, account.id, connection_id, Some(ACTIVE))
                .await
                .unwrap()
        );
        let (sender, mut output) = mpsc::channel(1);
        let port = std::sync::Arc::new(Port {
            service: service.clone(),
            account_id: account.id,
            connection_id,
            sender: OutboundSender::new(sender),
            queue_waiting: Notify::new(),
        });
        let (from, to) = match direction {
            Direction::Sent => (ORIGIN, PEER),
            Direction::Received => (PEER, ACCOUNT),
        };
        let forwarded = format!(
            "<message xmlns='jabber:client' from='{from}' to='{to}'><body>primary</body></message>"
        );
        assert!(service
            .allows_carbon(ACCOUNT, account.id, connection_id, Some(ACTIVE), PEER)
            .await
            .unwrap());
        port.sender.try_send(forwarded.clone()).unwrap();
        let sending_port = port.clone();
        let fanout = tokio::spawn(async move {
            match direction {
                Direction::Sent => {
                    send_sent_carbons(&*sending_port, ORIGIN, &forwarded, None, None).await
                }
                Direction::Received => {
                    send_received_carbons(&*sending_port, ACCOUNT, Some(ORIGIN), &forwarded).await
                }
            }
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            port.queue_waiting.notified(),
        )
        .await
        .unwrap();
        if block {
            roster::block_jids(&pool, account.id, &[PEER.to_owned()])
                .await
                .unwrap();
        } else {
            replace_active_list(&pool, account.id, PrivacyAction::Deny).await;
        }
        assert!(output
            .recv()
            .await
            .unwrap()
            .stanza
            .contains("<body>primary</body>"));
        fanout.await.unwrap();
        assert!(output.try_recv().is_err());
        if block {
            roster::unblock_jids(&pool, account.id, Some(&[PEER.to_owned()]))
                .await
                .unwrap();
        }
    }
    drop(service);
    drop_isolated_message_pool(admin, pool, schema).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn block_after_primary_acceptance_suppresses_sent_and_received_carbons() {
    assert_refused_in_both_directions(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn active_list_deny_after_primary_acceptance_suppresses_sent_and_received_carbons() {
    assert_refused_in_both_directions(false).await;
}
