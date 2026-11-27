use super::{privacy_get, privacy_set, PrivacySession};
use crate::blocking::{blocklist, BlockingSession};
use crate::SessionIdentity;
use anyhow::Result;
use northstar_roster_application::blocking::{
    BlockUpdateOutcome, BlockingRepository, BlockingService, RosterEntry, UnblockUpdateOutcome,
};
use northstar_roster_application::privacy::{
    commands::{
        ActorOutcome, PolicyCommandRepository, PrivacyListName, PrivacyOverviewSnapshot,
        TopologyProof, TopologyResource,
    },
    PrivacyItem, PrivacyList, PrivacyListMutationOutcome, PrivacyOverview, PrivacyRepository,
    PrivacySelectionOutcome, PrivacyService, PrivacyStanzaKind,
};
use northstar_roster_application::SystemRosterEvents;
use northstar_roster_core::{PresenceAccount, RosterActor, RosterEventSource};
use northstar_xml_builder::stanza::iq_error;
use roxmltree::Document;
use uuid::Uuid;

struct CommandSession {
    actor: RosterActor,
    repository: CommandRepository,
}

impl CommandSession {
    fn new(stale: bool) -> Self {
        let actor = RosterActor {
            account_id: Uuid::new_v4(),
            auth_generation: 7,
            connection_id: Uuid::new_v4(),
            full_jid: "alice@example.test/Phone".into(),
        };
        let repository = CommandRepository {
            expected_actor: actor.clone(),
            stale,
        };
        Self { actor, repository }
    }

    async fn privacy_reply(&self, kind: &str, controls: &str) -> String {
        let xml = format!(
            "<iq type='{kind}' id='p'><query xmlns='jabber:iq:privacy'>{controls}</query></iq>"
        );
        let doc = Document::parse(&xml).unwrap();
        let root = doc.root_element();
        let query = root.first_element_child().unwrap();
        if kind == "get" {
            privacy_get(self, "p", root, query).await.unwrap()
        } else {
            let (reply, push) = privacy_set(self, "p", root, query).await.unwrap();
            assert!(push.is_none());
            reply
        }
    }
}

impl SessionIdentity for CommandSession {
    fn session_account(&self) -> Option<PresenceAccount> {
        Some(PresenceAccount {
            id: self.actor.account_id,
            username: "alice".into(),
            auth_generation: self.actor.auth_generation,
        })
    }

    fn session_local_domain(&self) -> &str {
        "example.test"
    }

    fn roster_actor(&self) -> Option<RosterActor> {
        Some(self.actor.clone())
    }

    fn roster_events(&self) -> &dyn RosterEventSource {
        static EVENTS: SystemRosterEvents = SystemRosterEvents;
        &EVENTS
    }
}

impl PrivacySession for CommandSession {
    fn privacy_full_jid(&self) -> Option<&str> {
        Some(&self.actor.full_jid)
    }

    fn privacy_connection_id(&self) -> Uuid {
        self.actor.connection_id
    }

    fn privacy_service(&self) -> &PrivacyService<impl PrivacyRepository> {
        static UNUSED: std::sync::LazyLock<PrivacyService<UnusedRepository>> =
            std::sync::LazyLock::new(|| PrivacyService::new(UnusedRepository));
        &*UNUSED
    }

    fn privacy_commands(&self) -> &impl PolicyCommandRepository {
        &self.repository
    }

    fn privacy_mark_requested(&self) {}

    fn privacy_active_list(&self) -> Option<String> {
        Some("expired".into())
    }

    fn privacy_set_active_list(&self, _: Option<String>) {
        unreachable!()
    }

    fn privacy_local_resources(&self, _: &str) -> usize {
        unreachable!()
    }

    async fn privacy_has_remote_resources(&self, _: &str) -> Result<bool> {
        unreachable!()
    }

    fn privacy_list_active_locally(&self, _: &str, _: &str) -> bool {
        unreachable!()
    }

    async fn privacy_push_change(&self, _: &str, _: &str, _: &str) -> Option<String> {
        unreachable!()
    }
}

impl BlockingSession for CommandSession {
    fn blocking_service(&self) -> &BlockingService<impl BlockingRepository> {
        static UNUSED: std::sync::LazyLock<BlockingService<UnusedRepository>> =
            std::sync::LazyLock::new(|| BlockingService::new(UnusedRepository));
        &*UNUSED
    }

    fn blocking_mark_requested(&self) {
        unreachable!("stale blocklist GET must not register interest")
    }

    async fn blocking_push_change(&self, _: &str, _: &str) {
        unreachable!()
    }

    async fn blocking_presence_change(&self, _: &str, _: &[String], _: &[String], _: bool) {
        unreachable!()
    }
}

struct CommandRepository {
    expected_actor: RosterActor,
    stale: bool,
}

impl CommandRepository {
    fn outcome<T>(&self, actor: &RosterActor, value: T) -> ActorOutcome<T> {
        assert_eq!(actor, &self.expected_actor);
        if self.stale {
            ActorOutcome::Stale
        } else {
            ActorOutcome::Current(value)
        }
    }

    fn proof() -> TopologyProof {
        TopologyProof {
            other_resources: vec![TopologyResource {
                connection_id: Uuid::from_u128(42),
                effective_list: None,
            }],
        }
    }
}

impl PolicyCommandRepository for CommandRepository {
    async fn read_privacy_overview(
        &self,
        actor: &RosterActor,
    ) -> Result<ActorOutcome<PrivacyOverviewSnapshot>> {
        Ok(self.outcome(
            actor,
            PrivacyOverviewSnapshot {
                active: None,
                default: PrivacyListName::parse("work"),
                names: vec![
                    PrivacyListName::parse("expired").unwrap(),
                    PrivacyListName::parse("work").unwrap(),
                ],
            },
        ))
    }

    async fn read_privacy_list(
        &self,
        actor: &RosterActor,
        _: &PrivacyListName,
    ) -> Result<ActorOutcome<Option<Vec<PrivacyItem>>>> {
        Ok(self.outcome(actor, None))
    }

    async fn read_blocklist(&self, actor: &RosterActor) -> Result<ActorOutcome<Vec<String>>> {
        Ok(self.outcome(actor, Vec::new()))
    }

    async fn replace_privacy_list(
        &self,
        actor: &RosterActor,
        _: &PrivacyListName,
        _: &[PrivacyItem],
    ) -> Result<ActorOutcome<PrivacyListMutationOutcome>> {
        Ok(self.outcome(actor, PrivacyListMutationOutcome::Stored))
    }

    async fn select_default_privacy_list(
        &self,
        actor: &RosterActor,
        _: Option<&PrivacyListName>,
    ) -> Result<ActorOutcome<(PrivacySelectionOutcome, TopologyProof)>> {
        Ok(self.outcome(actor, (PrivacySelectionOutcome::Conflict, Self::proof())))
    }

    async fn remove_privacy_list(
        &self,
        actor: &RosterActor,
        _: &PrivacyListName,
    ) -> Result<ActorOutcome<(PrivacyListMutationOutcome, TopologyProof)>> {
        Ok(self.outcome(actor, (PrivacyListMutationOutcome::Conflict, Self::proof())))
    }
}

struct UnusedRepository;

impl PrivacyRepository for UnusedRepository {
    async fn clear_active_session(&self, _: Uuid, _: Uuid) -> Result<()> {
        unreachable!()
    }

    async fn overview(&self, _: Uuid) -> Result<PrivacyOverview> {
        unreachable!()
    }

    async fn list(&self, _: Uuid, _: &str) -> Result<Option<PrivacyList>> {
        unreachable!()
    }

    async fn select_active(
        &self,
        _: Uuid,
        _: Uuid,
        _: Option<&str>,
    ) -> Result<PrivacySelectionOutcome> {
        unreachable!()
    }

    async fn select_default(&self, _: Uuid, _: Option<&str>) -> Result<PrivacySelectionOutcome> {
        unreachable!()
    }

    async fn replace_list(&self, _: Uuid, _: &PrivacyList) -> Result<PrivacyListMutationOutcome> {
        unreachable!()
    }

    async fn remove_list(&self, _: Uuid, _: &str) -> Result<PrivacyListMutationOutcome> {
        unreachable!()
    }

    async fn denies(
        &self,
        _: Uuid,
        _: Option<&str>,
        _: &str,
        _: PrivacyStanzaKind,
    ) -> Result<bool> {
        unreachable!()
    }
}

impl BlockingRepository for UnusedRepository {
    async fn blocked_jids(&self, _: Uuid) -> Result<Vec<String>> {
        unreachable!()
    }

    async fn roster(&self, _: Uuid) -> Result<Vec<RosterEntry>> {
        unreachable!()
    }

    async fn block(&self, _: Uuid, _: &[String]) -> Result<BlockUpdateOutcome> {
        unreachable!()
    }

    async fn unblock(&self, _: Uuid, _: Option<&[String]>) -> Result<UnblockUpdateOutcome> {
        unreachable!()
    }
}

#[tokio::test]
async fn stale_actor_gets_not_authorized_for_privacy_commands_and_blocklist() {
    let session = CommandSession::new(true);
    for (kind, controls) in [
        ("get", ""),
        ("get", "<list name='work'/>"),
        ("set", "<default name='work'/>"),
        ("set", "<default/>"),
        ("set", "<list name='work'/>"),
        (
            "set",
            "<list name='work'><item action='deny' order='1'/></list>",
        ),
    ] {
        assert_eq!(
            session.privacy_reply(kind, controls).await,
            iq_error("p", "not-authorized")
        );
    }
    let doc = Document::parse("<iq type='get' id='b'><blocklist xmlns='urn:xmpp:blocking'/></iq>")
        .unwrap();
    assert_eq!(
        blocklist(&session, "b", doc.root_element()).await.unwrap(),
        iq_error("b", "not-authorized")
    );
}

#[tokio::test]
async fn overview_omits_an_expired_selection_even_if_the_session_remembers_it() {
    let session = CommandSession::new(false);
    let reply = session.privacy_reply("get", "").await;
    let doc = Document::parse(&reply).unwrap();
    let root = doc.root_element();
    assert_eq!(root.attribute("type"), Some("result"));
    let controls: Vec<_> = root
        .first_element_child()
        .unwrap()
        .children()
        .filter(roxmltree::Node::is_element)
        .map(|node| (node.tag_name().name(), node.attribute("name")))
        .collect();
    assert_eq!(
        controls,
        [
            ("default", Some("work")),
            ("list", Some("expired")),
            ("list", Some("work"))
        ]
    );
}

#[tokio::test]
async fn uncertain_publication_conflicts_on_default_change_and_decline() {
    let session = CommandSession::new(false);
    for control in ["<default name='work'/>", "<default/>"] {
        assert_eq!(
            session.privacy_reply("set", control).await,
            iq_error("p", "conflict")
        );
    }
}
