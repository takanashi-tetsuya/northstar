//! Data-only facts for one ordinary MIX message. Read evidence is distinct
//! from the fresh message transaction and from durable outbox delivery.

use northstar_xmpp_types::CanonicalJid;
pub use uuid::Uuid as Id;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Participant {
    pub participant_id: Id,
    pub jid: String,
    pub nick: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayIdentity {
    pub client_id: String,
    pub canonical_semantics: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Replay {
    Miss,
    Replay(Id),
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Stored(Id),
    Replay(Id),
    NotParticipant,
    Conflict,
    TooLarge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Admission {
    pub outcome: Outcome,
    pub recipients: Vec<Participant>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Existing {
    pub authoritative_id: Id,
    pub semantic_key_id: String,
    pub semantic_mac: Vec<u8>,
    pub target_id: Option<Id>,
}

impl std::fmt::Debug for Existing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Existing { commitment: [redacted] }")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ingress {
    pub channel_id: Id,
    pub channel_jid: String,
    pub actor_bare: String,
    pub actor_full: String,
    pub children: String,
    pub encrypted: bool,
    pub identity: Option<ReplayIdentity>,
}

impl Ingress {
    /// The argument must come from the receiving service's configuration.
    /// This checks a bound input; it does not authenticate a transport actor.
    pub fn matches_receiving_domain(&self, configured_mix_domain: &str) -> bool {
        let (Ok(channel), Ok(bare), Ok(full)) = (
            CanonicalJid::parse(&self.channel_jid),
            CanonicalJid::parse(&self.actor_bare),
            CanonicalJid::parse(&self.actor_full),
        ) else {
            return false;
        };
        channel.domainpart() == configured_mix_domain
            && channel.localpart().is_some()
            && channel.resourcepart().is_none()
            && channel.to_string() == self.channel_jid
            && bare.localpart().is_some()
            && bare.resourcepart().is_none()
            && bare.to_string() == self.actor_bare
            && full.resourcepart().is_some()
            && full.to_string() == self.actor_full
            && full.bare() == self.actor_bare
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreCommand {
    pub channel_id: Id,
    pub actor: String,
    pub item_id: Id,
    pub payload: String,
    pub identity: Option<ReplayIdentity>,
    pub delivery_payload: String,
    pub visible_jid: Option<String>,
    pub encrypted: bool,
}

impl StoreCommand {
    pub fn matches_ingress(&self, ingress: &Ingress) -> bool {
        self.channel_id == ingress.channel_id
            && self.actor == ingress.actor_bare
            && self.identity == ingress.identity
            && self.delivery_payload == ingress.children
            && self.encrypted == ingress.encrypted
            && self
                .visible_jid
                .as_ref()
                .is_none_or(|jid| jid == &ingress.actor_bare)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientProjection {
    pub participant: Participant,
    pub delivery_id: Id,
    pub sequence: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryProjection {
    pub event_id: Id,
    pub channel_id: Id,
    pub channel_jid: String,
    pub stanza_template: String,
    pub authoritative_stanza_id: Option<Id>,
    pub archive: bool,
    pub encrypted: bool,
    /// Original transaction audience order, with actual generated delivery
    /// IDs and database-returned recipient sequence values attached once.
    pub recipients: Vec<RecipientProjection>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Stored {
    pub authoritative_id: Id,
    pub storage_id: Id,
    pub channel_id: Id,
    pub channel_jid: String,
    /// Empty audience returns before durable event/sequence projection.
    pub projection: Option<DeliveryProjection>,
}

impl Stored {
    pub fn matches_command(&self, command: &StoreCommand, ingress: &Ingress) -> bool {
        self.authoritative_id == command.item_id
            && self.channel_id == command.channel_id
            && self.channel_jid == ingress.channel_jid
            && self.projection.as_ref().is_none_or(|projection| {
                projection.event_id == self.authoritative_id
                    && projection.channel_id == self.channel_id
                    && projection.channel_jid == self.channel_jid
                    && projection.authoritative_stanza_id == Some(self.authoritative_id)
                    && projection.archive
                    && projection.encrypted == command.encrypted
                    && !projection.stanza_template.is_empty()
                    && !projection.recipients.is_empty()
                    && projection
                        .recipients
                        .iter()
                        .all(|recipient| recipient.sequence > 0)
            })
    }

    pub fn matches_return(&self, admission: &Admission) -> bool {
        admission.outcome == Outcome::Stored(self.authoritative_id)
            && match &self.projection {
                None => admission.recipients.is_empty(),
                Some(projection) => projection
                    .recipients
                    .iter()
                    .map(|r| &r.participant)
                    .eq(admission.recipients.iter()),
            }
    }
}
