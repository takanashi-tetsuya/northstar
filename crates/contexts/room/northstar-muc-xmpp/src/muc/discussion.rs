//! MUC discussion envelopes and the live fan-out adapter.

use super::*;

/// The protocol's generated live stanza and its archive projection are bound
/// once, before admission. No later caller supplies replacement fanout bytes.
pub struct PreparedMucDiscussion {
    pub prepared: discussion_owner::PreparedDiscussion,
    pub live: MucDiscussionLive,
}

pub struct MucDiscussionLive {
    pub room_jid: String,
    pub room_from: String,
    pub sender: String,
    pub stanza: String,
}

impl PreparedMucDiscussion {
    pub fn new(
        prepared: discussion_owner::PreparedDiscussion,
        room: &MucRoom,
        room_jid: String,
        stanza: String,
    ) -> Result<Self> {
        let command = prepared.command();
        let room_from = format!("{room_jid}/{}", command.nick);
        anyhow::ensure!(
            command.room_id == room.id
                && command.authority.expected_room_epoch == room.room_epoch
                && CanonicalJid::parse_bare(&room_jid)?.localpart()
                    == Some(room.localpart.as_str()),
            "MUC discussion room projection mismatch"
        );
        let archive = if command.archive && command.encrypted {
            encrypted_archive_stanza(&stanza)
        } else {
            stanza.clone()
        };
        anyhow::ensure!(
            command.stanza == archive,
            "MUC discussion archive projection mismatch"
        );
        {
            let document = roxmltree::Document::parse(&stanza)?;
            let root = document.root_element();
            let stable_id = command.id.to_string();
            anyhow::ensure!(
                root.attribute("from") == Some(room_from.as_str())
                    && root.attribute("to") == Some(room_jid.as_str())
                    && root.attribute("type") == Some("groupchat")
                    && root.children().any(|child| {
                        child.is_element()
                            && child.tag_name().name() == "stanza-id"
                            && child.tag_name().namespace() == Some("urn:xmpp:sid:0")
                            && child.attribute("by") == Some(room_jid.as_str())
                            && child.attribute("id") == Some(stable_id.as_str())
                    }),
                "MUC discussion live identity mismatch"
            );
        }
        let sender = command.sender_jid.clone();
        Ok(Self {
            prepared,
            live: MucDiscussionLive {
                room_jid,
                room_from,
                sender,
                stanza,
            },
        })
    }

    pub fn bind(self, observation: discussion_owner::Observation) -> Result<BoundMucDiscussion> {
        anyhow::ensure!(
            observation.is_for(&self.prepared),
            "MUC discussion invocation mismatch"
        );
        let request = observation.request()?;
        Ok(BoundMucDiscussion {
            request,
            observation,
            live: self.live,
        })
    }
}

pub struct BoundMucDiscussion {
    pub request: discussion_owner::Request,
    pub observation: discussion_owner::Observation,
    pub live: MucDiscussionLive,
}

impl BoundMucDiscussion {
    pub fn finish(
        self,
        completion: discussion_owner::Completion,
    ) -> Result<Option<AcceptedMucDiscussion>> {
        let permit = completion.into_fanout(&self.observation)?;
        Ok(permit.map(|permit| AcceptedMucDiscussion {
            live: self.live,
            permit,
        }))
    }
}

pub struct AcceptedMucDiscussion {
    pub live: MucDiscussionLive,
    pub permit: discussion_owner::FanoutPermit,
}

impl AcceptedMucDiscussion {
    pub async fn fanout(self, session: &impl MucSession) -> Result<bool> {
        let Self { live, permit } = self;
        Ok(run_muc_discussion_fanout(
            &MucMessageFanout {
                session,
                room_jid: &live.room_jid,
                room_from: &live.room_from,
                sender: &live.sender,
                stanza: &live.stanza,
            },
            permit,
        )
        .await?)
    }
}

/// Adapts the accepted live-message effects without exposing persistence or
/// acknowledgement authority to the fan-out owner. The caller still owns its
/// standalone room mutation guard across this entire operation.
pub struct MucMessageFanout<'a, S> {
    pub session: &'a S,
    pub room_jid: &'a str,
    pub room_from: &'a str,
    pub sender: &'a str,
    pub stanza: &'a str,
}

impl<S: MucSession> MucFanoutPort for MucMessageFanout<'_, S> {
    type Recipient = Occupant<S::Host>;
    type Blocked = std::collections::HashSet<String>;

    fn enter(&self, stage: MucFanoutStage) {
        self.session.enter_frame_stage(match stage {
            MucFanoutStage::Cluster => MucFrameStage::ClusterFanout,
            MucFanoutStage::Local => MucFrameStage::LocalFanout,
        });
    }

    async fn publish_cluster(&self) {
        run_muc_cluster_fan_out(
            self.session.host(),
            self.room_jid,
            self.stanza,
            Some(self.sender),
            "cluster fan-out",
        )
        .await;
    }

    fn recipients(&self) -> Vec<Self::Recipient> {
        self.session
            .host()
            .muc_occupants_for(self.room_jid)
            .into_iter()
            .map(|(_, occupant)| occupant)
            .collect()
    }

    async fn blocked<'a>(&'a self, recipients: &'a [Self::Recipient]) -> Self::Blocked {
        self.session
            .host()
            .blocked_muc_recipient_accounts(
                recipients,
                &[self.room_from.to_owned(), self.sender.to_owned()],
            )
            .await
    }

    fn is_blocked(&self, recipient: &Self::Recipient, blocked: &Self::Blocked) -> bool {
        canonical_bare_key(&recipient.full_jid).is_ok_and(|owner| blocked.contains(&owner))
    }

    async fn deliver(&self, recipient: &Self::Recipient) -> bool {
        let delivery = set_to(self.stanza, &recipient.full_jid);
        tracing::debug!(room = self.room_jid, to = %recipient.full_jid, "MUC routing stanza");
        self.session
            .host()
            .deliver_to_muc_occupant_unchecked(recipient, delivery)
            .await
    }

    fn record_failure(&self, recipient: &Self::Recipient) {
        record_muc_post_commit_failure(
            self.session.host(),
            self.room_jid,
            &recipient.full_jid,
            "local/federated occupant queue",
        );
    }
}
