use super::*;
use northstar_room_core::mix::{MixChannelAddress, MixParticipantNick};

impl MixPublicationRepository for Repository {
    async fn publish_message(
        &self,
        message: &PreparedMessage,
        renderer: PublicationRenderer,
        _authenticators: Option<&ContentIdentityAuthenticators>,
        observation: Option<&foreground::StoreRequest>,
    ) -> Result<StoreMixMessageAdmission> {
        if let Some(request) = observation {
            let original = self.0.foreground_owner.lock().unwrap();
            assert!(std::ptr::eq(
                request.observation().ingress(),
                original.as_ref().unwrap().ingress()
            ));
        }
        self.0.record(Call::Store(observation.is_some()));
        let visibility = self.0.publisher_visibility.lock().unwrap().pop_front();
        let Some(visibility) = visibility else {
            anyhow::ensure!(observation.is_none(), "recorded observed store");
            return Ok(StoreMixMessageAdmission {
                outcome: StoreEventOutcome::NotParticipant,
                recipients: Vec::new(),
            });
        };
        let channel = channel();
        let publisher = LockedPublisher {
            channel: MixChannelAddress::parse(&channel.jid())?,
            nick: Some(MixParticipantNick::parse("Locked Bob")?),
            archive_jid: (visibility == "visible").then(|| message.actor.clone()),
        };
        let payload = renderer(message, &publisher)?;
        self.0
            .publisher_writes
            .lock()
            .unwrap()
            .push(PublisherWrite {
                identity: MixPublisherIdentity {
                    archive_jid_visible: publisher.archive_jid.is_some(),
                    participant_id: Uuid::from_u128(94),
                    nick: Some("Locked Bob".into()),
                },
                payload,
                tombstone: None,
            });
        if let Some(request) = observation {
            let mut stored = foreground::fixture::stored(false);
            stored.authoritative_id = message.item_id;
            stored.channel_id = message.channel_id.as_uuid();
            stored.channel_jid = channel.jid();
            request.received(request.enter_commit(stored)?)?;
        }
        Ok(StoreMixMessageAdmission {
            outcome: StoreEventOutcome::Stored(message.item_id),
            recipients: Vec::new(),
        })
    }

    async fn claimed_recipient_account(
        &self,
        _source: MixDelivery,
        address: &MixRealJid,
    ) -> Result<Option<Uuid>> {
        Ok(match address.as_str() {
            "legacy@local.test" => None,
            "reassigned@local.test" => Some(Uuid::from_u128(82)),
            _ => Some(Uuid::from_u128(81)),
        })
    }
}
