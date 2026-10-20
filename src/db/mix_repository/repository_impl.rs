//! Implement the MIX repository trait using PostgreSQL persistence operations.

use super::*;

impl MixRepository for PostgresMixRepository {
    async fn link_local_muc_mirror(
        &self,
        mix_domain: &str,
        localpart: &str,
        actor_bare_jid: &str,
        local_domain: &str,
    ) -> Result<MixMucLinkOutcome> {
        Ok(map_mix_muc_link_outcome(
            db::link_mix_muc_by_localpart(
                &self.pool,
                mix_domain,
                localpart,
                actor_bare_jid,
                local_domain,
            )
            .await?,
        ))
    }
    async fn create_mix_channel(
        &self,
        service_domain: &str,
        requested_localpart: Option<&str>,
        creator_jid: &str,
        max_channels_per_owner: i64,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<(CreateChannelOutcome, String)> {
        let (outcome, localpart) = db::create_mix_channel(
            &self.pool,
            service_domain,
            requested_localpart,
            creator_jid,
            max_channels_per_owner,
            &MixPayloads,
            federated,
        )
        .await?;
        Ok((create_outcome(outcome), localpart))
    }
    async fn mix_channel(
        &self,
        service_domain: &str,
        localpart: &str,
    ) -> Result<Option<MixChannel>> {
        db::mix_channel(&self.pool, service_domain, localpart).await
    }
    async fn discoverable_mix_channel_page(
        &self,
        service_domain: &str,
        requester: &str,
        after: Option<&str>,
        before: Option<Option<&str>>,
        max: i64,
    ) -> Result<Option<MixDiscoPage>> {
        Ok(db::discoverable_mix_channel_page(
            &self.pool,
            service_domain,
            requester,
            after,
            before,
            max,
        )
        .await?
        .map(|page| MixDiscoPage {
            channels: page.channels,
            total: page.total,
            first_index: page.first_index,
        }))
    }
    async fn mix_role(&self, channel_id: Uuid, jid: &str) -> Result<Option<String>> {
        db::mix_role(&self.pool, channel_id, jid).await
    }
    async fn mix_channel_discoverable_to(&self, channel: &MixChannel, actor: &str) -> Result<bool> {
        db::mix_channel_discoverable_to(&self.pool, channel, actor).await
    }
    async fn destroy_mix_channel(
        &self,
        channel_id: Uuid,
        actor: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        db::destroy_mix_channel(&self.pool, channel_id, actor, &MixPayloads, federated).await
    }
    async fn join_mix_channel(
        &self,
        channel_id: Uuid,
        request: JoinMixRequest,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<JoinChannelOutcome> {
        // The repository borrows the parsed request; owned invitation and
        // preference mirrors are materialized here so their lifetimes cover
        // the awaited transaction.
        let db_invitation = request
            .invitation
            .as_ref()
            .map(db::MixInvitationProof::from);
        let db_preference = request.preference.as_ref().cloned();

        let outcome = db::join_mix_channel(
            &self.pool,
            channel_id,
            db::JoinMixRequest {
                actor_jid: &request.actor_jid,
                nick: request.nick.as_deref(),
                nodes: &request.nodes,
                pam_user_id: request.pam_user_id,
                invitation: db_invitation.as_ref(),
                preference: db_preference.as_ref(),
                anonymous_profile: request.anonymous_profile,
            },
            &MixPayloads,
            federated,
        )
        .await?;
        Ok(join_outcome(outcome))
    }
    async fn mix_participant(&self, channel_id: Uuid, jid: &str) -> Result<Option<MixParticipant>> {
        db::mix_participant(&self.pool, channel_id, jid).await
    }
    async fn mix_participant_by_id(
        &self,
        channel_id: Uuid,
        participant_id: Uuid,
    ) -> Result<Option<MixParticipant>> {
        db::mix_participant_by_id(&self.pool, channel_id, participant_id).await
    }
    async fn mix_presence_source_jid(
        &self,
        channel_id: Uuid,
        item_id: &str,
    ) -> Result<Option<String>> {
        db::mix_presence_source_jid(&self.pool, channel_id, item_id).await
    }
    async fn expire_unrefreshed_mix_presence(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<ExpiredMixPresence>> {
        Ok(
            db::expire_unrefreshed_mix_presence(&self.pool, cutoff, &MixPayloads)
                .await?
                .into_iter()
                .map(|expired| ExpiredMixPresence {
                    channel_id: expired.channel_id,
                    participant: expired.participant,
                    item_id: expired.item_id,
                    payload: expired.payload,
                    source_full_jid: expired.source_full_jid,
                })
                .collect(),
        )
    }
    async fn update_mix_subscriptions(
        &self,
        channel_id: Uuid,
        actor: &str,
        subscribe: &[String],
        unsubscribe: &[String],
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<UpdateSubscriptionsOutcome>> {
        Ok(db::update_mix_subscriptions(
            &self.pool,
            channel_id,
            actor,
            subscribe,
            unsubscribe,
            &MixPayloads,
            federated,
        )
        .await?
        .map(|outcome| UpdateSubscriptionsOutcome {
            subscriptions: outcome.subscriptions,
            participant: outcome.participant,
            removed_presence: outcome
                .removed_presence
                .into_iter()
                .map(presence_item)
                .collect(),
        }))
    }
    async fn set_mix_nick(
        &self,
        channel_id: Uuid,
        actor: &str,
        nick: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<std::result::Result<MixParticipant, SetNickError>> {
        Ok(
            match db::set_mix_nick(&self.pool, channel_id, actor, nick, &MixPayloads, federated)
                .await?
            {
                Ok(stored_participant) => Ok(stored_participant),
                Err(db::SetNickError::NotParticipant) => Err(SetNickError::NotParticipant),
                Err(db::SetNickError::Conflict) => Err(SetNickError::Conflict),
            },
        )
    }
    async fn leave_mix_channel(
        &self,
        channel_id: Uuid,
        actor: &str,
        pam_user_id: Option<Uuid>,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<LeaveMixOutcome>> {
        Ok(db::leave_mix_channel(
            &self.pool,
            channel_id,
            actor,
            pam_user_id,
            &MixPayloads,
            federated,
        )
        .await?
        .map(|left| LeaveMixOutcome {
            participant: left.participant,
            presence_items: left.presence_items.into_iter().map(presence_item).collect(),
            roster_change: left.roster_change,
        }))
    }
    async fn store_mix_presence(
        &self,
        channel_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
        payload: &str,
        unavailable: bool,
    ) -> Result<PresenceOutcome> {
        Ok(presence_outcome(
            db::store_mix_presence(
                &self.pool,
                channel_id,
                actor_bare,
                actor_full,
                payload,
                unavailable,
                &MixPayloads,
            )
            .await?,
        ))
    }
    async fn ensure_mix_presence(
        &self,
        channel_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
        payload: &str,
    ) -> Result<PresenceOutcome> {
        Ok(presence_outcome(
            db::ensure_mix_presence(
                &self.pool,
                channel_id,
                actor_bare,
                actor_full,
                payload,
                &MixPayloads,
            )
            .await?,
        ))
    }
    async fn store_mix_message(
        &self,
        request: StoreMixMessageRequest<'_>,
        authenticators: Option<&crate::services::abuse::ContentIdentityAuthenticators>,
    ) -> Result<StoreMixMessageAdmission> {
        let StoreMixMessageRequest {
            channel_id,
            actor,
            item_id,
            payload,
            identity,
            delivery_payload,
            visible_jid,
            encrypted,
        } = request;
        let db_identity =
            identity
                .as_ref()
                .zip(authenticators.as_ref())
                .map(|(identity, authenticators)| {
                    let primary = authenticators.primary();
                    db::MixBusinessIdentity {
                        client_id: &identity.client_id,
                        semantic_key_id: primary.key_id(),
                        semantic_mac: primary.mac(),
                    }
                });

        let admission = db::store_mix_message(
            &self.pool,
            channel_id,
            actor,
            item_id,
            payload,
            db_identity,
            delivery_payload,
            visible_jid,
            encrypted,
            &MixPayloads,
        )
        .await?;

        let outcome = match admission.outcome {
            db::StoreEventOutcome::Existing(existing) => {
                let exact = authenticators.as_ref().is_some_and(|authenticators| {
                    existing.target_id.is_none()
                        && authenticators
                            .verifies(&existing.semantic_key_id, &existing.semantic_mac)
                });
                if exact {
                    StoreEventOutcome::Replay(existing.authoritative_id)
                } else {
                    StoreEventOutcome::Conflict
                }
            }
            outcome => store_event_outcome(outcome),
        };
        Ok(StoreMixMessageAdmission {
            outcome,
            recipients: admission.recipients,
        })
    }
    async fn store_mix_message_observed(
        &self,
        request: &foreground::StoreRequest,
        authenticators: Option<&crate::services::abuse::ContentIdentityAuthenticators>,
    ) -> Result<StoreMixMessageAdmission> {
        let identity = request.command().identity.as_ref().zip(authenticators).map(
            |(identity, authenticators)| {
                let primary = authenticators.primary();
                db::MixBusinessIdentity {
                    client_id: &identity.client_id,
                    semantic_key_id: primary.key_id(),
                    semantic_mac: primary.mac(),
                }
            },
        );
        let admission =
            db::store_mix_message_observed(&self.pool, request, identity, &MixPayloads).await?;
        let outcome = match admission.outcome {
            db::StoreEventOutcome::Existing(existing) => {
                let raw = db::mix::foreground_existing(&existing);
                let exact = authenticators.is_some_and(|authenticators| {
                    existing.target_id.is_none()
                        && authenticators
                            .verifies(&existing.semantic_key_id, &existing.semantic_mac)
                });
                let classified = if exact {
                    MixBusinessReplay::Replay(existing.authoritative_id)
                } else {
                    MixBusinessReplay::Conflict
                };
                request.authenticated(&raw, classified)?;
                if exact {
                    StoreEventOutcome::Replay(existing.authoritative_id)
                } else {
                    StoreEventOutcome::Conflict
                }
            }
            outcome => store_event_outcome(outcome),
        };
        Ok(StoreMixMessageAdmission {
            outcome,
            recipients: admission.recipients,
        })
    }

    async fn lookup_mix_message_replay_observed(
        &self,
        request: &foreground::ReplayRequest,
        authenticators: &crate::services::abuse::ContentIdentityAuthenticators,
    ) -> Result<MixBusinessReplay> {
        let ingress = request.ingress();
        let identity = ingress
            .identity
            .as_ref()
            .ok_or(foreground::Rejected::Input)?;
        let existing = db::lookup_mix_business_intent(
            &self.pool,
            ingress.channel_id,
            &ingress.actor_bare,
            "message",
            &identity.client_id,
        )
        .await?;
        let Some(existing) = existing else {
            request.observed_miss()?;
            return Ok(MixBusinessReplay::Miss);
        };
        let raw = db::mix::foreground_existing(&existing);
        request.observed_existing(raw.clone())?;
        let result = if existing.target_id.is_none()
            && authenticators.verifies(&existing.semantic_key_id, &existing.semantic_mac)
        {
            MixBusinessReplay::Replay(existing.authoritative_id)
        } else {
            MixBusinessReplay::Conflict
        };
        request.authenticated(&raw, result)?;
        Ok(result)
    }

    async fn lookup_mix_message_replay(
        &self,
        channel_id: Uuid,
        actor: &str,
        identity: &MixReplayIdentity,
        authenticators: &crate::services::abuse::ContentIdentityAuthenticators,
    ) -> Result<MixBusinessReplay> {
        let existing = db::lookup_mix_business_intent(
            &self.pool,
            channel_id,
            actor,
            "message",
            &identity.client_id,
        )
        .await?;
        Ok(match existing {
            None => MixBusinessReplay::Miss,
            Some(existing)
                if existing.target_id.is_none()
                    && authenticators
                        .verifies(&existing.semantic_key_id, &existing.semantic_mac) =>
            {
                MixBusinessReplay::Replay(existing.authoritative_id)
            }
            Some(_) => MixBusinessReplay::Conflict,
        })
    }
    async fn lookup_mix_retraction_replay(
        &self,
        channel_id: Uuid,
        actor: &str,
        target_id: Uuid,
        identity: &MixReplayIdentity,
        authenticators: &crate::services::abuse::ContentIdentityAuthenticators,
    ) -> Result<MixBusinessReplay> {
        let existing = db::lookup_mix_business_intent(
            &self.pool,
            channel_id,
            actor,
            "retraction",
            &identity.client_id,
        )
        .await?;
        Ok(match existing {
            None => MixBusinessReplay::Miss,
            Some(existing)
                if existing.target_id == Some(target_id)
                    && authenticators
                        .verifies(&existing.semantic_key_id, &existing.semantic_mac) =>
            {
                MixBusinessReplay::Replay(existing.authoritative_id)
            }
            Some(_) => MixBusinessReplay::Conflict,
        })
    }
    async fn authorized_mix_event_page(
        &self,
        channel_id: Uuid,
        actor: &str,
        node: &str,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> Result<MixReadOutcome<MixEventPage>> {
        Ok(
            match db::authorized_mix_event_page(&self.pool, channel_id, actor, node, before, limit)
                .await?
            {
                db::MixReadOutcome::Found(page) => MixReadOutcome::Found(MixEventPage {
                    events: page.events.into_iter().map(event).collect(),
                }),
                db::MixReadOutcome::Unauthorized => MixReadOutcome::Unauthorized,
                db::MixReadOutcome::NotFound => MixReadOutcome::NotFound,
            },
        )
    }
    async fn publish_mix_avatar(
        &self,
        channel_id: Uuid,
        actor: &str,
        node: &str,
        item_id: &str,
        payload: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        db::publish_mix_avatar(
            &self.pool,
            channel_id,
            actor,
            node,
            item_id,
            payload,
            &MixPayloads,
            federated,
        )
        .await
    }
    async fn retract_mix_avatar(
        &self,
        channel_id: Uuid,
        actor: &str,
        node: &str,
        item_id: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        db::retract_mix_avatar(
            &self.pool,
            channel_id,
            actor,
            node,
            item_id,
            &MixPayloads,
            federated,
        )
        .await
    }
    async fn authorized_mix_mam_page(
        &self,
        channel_id: Uuid,
        actor: &str,
        viewer_id: Option<Uuid>,
        query: &MamArchiveQuery,
    ) -> Result<MixReadOutcome<MixMamPage>> {
        Ok(
            match db::authorized_mix_mam_page(
                &self.pool,
                channel_id,
                actor,
                viewer_id,
                &mam_query_db(query),
            )
            .await?
            {
                db::MixReadOutcome::Found(page) => MixReadOutcome::Found(mam_page(page)),
                db::MixReadOutcome::Unauthorized => MixReadOutcome::Unauthorized,
                db::MixReadOutcome::NotFound => MixReadOutcome::NotFound,
            },
        )
    }
    async fn authorized_mix_mam_boundaries(
        &self,
        channel_id: Uuid,
        actor: &str,
        viewer_id: Option<Uuid>,
    ) -> Result<MixReadOutcome<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>> {
        Ok(
            match db::authorized_mix_mam_boundaries(&self.pool, channel_id, actor, viewer_id)
                .await?
            {
                db::MixReadOutcome::Found((first, last)) => {
                    MixReadOutcome::Found((first.map(boundary), last.map(boundary)))
                }
                db::MixReadOutcome::Unauthorized => MixReadOutcome::Unauthorized,
                db::MixReadOutcome::NotFound => MixReadOutcome::NotFound,
            },
        )
    }
    async fn authorized_mix_access_entries(
        &self,
        channel_id: Uuid,
        actor: &str,
        banned: bool,
        limit: i64,
    ) -> Result<MixReadOutcome<Vec<String>>> {
        Ok(
            match db::authorized_mix_access_entries(&self.pool, channel_id, actor, banned, limit)
                .await?
            {
                db::MixReadOutcome::Found(entries) => MixReadOutcome::Found(entries),
                db::MixReadOutcome::Unauthorized => MixReadOutcome::Unauthorized,
                db::MixReadOutcome::NotFound => MixReadOutcome::NotFound,
            },
        )
    }
    async fn update_mix_info(
        &self,
        channel_id: Uuid,
        actor: &str,
        update: MixInfoUpdate,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        Ok(
            match db::update_mix_info(
                &self.pool,
                channel_id,
                actor,
                db::MixInfoUpdate {
                    item_id: &update.item_id,
                    expected_revision: update.expected_revision,
                    name: update.name.as_deref(),
                    description: update.description.as_deref(),
                    contacts: &update.contacts,
                },
                &MixPayloads,
                federated,
            )
            .await?
            {
                db::MixMutationOutcome::Applied(admission) => {
                    MixMutationOutcome::Applied(Box::new(mutation_admission(*admission)))
                }
                db::MixMutationOutcome::Conflict => MixMutationOutcome::Conflict,
                db::MixMutationOutcome::Forbidden => MixMutationOutcome::Forbidden,
                db::MixMutationOutcome::NotFound => MixMutationOutcome::NotFound,
            },
        )
    }
    async fn update_mix_config(
        &self,
        channel_id: Uuid,
        actor: &str,
        update: MixConfigUpdate,
        roles: MixRoleUpdate,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<MixMutationOutcome> {
        Ok(
            match db::update_mix_config(
                &self.pool,
                channel_id,
                actor,
                db::MixConfigUpdate {
                    item_id: &update.item_id,
                    expected_revision: update.expected_revision,
                    access_model: &update.access_model,
                    jid_visibility: &update.jid_visibility,
                    nick_required: update.nick_required,
                    max_participants: update.max_participants,
                    max_events: update.max_events,
                    allow_private_messages: update.allow_private_messages,
                    allow_participant_invites: update.allow_participant_invites,
                    allow_user_message_retraction: update.allow_user_message_retraction,
                    administrator_retraction_rights: &update.administrator_retraction_rights,
                    enforce_registered_nick: update.enforce_registered_nick,
                },
                db::MixRoleUpdate {
                    owners: roles.owners.as_deref(),
                    administrators: roles.administrators.as_deref(),
                },
                &MixPayloads,
                federated,
            )
            .await?
            {
                db::MixMutationOutcome::Applied(admission) => {
                    MixMutationOutcome::Applied(Box::new(mutation_admission(*admission)))
                }
                db::MixMutationOutcome::Conflict => MixMutationOutcome::Conflict,
                db::MixMutationOutcome::Forbidden => MixMutationOutcome::Forbidden,
                db::MixMutationOutcome::NotFound => MixMutationOutcome::NotFound,
            },
        )
    }
    async fn set_mix_access_entry(
        &self,
        update: MixAccessEntryUpdate<'_>,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<AccessChangeOutcome>> {
        let list = match update.list {
            MixAccessList::Allowed => db::MixAccessList::Allowed,
            MixAccessList::Banned => db::MixAccessList::Banned,
        };
        let operation = match update.operation {
            MixAccessEntryOperation::Publish { reason } => {
                db::MixAccessEntryOperation::Publish { reason }
            }
            MixAccessEntryOperation::Retract => db::MixAccessEntryOperation::Retract,
        };

        Ok(db::set_mix_access_entry(
            &self.pool,
            db::MixAccessEntryUpdate {
                channel_id: update.channel_id,
                actor: update.actor,
                pattern: update.pattern,
                list,
                operation,
            },
            &MixPayloads,
            federated,
        )
        .await?
        .map(access_change_outcome))
    }
    async fn register_mix_nick(
        &self,
        service_domain: &str,
        actor: &str,
        nick: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<RegisterMixNickOutcome> {
        Ok(
            match db::register_mix_nick(
                &self.pool,
                service_domain,
                actor,
                nick,
                &MixPayloads,
                federated,
            )
            .await?
            {
                db::RegisterMixNickOutcome::Registered { nick } => {
                    RegisterMixNickOutcome::Registered { nick }
                }
                db::RegisterMixNickOutcome::Conflict => RegisterMixNickOutcome::Conflict,
            },
        )
    }
    async fn mix_participant_preference(
        &self,
        channel_id: Uuid,
        actor: &str,
    ) -> Result<Option<MixParticipantPreference>> {
        db::mix_participant_preference(&self.pool, channel_id, actor).await
    }
    async fn update_mix_participant_preference(
        &self,
        channel_id: Uuid,
        actor: &str,
        preference: &MixParticipantPreference,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<MixParticipantPreferenceUpdateOutcome>> {
        Ok(db::update_mix_participant_preference(
            &self.pool,
            channel_id,
            actor,
            preference,
            &MixPayloads,
            federated,
        )
        .await?
        .map(|outcome| MixParticipantPreferenceUpdateOutcome {
            participant: outcome.participant,
            roster_changes: outcome.roster_changes,
        }))
    }
    async fn authorized_mix_jid_map_entries(
        &self,
        channel_id: Uuid,
        actor: &str,
        limit: i64,
    ) -> Result<MixReadOutcome<Vec<(String, String)>>> {
        Ok(
            match db::authorized_mix_jid_map_entries(&self.pool, channel_id, actor, limit).await? {
                db::MixReadOutcome::Found(entries) => MixReadOutcome::Found(entries),
                db::MixReadOutcome::Unauthorized => MixReadOutcome::Unauthorized,
                db::MixReadOutcome::NotFound => MixReadOutcome::NotFound,
            },
        )
    }
    async fn issue_mix_invitation(
        &self,
        channel_id: Uuid,
        inviter: &str,
        invitee: &str,
        token: &str,
        lifetime: chrono::Duration,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        db::issue_mix_invitation(
            &self.pool,
            channel_id,
            inviter,
            invitee,
            token,
            lifetime,
            &MixPayloads,
            federated,
        )
        .await
    }
    async fn mix_private_message_recipient(
        &self,
        channel_id: Uuid,
        sender: &str,
        recipient_id: Uuid,
    ) -> Result<Option<(MixParticipant, MixParticipant)>> {
        db::mix_private_message_recipient(&self.pool, channel_id, sender, recipient_id).await
    }
    async fn retract_mix_message(
        &self,
        request: RetractMixMessageRequest<'_>,
        authenticators: Option<&crate::services::abuse::ContentIdentityAuthenticators>,
    ) -> Result<RetractMixMessageAdmission> {
        let RetractMixMessageRequest {
            channel_id,
            actor,
            target_id,
            retraction_id,
            tombstone_payload,
            retraction_payload,
            identity,
            visible_jid,
        } = request;
        let db_identity =
            identity
                .as_ref()
                .zip(authenticators.as_ref())
                .map(|(identity, authenticators)| {
                    let primary = authenticators.primary();
                    db::MixBusinessIdentity {
                        client_id: &identity.client_id,
                        semantic_key_id: primary.key_id(),
                        semantic_mac: primary.mac(),
                    }
                });

        let admission = db::retract_mix_message(
            &self.pool,
            channel_id,
            actor,
            target_id,
            retraction_id,
            tombstone_payload,
            retraction_payload,
            db_identity,
            visible_jid,
            &MixPayloads,
        )
        .await?;

        Ok(retract_mix_message_admission(admission, |existing| {
            let exact = authenticators.as_ref().is_some_and(|authenticators| {
                existing.target_id == Some(target_id)
                    && authenticators.verifies(&existing.semantic_key_id, &existing.semantic_mac)
            });
            if exact {
                RetractMixMessageOutcome::Replay(existing.authoritative_id)
            } else {
                RetractMixMessageOutcome::Conflict
            }
        }))
    }
    async fn begin_remote_pam_join(
        &self,
        request: BeginRemotePamJoin,
    ) -> Result<PamOperationReplay> {
        Ok(map_pam_replay(
            db::begin_remote_pam_join(
                &self.pool,
                db::BeginRemotePamJoin {
                    user_id: request.user_id,
                    actor_jid: &request.actor_jid,
                    channel_jid: &request.channel_jid,
                    nick: request.nick.as_deref(),
                    nodes: &request.nodes,
                    request_id: &request.request_id,
                    client_request_id: &request.client_request_id,
                    requester_full_jid: &request.requester_full_jid,
                    request_digest: &request.request_digest,
                    remote_domain: &request.remote_domain,
                    outbound_stanza: &request.outbound_stanza,
                    policy: db::S2sOutboxPolicy {
                        ttl_seconds: request.policy.ttl_seconds,
                        max_rows: request.policy.max_rows,
                        max_bytes: request.policy.max_bytes,
                        max_per_domain: request.policy.max_per_domain,
                    },
                },
            )
            .await?,
        ))
    }
    async fn lookup_remote_pam_operation(
        &self,
        user_id: Uuid,
        requester_full_jid: &str,
        client_request_id: &str,
        request_digest: &[u8; 32],
    ) -> Result<PamOperationReplay> {
        Ok(map_pam_replay(
            db::lookup_remote_pam_operation(
                &self.pool,
                user_id,
                requester_full_jid,
                client_request_id,
                request_digest,
            )
            .await?,
        ))
    }
    async fn begin_remote_pam_leave(
        &self,
        request: BeginRemotePamLeave,
    ) -> Result<PamOperationReplay> {
        Ok(map_pam_replay(
            db::begin_remote_pam_leave(
                &self.pool,
                db::BeginRemotePamLeave {
                    user_id: request.user_id,
                    actor_jid: &request.actor_jid,
                    channel_jid: &request.channel_jid,
                    request_id: &request.request_id,
                    client_request_id: &request.client_request_id,
                    requester_full_jid: &request.requester_full_jid,
                    request_digest: &request.request_digest,
                    remote_domain: &request.remote_domain,
                    outbound_stanza: &request.outbound_stanza,
                    policy: db::S2sOutboxPolicy {
                        ttl_seconds: request.policy.ttl_seconds,
                        max_rows: request.policy.max_rows,
                        max_bytes: request.policy.max_bytes,
                        max_per_domain: request.policy.max_per_domain,
                    },
                },
            )
            .await?,
        ))
    }
    async fn complete_remote_pam_success(
        &self,
        authenticated_domain: &str,
        channel_jid: &str,
        recipient_bare: &str,
        request_id: &str,
        response_digest: &[u8; 32],
        join: Option<RemotePamJoin<'_>>,
    ) -> Result<RemotePamCompletionOutcome> {
        let join = join.map(|join| db::RemotePamJoin {
            participant_id: join.participant_id,
            subscriptions: join.subscriptions,
            nick: join.nick,
        });
        Ok(map_pam_completion(
            db::complete_remote_pam_success(
                &self.pool,
                authenticated_domain,
                channel_jid,
                recipient_bare,
                request_id,
                response_digest,
                join,
                &MixPayloads,
            )
            .await?,
        ))
    }
    #[allow(clippy::too_many_arguments)]
    async fn complete_remote_pam_error(
        &self,
        authenticated_domain: &str,
        channel_jid: &str,
        recipient_bare: &str,
        request_id: &str,
        response_digest: &[u8; 32],
        error_type: &str,
        condition: &str,
    ) -> Result<RemotePamCompletionOutcome> {
        Ok(map_pam_completion(
            db::complete_remote_pam_error(
                &self.pool,
                authenticated_domain,
                channel_jid,
                recipient_bare,
                request_id,
                response_digest,
                error_type,
                condition,
                &MixPayloads,
            )
            .await?,
        ))
    }
    async fn pam_memberships(&self, user_id: Uuid) -> Result<Vec<PamMembership>> {
        Ok(db::pam_memberships(&self.pool, user_id)
            .await?
            .into_iter()
            .map(pam_membership)
            .collect())
    }
    async fn pam_membership(
        &self,
        user_id: Uuid,
        channel_jid: &str,
    ) -> Result<Option<PamMembership>> {
        Ok(db::pam_membership(&self.pool, user_id, channel_jid)
            .await?
            .map(pam_membership))
    }
    async fn local_pam_users_for_channel(&self, channel_jid: &str) -> Result<Vec<Uuid>> {
        db::local_pam_users_for_channel(&self.pool, channel_jid).await
    }
    async fn reconcile_expired_remote_pam(&self, limit: i64) -> Result<u64> {
        db::reconcile_expired_remote_pam(&self.pool, limit, &MixPayloads).await
    }
    async fn claim_pam_results(&self, limit: i64) -> Result<Vec<ClaimedPamResult>> {
        let results = {
            let results = db::claim_pam_results(&self.pool, limit).await?;
            results
        };
        Ok(results
            .into_iter()
            .map(|result| ClaimedPamResult {
                operation_id: result.operation_id,
                user_id: result.user_id,
                requester_full_jid: result.requester_full_jid,
                response_xml: result.response_xml,
                attempt_count: result.attempt_count,
                lease_token: result.lease_token,
            })
            .collect())
    }
    async fn renew_pam_result_lease(&self, operation_id: Uuid, lease_token: Uuid) -> Result<bool> {
        db::renew_pam_result_lease(&self.pool, operation_id, lease_token).await
    }
    async fn acknowledge_pam_result(&self, operation_id: Uuid, lease_token: Uuid) -> Result<bool> {
        db::acknowledge_pam_result(&self.pool, operation_id, lease_token).await
    }
    async fn defer_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
        delay_seconds: i64,
    ) -> Result<bool> {
        db::defer_pam_result(&self.pool, operation_id, lease_token, delay_seconds).await
    }
    async fn retry_pam_result(
        &self,
        operation_id: Uuid,
        lease_token: Uuid,
        attempt_count: i32,
        error: &str,
    ) -> Result<bool> {
        db::retry_pam_result(&self.pool, operation_id, lease_token, attempt_count, error).await
    }
    async fn prune_expired_pam_results(&self, limit: i64) -> Result<u64> {
        db::prune_expired_pam_results(&self.pool, limit).await
    }
    async fn find_enabled_user(&self, username: &str) -> Result<Option<MixAccount>> {
        Ok(db::find_enabled_user(&self.pool, username)
            .await?
            .map(|user| MixAccount {
                id: user.id,
                username: user.username,
            }))
    }

    async fn find_enabled_user_by_id(&self, user_id: Uuid) -> Result<Option<MixAccount>> {
        Ok(db::find_enabled_user_by_id(&self.pool, user_id)
            .await?
            .map(|user| MixAccount {
                id: user.id,
                username: user.username,
            }))
    }
    async fn is_blocked(&self, owner_id: Uuid, candidate: &str) -> Result<bool> {
        db::is_blocked(&self.pool, owner_id, candidate).await
    }

    async fn pep_node(&self, owner_id: Uuid, node: &str) -> Result<Option<PepNodeConfig>> {
        Ok(db::pep_node(&self.pool, owner_id, node)
            .await?
            .map(|config| PepNodeConfig {
                access_model: config.access_model,
                max_items: config.max_items,
                persist_items: config.persist_items,
                send_last_published_item: config.send_last_published_item,
                deliver_notifications: config.deliver_notifications,
                roster_groups_allowed: config.roster_groups_allowed,
                access_whitelist: config.access_whitelist,
            }))
    }
    async fn pep_items(
        &self,
        owner_id: Uuid,
        node: &str,
        item_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<(String, String)>> {
        db::pep_items(&self.pool, owner_id, node, item_id, limit).await
    }
    async fn get_vcard(&self, user_id: Uuid) -> Result<VCardRecord> {
        let record = db::get_vcard(&self.pool, user_id).await?;
        Ok(VCardRecord {
            payload_vcard_temp: record.payload_vcard_temp,
        })
    }
    async fn latest_roster_change_for_contact(
        &self,
        user_id: Uuid,
        contact_jid: &str,
    ) -> Result<Option<northstar_roster_core::RosterChange>> {
        db::latest_roster_change_for_contact(&self.pool, user_id, contact_jid).await
    }
    async fn mix_muc_mirror_for_mix(&self, mix_channel_id: Uuid) -> Result<Option<MixMucMirror>> {
        Ok(db::mix_muc_mirror_for_mix(&self.pool, mix_channel_id)
            .await?
            .map(mix_muc_mirror))
    }
    async fn mix_muc_mirror_for_muc(&self, muc_room_id: Uuid) -> Result<Option<MixMucMirror>> {
        Ok(db::mix_muc_mirror_for_muc(&self.pool, muc_room_id)
            .await?
            .map(mix_muc_mirror))
    }
    async fn mix_muc_mirror_service_complete(&self, mix_domain: &str) -> Result<bool> {
        db::mix_muc_mirror_service_complete(&self.pool, mix_domain).await
    }
    #[allow(clippy::too_many_arguments)]
    async fn archive_mix_message_once(
        &self,
        personal_archive_id: Uuid,
        owner_id: Uuid,
        channel_jid: &str,
        authoritative_stanza_id: Uuid,
        stanza: &str,
        encrypted: bool,
        client_stanza_id: Option<&str>,
    ) -> Result<SourceArchiveAdmission> {
        Ok(
            match db::archive_mix_message_once(
                &self.pool,
                personal_archive_id,
                owner_id,
                channel_jid,
                authoritative_stanza_id,
                stanza,
                encrypted,
                client_stanza_id,
            )
            .await?
            {
                db::SourceArchiveAdmission::Stored(id) => SourceArchiveAdmission::Stored(id),
                db::SourceArchiveAdmission::Replay(id) => SourceArchiveAdmission::Replay(id),
            },
        )
    }

    async fn enqueue_s2s_response_batch(
        &self,
        target_domain: &str,
        responses: &[String],
        policy: S2sOutboxPolicy,
    ) -> Result<()> {
        let policy = db::S2sOutboxPolicy {
            ttl_seconds: policy.ttl_seconds,
            max_rows: policy.max_rows,
            max_bytes: policy.max_bytes,
            max_per_domain: policy.max_per_domain,
        };
        let mut transaction = self.pool.begin().await?;
        for response in responses {
            db::enqueue_s2s_outbox_in_transaction(
                &mut transaction,
                target_domain,
                response,
                None,
                policy,
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }
    async fn federated_mix_iq_replay(
        &self,
        authenticated_domain: &str,
        actor_jid: &str,
        request_id: &str,
        request_digest: &[u8; 32],
    ) -> Result<FederatedMixIqReplay> {
        Ok(
            match db::federated_mix_iq_replay(
                &self.pool,
                authenticated_domain,
                actor_jid,
                request_id,
                request_digest,
            )
            .await?
            {
                db::FederatedMixIqReplay::Miss => FederatedMixIqReplay::Miss,
                db::FederatedMixIqReplay::Replay(response) => {
                    FederatedMixIqReplay::Replay(response)
                }
                db::FederatedMixIqReplay::Conflict => FederatedMixIqReplay::Conflict,
            },
        )
    }
    async fn admit_federated_mix_iq_result(
        &self,
        authenticated_domain: &str,
        actor_jid: &str,
        request_id: &str,
        request_digest: &[u8; 32],
        response: &str,
        policy: S2sOutboxPolicy,
    ) -> Result<FederatedMixIqReplay> {
        let policy = db::S2sOutboxPolicy {
            ttl_seconds: policy.ttl_seconds,
            max_rows: policy.max_rows,
            max_bytes: policy.max_bytes,
            max_per_domain: policy.max_per_domain,
        };
        Ok(
            match db::admit_federated_mix_iq_result(
                &self.pool,
                authenticated_domain,
                actor_jid,
                request_id,
                request_digest,
                response,
                policy,
            )
            .await?
            {
                db::FederatedMixIqReplay::Miss => FederatedMixIqReplay::Miss,
                db::FederatedMixIqReplay::Replay(response) => {
                    FederatedMixIqReplay::Replay(response)
                }
                db::FederatedMixIqReplay::Conflict => FederatedMixIqReplay::Conflict,
            },
        )
    }
    async fn claim_mix_deliveries(
        &self,
        limit: i64,
        max_bytes: i64,
    ) -> Result<Vec<ClaimedMixDelivery>> {
        let deliveries = {
            let deliveries = db::claim_mix_deliveries(&self.pool, limit, max_bytes).await?;
            deliveries
        };
        Ok(deliveries
            .into_iter()
            .map(|delivery| ClaimedMixDelivery {
                delivery_id: delivery.delivery_id,
                event_id: delivery.event_id,
                channel_id: delivery.channel_id,
                channel_jid: delivery.channel_jid,
                recipient: delivery.recipient,
                stanza: delivery.stanza,
                authoritative_stanza_id: delivery.authoritative_stanza_id,
                archive: delivery.archive,
                encrypted: delivery.encrypted,
                attempt_count: delivery.attempt_count,
                lease_token: delivery.lease_token,
                route_wake_generation: delivery.route_wake_generation,
            })
            .collect())
    }
    async fn claim_mix_deliveries_observed(
        &self,
        request: &outbox::core::ClaimRequest,
    ) -> Result<outbox::core::Rows> {
        db::claim_mix_deliveries_observed(&self.pool, request).await
    }
    async fn archive_mix_message_once_observed(
        &self,
        request: &outbox::core::ArchiveRequest,
    ) -> Result<outbox::core::ArchiveResult> {
        Ok(
            match db::archive_mix_message_once_observed(&self.pool, request).await? {
                db::SourceArchiveAdmission::Stored(id) => outbox::core::ArchiveResult::Stored(id),
                db::SourceArchiveAdmission::Replay(id) => outbox::core::ArchiveResult::Replay(id),
            },
        )
    }
    async fn renew_mix_delivery_lease_observed(
        &self,
        request: &outbox::core::RenewalRequest,
    ) -> Result<bool> {
        db::renew_mix_delivery_lease_observed(&self.pool, request).await
    }
    async fn settle_mix_delivery_observed(
        &self,
        request: &outbox::core::SettlementRequest,
    ) -> Result<outbox::core::SettlementResult> {
        use outbox::core::{SettlementCommand, SettlementResult};
        Ok(match request.command() {
            SettlementCommand::Ack => SettlementResult::Ack(
                db::acknowledge_mix_delivery_worker_observed(&self.pool, request).await?,
            ),
            SettlementCommand::Defer { .. } => SettlementResult::Defer(
                db::defer_mix_delivery_worker_observed(&self.pool, request).await?,
            ),
            SettlementCommand::Retry { .. } => SettlementResult::Retry(
                db::retry_mix_delivery_worker_observed(&self.pool, request).await?,
            ),
            SettlementCommand::DeadLetter { .. } => SettlementResult::DeadLetter(
                db::dead_letter_mix_delivery_worker_observed(&self.pool, request).await?,
            ),
        })
    }
    async fn maintain_mix_delivery_retention(&self) -> Result<()> {
        db::maintain_mix_delivery_retention(&self.pool).await
    }
    async fn prune_expired_business_intents(&self, limit: i64) -> Result<u64> {
        db::prune_expired_mix_business_intents(&self.pool, limit).await
    }
    async fn prune_expired_federated_iq_results(&self, limit: i64) -> Result<u64> {
        db::prune_expired_federated_mix_iq_results(&self.pool, limit).await
    }
    async fn acknowledge_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        observation: Option<&northstar_delivery_core::native_write::AckRequest>,
    ) -> Result<bool> {
        match observation {
            Some(observation) => {
                db::mix::acknowledge_mix_delivery_observed(
                    &self.pool,
                    delivery_id,
                    lease_token,
                    Some(observation),
                )
                .await
            }
            None => db::acknowledge_mix_delivery(&self.pool, delivery_id, lease_token).await,
        }
    }
    async fn fence_mix_socket_write(
        &self,
        source: crate::xmpp::outbound::MixDelivery,
    ) -> Result<crate::xmpp::outbound::MixDelivery> {
        db::mix::fence_mix_socket_write(&self.pool, source).await
    }
    async fn transfer_mix_delivery_to_cluster(
        &self,
        source: crate::xmpp::outbound::MixDelivery,
        node_id: &str,
        request_id: Uuid,
        ttl_seconds: u64,
    ) -> Result<crate::xmpp::outbound::MixDelivery> {
        db::mix::transfer_mix_delivery_to_cluster(
            &self.pool,
            source,
            node_id,
            request_id,
            ttl_seconds,
        )
        .await
    }
    async fn release_mix_cluster_delivery(
        &self,
        source: crate::xmpp::outbound::MixDelivery,
        node_id: &str,
        request_id: Uuid,
    ) -> Result<bool> {
        let released =
            db::mix::release_mix_cluster_delivery(&self.pool, source, node_id, request_id).await?;

        Ok(released)
    }
    async fn transfer_mix_delivery_to_bosh(
        &self,
        request: &northstar_delivery_core::bosh_ownership::TransferRequest,
    ) -> Result<crate::xmpp::outbound::MixDelivery> {
        db::mix::transfer_mix_delivery_to_bosh(&self.pool, request).await
    }

    async fn renew_mix_delivery_lease(&self, delivery_id: Uuid, lease_token: Uuid) -> Result<bool> {
        db::renew_mix_delivery_lease(&self.pool, delivery_id, lease_token).await
    }
    async fn dead_letter_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        terminal_reason: &str,
        error: &str,
    ) -> Result<bool> {
        let moved = db::dead_letter_mix_delivery(
            &self.pool,
            delivery_id,
            lease_token,
            terminal_reason,
            error,
        )
        .await?;

        Ok(moved)
    }
    async fn retry_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        _claimed_attempt_count: i32,
        route_wake_generation: i64,
        error: &str,
    ) -> Result<MixDeliveryRetryOutcome> {
        // The repository rereads the authoritative attempt count under the
        // exact lease row lock. Keep the protocol-facing snapshot argument
        // until the protocol completion DTO can be narrowed independently,
        // but never let it decide the terminal boundary.
        let outcome = db::retry_mix_delivery(
            &self.pool,
            delivery_id,
            lease_token,
            route_wake_generation,
            error,
        )
        .await?;
        Ok(outcome)
    }
    async fn defer_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        route_wake_generation: i64,
        delay_seconds: i64,
    ) -> Result<bool> {
        db::defer_mix_delivery(
            &self.pool,
            delivery_id,
            lease_token,
            route_wake_generation,
            delay_seconds,
        )
        .await
    }
    async fn wake_mix_delivery_recipient(&self, recipient_jid: &str) -> Result<u64> {
        let woken = db::wake_mix_delivery_recipient(&self.pool, recipient_jid).await?;

        Ok(woken)
    }
    #[allow(dead_code)]
    async fn mix_delivery_dead_letters(
        &self,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> Result<Vec<MixDeliveryDeadLetter>> {
        let dead_letters = { db::mix_delivery_dead_letters(&self.pool, before, limit).await? };
        Ok(dead_letters
            .into_iter()
            .map(|dead| MixDeliveryDeadLetter {
                dead_letter_id: dead.dead_letter_id,
                delivery_id: dead.delivery_id,
                event_id: dead.event_id,
                channel_id: dead.channel_id,
                channel_jid: dead.channel_jid,
                recipient_jid: dead.recipient_jid,
                attempt_count: dead.attempt_count,
                terminal_reason: dead.terminal_reason,
                last_error: dead.last_error,
                failed_at: dead.failed_at,
            })
            .collect())
    }
    #[allow(dead_code)]
    async fn requeue_mix_delivery_dead_letter(&self, dead_letter_id: Uuid) -> Result<bool> {
        let requeued = db::requeue_mix_delivery_dead_letter(&self.pool, dead_letter_id).await?;

        Ok(requeued)
    }
}
