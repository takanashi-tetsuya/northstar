//! Implement the MIX repository trait using PostgreSQL persistence operations.

use super::*;

impl<E: RoomEffects> MixRepository for PostgresMixRepository<E> {
    async fn link_local_muc_mirror(
        &self,
        mix_domain: &str,
        localpart: &str,
        actor_bare_jid: &str,
        local_domain: &str,
    ) -> Result<MixMucLinkOutcome> {
        Ok(map_mix_muc_link_outcome(
            crate::mix_muc::link_mix_muc_by_localpart(
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
        let (outcome, localpart) = crate::mix::create_mix_channel(
            &self.effects,
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
        crate::mix::mix_channel(&self.pool, service_domain, localpart).await
    }
    async fn discoverable_mix_channel_page(
        &self,
        service_domain: &str,
        requester: &str,
        after: Option<&str>,
        before: Option<Option<&str>>,
        max: i64,
    ) -> Result<Option<MixDiscoPage>> {
        Ok(crate::mix::discoverable_mix_channel_page(
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
        crate::mix::mix_role(&self.pool, channel_id, jid).await
    }
    async fn mix_channel_discoverable_to(&self, channel: &MixChannel, actor: &str) -> Result<bool> {
        crate::mix::mix_channel_discoverable_to(&self.pool, channel, actor).await
    }
    async fn destroy_mix_channel(
        &self,
        channel_id: Uuid,
        actor: &str,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        crate::mix::destroy_mix_channel(
            &self.effects,
            &self.pool,
            channel_id,
            actor,
            &MixPayloads,
            federated,
        )
        .await
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
            .map(crate::mix::MixInvitationProof::from);
        let db_preference = request.preference.as_ref().cloned();

        let outcome = crate::mix::join_mix_channel(
            &self.effects,
            &self.pool,
            channel_id,
            crate::mix::JoinMixRequest {
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
        crate::mix::mix_participant(&self.pool, channel_id, jid).await
    }
    async fn expire_unrefreshed_mix_presence(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<Vec<ExpiredMixPresence>> {
        Ok(
            crate::mix::expire_unrefreshed_mix_presence(&self.pool, cutoff, &MixPayloads)
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
        Ok(crate::mix::update_mix_subscriptions(
            &self.effects,
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
            match crate::mix::set_mix_nick(
                &self.effects,
                &self.pool,
                channel_id,
                actor,
                nick,
                &MixPayloads,
                federated,
            )
            .await?
            {
                Ok(stored_participant) => Ok(stored_participant),
                Err(crate::mix::SetNickError::NotParticipant) => Err(SetNickError::NotParticipant),
                Err(crate::mix::SetNickError::Conflict) => Err(SetNickError::Conflict),
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
        Ok(crate::mix::leave_mix_channel(
            &self.effects,
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
            crate::mix::store_mix_presence(
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
            crate::mix::ensure_mix_presence(
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
        authenticators: Option<&northstar_abuse_policy::ContentIdentityAuthenticators>,
    ) -> Result<StoreMixMessageAdmission> {
        let StoreMixMessageRequest {
            channel_id,
            actor,
            item_id,
            payload,
            identity,
            delivery_payload,
            publisher_identity,
            visible_jid,
            encrypted,
        } = request;
        let db_identity =
            identity
                .as_ref()
                .zip(authenticators.as_ref())
                .map(|(identity, authenticators)| {
                    let primary = authenticators.primary();
                    crate::mix::MixBusinessIdentity {
                        client_id: &identity.client_id,
                        semantic_key_id: primary.key_id(),
                        semantic_mac: primary.mac(),
                    }
                });

        let admission = crate::mix::store_mix_message(
            &self.pool,
            channel_id,
            actor,
            item_id,
            payload,
            db_identity,
            delivery_payload,
            publisher_identity,
            visible_jid,
            encrypted,
            &MixPayloads,
        )
        .await?;

        let outcome = match admission.outcome {
            crate::mix::StoreEventOutcome::Existing(existing) => {
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
        authenticators: Option<&northstar_abuse_policy::ContentIdentityAuthenticators>,
    ) -> Result<StoreMixMessageAdmission> {
        let identity = request.command().identity.as_ref().zip(authenticators).map(
            |(identity, authenticators)| {
                let primary = authenticators.primary();
                crate::mix::MixBusinessIdentity {
                    client_id: &identity.client_id,
                    semantic_key_id: primary.key_id(),
                    semantic_mac: primary.mac(),
                }
            },
        );
        let admission =
            crate::mix::store_mix_message_observed(&self.pool, request, identity, &MixPayloads)
                .await?;
        let outcome = match admission.outcome {
            crate::mix::StoreEventOutcome::Existing(existing) => {
                let raw = crate::mix::foreground_existing(&existing);
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
        authenticators: &northstar_abuse_policy::ContentIdentityAuthenticators,
    ) -> Result<MixBusinessReplay> {
        let ingress = request.ingress();
        let identity = ingress
            .identity
            .as_ref()
            .ok_or(foreground::Rejected::Input)?;
        let existing = crate::mix::lookup_mix_business_intent(
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
        let raw = crate::mix::foreground_existing(&existing);
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
        authenticators: &northstar_abuse_policy::ContentIdentityAuthenticators,
    ) -> Result<MixBusinessReplay> {
        let existing = crate::mix::lookup_mix_business_intent(
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
        authenticators: &northstar_abuse_policy::ContentIdentityAuthenticators,
    ) -> Result<MixBusinessReplay> {
        let existing = crate::mix::lookup_mix_business_intent(
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
            match crate::mix::authorized_mix_event_page(
                &self.pool, channel_id, actor, node, before, limit,
            )
            .await?
            {
                crate::mix::MixReadOutcome::Found(page) => MixReadOutcome::Found(MixEventPage {
                    events: page.events.into_iter().map(event).collect(),
                }),
                crate::mix::MixReadOutcome::Unauthorized => MixReadOutcome::Unauthorized,
                crate::mix::MixReadOutcome::NotFound => MixReadOutcome::NotFound,
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
        crate::mix::publish_mix_avatar(
            &self.effects,
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
        crate::mix::retract_mix_avatar(
            &self.effects,
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
    async fn authorized_mix_access_entries(
        &self,
        channel_id: Uuid,
        actor: &str,
        banned: bool,
        limit: i64,
    ) -> Result<MixReadOutcome<Vec<String>>> {
        Ok(
            match crate::mix::authorized_mix_access_entries(
                &self.pool, channel_id, actor, banned, limit,
            )
            .await?
            {
                crate::mix::MixReadOutcome::Found(entries) => MixReadOutcome::Found(entries),
                crate::mix::MixReadOutcome::Unauthorized => MixReadOutcome::Unauthorized,
                crate::mix::MixReadOutcome::NotFound => MixReadOutcome::NotFound,
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
            match crate::mix::update_mix_info(
                &self.effects,
                &self.pool,
                channel_id,
                actor,
                crate::mix::MixInfoUpdate {
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
                crate::mix::MixMutationOutcome::Applied(admission) => {
                    MixMutationOutcome::Applied(Box::new(mutation_admission(*admission)))
                }
                crate::mix::MixMutationOutcome::Conflict => MixMutationOutcome::Conflict,
                crate::mix::MixMutationOutcome::Forbidden => MixMutationOutcome::Forbidden,
                crate::mix::MixMutationOutcome::NotFound => MixMutationOutcome::NotFound,
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
            match crate::mix::update_mix_config(
                &self.effects,
                &self.pool,
                channel_id,
                actor,
                crate::mix::MixConfigUpdate {
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
                crate::mix::MixRoleUpdate {
                    owners: roles.owners.as_deref(),
                    administrators: roles.administrators.as_deref(),
                },
                &MixPayloads,
                federated,
            )
            .await?
            {
                crate::mix::MixMutationOutcome::Applied(admission) => {
                    MixMutationOutcome::Applied(Box::new(mutation_admission(*admission)))
                }
                crate::mix::MixMutationOutcome::Conflict => MixMutationOutcome::Conflict,
                crate::mix::MixMutationOutcome::Forbidden => MixMutationOutcome::Forbidden,
                crate::mix::MixMutationOutcome::NotFound => MixMutationOutcome::NotFound,
            },
        )
    }
    async fn set_mix_access_entry(
        &self,
        update: MixAccessEntryUpdate<'_>,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<AccessChangeOutcome>> {
        let list = match update.list {
            MixAccessList::Allowed => crate::mix::MixAccessList::Allowed,
            MixAccessList::Banned => crate::mix::MixAccessList::Banned,
        };
        let operation = match update.operation {
            MixAccessEntryOperation::Publish { reason } => {
                crate::mix::MixAccessEntryOperation::Publish { reason }
            }
            MixAccessEntryOperation::Retract => crate::mix::MixAccessEntryOperation::Retract,
        };

        Ok(crate::mix::set_mix_access_entry(
            &self.effects,
            &self.pool,
            crate::mix::MixAccessEntryUpdate {
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
            match crate::mix::register_mix_nick(
                &self.effects,
                &self.pool,
                service_domain,
                actor,
                nick,
                &MixPayloads,
                federated,
            )
            .await?
            {
                crate::mix::RegisterMixNickOutcome::Registered { nick } => {
                    RegisterMixNickOutcome::Registered { nick }
                }
                crate::mix::RegisterMixNickOutcome::Conflict => RegisterMixNickOutcome::Conflict,
            },
        )
    }
    async fn mix_participant_preference(
        &self,
        channel_id: Uuid,
        actor: &str,
    ) -> Result<Option<MixParticipantPreference>> {
        crate::mix::mix_participant_preference(&self.pool, channel_id, actor).await
    }
    async fn update_mix_participant_preference(
        &self,
        channel_id: Uuid,
        actor: &str,
        preference: &MixParticipantPreference,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<Option<MixParticipantPreferenceUpdateOutcome>> {
        Ok(crate::mix::update_mix_participant_preference(
            &self.effects,
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
            match crate::mix::authorized_mix_jid_map_entries(&self.pool, channel_id, actor, limit)
                .await?
            {
                crate::mix::MixReadOutcome::Found(entries) => MixReadOutcome::Found(entries),
                crate::mix::MixReadOutcome::Unauthorized => MixReadOutcome::Unauthorized,
                crate::mix::MixReadOutcome::NotFound => MixReadOutcome::NotFound,
            },
        )
    }
    async fn issue_mix_invitation(
        &self,
        channel_id: Uuid,
        inviter: &str,
        invitee: &str,
        token: &str,
        lifetime: northstar_time::Duration,
        federated: Option<&FederatedMixMutation>,
    ) -> Result<bool> {
        crate::mix::issue_mix_invitation(
            &self.effects,
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
        crate::mix::mix_private_message_recipient(&self.pool, channel_id, sender, recipient_id)
            .await
    }
    async fn retract_mix_message(
        &self,
        request: RetractMixMessageRequest<'_>,
        authenticators: Option<&northstar_abuse_policy::ContentIdentityAuthenticators>,
    ) -> Result<RetractMixMessageAdmission> {
        let RetractMixMessageRequest {
            channel_id,
            actor,
            target_id,
            retraction_id,
            tombstone_payload,
            retraction_payload,
            identity,
            publisher_identity,
            visible_jid,
        } = request;
        let db_identity =
            identity
                .as_ref()
                .zip(authenticators.as_ref())
                .map(|(identity, authenticators)| {
                    let primary = authenticators.primary();
                    crate::mix::MixBusinessIdentity {
                        client_id: &identity.client_id,
                        semantic_key_id: primary.key_id(),
                        semantic_mac: primary.mac(),
                    }
                });

        let admission = crate::mix::retract_mix_message(
            &self.pool,
            channel_id,
            actor,
            target_id,
            retraction_id,
            tombstone_payload,
            retraction_payload,
            db_identity,
            publisher_identity,
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
    async fn find_enabled_user(&self, username: &str) -> Result<Option<MixAccount>> {
        Ok(crate::accounts::find_enabled_user(&self.pool, username)
            .await?
            .map(|user| MixAccount {
                id: user.id,
                username: user.username,
            }))
    }

    async fn find_enabled_user_by_id(&self, user_id: Uuid) -> Result<Option<MixAccount>> {
        Ok(
            crate::accounts::find_enabled_user_by_id(&self.pool, user_id)
                .await?
                .map(|user| MixAccount {
                    id: user.id,
                    username: user.username,
                }),
        )
    }
    async fn is_blocked(&self, owner_id: Uuid, candidate: &str) -> Result<bool> {
        self.effects
            .is_blocked(&self.pool, owner_id, candidate)
            .await
    }

    async fn relay_profile_snapshot(
        &self,
        query: MixRelayProfileQuery,
    ) -> Result<MixRelayProfileResult> {
        relay_profile_snapshot::read(&self.pool, &self.effects, query).await
    }
    async fn latest_roster_change_for_contact(
        &self,
        user_id: Uuid,
        contact_jid: &str,
    ) -> Result<Option<northstar_roster_core::RosterChange>> {
        self.effects
            .latest_roster_change_for_contact(&self.pool, user_id, contact_jid)
            .await
    }
    async fn mix_muc_mirror_for_mix(&self, mix_channel_id: Uuid) -> Result<Option<MixMucMirror>> {
        Ok(
            crate::mix_muc::mix_muc_mirror_for_mix(&self.pool, mix_channel_id)
                .await?
                .map(mix_muc_mirror),
        )
    }
    async fn mix_muc_mirror_for_muc(&self, muc_room_id: Uuid) -> Result<Option<MixMucMirror>> {
        Ok(
            crate::mix_muc::mix_muc_mirror_for_muc(&self.pool, muc_room_id)
                .await?
                .map(mix_muc_mirror),
        )
    }
    async fn mix_muc_mirror_service_complete(&self, mix_domain: &str) -> Result<bool> {
        crate::mix_muc::mix_muc_mirror_service_complete(&self.pool, mix_domain).await
    }
    async fn enqueue_s2s_response_batch(
        &self,
        target_domain: &str,
        responses: &[String],
        policy: S2sOutboxPolicy,
    ) -> Result<()> {
        let policy = northstar_federation_core::S2sOutboxPolicy {
            ttl_seconds: policy.ttl_seconds,
            max_rows: policy.max_rows,
            max_bytes: policy.max_bytes,
            max_per_domain: policy.max_per_domain,
        };
        let mut transaction = self.pool.begin().await?;
        for response in responses {
            self.effects
                .enqueue_federated_stanza(&mut transaction, target_domain, response, None, policy)
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
            match crate::mix::federated_mix_iq_replay(
                &self.pool,
                authenticated_domain,
                actor_jid,
                request_id,
                request_digest,
            )
            .await?
            {
                crate::mix::FederatedMixIqReplay::Miss => FederatedMixIqReplay::Miss,
                crate::mix::FederatedMixIqReplay::Replay(response) => {
                    FederatedMixIqReplay::Replay(response)
                }
                crate::mix::FederatedMixIqReplay::Conflict => FederatedMixIqReplay::Conflict,
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
        let policy = northstar_federation_core::S2sOutboxPolicy {
            ttl_seconds: policy.ttl_seconds,
            max_rows: policy.max_rows,
            max_bytes: policy.max_bytes,
            max_per_domain: policy.max_per_domain,
        };
        Ok(
            match crate::mix::admit_federated_mix_iq_result(
                &self.effects,
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
                crate::mix::FederatedMixIqReplay::Miss => FederatedMixIqReplay::Miss,
                crate::mix::FederatedMixIqReplay::Replay(response) => {
                    FederatedMixIqReplay::Replay(response)
                }
                crate::mix::FederatedMixIqReplay::Conflict => FederatedMixIqReplay::Conflict,
            },
        )
    }
    async fn prune_expired_business_intents(&self, limit: i64) -> Result<u64> {
        crate::mix::prune_expired_mix_business_intents(&self.pool, limit).await
    }
    async fn prune_expired_federated_iq_results(&self, limit: i64) -> Result<u64> {
        crate::mix::prune_expired_federated_mix_iq_results(&self.pool, limit).await
    }
}
