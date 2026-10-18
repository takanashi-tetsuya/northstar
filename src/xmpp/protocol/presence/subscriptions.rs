//! Handles local, federated and component presence subscription transitions and subscription stanza helpers.

use super::*;

impl ProtocolSession {
    pub(super) async fn update_remote_presence_subscription(
        &self,
        request: RemoteSubscriptionRequest<'_>,
    ) -> Result<SubscriptionMutationDisposition> {
        let RemoteSubscriptionRequest {
            actor_id,
            expected_auth_generation,
            contact,
            kind,
            target_domain,
            stanza,
            bounce_to,
        } = request;
        let contact = crate::jid::canonicalize_bare(contact)?;
        let outcome = self
            .state
            .presence_service()
            .transition_remote_with_outbox(
                actor_id,
                expected_auth_generation,
                self.connection_id,
                self.state.local_domain(),
                &contact,
                kind,
                target_domain,
                stanza,
                Some(bounce_to),
                self.state.federation_outbox().outbox_policy(),
            )
            .await?;
        let transition = match outcome {
            PresenceMutation::Unauthorized => {
                return Ok(SubscriptionMutationDisposition::Unauthorized);
            }
            PresenceMutation::PolicyDenied(reason) => {
                return Ok(SubscriptionMutationDisposition::PolicyDenied(reason));
            }
            PresenceMutation::Missing => return Ok(SubscriptionMutationDisposition::Missing),
            PresenceMutation::Transition(transition) => transition,
        };
        if transition.routed {
            self.state.federation_outbox().wake_outbox();
        }
        self.finish_remote_presence_transition(&contact, transition)
            .await;
        Ok(SubscriptionMutationDisposition::Accepted(false))
    }

    pub(super) async fn update_component_presence_subscription(
        &self,
        actor_id: uuid::Uuid,
        expected_auth_generation: i64,
        contact: &str,
        kind: &str,
    ) -> Result<SubscriptionMutationDisposition> {
        let contact = crate::jid::canonicalize_bare(contact)?;
        let outcome = self
            .state
            .presence_service()
            .transition_remote(
                actor_id,
                expected_auth_generation,
                self.connection_id,
                self.state.local_domain(),
                &contact,
                kind,
            )
            .await?;
        let transition = match outcome {
            PresenceMutation::Unauthorized => {
                return Ok(SubscriptionMutationDisposition::Unauthorized);
            }
            PresenceMutation::PolicyDenied(reason) => {
                return Ok(SubscriptionMutationDisposition::PolicyDenied(reason));
            }
            PresenceMutation::Missing => return Ok(SubscriptionMutationDisposition::Missing),
            PresenceMutation::Transition(transition) => transition,
        };
        let routed = transition.routed;
        self.finish_remote_presence_transition(&contact, transition)
            .await;
        Ok(SubscriptionMutationDisposition::Accepted(routed))
    }

    pub(super) async fn finish_remote_presence_transition(
        &self,
        contact: &str,
        transition: RemoteSubscriptionTransition,
    ) {
        if let Some(change) = transition.change.as_ref() {
            if let Err(error) = self
                .push_roster_change(
                    transition.actor.id,
                    &transition.actor.username,
                    change,
                    None,
                )
                .await
            {
                tracing::warn!(
                    owner = %transition.actor.username,
                    version = change.version,
                    ?error,
                    "failed to deliver committed federated roster transition"
                );
            }
        }
        if matches!(transition.subscription.as_str(), "from" | "both") {
            self.remove_directed_presence_for_bare(contact);
        }
    }

    pub(super) async fn update_presence_subscription(
        &self,
        actor_id: uuid::Uuid,
        actor_username: &str,
        expected_auth_generation: i64,
        target_jid: &str,
        kind: &str,
        raw: &str,
    ) -> Result<SubscriptionMutationDisposition> {
        let target_jid = crate::jid::CanonicalJid::parse_bare(target_jid)?;
        if target_jid.domainpart() != self.state.local_domain() {
            return Ok(SubscriptionMutationDisposition::Missing);
        }
        let Some(target_name) = target_jid.localpart() else {
            return Ok(SubscriptionMutationDisposition::Missing);
        };
        let actor_jid = format!("{}@{}", actor_username, self.state.local_domain());
        let target_jid = format!("{}@{}", target_name, self.state.local_domain());
        let stamped_stanza = set_to(&set_from(raw, &actor_jid), &target_jid);
        let outcome = self
            .state
            .presence_service()
            .transition_local(LocalSubscriptionRequest {
                actor_id,
                expected_auth_generation,
                connection_id: self.connection_id,
                local_domain: self.state.local_domain(),
                target_username: target_name,
                kind,
                stanza: &stamped_stanza,
            })
            .await?;
        let transition = match outcome {
            PresenceMutation::Unauthorized => {
                return Ok(SubscriptionMutationDisposition::Unauthorized);
            }
            PresenceMutation::PolicyDenied(reason) => {
                return Ok(SubscriptionMutationDisposition::PolicyDenied(reason));
            }
            PresenceMutation::Missing => return Ok(SubscriptionMutationDisposition::Missing),
            PresenceMutation::Transition(transition) => transition,
        };
        let actor = transition.actor.clone();
        let target = transition.target.clone();
        let actor_jid = format!("{}@{}", actor.username, self.state.local_domain());
        let target_jid = format!("{}@{}", target.username, self.state.local_domain());
        let stamped_stanza = set_to(&set_from(raw, &actor_jid), &target_jid);

        // RFC 6121 requires the subscription notification to be delivered
        // before the resulting roster push.  Keep that ordering explicit here
        // instead of returning to the generic presence router (which cannot
        // distinguish available from roster-interested resources).
        match transition.effect {
            LocalPresenceEffect::AutoApproved => {
                let approved = XmlElement::namespaced("presence", "jabber:client")
                    .attr("from", &target_jid)
                    .attr("to", &actor_jid)
                    .attr("type", "subscribed")
                    .finish();
                let current = self.full_jid.as_deref();
                let active_privacy = self
                    .privacy_active
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                if !self
                    .state
                    .privacy_service()
                    .denies(
                        actor.id,
                        active_privacy.as_deref(),
                        &target_jid,
                        PrivacyStanzaKind::PresenceIn,
                    )
                    .await?
                {
                    let _ = self.outbound.try_send(approved.clone());
                }
                for (jid, session) in self
                    .state
                    .session_entries_for(&actor_jid)
                    .into_iter()
                    .filter(|(_, session)| {
                        session.user_id == actor.id
                            && session.auth_generation == actor.auth_generation
                            && session.available.load(Ordering::Acquire)
                    })
                {
                    if current != Some(jid.as_str())
                        && self
                            .state
                            .privacy_allows_session(
                                &session,
                                &target_jid,
                                PrivacyStanzaKind::PresenceIn,
                            )
                            .await?
                    {
                        let _ = session.sender.try_send(approved.clone());
                    }
                }
                self.state
                    .route_presence_subscription_remote(
                        &actor_jid,
                        &approved,
                        crate::cluster::ClusterPresenceAuthority {
                            owner_id: target.id,
                            owner_auth_generation: target.auth_generation,
                            recipient_id: actor.id,
                            recipient_auth_generation: actor.auth_generation,
                        },
                    )
                    .await;
            }
            LocalPresenceEffect::Forward => {
                let mut targets = self.state.session_entries_for(&target_jid);
                // RFC 6121 subscription-related presence is delivered to
                // available resources independently of roster interest.
                // `roster_requested` gates roster pushes only; using it here
                // can drop the approval on the exact resource that just sent
                // the subscription request after reconnecting.
                targets.retain(|(_, session)| {
                    session.user_id == target.id
                        && session.auth_generation == target.auth_generation
                        && session.available.load(Ordering::Acquire)
                });
                for (target_full, session) in targets {
                    if self
                        .state
                        .privacy_allows_session(&session, &actor_jid, PrivacyStanzaKind::PresenceIn)
                        .await?
                    {
                        let _ = session
                            .sender
                            .try_send(set_to(&stamped_stanza, &target_full));
                    }
                }
                self.state
                    .route_presence_subscription_remote(
                        &target_jid,
                        &stamped_stanza,
                        crate::cluster::ClusterPresenceAuthority {
                            owner_id: actor.id,
                            owner_auth_generation: actor.auth_generation,
                            recipient_id: target.id,
                            recipient_auth_generation: target.auth_generation,
                        },
                    )
                    .await;
            }
            LocalPresenceEffect::Suppressed => {}
        }

        if let Some(change) = transition.actor_change.as_ref() {
            if let Err(error) = self
                .push_roster_change(actor.id, &actor.username, change, None)
                .await
            {
                tracing::warn!(owner = %actor.username, version = change.version, ?error, "failed to deliver committed actor roster transition");
            }
        }
        if let Some(change) = transition.target_change.as_ref() {
            if let Err(error) = self
                .push_roster_change(target.id, &target.username, change, None)
                .await
            {
                tracing::warn!(owner = %target.username, version = change.version, ?error, "failed to deliver committed target roster transition");
            }
        }
        match transition.effect {
            LocalPresenceEffect::AutoApproved => {
                self.send_current_availability_exact(
                    &target_jid,
                    target.id,
                    target.auth_generation,
                    &actor_jid,
                    actor.id,
                    actor.auth_generation,
                )
                .await;
                return Ok(SubscriptionMutationDisposition::Accepted(false));
            }
            LocalPresenceEffect::Suppressed => {
                return Ok(SubscriptionMutationDisposition::Accepted(false));
            }
            LocalPresenceEffect::Forward => {}
        }
        if kind == "subscribe" && self.state.sessions_for(&target_jid).is_empty() {
            if let Err(error) = self.state.dispatch_push_notification(target.id).await {
                tracing::warn!(target = %target.username, ?error, "failed to send post-commit subscription notification");
            }
        }
        if matches!(transition.actor_subscription.as_str(), "from" | "both") {
            self.remove_directed_presence_for_bare(&target_jid);
        }
        if kind == "subscribed" {
            self.send_current_availability_exact(
                &actor_jid,
                actor.id,
                actor.auth_generation,
                &target_jid,
                target.id,
                target.auth_generation,
            )
            .await;
        }
        // Subscription stanzas were routed above to preserve notification ->
        // roster-push ordering and exact interested-resource semantics.
        Ok(SubscriptionMutationDisposition::Accepted(false))
    }
}

pub(super) fn should_resend_pending_outbound_subscription(
    first_available: bool,
    ask: Option<&str>,
) -> bool {
    northstar_presence_core::should_resend_pending_subscription(first_available, ask)
}

pub(super) fn subscription_policy_error(
    root: Node<'_, '_>,
    reason: PresencePolicyDenial,
) -> String {
    match reason {
        PresencePolicyDenial::Blocking => blocked_stanza_error(root),
        PresencePolicyDenial::Privacy => stanza_error(root, "cancel", "service-unavailable"),
    }
}

pub(super) fn stamped_subscription_presence(raw: &str, from_bare: &str, to_bare: &str) -> String {
    set_to(&set_from(raw, from_bare), to_bare)
}
