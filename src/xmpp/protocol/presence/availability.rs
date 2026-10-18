//! Handles directed presence tracking, authorized probes, current availability delivery and their supporting helpers.

use super::*;

impl ProtocolSession {
    pub(super) async fn plan_directed_presence(
        &self,
        user: &crate::services::authentication::AuthenticatedAccount,
        target: &str,
        kind: &str,
    ) -> Result<DirectedPresencePlan> {
        if kind == "unavailable" {
            return Ok(DirectedPresencePlan::Remove(target.to_owned()));
        }
        if kind != "available" {
            return Ok(DirectedPresencePlan::None);
        }
        let target_bare = crate::jid::canonical_bare_key(target)?;
        let receives_broadcast = self
            .available
            .as_ref()
            .is_some_and(|available| available.load(Ordering::Relaxed))
            && self
                .state
                .presence_service()
                .roster_subscription(user.id, &target_bare)
                .await?
                .is_some_and(|subscription| matches!(subscription.as_str(), "from" | "both"));
        if receives_broadcast {
            return Ok(DirectedPresencePlan::RemoveBroadcastScope(target_bare));
        }
        if self.directed_presence.contains(target) {
            return Ok(DirectedPresencePlan::None);
        }
        if directed_presence_capacity_reached(self.directed_presence.len(), false) {
            return Ok(DirectedPresencePlan::AtCapacity);
        }
        Ok(DirectedPresencePlan::Insert(target.to_owned()))
    }

    pub(super) fn commit_directed_presence(&self, plan: DirectedPresencePlan) {
        match plan {
            DirectedPresencePlan::Insert(target) => {
                self.directed_presence.insert(target);
            }
            DirectedPresencePlan::Remove(target) => {
                self.directed_presence.remove(&target);
            }
            DirectedPresencePlan::RemoveBroadcastScope(target_bare) => {
                self.remove_directed_presence_for_bare(&target_bare);
            }
            DirectedPresencePlan::None | DirectedPresencePlan::AtCapacity => {}
        }
    }

    pub(super) fn remove_directed_presence_for_bare(&self, target_bare: &str) {
        self.directed_presence
            .retain(|target| directed_presence_target_is_outside_bare_scope(target, target_bare));
    }

    pub(super) async fn answer_directed_presence_probe(
        &self,
        owner_full: &str,
        owner_bare: &str,
        requester: &str,
        probe_id: Option<&str>,
    ) -> Result<bool> {
        let authorized =
            self.state
                .session_entries_for(owner_full)
                .into_iter()
                .any(|(_, owner)| {
                    owner
                        .directed_presence
                        .iter()
                        .any(|target| directed_recipient_matches(target.key(), requester))
                });
        if !authorized {
            return Ok(false);
        }
        self.answer_authorized_full_presence_probe(owner_full, owner_bare, requester, probe_id)
            .await?;
        Ok(true)
    }

    pub(super) async fn answer_authorized_full_presence_probe(
        &self,
        owner_full: &str,
        owner_bare: &str,
        requester: &str,
        probe_id: Option<&str>,
    ) -> Result<()> {
        // RFC 6121 section 4.3.2 requires a full-JID probe response to
        // communicate only the availability fact.  Replaying last_presence
        // here would leak show/status/priority and arbitrary extensions.
        let requester_sessions = self.state.sessions_for(requester);
        let mut requester_allows = false;
        for requester_session in requester_sessions {
            if self
                .state
                .privacy_allows_session(
                    &requester_session,
                    owner_full,
                    PrivacyStanzaKind::PresenceIn,
                )
                .await?
            {
                requester_allows = true;
                break;
            }
        }
        if !requester_allows {
            return Ok(());
        }

        let owners = self.state.session_entries_for(owner_full);
        let mut available = false;
        let mut available_but_private = false;
        let mut original_presence_id = None;
        for (_, owner) in &owners {
            if !owner.available.load(Ordering::Acquire) {
                continue;
            }
            if self
                .state
                .privacy_allows_session(owner, requester, PrivacyStanzaKind::PresenceOut)
                .await?
            {
                available = true;
                if original_presence_id.is_none() {
                    original_presence_id = owner
                        .last_presence
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .as_deref()
                        .and_then(presence_id);
                }
            } else {
                available_but_private = true;
            }
        }
        if available {
            let _ = self.outbound.try_send(full_jid_probe_available_response(
                owner_full,
                requester,
                original_presence_id.as_deref(),
            ));
            return Ok(());
        }
        if available_but_private {
            return Ok(());
        }

        let owner_identity = crate::jid::CanonicalJid::parse(owner_full)
            .ok()
            .and_then(|jid| jid.localpart().map(str::to_owned));
        let recipient_identity = crate::jid::CanonicalJid::parse(requester)
            .ok()
            .and_then(|jid| jid.localpart().map(str::to_owned));
        let authority = match (owner_identity, recipient_identity) {
            (Some(owner), Some(recipient)) => self
                .state
                .presence_service()
                .find_enabled_user(&owner)
                .await?
                .zip(
                    self.state
                        .presence_service()
                        .find_enabled_user(&recipient)
                        .await?,
                )
                .map(
                    |(owner, recipient)| crate::cluster::ClusterPresenceAuthority {
                        owner_id: owner.id,
                        owner_auth_generation: owner.auth_generation,
                        recipient_id: recipient.id,
                        recipient_auth_generation: recipient.auth_generation,
                    },
                ),
            _ => None,
        };
        let delegated = self
            .state
            .delegate_authorized_full_presence_probe_remote(owner_full, requester, authority)
            .await?;
        if !delegated {
            let _ = self.outbound.try_send(presence_probe_status_response(
                owner_bare,
                requester,
                "unavailable",
                probe_id,
            ));
        }
        Ok(())
    }

    pub(super) async fn broadcast_directed_unavailable(&self, unavailable: &str, from: &str) {
        let targets = self
            .directed_presence
            .iter()
            .map(|target| target.key().clone())
            .collect::<Vec<_>>();
        self.directed_presence.clear();
        for target in targets {
            let delivery = set_to(unavailable, &target);
            let Ok(jid) = crate::jid::CanonicalJid::parse(&target) else {
                continue;
            };
            if jid.domainpart() == self.state.local_domain() {
                let mut recipients = self.state.session_entries_for(&target);
                if jid.resourcepart().is_none() {
                    recipients.retain(|(_, session)| session.available.load(Ordering::Relaxed));
                }
                for (_, recipient) in recipients {
                    if self
                        .state
                        .privacy_allows_session(&recipient, from, PrivacyStanzaKind::PresenceIn)
                        .await
                        .unwrap_or(false)
                    {
                        let _ = recipient.sender.try_send(delivery.clone());
                    }
                }
            } else {
                let _ = self
                    .state
                    .federation_outbox()
                    .send(jid.domainpart(), delivery, Some(from.to_owned()))
                    .await;
            }
        }
    }

    pub(crate) async fn send_current_availability(&self, owner: &str, recipient: &str) {
        self.send_current_availability_inner(owner, recipient, None, None, None, None)
            .await;
    }

    pub(super) async fn send_current_availability_exact(
        &self,
        owner: &str,
        expected_owner_id: uuid::Uuid,
        expected_owner_auth_generation: i64,
        recipient: &str,
        expected_recipient_id: uuid::Uuid,
        expected_recipient_auth_generation: i64,
    ) {
        self.send_current_availability_inner(
            owner,
            recipient,
            Some(expected_owner_id),
            Some(expected_owner_auth_generation),
            Some(expected_recipient_id),
            Some(expected_recipient_auth_generation),
        )
        .await;
    }

    pub(super) async fn send_current_availability_inner(
        &self,
        owner: &str,
        recipient: &str,
        expected_owner_id: Option<uuid::Uuid>,
        expected_owner_auth_generation: Option<i64>,
        expected_recipient_id: Option<uuid::Uuid>,
        expected_recipient_auth_generation: Option<i64>,
    ) {
        let Ok(owner_jid) = crate::jid::CanonicalJid::parse(owner) else {
            return;
        };
        let owner_bare = owner_jid.bare();
        let owner_full = owner_jid
            .resourcepart()
            .is_some()
            .then(|| owner_jid.to_string());
        let resolved_owner = if expected_owner_id.is_none() {
            match owner_jid.localpart() {
                Some(localpart) if owner_jid.domainpart() == self.state.local_domain() => self
                    .state
                    .presence_service()
                    .find_enabled_user(localpart)
                    .await
                    .ok()
                    .flatten(),
                _ => None,
            }
        } else {
            None
        };
        let expected_owner_id = expected_owner_id.or_else(|| resolved_owner.as_ref().map(|a| a.id));
        let expected_owner_auth_generation = expected_owner_auth_generation
            .or_else(|| resolved_owner.as_ref().map(|a| a.auth_generation));
        let Ok(recipient_jid) = crate::jid::CanonicalJid::parse(recipient) else {
            return;
        };
        let resolved_recipient = if expected_recipient_id.is_none() {
            match recipient_jid.localpart() {
                Some(localpart) if recipient_jid.domainpart() == self.state.local_domain() => self
                    .state
                    .presence_service()
                    .find_enabled_user(localpart)
                    .await
                    .ok()
                    .flatten(),
                _ => None,
            }
        } else {
            None
        };
        let expected_recipient_id =
            expected_recipient_id.or_else(|| resolved_recipient.as_ref().map(|a| a.id));
        let expected_recipient_auth_generation = expected_recipient_auth_generation
            .or_else(|| resolved_recipient.as_ref().map(|a| a.auth_generation));
        let (
            Some(expected_owner_id),
            Some(expected_owner_auth_generation),
            Some(expected_recipient_id),
            Some(expected_recipient_auth_generation),
        ) = (
            expected_owner_id,
            expected_owner_auth_generation,
            expected_recipient_id,
            expected_recipient_auth_generation,
        )
        else {
            return;
        };
        let authoritative_avatar_hash = {
            self.state
                .presence_service()
                .avatar_hash(expected_owner_id)
                .await
                .ok()
        };
        let Ok(recipient) = crate::jid::canonicalize(recipient) else {
            return;
        };
        let recipients = self
            .state
            .sessions_for(&recipient)
            .into_iter()
            .filter(|session| {
                session.user_id == expected_recipient_id
                    && session.auth_generation == expected_recipient_auth_generation
                    && session.available.load(Ordering::Acquire)
            })
            .collect::<Vec<_>>();
        // Iterate owned keys so a privacy database await never holds a DashMap
        // shard guard. Re-read each exact route after the await: a key may have
        // been rebound to a different connection in the meantime.
        let owner_keys = self.state.local_presence_owner_keys();
        for owner_key in owner_keys {
            if !owner_full.as_ref().map_or_else(
                || {
                    crate::jid::canonical_bare_key(&owner_key)
                        .is_ok_and(|session_owner| session_owner == owner_bare)
                },
                |owner_full| &owner_key == owner_full,
            ) {
                continue;
            }
            let Some(session) = self.state.local_presence_owner_candidate(
                &owner_key,
                expected_owner_id,
                expected_owner_auth_generation,
            ) else {
                continue;
            };
            if !self
                .state
                .privacy_allows_session(&session, &recipient, PrivacyStanzaKind::PresenceOut)
                .await
                .unwrap_or(false)
            {
                continue;
            }
            let Some(current_owner) = self.state.local_presence_owner_if_current(
                &owner_key,
                &session,
                expected_owner_id,
                expected_owner_auth_generation,
            ) else {
                continue;
            };
            let presence = current_owner
                .last_presence
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
                .map(|presence| {
                    let presence = authoritative_avatar_hash
                        .as_ref()
                        .and_then(|hash| {
                            let document = roxmltree::Document::parse(&presence).ok()?;
                            Some(inject_vcard_avatar_hash(
                                &presence,
                                document.root_element(),
                                hash.as_deref(),
                            ))
                        })
                        .unwrap_or(presence);
                    set_to(&presence, &recipient)
                })
                .unwrap_or_else(|| {
                    XmlElement::namespaced("presence", "jabber:client")
                        .attr("from", &owner_key)
                        .attr("to", &recipient)
                        .finish()
                });
            for recipient_session in &recipients {
                if self
                    .state
                    .privacy_allows_session(
                        recipient_session,
                        &owner_key,
                        PrivacyStanzaKind::PresenceIn,
                    )
                    .await
                    .unwrap_or(false)
                {
                    self.state.send_presence_if_owner_current(
                        &owner_key,
                        &session,
                        expected_owner_id,
                        expected_owner_auth_generation,
                        &recipient_session.sender,
                        &presence,
                    );
                }
            }
        }
        let owner_lookup = owner_full.as_deref().unwrap_or(&owner_bare);
        let authority = crate::cluster::ClusterPresenceAuthority {
            owner_id: expected_owner_id,
            owner_auth_generation: expected_owner_auth_generation,
            recipient_id: expected_recipient_id,
            recipient_auth_generation: expected_recipient_auth_generation,
        };
        self.state
            .replay_current_presence_from_remote_owners(
                owner_lookup,
                &recipient,
                owner_full.is_some(),
                authority,
            )
            .await;
    }

    pub(super) async fn probe_contact_presence(&self, contact: &str, requester_bare: &str) {
        let Ok(contact_jid) = crate::jid::CanonicalJid::parse_bare(contact) else {
            return;
        };
        if contact_jid.domainpart() == self.state.local_domain() {
            self.send_current_availability(contact, requester_bare)
                .await;
            return;
        }
        if !self
            .state
            .xmpp_external_route_domain_allowed(contact_jid.domainpart())
        {
            return;
        }
        let probe = XmlElement::namespaced("presence", "jabber:client")
            .attr("from", requester_bare)
            .attr("to", contact)
            .attr("type", "probe")
            .finish();
        let _ = self
            .state
            .federation_outbox()
            .send(
                contact_jid.domainpart(),
                probe,
                Some(requester_bare.to_owned()),
            )
            .await;
    }
}

pub(super) fn presence_id(raw: &str) -> Option<String> {
    let document = roxmltree::Document::parse(raw).ok()?;
    document
        .root_element()
        .attribute("id")
        .filter(|id| !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control))
        .map(str::to_owned)
}

pub(super) fn full_jid_probe_available_response(
    owner_full: &str,
    requester: &str,
    original_presence_id: Option<&str>,
) -> String {
    XmlElement::namespaced("presence", "jabber:client")
        .attr("from", owner_full)
        .attr("to", requester)
        .optional_attr("id", original_presence_id)
        .finish()
}

pub(super) fn presence_probe_status_response(
    target_bare: &str,
    requester: &str,
    kind: &str,
    id: Option<&str>,
) -> String {
    XmlElement::namespaced("presence", "jabber:client")
        .attr("from", target_bare)
        .attr("to", requester)
        .attr("type", kind)
        .optional_attr("id", id)
        .finish()
}

pub(super) fn unsubscribed_probe_response(
    target_bare: &str,
    requester: &str,
    id: Option<&str>,
) -> String {
    presence_probe_status_response(target_bare, requester, "unsubscribed", id)
}

pub(super) fn directed_presence_capacity_reached(current: usize, already_present: bool) -> bool {
    northstar_presence_core::directed_presence_capacity_reached(current, already_present)
}

pub(super) fn directed_presence_target_is_outside_bare_scope(
    target: &str,
    target_bare: &str,
) -> bool {
    northstar_presence_core::directed_presence_target_is_outside_bare_scope(target, target_bare)
}
