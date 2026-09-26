use super::*;

impl ProtocolSession {
    pub(super) async fn handle_muc_invitation_decline(
        &self,
        root: Node<'_, '_>,
        raw: &str,
        from: &str,
        room_jid: String,
        to_jid: &CanonicalJid,
        decline: (String, Option<String>),
    ) -> Result<Action> {
        let (target_raw, reason) = decline;
        if to_jid.resourcepart().is_some()
            || !matches!(root.attribute("type"), None | Some("normal"))
        {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "bad-request",
            )));
        }
        if self
            .state
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await?
            .is_none()
        {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "cancel",
                "item-not-found",
            )));
        }
        let target = CanonicalJid::parse(&target_raw).map_err(|error| {
            anyhow::anyhow!("validated MUC decline target became invalid: {error}")
        })?;
        let mut decline = XmlElement::new("decline").attr("from", bare_jid(from));
        if let Some(reason) = reason.as_deref() {
            decline.push_child(XmlElement::new("reason").text(reason.to_owned()));
        }
        let extension =
            XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user").child(decline);
        let hints = processing_hints_fragment(root, raw);
        let temporary_storage = offline_storage_permitted(root);
        let forwarded = XmlElement::new("message")
            .attr("from", &room_jid)
            .attr("to", &target_raw)
            .attr("type", "normal")
            .attr(
                "id",
                root.attribute("id")
                    .filter(|id| !id.is_empty() && id.len() <= 128)
                    .unwrap_or("muc-decline"),
            )
            .child(extension)
            .validated_fragment(&hints)?
            .finish();
        if target.domainpart() == self.muc_domain()
            && target.bare() == room_jid
            && target.resourcepart().is_some()
        {
            let nick = target
                .resourcepart()
                .expect("decline occupant resource checked");
            if let Some(recipient) = self.state.local_muc_occupant_by_nick(&room_jid, nick) {
                let _ = self
                    .state
                    .deliver_to_muc_occupant(&recipient, forwarded.clone())
                    .await;
            }
            self.state
                .publish_muc_cluster_private_message(&room_jid, nick, &forwarded, from)
                .await?;
            return Ok(Action::None);
        }
        if target.domainpart() == self.state.local_domain() {
            let Some(username) = target.localpart() else {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "modify",
                    "jid-malformed",
                )));
            };
            let Some(recipient) = self
                .state
                .muc_service()
                .enabled_local_account(username)
                .await?
            else {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "cancel",
                    "item-not-found",
                )));
            };
            if self
                .state
                .muc_service()
                .is_blocked_for_account(recipient.id, &target.bare(), &room_jid)
                .await?
                || self
                    .state
                    .muc_service()
                    .is_blocked_for_account(recipient.id, &target.bare(), from)
                    .await?
            {
                return Ok(Action::None);
            }
            let mut sessions = self.state.session_entries_for(&target_raw);
            if target.resourcepart().is_none() {
                sessions.retain(|(_, session)| {
                    session.available.load(Ordering::Relaxed)
                        && session.priority.load(Ordering::Relaxed) >= 0
                });
                sessions.sort_by(|(left_jid, left), (right_jid, right)| {
                    right
                        .priority
                        .load(Ordering::Relaxed)
                        .cmp(&left.priority.load(Ordering::Relaxed))
                        .then_with(|| left_jid.cmp(right_jid))
                });
            }
            let mut delivered = sessions
                .into_iter()
                .any(|(_, session)| session.sender.try_send(forwarded.clone()).is_ok());
            if !delivered {
                delivered = self
                    .state
                    .deliver_muc_primary_to_remote_node(&target_raw, &forwarded, None)
                    .await
                    .is_some();
            }
            if !delivered && temporary_storage {
                let delayed = add_delay_from(&forwarded, chrono::Utc::now(), Some(&room_jid));
                let outcome = self
                    .state
                    .muc_service()
                    .store_local_muc_offline(
                        recipient.id,
                        &room_jid,
                        &delayed,
                        false,
                        temporary_muc_offline_policy(&self.state),
                    )
                    .await?;
                if outcome == OfflineStoreOutcome::QuotaExceeded {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "wait",
                        "resource-constraint",
                    )));
                }
                if outcome == OfflineStoreOutcome::RecipientUnavailable {
                    return Ok(Action::None);
                }
                if let Err(error) = self.state.dispatch_push_notification(recipient.id).await {
                    tracing::warn!(?error, recipient_id = %recipient.id, %room_jid, "accepted offline MUC invitation decline could not trigger push notification");
                }
            }
            return Ok(Action::None);
        }
        if !self
            .state
            .xmpp_external_route_domain_allowed(target.domainpart())
            || !self
                .state
                .federation_outbox()
                .send(target.domainpart(), forwarded, Some(room_jid.clone()))
                .await
        {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "wait",
                "remote-server-timeout",
            )));
        }
        Ok(Action::None)
    }

    pub(super) async fn handle_muc_voice_form(
        &self,
        root: Node<'_, '_>,
        from: &str,
        to_jid: &CanonicalJid,
        room_jid: String,
        own: &crate::state::MucOccupant,
        voice_form: MucVoiceForm,
    ) -> Result<Action> {
        if to_jid.resourcepart().is_some()
            || !matches!(root.attribute("type"), None | Some("normal"))
        {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "bad-request",
            )));
        }
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await?
        else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "cancel",
                "item-not-found",
            )));
        };
        let mut occupants = self
            .state
            .cached_muc_cluster_occupants(&room_jid)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(nick, json)| {
                serde_json::from_str::<crate::state::SerializableMucOccupant>(&json)
                    .ok()
                    .map(|occupant| (nick, occupant))
            })
            .collect::<std::collections::HashMap<_, _>>();
        for (_, occupant) in self.state.muc_occupants_for(&room_jid) {
            occupants.insert(
                occupant.nick.clone(),
                crate::state::SerializableMucOccupant::from(&occupant),
            );
        }
        match voice_form {
            MucVoiceForm::Request => {
                if !room.moderated || own.role != "visitor" {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "auth",
                        "forbidden",
                    )));
                }
                let request = muc_voice_request(&room_jid, &own.full_jid, &own.nick);
                for moderator in occupants
                    .values()
                    .filter(|occupant| occupant.role == "moderator")
                {
                    if let Some(local) = self
                        .state
                        .local_muc_occupant_by_nick(&room_jid, &moderator.nick)
                    {
                        let _ = self
                            .state
                            .deliver_to_muc_occupant(&local, set_to(&request, &local.full_jid))
                            .await;
                    }
                    self.state
                        .publish_muc_cluster_private_message(
                            &room_jid,
                            &moderator.nick,
                            &request,
                            &own.full_jid,
                        )
                        .await?;
                }
                Ok(Action::None)
            }
            MucVoiceForm::Approval { jid, nick, allow } => {
                if own.role != "moderator" {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "auth",
                        "forbidden",
                    )));
                }
                let Some(target) = occupants.get(&nick) else {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "cancel",
                        "item-not-found",
                    )));
                };
                if target.full_jid != jid || target.role != "visitor" {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "cancel",
                        "not-allowed",
                    )));
                }
                if !allow {
                    return Ok(Action::None);
                }
                if !self.state.muc_pg_authority_enabled() {
                    // The legacy in-memory path still serializes with
                    // other room mutations when PostgreSQL occupancy is
                    // unavailable.
                    let service = self.state.muc_service();
                    let _guard = service.lock_local_room_mutation(room.id).await;
                    let Some(current_room) =
                        service.local_room_snapshot(localpart(&room_jid)).await?
                    else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            from,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    if current_room.id != room.id || current_room.room_epoch != room.room_epoch {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            from,
                            "cancel",
                            "item-not-found",
                        )));
                    }
                    let Some(current_actor) = self.authorized_muc_occupant(&room_jid).await? else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            from,
                            "auth",
                            "forbidden",
                        )));
                    };
                    if current_actor.full_jid != own.full_jid
                        || current_actor.connection_id != own.connection_id
                        || current_actor.cluster_epoch != own.cluster_epoch
                        || current_actor.role != "moderator"
                    {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            from,
                            "auth",
                            "forbidden",
                        )));
                    }
                    let Some(updated_occupant) = self.state.set_local_muc_role_exact(
                        crate::state::LocalMucOccupantIdentity::from(target),
                        "visitor",
                        "participant",
                        None,
                    ) else {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            from,
                            "cancel",
                            "item-not-found",
                        )));
                    };
                    let updated = crate::state::SerializableMucOccupant::from(&updated_occupant);
                    drop(_guard);
                    for (_, recipient) in self.state.muc_occupants_for(&room_jid) {
                        let self_presence = recipient.full_jid == updated.full_jid
                            && recipient.connection_id == updated.connection_id
                            && recipient.cluster_epoch == updated.cluster_epoch;
                        let presence = muc_presence_stanza(
                            &updated,
                            &recipient.full_jid,
                            false,
                            self_presence,
                            false,
                            root.attribute("id"),
                            updated.room_non_anonymous
                                || self_presence
                                || recipient.role == "moderator",
                        );
                        let _ = self
                            .state
                            .deliver_to_muc_occupant(&recipient, presence)
                            .await;
                    }
                    return Ok(Action::None);
                }
                let service = self.state.muc_service();
                let Some(actor_target) = service
                    .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &own.nick)
                    .await?
                else {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "auth",
                        "forbidden",
                    )));
                };
                let Some(target_authority) = service
                    .local_cluster_occupancy_target_by_nick(room.id, room.room_epoch, &target.nick)
                    .await?
                else {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "cancel",
                        "item-not-found",
                    )));
                };
                if actor_target.full_jid != own.full_jid
                    || actor_target.connection_uuid != own.connection_id
                    || target_authority.full_jid != target.full_jid
                    || target_authority.connection_uuid != target.connection_id
                {
                    return Ok(Action::Send(muc_stanza_error(
                        root,
                        from,
                        "cancel",
                        "item-not-found",
                    )));
                }
                let operation_id = crate::services::muc::operation_id(&serde_json::json!({
                    "kind":"voice_approval","stream":self.connection_id,
                    "stanza_id":root.attribute("id"),"room":room_jid,
                    "actor":actor_target,"target":target_authority,"role":"participant"
                }))?;
                match service
                    .change_local_cluster_role(
                        operation_id,
                        &actor_target,
                        &target_authority,
                        "participant",
                        None,
                    )
                    .await?
                {
                    ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {}
                    ClusterMucTransitionOutcome::Unauthorized => {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            from,
                            "auth",
                            "forbidden",
                        )));
                    }
                    _ => {
                        return Ok(Action::Send(muc_stanza_error(
                            root,
                            from,
                            "cancel",
                            "item-not-found",
                        )));
                    }
                }
                if let Err(error) = self.state.wake_committed_muc_operation(operation_id).await {
                    tracing::warn!(?error, %operation_id, "committed MUC voice approval wake failed; PostgreSQL outbox will catch up");
                }
                Ok(Action::None)
            }
        }
    }

    pub(super) async fn handle_muc_private_message(
        &self,
        root: Node<'_, '_>,
        raw: &str,
        from: &str,
        room_jid: String,
        to_jid: &CanonicalJid,
        own: &crate::state::MucOccupant,
    ) -> Result<Action> {
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await?
        else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "cancel",
                "item-not-found",
            )));
        };
        if !room.allow_private_messages {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "auth",
                "forbidden",
            )));
        }
        if !matches!(
            root.attribute("type").unwrap_or("normal"),
            "chat" | "normal"
        ) {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "bad-request",
            )));
        }
        let Some(target_nick) = to_jid.resourcepart() else {
            return Ok(Action::Send(muc_stanza_error(
                root,
                from,
                "modify",
                "jid-malformed",
            )));
        };
        let local_target = self
            .state
            .local_muc_occupant_by_nick(&room_jid, target_nick);
        let (target_full_jid, route_via_cluster) = if let Some(target) = &local_target {
            (target.full_jid.clone(), false)
        } else {
            let occupants = self
                .state
                .cached_muc_cluster_occupants(&room_jid)
                .await
                .unwrap_or_default();
            let Some(target) = occupants.get(target_nick).and_then(|json| {
                serde_json::from_str::<crate::state::SerializableMucOccupant>(json).ok()
            }) else {
                return Ok(Action::Send(muc_stanza_error(
                    root,
                    from,
                    "cancel",
                    "item-not-found",
                )));
            };
            (target.full_jid, true)
        };

        let rewritten = set_muc_occupant_id(
            &add_stanza_id(
                &set_to(
                    &set_from(raw, &format!("{room_jid}/{}", own.nick)),
                    &target_full_jid,
                ),
                &room_jid,
                uuid::Uuid::new_v4(),
            ),
            &own.occupant_id,
        );

        if route_via_cluster {
            self.state
                .publish_muc_cluster_private_message(&room_jid, target_nick, &rewritten, from)
                .await?;
        } else if let Some(target) = local_target {
            let blocked = self
                .state
                .blocked_muc_recipient_accounts(
                    std::slice::from_ref(&target),
                    &[format!("{room_jid}/{}", own.nick), from.to_owned()],
                )
                .await;
            if crate::jid::canonical_bare_key(&target.full_jid)
                .is_ok_and(|owner| blocked.contains(&owner))
            {
                return Ok(Action::None);
            }
            let _ = self
                .state
                .deliver_to_muc_occupant_unchecked(&target, rewritten)
                .await;
        }
        Ok(Action::None)
    }

    pub(super) async fn handle_muc_invitation(
        &self,
        root: Node<'_, '_>,
        raw: &str,
        from: &str,
        room_jid: String,
        own: &crate::state::MucOccupant,
    ) -> Result<Action> {
        let mut has_invites = false;
        if let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(localpart(&room_jid))
            .await?
        {
            for x in root.children().filter(|n| {
                n.is_element()
                    && n.tag_name().name() == "x"
                    && n.tag_name().namespace() == Some("http://jabber.org/protocol/muc#user")
            }) {
                for invite in x
                    .children()
                    .filter(|n| n.is_element() && n.tag_name().name() == "invite")
                {
                    if let Some(invitee_raw) = invite.attribute("to") {
                        has_invites = true;
                        let Ok(invitee) = CanonicalJid::parse(invitee_raw) else {
                            return Ok(Action::Send(muc_stanza_error(
                                root,
                                from,
                                "modify",
                                "jid-malformed",
                            )));
                        };
                        let Some(invitee_localpart) = invitee.localpart() else {
                            return Ok(Action::Send(muc_stanza_error(
                                root,
                                from,
                                "modify",
                                "jid-malformed",
                            )));
                        };
                        let invitee_jid = invitee.to_string();
                        let invitee_bare = invitee.bare();
                        let invitee_domain = invitee.domainpart();
                        if invitee_domain == self.state.local_domain() {
                            if let Some(invitee_user) = self
                                .state
                                .muc_service()
                                .enabled_local_account(invitee_localpart)
                                .await?
                            {
                                let blocked_room = self
                                    .state
                                    .muc_service()
                                    .is_blocked_for_account(
                                        invitee_user.id,
                                        &invitee_bare,
                                        &room_jid,
                                    )
                                    .await?;
                                let blocked_inviter = self
                                    .state
                                    .muc_service()
                                    .is_blocked_for_account(invitee_user.id, &invitee_bare, from)
                                    .await?;
                                if blocked_room || blocked_inviter {
                                    continue;
                                }
                            }
                        }
                        // XEP-0045 roomconfig_allowinvites grants members
                        // an additional privilege; it never restricts an
                        // owner or administrator's inherent privilege.
                        let privileged_inviter =
                            matches!(own.affiliation.as_str(), "owner" | "admin");
                        if !privileged_inviter && (own.role == "visitor" || !room.allow_invites) {
                            return Ok(Action::Send(muc_stanza_error(
                                root,
                                from,
                                "auth",
                                "forbidden",
                            )));
                        }
                        let reason = child_text(invite, "reason");
                        let mut invite_out = XmlElement::new("invite").attr("from", from);
                        if let Some(r) = reason {
                            invite_out.push_child(XmlElement::new("reason").text(r.to_owned()));
                        }
                        let hints = processing_hints_fragment(root, raw);
                        let temporary_storage = offline_storage_permitted(root);

                        let local_durable_invite_id =
                            if room.members_only && invitee_domain == self.state.local_domain() {
                                Some(crate::services::muc::operation_id(&serde_json::json!({
                                    "kind":"muc_invitation","stream":self.connection_id,
                                    "stanza_id":root.attribute("id"),"room":room_jid,
                                    "actor":from,"invitee":invitee_bare,"reason":reason,
                                }))?)
                            } else {
                                None
                            };
                        let forwarded = set_muc_occupant_id(
                            &add_stanza_id(
                                &XmlElement::new("message")
                                    .attr("from", &room_jid)
                                    .attr("to", &invitee_jid)
                                    .attr("type", "normal")
                                    .child(
                                        XmlElement::namespaced(
                                            "x",
                                            "http://jabber.org/protocol/muc#user",
                                        )
                                        .child(invite_out),
                                    )
                                    .validated_fragment(&hints)?
                                    .finish(),
                                &room_jid,
                                uuid::Uuid::new_v4(),
                            ),
                            &own.occupant_id,
                        );
                        // Cluster protocol v6 can infer a durable delivery
                        // only when the recipient-authoritative stanza-id
                        // is the exact spool key. Protocol v7 also carries
                        // the explicit fence, so keeping both makes rolling
                        // upgrades fail safe without weakening identity.
                        let forwarded = local_durable_invite_id.map_or(forwarded.clone(), |id| {
                            add_stanza_id(&forwarded, &invitee_bare, id)
                        });

                        if invitee_domain == self.state.local_domain() {
                            let Some(recipient) = self
                                .state
                                .muc_service()
                                .enabled_local_account(invitee_localpart)
                                .await?
                            else {
                                return Ok(Action::Send(muc_stanza_error(
                                    root,
                                    from,
                                    "cancel",
                                    "service-unavailable",
                                )));
                            };
                            if room.members_only && !temporary_storage {
                                return Ok(Action::Send(muc_stanza_error(
                                    root,
                                    from,
                                    "wait",
                                    "service-unavailable",
                                )));
                            }
                            let (durable_invite, affiliation_changed) = if room.members_only {
                                let delayed =
                                    add_delay_from(&forwarded, chrono::Utc::now(), Some(&room_jid));
                                let cluster_authority = if self.state.muc_pg_authority_enabled() {
                                    self.state.admit_muc_pg_mutation()?;
                                    let Some(actor_target) = self
                                        .state
                                        .muc_service()
                                        .local_cluster_occupancy_target(
                                            room.id,
                                            own.cluster_epoch,
                                            own.connection_id,
                                        )
                                        .await?
                                    else {
                                        return Ok(Action::Send(muc_stanza_error(
                                            root,
                                            from,
                                            "auth",
                                            "forbidden",
                                        )));
                                    };
                                    let actor_user = self
                                        .authenticated
                                        .as_ref()
                                        .expect("MUC message actor is authenticated");
                                    Some(ClusterMucInviteAuthority {
                                        operation_id: local_durable_invite_id
                                            .expect("local members-only invite allocates a fence"),
                                        expected_room_epoch: room.room_epoch,
                                        expected_config_version: room.config_version,
                                        actor: ClusterMucPrincipal::Local {
                                            user_id: actor_user.id,
                                            bare_jid: bare_jid(from).to_owned(),
                                        },
                                        actor_full_jid: from.to_owned(),
                                        actor_target: Some(actor_target),
                                        subject: ClusterMucAffiliationSubject::Local {
                                            user_id: recipient.id,
                                            bare_jid: invitee_bare.clone(),
                                        },
                                        reason: reason.map(str::to_owned),
                                    })
                                } else {
                                    None
                                };
                                match self
                                    .state
                                    .muc_service()
                                    .admit_local_invite_command(
                                        local_durable_invite_id
                                            .expect("local members-only invite allocates a fence"),
                                        room.id,
                                        recipient.id,
                                        &room_jid,
                                        &delayed,
                                        false,
                                        temporary_muc_offline_policy(&self.state),
                                        cluster_authority.as_ref(),
                                    )
                                    .await?
                                {
                                    DurableMucInviteOutcome::Stored {
                                        id,
                                        affiliation_changed,
                                    } => {
                                        if let Some(authority) = &cluster_authority {
                                            self.state
                                                .wake_committed_muc_operation(
                                                    authority.operation_id,
                                                )
                                                .await?;
                                        }
                                        (Some(id), affiliation_changed)
                                    }
                                    DurableMucInviteOutcome::Replay { id: _ } => {
                                        if let Some(authority) = &cluster_authority {
                                            self.state
                                                .wake_committed_muc_operation(
                                                    authority.operation_id,
                                                )
                                                .await?;
                                        }
                                        return Ok(Action::None);
                                    }
                                    DurableMucInviteOutcome::QuotaExceeded => {
                                        return Ok(Action::Send(muc_stanza_error(
                                            root,
                                            from,
                                            "wait",
                                            "resource-constraint",
                                        )));
                                    }
                                    DurableMucInviteOutcome::RecipientUnavailable => {
                                        continue;
                                    }
                                    DurableMucInviteOutcome::Outcast => {
                                        return Ok(Action::Send(muc_stanza_error(
                                            root,
                                            from,
                                            "auth",
                                            "forbidden",
                                        )));
                                    }
                                    DurableMucInviteOutcome::AuthorityRejected => {
                                        return Ok(Action::Send(muc_stanza_error(
                                            root,
                                            from,
                                            "auth",
                                            "forbidden",
                                        )));
                                    }
                                    DurableMucInviteOutcome::Stale => {
                                        return Ok(Action::Send(muc_stanza_error(
                                            root,
                                            from,
                                            "cancel",
                                            "item-not-found",
                                        )));
                                    }
                                }
                            } else {
                                (None, false)
                            };
                            if affiliation_changed && !self.state.muc_pg_authority_enabled() {
                                let locally_present =
                                    self.state.muc_occupants_for(&room_jid).iter().any(
                                        |(_, occupant)| {
                                            canonical_bare_key(&occupant.full_jid).ok()
                                                == Some(invitee_bare.clone())
                                        },
                                    );
                                let remotely_present = match self
                                    .state
                                    .cached_muc_cluster_occupants(&room_jid)
                                    .await
                                {
                                    Ok(occupants) => occupants.into_values().any(|json| {
                                        serde_json::from_str::<
                                            crate::state::SerializableMucOccupant,
                                        >(&json)
                                        .ok()
                                        .and_then(|occupant| {
                                            canonical_bare_key(&occupant.full_jid).ok()
                                        }) == Some(invitee_bare.clone())
                                    }),
                                    Err(error) => {
                                        record_muc_post_commit_failure(
                                            &self.state,
                                            &room_jid,
                                            &invitee_bare,
                                            "invite-affiliation-presence-check",
                                        );
                                        tracing::warn!(
                                            ?error,
                                            room = %room_jid,
                                            target = %invitee_bare,
                                            "could not determine whether a newly invited member is already in the room"
                                        );
                                        true
                                    }
                                };
                                if should_broadcast_offline_affiliation_change(
                                    room.non_anonymous,
                                    locally_present || remotely_present,
                                    "none",
                                    "member",
                                ) {
                                    deliver_muc_offline_affiliation_change_notice(
                                        &self.state,
                                        &room_jid,
                                        &invitee_bare,
                                        "member",
                                        None,
                                        reason,
                                    )
                                    .await;
                                }
                            }
                            let mut targets = self.state.session_entries_for(&invitee_jid);
                            if invitee.resourcepart().is_none() {
                                targets.retain(|(_, session)| {
                                    session.available.load(Ordering::Relaxed)
                                        && session.priority.load(Ordering::Relaxed) >= 0
                                });
                                targets.sort_by(|(left_jid, left), (right_jid, right)| {
                                    right
                                        .priority
                                        .load(Ordering::Relaxed)
                                        .cmp(&left.priority.load(Ordering::Relaxed))
                                        .then_with(|| left_jid.cmp(right_jid))
                                });
                            }
                            let carbon_eligible = should_carbon(root);
                            let live_delivery =
                                durable_invite.map(|message_id| crate::outbound::DurableDelivery {
                                    recipient_id: recipient.id,
                                    message_id,
                                    claim_id: None,
                                });
                            let mut delivered = false;
                            let mut delivered_full_jid = None;
                            for (full_jid, target) in targets {
                                let accepted = if let Some(delivery) = live_delivery {
                                    target
                                        .sender
                                        .try_send_durable(forwarded.clone(), delivery)
                                        .is_ok()
                                } else {
                                    target.sender.try_send(forwarded.clone()).is_ok()
                                };
                                if accepted {
                                    self.state
                                        .muc_telemetry()
                                        .online_queue_accepted(live_delivery.is_some());
                                    delivered = true;
                                    delivered_full_jid = Some(full_jid);
                                    break;
                                }
                            }
                            if !delivered {
                                if let Some(receipt) = self
                                    .state
                                    .deliver_muc_primary_to_remote_node(
                                        &invitee_jid,
                                        &forwarded,
                                        live_delivery,
                                    )
                                    .await
                                {
                                    delivered = true;
                                    delivered_full_jid = receipt.accepted_full_jid;
                                }
                            }
                            if delivered && carbon_eligible {
                                super::super::messaging::send_received_carbons_for_state(
                                    &self.state,
                                    &invitee_bare,
                                    delivered_full_jid.as_deref(),
                                    &forwarded,
                                )
                                .await;
                            }
                            if !delivered && durable_invite.is_none() && temporary_storage {
                                let delayed =
                                    add_delay_from(&forwarded, chrono::Utc::now(), Some(&room_jid));
                                let offline_outcome = self
                                    .state
                                    .muc_service()
                                    .store_local_muc_offline(
                                        recipient.id,
                                        &room_jid,
                                        &delayed,
                                        false,
                                        temporary_muc_offline_policy(&self.state),
                                    )
                                    .await?;
                                if offline_outcome == OfflineStoreOutcome::QuotaExceeded {
                                    return Ok(Action::Send(muc_stanza_error(
                                        root,
                                        from,
                                        "wait",
                                        "resource-constraint",
                                    )));
                                }
                                if offline_outcome == OfflineStoreOutcome::RecipientUnavailable {
                                    return Ok(Action::None);
                                }
                            }
                            if !delivered && temporary_storage {
                                if let Err(error) =
                                    self.state.dispatch_push_notification(recipient.id).await
                                {
                                    tracing::warn!(?error, recipient_id = %recipient.id, %room_jid, "accepted offline mediated MUC invitation could not trigger push notification");
                                }
                            }
                        } else if room.members_only {
                            let operation_id =
                                crate::services::muc::operation_id(&serde_json::json!({
                                    "kind":"muc_invitation","stream":self.connection_id,
                                    "stanza_id":root.attribute("id"),"room":room_jid,
                                    "actor":from,"invitee":invitee_bare,"reason":reason,
                                }))?;
                            let cluster_authority = if self.state.muc_pg_authority_enabled() {
                                self.state.admit_muc_pg_mutation()?;
                                let Some(actor_target) = self
                                    .state
                                    .muc_service()
                                    .local_cluster_occupancy_target(
                                        room.id,
                                        own.cluster_epoch,
                                        own.connection_id,
                                    )
                                    .await?
                                else {
                                    return Ok(Action::Send(muc_stanza_error(
                                        root,
                                        from,
                                        "auth",
                                        "forbidden",
                                    )));
                                };
                                let actor_user = self
                                    .authenticated
                                    .as_ref()
                                    .expect("MUC message actor is authenticated");
                                Some(ClusterMucInviteAuthority {
                                    operation_id,
                                    expected_room_epoch: room.room_epoch,
                                    expected_config_version: room.config_version,
                                    actor: ClusterMucPrincipal::Local {
                                        user_id: actor_user.id,
                                        bare_jid: bare_jid(from).to_owned(),
                                    },
                                    actor_full_jid: from.to_owned(),
                                    actor_target: Some(actor_target),
                                    subject: ClusterMucAffiliationSubject::Federated {
                                        bare_jid: invitee_bare.clone(),
                                    },
                                    reason: reason.map(str::to_owned),
                                })
                            } else {
                                None
                            };
                            match self
                                .state
                                .muc_service()
                                .admit_federated_invite_command(
                                    room.id,
                                    &invitee_bare,
                                    invitee_domain,
                                    &forwarded,
                                    Some(&room_jid),
                                    self.state.federation_outbox().outbox_policy(),
                                    cluster_authority.as_ref(),
                                )
                                .await
                            {
                                Ok(true) => {
                                    self.state.federation_outbox().wake_outbox();
                                    if cluster_authority.is_some() {
                                        self.state
                                            .wake_committed_muc_operation(operation_id)
                                            .await?;
                                    }
                                }
                                Ok(false) => {
                                    return Ok(Action::Send(muc_stanza_error(
                                        root,
                                        from,
                                        "auth",
                                        "forbidden",
                                    )));
                                }
                                Err(error) => {
                                    tracing::warn!(?error, %invitee_bare, %room_jid, "federated mediated MUC invite admission failed atomically");
                                    return Ok(Action::Send(muc_stanza_error(
                                        root,
                                        from,
                                        "wait",
                                        "resource-constraint",
                                    )));
                                }
                            }
                        } else {
                            if !self
                                .state
                                .federation_outbox()
                                .send(invitee_domain, forwarded, Some(room_jid.clone()))
                                .await
                            {
                                return Ok(Action::Send(muc_stanza_error(
                                    root,
                                    from,
                                    "wait",
                                    "remote-server-timeout",
                                )));
                            }
                        }
                    }
                }
            }
        }
        if has_invites {
            return Ok(Action::None);
        }
        Ok(Action::Send(muc_stanza_error(
            root,
            from,
            "modify",
            "bad-request",
        )))
    }
}
