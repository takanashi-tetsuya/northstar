//! XEP-0045 room registration IQ handlers.

use super::*;

impl ProtocolSession {
    pub(crate) async fn muc_register_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some((room_jid, room_localpart)) = iq
            .attribute("to")
            .and_then(|value| canonical_local_muc_room(value, &self.muc_domain()))
        else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")));
        };
        if !room.allow_registration {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "not-allowed")));
        }
        let payload = if let Some(nick) = self
            .state
            .muc_service()
            .local_reserved_nick(room.id, user.id)
            .await?
        {
            XmlElement::namespaced("query", "jabber:iq:register")
                .child(XmlElement::new("registered"))
                .child(XmlElement::new("username").text(nick))
                .finish()
        } else {
            let title = format!(
                "{} Registration",
                room.title.as_deref().unwrap_or(&room.localpart)
            );
            XmlElement::namespaced("query", "jabber:iq:register")
                .child(
                    XmlElement::namespaced("x", "jabber:x:data")
                        .attr("type", "form")
                        .child(XmlElement::new("title").text(title))
                        .child(
                            XmlElement::new("instructions")
                                .text("Choose the nickname to reserve in this room."),
                        )
                        .child(xdata_value_field(
                            "FORM_TYPE",
                            "hidden",
                            "http://jabber.org/protocol/muc#register",
                        ))
                        .child(
                            XmlElement::new("field")
                                .attr("var", "muc#register_roomnick")
                                .attr("type", "text-single")
                                .child(XmlElement::new("required")),
                        ),
                )
                .finish()
        };
        Ok(Action::Send(iq_result_from(id, &room_jid, &payload)))
    }

    pub(crate) async fn muc_register_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        if self.full_jid.is_none() {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        }
        let Some((room_jid, room_localpart)) = iq
            .attribute("to")
            .and_then(|value| canonical_local_muc_room(value, &self.muc_domain()))
        else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        let Some(initial_room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")));
        };
        let gated_room_id = initial_room.id;
        let gated_room_epoch = initial_room.room_epoch;
        let _local_room_guard = if self.state.muc_pg_authority_enabled() {
            None
        } else {
            Some(
                self.state
                    .muc_service()
                    .lock_local_room_mutation(initial_room.id)
                    .await,
            )
        };
        // The initial snapshot only identifies the room gate. Re-read all
        // mutable policy after acquiring it so a concurrent owner/admin
        // command cannot commit a new access model while this request applies
        // stale in-memory side effects.
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")));
        };
        if room.id != gated_room_id || room.room_epoch != gated_room_epoch {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")));
        }
        if !room.allow_registration {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "not-allowed")));
        }
        let requester_bare = format!("{}@{}", user.username, self.state.local_domain());
        let elements = query
            .children()
            .filter(|node| node.is_element())
            .collect::<Vec<_>>();
        if elements.len() == 1
            && elements[0].tag_name().name() == "remove"
            && elements[0].tag_name().namespace() == Some("jabber:iq:register")
            && !elements[0].children().any(|node| node.is_element())
        {
            if self.state.muc_pg_authority_enabled() {
                self.state.admit_muc_pg_mutation()?;
                let Some(full_jid) = self.full_jid.as_deref() else {
                    return Ok(Action::Send(iq_error_from(id, &room_jid, "not-authorized")));
                };
                let operation_id = uuid::Uuid::new_v4();
                let outcome = self
                    .state
                    .muc_service()
                    .mutate_local_cluster_registration(
                        operation_id,
                        room.id,
                        room.room_epoch,
                        room.config_version,
                        &ClusterMucPrincipal::Local {
                            user_id: user.id,
                            bare_jid: requester_bare.clone(),
                        },
                        full_jid,
                        None,
                    )
                    .await?;
                return match outcome {
                    ClusterMucRegistrationOutcome::Applied { .. }
                    | ClusterMucRegistrationOutcome::Replay { .. } => {
                        self.state
                            .wake_committed_muc_operation(operation_id)
                            .await?;
                        Ok(Action::Send(iq_result_from(id, &room_jid, "")))
                    }
                    ClusterMucRegistrationOutcome::Outcast
                    | ClusterMucRegistrationOutcome::NotAllowed => {
                        Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")))
                    }
                    ClusterMucRegistrationOutcome::Conflict => {
                        Ok(Action::Send(iq_error_from(id, &room_jid, "conflict")))
                    }
                    ClusterMucRegistrationOutcome::Stale
                    | ClusterMucRegistrationOutcome::Destroyed => {
                        Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")))
                    }
                };
            }
            let affiliation_changed = self
                .state
                .muc_service()
                .unregister_local_member(room.id, user.id)
                .await?;
            let affiliation = self
                .state
                .muc_service()
                .local_affiliation(room.id, user.id)
                .await?
                .unwrap_or_else(|| "none".to_owned());
            let mut target_is_occupant = false;
            if let Some(joined) = self.joined_rooms.get(&room_jid) {
                let joined_nick = joined.nick.clone();
                let joined_epoch = joined.cluster_epoch;
                drop(joined);
                if let Some(occupant) = self.state.set_local_muc_affiliation_exact(
                    crate::state::LocalMucOccupantIdentity {
                        room_jid: &room_jid,
                        nick: &joined_nick,
                        full_jid: self
                            .full_jid
                            .as_deref()
                            .expect("bound session checked above"),
                        connection_id: self.connection_id,
                        cluster_epoch: joined_epoch,
                    },
                    &affiliation,
                    room.moderated,
                    false,
                    None,
                ) {
                    target_is_occupant = true;
                    let updated = crate::state::SerializableMucOccupant::from(&occupant);
                    let updated_json = serde_json::to_string(&updated)?;
                    let _ = self
                        .state
                        .register_cluster_muc_occupant(&room_jid, &joined_nick, &updated_json)
                        .await;
                    for (_, recipient) in self.state.muc_occupants_for(&room_jid) {
                        let self_presence = recipient.full_jid == updated.full_jid;
                        let presence = muc_presence_stanza(
                            &updated,
                            &recipient.full_jid,
                            false,
                            self_presence,
                            false,
                            None,
                            room.non_anonymous || self_presence || recipient.role == "moderator",
                        );
                        let _ = self
                            .state
                            .deliver_to_muc_occupant(&recipient, presence)
                            .await;
                    }
                }
            }
            if affiliation_changed
                && should_broadcast_offline_affiliation_change(
                    room.non_anonymous,
                    target_is_occupant,
                    "member",
                    "none",
                )
            {
                deliver_muc_offline_affiliation_change_notice(
                    &self.state,
                    &room_jid,
                    &requester_bare,
                    "none",
                    None,
                    None,
                )
                .await;
            }
            return Ok(Action::Send(iq_result_from(id, &room_jid, "")));
        }
        if elements.len() != 1
            || elements[0].tag_name().name() != "x"
            || elements[0].tag_name().namespace() != Some("jabber:x:data")
            || elements[0].attribute("type") != Some("submit")
            || xdata_field(elements[0], "FORM_TYPE")
                != Some("http://jabber.org/protocol/muc#register")
        {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "bad-request")));
        }
        let Some(nick) = xdata_field(elements[0], "muc#register_roomnick") else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "bad-request")));
        };
        let Ok(nick) = prepare_muc_nick(nick) else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "not-acceptable")));
        };
        if self.state.muc_pg_authority_enabled() {
            self.state.admit_muc_pg_mutation()?;
            let Some(full_jid) = self.full_jid.as_deref() else {
                return Ok(Action::Send(iq_error_from(id, &room_jid, "not-authorized")));
            };
            let operation_id = uuid::Uuid::new_v4();
            let outcome = self
                .state
                .muc_service()
                .mutate_local_cluster_registration(
                    operation_id,
                    room.id,
                    room.room_epoch,
                    room.config_version,
                    &ClusterMucPrincipal::Local {
                        user_id: user.id,
                        bare_jid: requester_bare.clone(),
                    },
                    full_jid,
                    Some(&nick),
                )
                .await?;
            return match outcome {
                ClusterMucRegistrationOutcome::Applied { .. }
                | ClusterMucRegistrationOutcome::Replay { .. } => {
                    self.state
                        .wake_committed_muc_operation(operation_id)
                        .await?;
                    Ok(Action::Send(iq_result_from(id, &room_jid, "")))
                }
                ClusterMucRegistrationOutcome::Conflict => {
                    Ok(Action::Send(iq_error_from(id, &room_jid, "conflict")))
                }
                ClusterMucRegistrationOutcome::Outcast
                | ClusterMucRegistrationOutcome::NotAllowed => {
                    Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")))
                }
                ClusterMucRegistrationOutcome::Stale | ClusterMucRegistrationOutcome::Destroyed => {
                    Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")))
                }
            };
        }
        let occupants = self
            .state
            .cached_muc_cluster_occupants(&room_jid)
            .await
            .unwrap_or_default();
        if occupants.get(&nick).is_some_and(|json| {
            serde_json::from_str::<crate::state::SerializableMucOccupant>(json)
                .ok()
                .is_some_and(|occupant| bare_jid(&occupant.full_jid) != requester_bare)
        }) || self
            .state
            .muc_occupants_for(&room_jid)
            .iter()
            .any(|(_, occupant)| {
                occupant.nick == nick && bare_jid(&occupant.full_jid) != requester_bare
            })
        {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "conflict")));
        }
        let affiliation_changed = match self
            .state
            .muc_service()
            .execute_muc_registration(MucRegistrationCommand::from(MucRegistrationWrite {
                room_id: room.id,
                target: MucRegistrationTarget::Local { user_id: user.id },
                nick: &nick,
            }))
            .await?
            .outcome
        {
            MucRegistrationOutcome::Registered {
                affiliation_changed,
            } => affiliation_changed,
            MucRegistrationOutcome::Conflict => {
                return Ok(Action::Send(iq_error_from(id, &room_jid, "conflict")));
            }
            MucRegistrationOutcome::Outcast => {
                return Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")));
            }
        };
        let mut target_is_occupant = false;
        if let Some(joined) = self.joined_rooms.get(&room_jid) {
            let joined_nick = joined.nick.clone();
            let joined_epoch = joined.cluster_epoch;
            drop(joined);
            if let Some(occupant) = self.state.set_local_muc_affiliation_exact(
                crate::state::LocalMucOccupantIdentity {
                    room_jid: &room_jid,
                    nick: &joined_nick,
                    full_jid: self
                        .full_jid
                        .as_deref()
                        .expect("bound session checked above"),
                    connection_id: self.connection_id,
                    cluster_epoch: joined_epoch,
                },
                "member",
                room.moderated,
                true,
                None,
            ) {
                target_is_occupant = true;
                let updated = crate::state::SerializableMucOccupant::from(&occupant);
                let updated_json = serde_json::to_string(&updated)?;
                let _ = self
                    .state
                    .register_cluster_muc_occupant(&room_jid, &joined_nick, &updated_json)
                    .await;
                for (_, recipient) in self.state.muc_occupants_for(&room_jid) {
                    let self_presence = recipient.full_jid == updated.full_jid;
                    let presence = muc_presence_stanza(
                        &updated,
                        &recipient.full_jid,
                        false,
                        self_presence,
                        false,
                        None,
                        room.non_anonymous || self_presence || recipient.role == "moderator",
                    );
                    let _ = self
                        .state
                        .deliver_to_muc_occupant(&recipient, presence)
                        .await;
                }
            }
        }
        if affiliation_changed
            && should_broadcast_offline_affiliation_change(
                room.non_anonymous,
                target_is_occupant,
                "none",
                "member",
            )
        {
            deliver_muc_offline_affiliation_change_notice(
                &self.state,
                &room_jid,
                &requester_bare,
                "member",
                Some(&nick),
                None,
            )
            .await;
        }
        Ok(Action::Send(iq_result_from(id, &room_jid, "")))
    }
}
