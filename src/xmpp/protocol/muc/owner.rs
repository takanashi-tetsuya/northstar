//! XEP-0045 owner IQ handlers and the room configuration form.

use super::*;

pub(super) fn muc_xdata_option(value: &'static str, label: Option<&'static str>) -> XmlElement {
    XmlElement::new("option")
        .optional_attr("label", label)
        .child(XmlElement::new("value").text(value))
}

pub(in crate::xmpp::protocol) fn muc_room_configuration_form(
    room: &MucRoom,
    whois: &str,
) -> String {
    let allow_private_messages = if room.allow_private_messages {
        "anyone"
    } else {
        "none"
    };
    let allow_pm = xdata_value_field(
        "muc#roomconfig_allowpm",
        "list-single",
        allow_private_messages,
    )
    .child(muc_xdata_option("anyone", None))
    .child(muc_xdata_option("none", None));
    let whois_field = xdata_value_field("muc#roomconfig_whois", "list-single", whois)
        .child(muc_xdata_option("anyone", Some("Anyone")))
        .child(muc_xdata_option("moderators", Some("Moderators only")));
    let mut max_users =
        xdata_value_field("muc#roomconfig_maxusers", "list-single", room.max_occupants);
    for value in ["10", "20", "50", "100", "500", "1000"] {
        max_users.push_child(muc_xdata_option(value, None));
    }
    let form = XmlElement::namespaced("x", "jabber:x:data")
        .attr("type", "form")
        .child(XmlElement::new("title").text("Room configuration"))
        .child(xdata_value_field(
            "FORM_TYPE",
            "hidden",
            "http://jabber.org/protocol/muc#roomconfig",
        ))
        .child(xdata_value_field(
            "muc#roomconfig_roomname",
            "text-single",
            room.title.as_deref().unwrap_or(&room.localpart),
        ))
        .child(xdata_value_field(
            "muc#roomconfig_roomdesc",
            "text-single",
            room.description.as_deref().unwrap_or_default(),
        ))
        .child(xdata_value_field(
            "muc#roomconfig_persistentroom",
            "boolean",
            bool_value(room.persistent),
        ))
        .child(xdata_value_field(
            "muc#roomconfig_membersonly",
            "boolean",
            bool_value(room.members_only),
        ))
        .child(xdata_value_field(
            "muc#roomconfig_publicroom",
            "boolean",
            bool_value(room.public),
        ))
        .child(xdata_value_field(
            "muc#roomconfig_moderatedroom",
            "boolean",
            bool_value(room.moderated),
        ))
        .child(xdata_value_field(
            "muc#roomconfig_changesubject",
            "boolean",
            bool_value(room.allow_subject_change),
        ))
        .child(xdata_value_field(
            "muc#roomconfig_allowinvites",
            "boolean",
            bool_value(room.allow_invites),
        ))
        .child(allow_pm)
        .child(xdata_value_field(
            "muc#roomconfig_enablelogging",
            "boolean",
            bool_value(room.logging_enabled),
        ))
        .child(xdata_value_field(
            "muc#roomconfig_allowregister",
            "boolean",
            bool_value(room.allow_registration),
        ))
        .child(whois_field)
        .child(max_users)
        .child(xdata_value_field(
            "muc#roomconfig_passwordprotectedroom",
            "boolean",
            bool_value(room.password_hash.is_some()),
        ))
        .child(xdata_value_field(
            "muc#roomconfig_roomsecret",
            "text-private",
            "",
        ));
    XmlElement::namespaced("query", "http://jabber.org/protocol/muc#owner")
        .child(form)
        .finish()
}

impl ProtocolSession {
    pub(crate) async fn muc_owner_get(&self, id: &str, iq: Node<'_, '_>) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some((room_jid_owned, room_localpart)) = iq
            .attribute("to")
            .and_then(|value| canonical_local_muc_room(value, &self.muc_domain()))
        else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        let room_jid = room_jid_owned.as_str();
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        };
        if room.configuration_is_expired(chrono::Utc::now()) {
            // The lifecycle helper commits the tombstone and immutable
            // audience outbox atomically.  Cluster workers poll that outbox;
            // never publish the old executable Redis destroy command here.
            let _ = self
                .state
                .muc_service()
                .delete_expired_locked_room(room.id)
                .await?;
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        }
        if room.is_locked() && !room.can_configure_locked_room(full_jid, chrono::Utc::now()) {
            return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
        }
        if self
            .state
            .muc_service()
            .local_affiliation(room.id, user.id)
            .await?
            .as_deref()
            != Some("owner")
        {
            return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
        }
        let whois = if room.non_anonymous {
            "anyone"
        } else {
            "moderators"
        };
        let form = muc_room_configuration_form(&room, whois);
        Ok(Action::Send(iq_result_from(id, room_jid, &form)))
    }

    pub(crate) async fn muc_owner_set(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        query: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some((room_jid_owned, room_localpart)) = iq
            .attribute("to")
            .and_then(|value| canonical_local_muc_room(value, &self.muc_domain()))
        else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        let room_jid = room_jid_owned.as_str();
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        };
        let gated_room_id = room.id;
        let gated_room_epoch = room.room_epoch;
        let mut local_room_guard = if self.state.muc_pg_authority_enabled() {
            None
        } else {
            Some(
                self.state
                    .muc_service()
                    .lock_local_room_mutation(room.id)
                    .await,
            )
        };
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        };
        if room.id != gated_room_id || room.room_epoch != gated_room_epoch {
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        }
        if room.configuration_is_expired(chrono::Utc::now()) {
            let _ = self
                .state
                .muc_service()
                .delete_expired_locked_room(room.id)
                .await?;
            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
        }
        if room.is_locked() && !room.can_configure_locked_room(full_jid, chrono::Utc::now()) {
            return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
        }
        if self
            .state
            .muc_service()
            .local_affiliation(room.id, user.id)
            .await?
            .as_deref()
            != Some("owner")
        {
            return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
        }

        if let Some(destroy) = query.children().find(|node| {
            node.is_element()
                && node.tag_name().name() == "destroy"
                && node.tag_name().namespace() == Some("http://jabber.org/protocol/muc#owner")
        }) {
            let alternate = match destroy.attribute("jid") {
                Some(jid) => match CanonicalJid::parse_bare(jid) {
                    Ok(jid) => Some(jid.to_string()),
                    Err(_) => {
                        return Ok(Action::Send(iq_error_from(id, room_jid, "jid-malformed")));
                    }
                },
                None => None,
            };
            let reason = child_text(destroy, "reason");
            if reason.is_some_and(|value| value.len() > 4096) {
                return Ok(Action::Send(iq_error_from(id, room_jid, "not-acceptable")));
            }
            let occupants = self.state.muc_occupants_for(room_jid);
            let mut cluster_destroy_operation = None;
            if self.state.muc_pg_authority_enabled() {
                self.state.admit_muc_pg_mutation()?;
                let Some(actor) = self.authorized_muc_occupant(room_jid).await? else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                };
                let Some(target) = self
                    .state
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        actor.cluster_epoch,
                        actor.connection_id,
                    )
                    .await?
                else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                };
                let operation_id = uuid::Uuid::new_v4();
                match self
                    .state
                    .muc_service()
                    .destroy_local_cluster_room(
                        operation_id,
                        room.id,
                        room.room_epoch,
                        Some(&target),
                        "local_database",
                        Some(full_jid),
                        alternate.as_deref(),
                        reason,
                    )
                    .await?
                {
                    ClusterMucTransitionOutcome::Applied | ClusterMucTransitionOutcome::Replay => {
                        cluster_destroy_operation = Some(operation_id)
                    }
                    ClusterMucTransitionOutcome::Unauthorized => {
                        return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                    }
                    ClusterMucTransitionOutcome::Stale
                    | ClusterMucTransitionOutcome::Destroyed
                    | ClusterMucTransitionOutcome::Conflict => {
                        return Ok(Action::Send(iq_error_from(id, room_jid, "conflict")));
                    }
                }
            } else {
                self.state.muc_service().delete_room(room.id).await?;
            }
            let mut direct_destroy_deliveries = Vec::new();
            for (_, occupant) in occupants {
                let Some(occupant) = self
                    .state
                    .remove_local_muc_occupant_exact((&occupant).into())
                else {
                    continue;
                };
                let serializable = crate::state::SerializableMucOccupant::from(&occupant);
                self.state.remove_live_muc_membership(&serializable);
                if cluster_destroy_operation.is_none() {
                    let unavailable =
                        muc_destroy_presence(&serializable, alternate.as_deref(), reason);
                    direct_destroy_deliveries.push((occupant, unavailable));
                }
            }
            drop(local_room_guard.take());
            for (occupant, unavailable) in direct_destroy_deliveries {
                let _ = self
                    .state
                    .deliver_to_muc_occupant(&occupant, unavailable)
                    .await;
            }
            if let Some(operation_id) = cluster_destroy_operation {
                if let Err(error) = self.state.wake_committed_muc_operation(operation_id).await {
                    tracing::warn!(?error, room=%room_jid, %operation_id,
                        "room destruction committed; signed wake will be recovered by polling");
                }
            }
            return Ok(Action::Send(iq_result_from(id, room_jid, "")));
        }

        let form = query.children().find(|node| {
            node.is_element()
                && node.tag_name().name() == "x"
                && node.tag_name().namespace() == Some("jabber:x:data")
        });
        if form.is_some_and(|form| form.attribute("type") == Some("cancel")) {
            if room.is_locked()
                && self
                    .state
                    .muc_service()
                    .cancel_locked_room(room.id, full_jid)
                    .await?
            {
                let mut direct_cancel_deliveries = Vec::new();
                for (_, occupant) in self.state.muc_occupants_for(room_jid) {
                    let Some(occupant) = self
                        .state
                        .remove_local_muc_occupant_exact((&occupant).into())
                    else {
                        continue;
                    };
                    let serializable = crate::state::SerializableMucOccupant::from(&occupant);
                    self.state.remove_live_muc_membership(&serializable);
                    self.joined_rooms.remove_if(room_jid, |_, membership| {
                        membership.cluster_epoch == occupant.cluster_epoch
                    });
                    if !self.state.muc_pg_authority_enabled() {
                        let unavailable = muc_destroy_presence(&serializable, None, None);
                        direct_cancel_deliveries.push((occupant, unavailable));
                    }
                }
                drop(local_room_guard.take());
                for (occupant, unavailable) in direct_cancel_deliveries {
                    let _ = self
                        .state
                        .deliver_to_muc_occupant(&occupant, unavailable)
                        .await;
                }
            }
            return Ok(Action::Send(iq_result_from(id, room_jid, "")));
        }
        if let Some(form) = form {
            if !matches!(form.attribute("type"), None | Some("submit"))
                || xdata_field(form, "FORM_TYPE")
                    .is_some_and(|value| value != "http://jabber.org/protocol/muc#roomconfig")
            {
                return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
            }
            let title = xdata_field(form, "muc#roomconfig_roomname")
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(room.title.as_deref().unwrap_or(&room.localpart));
            if title.len() > 255 {
                return Ok(Action::Send(iq_error_from(id, room_jid, "not-acceptable")));
            }
            let description = xdata_field(form, "muc#roomconfig_roomdesc")
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if description.is_some_and(|value| value.len() > 4096) {
                return Ok(Action::Send(iq_error_from(id, room_jid, "not-acceptable")));
            }
            let persistent = match xdata_bool(form, "muc#roomconfig_persistentroom") {
                Ok(value) => value.unwrap_or(room.persistent),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let members_only = match xdata_bool(form, "muc#roomconfig_membersonly") {
                Ok(value) => value.unwrap_or(room.members_only),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let public = match xdata_bool(form, "muc#roomconfig_publicroom") {
                Ok(value) => value.unwrap_or(room.public),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let moderated = match xdata_bool(form, "muc#roomconfig_moderatedroom") {
                Ok(value) => value.unwrap_or(room.moderated),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let non_anonymous = match xdata_field(form, "muc#roomconfig_whois") {
                None => room.non_anonymous,
                Some("anyone") => true,
                Some("moderators") => false,
                Some(_) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let max_occupants = match xdata_field(form, "muc#roomconfig_maxusers") {
                None => room.max_occupants,
                Some(value) => match value.parse::<i32>() {
                    Ok(value @ 2..=1000) => value,
                    _ => return Ok(Action::Send(iq_error_from(id, room_jid, "not-acceptable"))),
                },
            };
            let password_protected = match xdata_bool(form, "muc#roomconfig_passwordprotectedroom")
            {
                Ok(value) => value.unwrap_or(room.password_hash.is_some()),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let allow_subject_change = match xdata_bool(form, "muc#roomconfig_changesubject") {
                Ok(value) => value.unwrap_or(room.allow_subject_change),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let allow_invites = match xdata_bool(form, "muc#roomconfig_allowinvites") {
                Ok(value) => value.unwrap_or(room.allow_invites),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let allow_private_messages = match xdata_field(form, "muc#roomconfig_allowpm") {
                None => room.allow_private_messages,
                Some("anyone") => true,
                Some("none") => false,
                Some(_) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let logging_enabled = match xdata_bool(form, "muc#roomconfig_enablelogging") {
                Ok(value) => value.unwrap_or(room.logging_enabled),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let allow_registration = match xdata_bool(form, "muc#roomconfig_allowregister") {
                Ok(value) => value.unwrap_or(room.allow_registration),
                Err(()) => return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request"))),
            };
            let supplied_room_secret = xdata_field(form, "muc#roomconfig_roomsecret")
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let replacement_password_hash = if password_protected {
                if let Some(secret) = supplied_room_secret {
                    let secret = zeroize::Zeroizing::new(secret.to_owned());
                    // Argon2 is intentionally outside the room writer gate.
                    // Reacquire and validate the exact room/config/owner
                    // snapshot before committing the prepared hash.
                    drop(local_room_guard.take());
                    let password_hash = match crate::password_work::run(move || {
                        crate::services::muc::hash_room_password(&secret)
                    })
                    .await
                    {
                        Ok(hash) => hash,
                        Err(error) if error.is_overloaded() => {
                            return Ok(Action::Send(iq_error_from(
                                id,
                                room_jid,
                                "resource-constraint",
                            )));
                        }
                        Err(crate::password_work::PasswordWorkError::Computation(_)) => {
                            return Ok(Action::Send(iq_error_from(id, room_jid, "not-acceptable")));
                        }
                        Err(error) => {
                            return Err(anyhow::anyhow!(
                                "room password hashing task failed: {error}"
                            ));
                        }
                    };
                    if !self.state.muc_pg_authority_enabled() {
                        local_room_guard = Some(
                            self.state
                                .muc_service()
                                .lock_local_room_mutation(room.id)
                                .await,
                        );
                        let Some(refreshed_room) = self
                            .state
                            .muc_service()
                            .local_room_snapshot(&room_localpart)
                            .await?
                        else {
                            return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
                        };
                        if refreshed_room.room_epoch != room.room_epoch
                            || refreshed_room.config_version != room.config_version
                        {
                            return Ok(Action::Send(iq_error_from(id, room_jid, "conflict")));
                        }
                        if self
                            .state
                            .muc_service()
                            .local_affiliation(room.id, user.id)
                            .await?
                            .as_deref()
                            != Some("owner")
                        {
                            return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                        }
                    }
                    Some(password_hash)
                } else if let Some(existing) = room.password_hash.clone() {
                    Some(existing)
                } else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "bad-request")));
                }
            } else {
                None
            };
            let configuration_outcome = if self.state.muc_pg_authority_enabled() {
                self.state.admit_muc_pg_mutation()?;
                let Some(actor) = self.authorized_muc_occupant(room_jid).await? else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                };
                let Some(actor_target) = self
                    .state
                    .muc_service()
                    .local_cluster_occupancy_target(
                        room.id,
                        actor.cluster_epoch,
                        actor.connection_id,
                    )
                    .await?
                else {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                };
                let operation_id = uuid::Uuid::new_v4();
                let outcome = self
                    .state
                    .muc_service()
                    .update_local_cluster_config(
                        operation_id,
                        room.id,
                        room.room_epoch,
                        room.config_version,
                        &actor_target,
                        &ClusterMucPrincipal::Local {
                            user_id: user.id,
                            bare_jid: bare_jid(full_jid).to_owned(),
                        },
                        full_jid,
                        MucConfigUpdate {
                            title: Some(title),
                            description,
                            persistent,
                            members_only,
                            public,
                            moderated,
                            non_anonymous,
                            max_occupants,
                            password_hash: replacement_password_hash.as_deref(),
                            allow_subject_change,
                            allow_invites,
                            allow_private_messages,
                            logging_enabled,
                            allow_registration,
                        },
                    )
                    .await?;
                match outcome {
                    ClusterMucConfigurationOutcome::Applied
                    | ClusterMucConfigurationOutcome::Replay => {
                        if let Err(error) =
                            self.state.wake_committed_muc_operation(operation_id).await
                        {
                            tracing::warn!(?error, %operation_id, room=%room_jid,
                                "durable MUC config committed; signed wake will be recovered by polling");
                        }
                        MucConfigurationOutcome::Applied
                    }
                    ClusterMucConfigurationOutcome::LockedByAnother
                    | ClusterMucConfigurationOutcome::Unauthorized => {
                        MucConfigurationOutcome::LockedByAnother
                    }
                    ClusterMucConfigurationOutcome::Expired => MucConfigurationOutcome::Expired,
                    ClusterMucConfigurationOutcome::Missing
                    | ClusterMucConfigurationOutcome::Stale
                    | ClusterMucConfigurationOutcome::Destroyed => MucConfigurationOutcome::Missing,
                }
            } else {
                self.state
                    .muc_service()
                    .execute_muc_configuration(MucConfigurationCommand::from(
                        MucConfigurationWrite {
                            room_id: room.id,
                            actor_full_jid: full_jid,
                            config: MucConfigUpdate {
                                title: Some(title),
                                description,
                                persistent,
                                members_only,
                                public,
                                moderated,
                                non_anonymous,
                                max_occupants,
                                password_hash: replacement_password_hash.as_deref(),
                                allow_subject_change,
                                allow_invites,
                                allow_private_messages,
                                logging_enabled,
                                allow_registration,
                            },
                        },
                    ))
                    .await?
                    .outcome
            };
            match configuration_outcome {
                MucConfigurationOutcome::Applied => {}
                MucConfigurationOutcome::LockedByAnother => {
                    return Ok(Action::Send(iq_error_from(id, room_jid, "forbidden")));
                }
                MucConfigurationOutcome::Expired | MucConfigurationOutcome::Missing => {
                    let _ = self
                        .state
                        .muc_service()
                        .delete_expired_locked_room(room.id)
                        .await;
                    return Ok(Action::Send(iq_error_from(id, room_jid, "item-not-found")));
                }
            }
            if self.state.muc_pg_authority_enabled() {
                // The immutable PostgreSQL audience/outbox owns every
                // clustered consequence, including members-only eviction and
                // role/privacy refresh. Returning here prevents the legacy
                // Redis mutation messages below from becoming a second,
                // unauthorised control plane.
                return Ok(Action::Send(iq_result_from(id, room_jid, "")));
            }
            // Complete every authoritative in-memory transition under the
            // room writer gate, but execute Redis/network fan-out only after
            // releasing it. This keeps policy and occupancy linearizable
            // without allowing slow recipients to block unrelated commands
            // which hash to the same fixed shard.
            let actor_nick = self
                .joined_rooms
                .get(room_jid)
                .map(|membership| membership.nick.clone());
            let mut evicted = Vec::new();
            let mut refreshed = Vec::new();
            for (_, occupant) in self.state.muc_occupants_for(room_jid) {
                if members_only && !room.members_only && occupant.affiliation == "none" {
                    if let Some(mut departed) = self.state.remove_local_muc_occupant_exact(
                        crate::state::LocalMucOccupantIdentity::from(&occupant),
                    ) {
                        departed.role = "none".to_owned();
                        let serializable = crate::state::SerializableMucOccupant::from(&departed);
                        self.state.remove_live_muc_membership(&serializable);
                        evicted.push(departed);
                    }
                    continue;
                }

                let moderated_change = (moderated != room.moderated).then_some(moderated);
                let visibility_change =
                    (non_anonymous != room.non_anonymous).then_some(non_anonymous);
                if moderated_change.is_some() || visibility_change.is_some() {
                    if let Some((updated, true)) = self.state.refresh_local_muc_policy_exact(
                        crate::state::LocalMucOccupantIdentity::from(&occupant),
                        moderated_change,
                        visibility_change,
                    ) {
                        refreshed.push(updated);
                    }
                }
            }
            let room_empty_after_policy = self.state.muc_occupants_for(room_jid).is_empty();
            drop(local_room_guard.take());

            let eviction_count = evicted.len();
            for (index, occupant) in evicted.into_iter().enumerate() {
                let serializable = crate::state::SerializableMucOccupant::from(&occupant);
                run_muc_cluster_eviction(
                    &self.state,
                    room_jid,
                    serializable.clone(),
                    322,
                    actor_nick.as_deref(),
                    None,
                    room_empty_after_policy && index + 1 == eviction_count,
                )
                .await;
                for (_, recipient) in self.state.muc_occupants_for(room_jid) {
                    let presence = muc_presence_stanza_with_status(
                        &serializable,
                        &recipient.full_jid,
                        true,
                        false,
                        false,
                        None,
                        occupant.room_non_anonymous || recipient.role == "moderator",
                        Some(322),
                        actor_nick.as_deref(),
                        None,
                    );
                    let _ = self
                        .state
                        .deliver_to_muc_occupant(&recipient, presence)
                        .await;
                }
                let self_presence = muc_presence_stanza_with_status(
                    &serializable,
                    &occupant.full_jid,
                    true,
                    true,
                    false,
                    None,
                    true,
                    Some(322),
                    actor_nick.as_deref(),
                    None,
                );
                let _ = self
                    .state
                    .deliver_to_muc_occupant(&occupant, self_presence)
                    .await;
            }
            for occupant in refreshed {
                let serializable = crate::state::SerializableMucOccupant::from(&occupant);
                if self.state.muc_redis_transport_enabled() {
                    if let Ok(json) = serde_json::to_string(&serializable) {
                        run_muc_cluster_occupant_refresh(
                            &self.state,
                            room_jid,
                            &occupant.nick,
                            json,
                            serializable.clone(),
                        )
                        .await;
                    }
                }
                for (_, recipient) in self.state.muc_occupants_for(room_jid) {
                    let self_presence = occupant.full_jid == recipient.full_jid;
                    let presence = muc_presence_stanza(
                        &serializable,
                        &recipient.full_jid,
                        false,
                        self_presence,
                        false,
                        None,
                        non_anonymous || self_presence || recipient.role == "moderator",
                    );
                    let _ = self
                        .state
                        .deliver_to_muc_occupant(&recipient, presence)
                        .await;
                }
            }
            if non_anonymous != room.non_anonymous {
                let occupants = self.state.muc_occupants_for(room_jid);
                for (_, subject) in &occupants {
                    for (_, recipient) in &occupants {
                        let self_presence = subject.full_jid == recipient.full_jid;
                        let presence = muc_presence_stanza(
                            &crate::state::SerializableMucOccupant::from(subject),
                            &recipient.full_jid,
                            false,
                            self_presence,
                            false,
                            None,
                            non_anonymous || self_presence || recipient.role == "moderator",
                        );
                        let _ = self
                            .state
                            .deliver_to_muc_occupant(recipient, presence)
                            .await;
                    }
                }
            }
            let mut config_statuses = vec!["104"];
            if logging_enabled != room.logging_enabled {
                config_statuses.push(if logging_enabled { "170" } else { "171" });
            }
            if non_anonymous != room.non_anonymous {
                config_statuses.push(if non_anonymous { "172" } else { "173" });
            }
            for (_, recipient) in self.state.muc_occupants_for(room_jid) {
                let mut extension =
                    XmlElement::namespaced("x", "http://jabber.org/protocol/muc#user");
                for code in &config_statuses {
                    extension.push_child(XmlElement::new("status").attr("code", code));
                }
                let notice = XmlElement::namespaced("message", "jabber:client")
                    .attr("from", room_jid)
                    .attr("to", &recipient.full_jid)
                    .attr("type", "groupchat")
                    .child(extension)
                    .finish();
                let _ = self.state.deliver_to_muc_occupant(&recipient, notice).await;
            }
        }
        Ok(Action::Send(iq_result_from(id, room_jid, "")))
    }
}
