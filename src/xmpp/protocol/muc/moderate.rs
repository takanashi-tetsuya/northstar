//! XEP-0425 moderated message retraction.

use super::*;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct ModerationRequest {
    pub(super) target_id: uuid::Uuid,
    pub(super) reason: Option<String>,
}

pub(super) fn parse_moderation_request(
    moderate: Node<'_, '_>,
) -> std::result::Result<ModerationRequest, &'static str> {
    if moderate.tag_name().name() != "moderate"
        || moderate.tag_name().namespace() != Some("urn:xmpp:message-moderate:1")
        || moderate
            .attributes()
            .any(|attribute| attribute.namespace().is_some() || attribute.name() != "id")
        || moderate
            .children()
            .filter(|child| child.is_text())
            .any(|child| child.text().is_some_and(|text| !text.trim().is_empty()))
    {
        return Err("bad-request");
    }
    let target = moderate.attribute("id").ok_or("bad-request")?;
    let target_id = uuid::Uuid::parse_str(target).map_err(|_| "item-not-found")?;
    if target_id.to_string() != target {
        // Archive IDs are opaque. Accepting another spelling of the UUID
        // would make an identifier compare equal even though it was never
        // issued on the wire by this room.
        return Err("item-not-found");
    }
    let mut retract_seen = false;
    let mut reason = None;
    for child in moderate.children().filter(|child| child.is_element()) {
        match (child.tag_name().name(), child.tag_name().namespace()) {
            ("retract", Some("urn:xmpp:message-retract:1")) => {
                if retract_seen
                    || child.attributes().len() != 0
                    || child.children().any(|node| node.is_element())
                    || child.text().is_some_and(|text| !text.trim().is_empty())
                {
                    return Err("bad-request");
                }
                retract_seen = true;
            }
            ("reason", Some("urn:xmpp:message-moderate:1")) => {
                if reason.is_some()
                    || child.attributes().len() != 0
                    || child.children().any(|node| node.is_element())
                {
                    return Err("bad-request");
                }
                let value = child.text().unwrap_or_default().trim();
                if value.is_empty() {
                    return Err("bad-request");
                }
                if value.len() > 1_024 {
                    return Err("not-acceptable");
                }
                reason = Some(value.to_owned());
            }
            _ => return Err("bad-request"),
        }
    }
    if !retract_seen {
        return Err("bad-request");
    }
    Ok(ModerationRequest { target_id, reason })
}

impl ProtocolSession {
    /// XEP-0425 moderated message retraction. Only a currently joined room
    /// moderator may act, and only the room-issued XEP-0359 ID is accepted.
    pub(crate) async fn muc_moderate(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        moderate: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(user) = self.authenticated.as_ref() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(full_jid) = self.full_jid.as_deref() else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some((room_jid, room_localpart)) = iq
            .attribute("to")
            .and_then(|value| canonical_local_muc_room(value, &self.muc_domain()))
        else {
            return Ok(Action::Send(iq_error(id, "jid-malformed")));
        };
        let Some(initial_moderator) = self.authorized_muc_occupant(&room_jid).await? else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")));
        };
        if initial_moderator.role != "moderator" {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")));
        }
        let moderation = match parse_moderation_request(moderate) {
            Ok(moderation) => moderation,
            Err(condition) => {
                return Ok(Action::Send(iq_error_from(id, &room_jid, condition)));
            }
        };
        let target_id = moderation.target_id;
        let reason = moderation.reason.as_deref();
        let Some(initial_room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")));
        };
        let local_authority_guard = if self.state.muc_pg_authority_enabled() {
            None
        } else {
            Some(
                self.state
                    .muc_service()
                    .lock_local_room_mutation(initial_room.id)
                    .await,
            )
        };
        let Some(room) = self
            .state
            .muc_service()
            .local_room_snapshot(&room_localpart)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")));
        };
        if room.id != initial_room.id || room.room_epoch != initial_room.room_epoch {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "conflict")));
        }
        let Some(moderator) = self.validated_muc_occupant(&room_jid) else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")));
        };
        if moderator.full_jid != initial_moderator.full_jid
            || moderator.connection_id != initial_moderator.connection_id
            || moderator.cluster_epoch != initial_moderator.cluster_epoch
            || moderator.role != "moderator"
        {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")));
        }
        let current_affiliation = self
            .state
            .muc_service()
            .local_affiliation(room.id, user.id)
            .await?
            .unwrap_or_else(|| "none".to_owned());
        if current_affiliation != moderator.affiliation || current_affiliation == "outcast" {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")));
        }
        let cluster_target = if self.state.muc_pg_authority_enabled() {
            let Some(target) = self
                .state
                .muc_service()
                .local_cluster_occupancy_target(
                    room.id,
                    moderator.cluster_epoch,
                    moderator.connection_id,
                )
                .await?
                .filter(|target| {
                    target.room_epoch == room.room_epoch
                        && target.full_jid == moderator.full_jid
                        && target.nick == moderator.nick
                        && target.connection_uuid == moderator.connection_id
                })
            else {
                return Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")));
            };
            Some(target)
        } else {
            None
        };
        let Some(original) = self
            .state
            .muc_service()
            .local_message_by_id(room.id, target_id)
            .await?
        else {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "item-not-found")));
        };
        let Ok(original_document) = roxmltree::Document::parse(&original.stanza) else {
            tracing::error!(room=%room_jid, stanza_id=%target_id, "archived MUC stanza is not valid XML");
            return Ok(Action::Send(iq_error_from(
                id,
                &room_jid,
                "internal-server-error",
            )));
        };
        let original_root = original_document.root_element();
        if original_root.tag_name().name() != "message"
            || original_root.attribute("type") != Some("groupchat")
            || !is_abuse_rated_message(original_root)
        {
            return Ok(Action::Send(iq_error_from(id, &room_jid, "not-acceptable")));
        }

        let moderator_occupant = format!("{room_jid}/{}", moderator.nick);
        let author_occupant_id = muc_occupant_id(&room.occupant_id_secret, &original.sender_jid);
        let stamp = chrono::Utc::now();
        let action_id = uuid::Uuid::new_v4();
        let target_text = target_id.to_string();
        let moderated = XmlElement::namespaced("moderated", "urn:xmpp:message-moderate:1")
            .attr("by", &moderator_occupant)
            .child(
                XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0")
                    .attr("id", &moderator.occupant_id),
            );
        let mut retracted = XmlElement::namespaced("retracted", "urn:xmpp:message-retract:1")
            .attr("id", action_id)
            .attr("stamp", stamp.format("%Y-%m-%dT%H:%M:%SZ"))
            .child(moderated.clone());
        if let Some(reason) = reason {
            retracted.push_child(XmlElement::new("reason").text(reason.to_owned()));
        }
        let tombstone = XmlElement::namespaced("message", "jabber:client")
            .attr("from", original_root.attribute("from").unwrap_or(&room_jid))
            .attr("to", &room_jid)
            .attr("type", "groupchat")
            .attr("id", original_root.attribute("id").unwrap_or(&target_text))
            .child(
                XmlElement::namespaced("stanza-id", "urn:xmpp:sid:0")
                    .attr("id", target_id)
                    .attr("by", &room_jid),
            )
            .child(
                XmlElement::namespaced("occupant-id", "urn:xmpp:occupant-id:0")
                    .attr("id", &author_occupant_id),
            )
            .child(retracted)
            .finish();
        let mut retract = XmlElement::namespaced("retract", "urn:xmpp:message-retract:1")
            .attr("id", target_id)
            .child(moderated);
        if let Some(reason) = reason {
            retract.push_child(XmlElement::new("reason").text(reason.to_owned()));
        }
        let notice_xml = XmlElement::namespaced("message", "jabber:client")
            .attr("from", &room_jid)
            .attr("to", &room_jid)
            .attr("type", "groupchat")
            .attr("id", action_id)
            .child(retract)
            .finish();
        let moderation_notice = add_stanza_id(
            &set_muc_occupant_id(&notice_xml, &moderator.occupant_id),
            &room_jid,
            action_id,
        );
        let actor_scope = canonical_bare_key(full_jid)?;
        match self
            .state
            .muc_service()
            .execute_muc_retraction(MucRetractionCommand {
                mutation: MucRetractionMutation {
                    action_id,
                    room_id: room.id,
                    target_id,
                    expected_stanza: &original.stanza,
                    actor_scope: &actor_scope,
                    sender_jid: full_jid,
                    nick: &moderator.nick,
                    tombstone: &tombstone,
                    action_stanza: &moderation_notice,
                    reason,
                    kind: MucRetractionKind::Moderator,
                    authority: MucActorAuthority {
                        clustered: self.state.muc_pg_authority_enabled(),
                        expected_room_epoch: room.room_epoch,
                        principal: MucActorPrincipal::Local {
                            user_id: user.id,
                            local_domain: self.state.local_domain().to_owned(),
                        },
                        actor_scope: actor_scope.clone(),
                        full_jid: full_jid.to_owned(),
                        nick: moderator.nick.clone(),
                        occupant_incarnation: moderator.cluster_epoch,
                        connection_uuid: moderator.connection_id,
                        expected_role: moderator.role.clone(),
                        expected_affiliation: current_affiliation.clone(),
                        cluster_target,
                    },
                },
            })
            .await?
            .outcome
        {
            MucRetractionOutcome::Applied => {}
            MucRetractionOutcome::Unauthorized => {
                return Ok(Action::Send(iq_error_from(id, &room_jid, "forbidden")));
            }
            MucRetractionOutcome::Conflict | MucRetractionOutcome::Stale => {
                return Ok(Action::Send(iq_error_from(id, &room_jid, "conflict")));
            }
        }
        run_muc_cluster_fan_out(
            &self.state,
            &room_jid,
            &moderation_notice,
            None,
            "cluster moderation fan-out",
        )
        .await;
        for (_, occupant) in self.state.muc_occupants_for(&room_jid) {
            let delivery = set_to(&moderation_notice, &occupant.full_jid);
            if !self
                .state
                .deliver_to_muc_occupant(&occupant, delivery)
                .await
            {
                record_muc_post_commit_failure(
                    &self.state,
                    &room_jid,
                    &occupant.full_jid,
                    "moderation occupant queue",
                );
            }
        }
        drop(local_authority_guard);
        Ok(Action::Send(iq_result_from(id, &room_jid, "")))
    }
}
