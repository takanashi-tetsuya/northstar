//! Saved direct case validation.

use super::*;

impl Case {
    pub(crate) fn validate(&self) -> Result<(), Rejection> {
        if self.schema != CASE_SCHEMA || self.adapter_contract != ADAPTER_CONTRACT {
            return Err(Rejection::InvalidSchema);
        }
        let count = self.originals.len();
        if !(1..=2).contains(&count)
            || self.case_id.is_empty()
            || self.case_id.len() > 64
            || [
                self.identities.originals.len(),
                self.policy.len(),
                self.admission.len(),
                self.direct_repository.len(),
                self.route.len(),
            ]
            .iter()
            .any(|length| *length != count)
        {
            return Err(Rejection::Limit);
        }
        let mut ids = BTreeSet::new();
        let mut xml_bytes = 0usize;
        let mut items = count;
        for index in 0..count {
            let original = &self.originals[index];
            let identity = &self.identities.originals[index];
            let policy = &self.policy[index];
            let direct = &self.direct_repository[index];
            let route = &self.route[index];
            if [
                identity.frame_id,
                policy.frame_id,
                self.admission[index].frame_id(),
                direct.frame_id,
                route.frame_id,
            ]
            .iter()
            .any(|id| *id != original.frame_id)
                || !ids.insert(identity.frame_id)
                || !ids.insert(identity.sender_stable_id)
                || !ids.insert(identity.recipient_stable_id)
            {
                return Err(Rejection::IdentityBinding);
            }
            xml_bytes = xml_bytes
                .checked_add(original.xml.len())
                .ok_or(Rejection::Limit)?;
            if original.xml.len() > 4096
                || original.sender_full.len() > 1024
                || original.target.len() > 1024
                || policy.domain.len() > 256
                || policy.recipient_bare.len() > 1024
                || chrono::DateTime::parse_from_rfc3339(&original.at_utc).is_err()
            {
                return Err(Rejection::Limit);
            }
            let parsed =
                roxmltree::Document::parse(&original.xml).map_err(|_| Rejection::Malformed)?;
            let root = parsed.root_element();
            if root.tag_name().name() != "message"
                || root
                    .attribute("to")
                    .unwrap_or(crate::state::bare_jid(&original.sender_full))
                    != original.target
                || crate::state::bare_jid(&original.target) != policy.recipient_bare
            {
                return Err(Rejection::IdentityBinding);
            }
            if crate::xmpp::xml_util::is_abuse_rated_message(root)
                != matches!(self.admission[index], Admission::Reserved { .. })
                || crate::xmpp::xml_util::is_encrypted(root) != policy.encrypted
            {
                return Err(Rejection::IdentityBinding);
            }
            if let Admission::Reserved {
                fence,
                requirement,
                begin_commit,
                finalize_commit,
                ..
            } = &self.admission[index]
            {
                if *begin_commit != CommitCut::Complete || *finalize_commit == CommitCut::Pending {
                    return Err(Rejection::IdentityBinding);
                }
                if [
                    unhex(&fence.admission_key_hex)?.len(),
                    unhex(&fence.payload_mac_hex)?.len(),
                    unhex(&fence.dedupe_digest_hex)?.len(),
                ] != [32; 3]
                    || requirement.action != "message"
                    || requirement.notice.len() > 1024
                {
                    return Err(Rejection::Limit);
                }
            }
            if let Transaction::Stored {
                recipient_id,
                delivery_id,
                archive_ids,
                live_claim_id,
            } = &direct.transaction
            {
                let mut expected = Vec::new();
                if policy.sender_archive {
                    expected.push(identity.sender_stable_id);
                }
                if policy.recipient_archive
                    && self.identities.actor_id != self.identities.recipient_id
                {
                    expected.push(identity.recipient_stable_id);
                }
                if *recipient_id != self.identities.recipient_id
                    || *delivery_id != identity.recipient_stable_id
                    || *archive_ids != expected
                    || live_claim_id
                        .get()
                        .is_some_and(|claim| *claim != *delivery_id)
                {
                    return Err(Rejection::IdentityBinding);
                }
            }
            let drop_direct = matches!(&self.drive, Drive::DropDirectCommit { frame_id } if *frame_id == original.frame_id);
            let drop_rearm = matches!(&self.drive, Drive::DropRearm { frame_id } if *frame_id == original.frame_id);
            if (direct.commit == CommitCut::Pending) != drop_direct
                || (route.rearm == Rearm::Pending) != drop_rearm
            {
                return Err(Rejection::IdentityBinding);
            }
            if direct.admitted_mode == Mode::SpoolOnly
                && !(policy.degraded_spool_eligible && policy.spool_privacy_permits)
            {
                return Err(Rejection::IdentityBinding);
            }
            if route.targets.len() > 4
                || route.health_modes.len() > 16
                || route.remote_primary_returns.len() > 4
                || (route.initial_queue == Queue::PrefilledPlain) != route.prefill.get().is_some()
            {
                return Err(Rejection::Limit);
            }
            for target in &route.targets {
                if crate::state::bare_jid(&target.jid) != policy.recipient_bare
                    || Some(&target.connection_id) != self.identities.connection_id.get()
                {
                    return Err(Rejection::IdentityBinding);
                }
            }
            if let Some(item) = route.prefill.get() {
                items += 1;
                let Item::Plain { xml, .. } = item else {
                    return Err(Rejection::IdentityBinding);
                };
                xml_bytes += xml.len();
                if xml.len() > 4096 {
                    return Err(Rejection::Limit);
                }
            }
        }
        if xml_bytes > 16384 || items > 4 {
            return Err(Rejection::Limit);
        }
        match &self.recipient_owner {
            RecipientOwner::None {} => {}
            RecipientOwner::Native { frame_id, native } => {
                let index = self
                    .originals
                    .iter()
                    .position(|original| original.frame_id == *frame_id)
                    .ok_or(Rejection::IdentityBinding)?;
                let Source::C2s {
                    recipient_id,
                    message_id,
                    claim_id,
                } = &native.fence.returned_source
                else {
                    return Err(Rejection::IdentityBinding);
                };
                if Some(&native.connection_id) != self.identities.connection_id.get()
                    || *recipient_id != self.identities.recipient_id
                    || *message_id != self.identities.originals[index].recipient_stable_id
                    || claim_id.get() != self.identities.native_claim_id.get()
                    || claim_id.get().is_none()
                {
                    return Err(Rejection::IdentityBinding);
                }
                let drop_ack = matches!(&self.drive, Drive::DropNativeAckCommit { frame_id: target } if *target == *frame_id);
                if (native.ack.commit == CommitCut::Pending) != drop_ack {
                    return Err(Rejection::IdentityBinding);
                }
                if native.write.chunk_limit == 0
                    || native.write.chunk_limit > 4096
                    || native
                        .write
                        .fail_after_accepted_bytes
                        .get()
                        .is_some_and(|bytes| *bytes != 1)
                {
                    return Err(Rejection::Limit);
                }
            }
            RecipientOwner::Sm {
                frame_id,
                connection_id,
                config,
                extra_items,
                record_replies,
                write,
                ack,
            } => {
                if !self
                    .originals
                    .iter()
                    .any(|original| original.frame_id == *frame_id)
                    || Some(connection_id) != self.identities.connection_id.get()
                    || config.session_id.get() != self.identities.sm_session_id.get()
                    || config.session_id.get().is_none()
                    || !config.enabled
                    || !config.resume_allowed
                    || config.outbound_h != config.acked_h
                    || self.identities.native_claim_id.get().is_some()
                    || config.peer_ip.parse::<std::net::IpAddr>().is_err()
                {
                    return Err(Rejection::IdentityBinding);
                }
                if extra_items.len() > 3
                    || items + extra_items.len() > 4
                    || record_replies.len() != 1 + extra_items.len()
                    || config.governor.max_bytes < config.governor.max_snapshot_bytes
                    || config.governor.max_recovery_bytes < config.governor.max_snapshot_bytes
                    || config.governor.max_recovery_jobs == 0
                    || config.governor.max_snapshot_bytes == 0
                    || write.chunk_limit == 0
                    || write.chunk_limit > 4096
                    || write
                        .fail_after_accepted_bytes
                        .get()
                        .is_some_and(|bytes| *bytes != 1)
                {
                    return Err(Rejection::Limit);
                }
                let mut mix = None;
                for item in extra_items {
                    let xml = match item {
                        Item::Plain { xml, .. } => xml,
                        Item::Mix { xml, source } => {
                            let Source::Mix {
                                delivery_id,
                                lease_token,
                            } = source
                            else {
                                return Err(Rejection::IdentityBinding);
                            };
                            if mix.is_some()
                                || Some(delivery_id) != self.identities.mix_delivery_id.get()
                                || Some(lease_token) != self.identities.mix_old_token.get()
                                || self.identities.mix_new_token.get().is_none()
                            {
                                return Err(Rejection::IdentityBinding);
                            }
                            mix = Some(source.actual());
                            xml
                        }
                    };
                    xml_bytes += xml.len();
                    if xml.len() > 4096 || roxmltree::Document::parse(xml).is_err() {
                        return Err(Rejection::Limit);
                    }
                }
                if xml_bytes > 16384 {
                    return Err(Rejection::Limit);
                }
                if mix.is_none()
                    && [
                        self.identities.mix_delivery_id.get(),
                        self.identities.mix_old_token.get(),
                        self.identities.mix_new_token.get(),
                    ]
                    .iter()
                    .any(Option::is_some)
                {
                    return Err(Rejection::IdentityBinding);
                }
                let drop_sm = matches!(&self.drive, Drive::DropSmCheckpointCommit { frame_id: target } if target == frame_id);
                for (index, reply) in record_replies.iter().enumerate() {
                    if !reply.updated
                        || (reply.commit == CommitCut::Pending) != (drop_sm && index == 0)
                    {
                        return Err(Rejection::IdentityBinding);
                    }
                    let newly_entering = index
                        .checked_sub(1)
                        .and_then(|index| extra_items.get(index))
                        .and_then(|item| match item {
                            Item::Mix { source, .. } => Some(source.actual()),
                            Item::Plain { .. } => None,
                        });
                    if let Some(previous) = newly_entering {
                        if reply.rotations.len() != 1 {
                            return Err(Rejection::IdentityBinding);
                        }
                        let rotation = &reply.rotations[0];
                        let Source::Mix {
                            delivery_id,
                            lease_token,
                        } = &rotation.current
                        else {
                            return Err(Rejection::IdentityBinding);
                        };
                        if rotation.previous.actual() != previous
                            || Some(delivery_id) != self.identities.mix_delivery_id.get()
                            || Some(lease_token) != self.identities.mix_new_token.get()
                        {
                            return Err(Rejection::IdentityBinding);
                        }
                    } else if !reply.rotations.is_empty() {
                        return Err(Rejection::IdentityBinding);
                    }
                }
                if drop_sm && ack.get().is_some() {
                    return Err(Rejection::IdentityBinding);
                }
                if let Some(ack) = ack.get() {
                    // Existing SM-owned MIX suffixes retain their last returned
                    // token. This profile has no re-rotation-on-ACK scenario.
                    if !ack.reply.updated
                        || ack.reply.commit != CommitCut::Complete
                        || !ack.reply.rotations.is_empty()
                    {
                        return Err(Rejection::IdentityBinding);
                    }
                }
            }
            RecipientOwner::NativeReplacement {
                frame_id,
                initial_row,
                old,
                replacement,
                replacement_claim_id,
            } => {
                if self.originals.len() != 1
                    || self.originals[0].frame_id != *frame_id
                    || !matches!(&self.drive, Drive::ReplaceBeforeOldAckRead { frame_id: target } if target == frame_id)
                    || Some(&old.connection_id) != self.identities.connection_id.get()
                    || Some(&replacement.connection_id)
                        != self.identities.replacement_connection_id.get()
                    || Some(replacement_claim_id) != self.identities.replacement_claim_id.get()
                    || old.connection_id == replacement.connection_id
                {
                    return Err(Rejection::IdentityBinding);
                }
                let Transaction::Stored {
                    recipient_id,
                    delivery_id,
                    live_claim_id,
                    ..
                } = &self.direct_repository[0].transaction
                else {
                    return Err(Rejection::IdentityBinding);
                };
                let expected_initial = northstar_delivery_core::TransportOwnershipSource::C2s(
                    northstar_delivery_core::DurableDelivery {
                        recipient_id: recipient_id.0,
                        message_id: delivery_id.0,
                        claim_id: live_claim_id.get().map(|id| id.0),
                    },
                );
                if initial_row.actual() != expected_initial
                    || !self.policy[0].clustered
                    || live_claim_id.get() != Some(delivery_id)
                    || self.direct_repository[0].admitted_mode != Mode::Live
                    || self.direct_repository[0].commit != CommitCut::Complete
                    || !matches!(
                        self.direct_repository[0].completion,
                        Completion::Return { mode: Mode::Live }
                    )
                {
                    return Err(Rejection::IdentityBinding);
                }
                for (native, claim) in [
                    (old, self.identities.native_claim_id.get()),
                    (replacement, Some(replacement_claim_id)),
                ] {
                    let Source::C2s {
                        recipient_id: returned_recipient,
                        message_id,
                        claim_id,
                    } = &native.fence.returned_source
                    else {
                        return Err(Rejection::IdentityBinding);
                    };
                    if returned_recipient != recipient_id
                        || message_id != delivery_id
                        || claim_id.get() != claim
                        || claim.is_none()
                        || native.ack.commit != CommitCut::Complete
                        || native.write.flush != Flush::Ok
                        || native.write.fail_after_accepted_bytes.get().is_some()
                    {
                        return Err(Rejection::IdentityBinding);
                    }
                    if native.write.chunk_limit == 0 || native.write.chunk_limit > 4096 {
                        return Err(Rejection::Limit);
                    }
                }
                if self.identities.native_claim_id.get() == Some(replacement_claim_id) {
                    return Err(Rejection::IdentityBinding);
                }
            }
            RecipientOwner::Bosh { .. } => {
                crate::bosh::validate_saved_case(self, items, xml_bytes)?
            }
        }
        if (!matches!(self.recipient_owner, RecipientOwner::Bosh { .. })
            && self.identities.bosh_session_id.get().is_some())
            || (!matches!(
                self.recipient_owner,
                RecipientOwner::NativeReplacement { .. }
            ) && [
                self.identities.replacement_connection_id.get(),
                self.identities.replacement_claim_id.get(),
            ]
            .iter()
            .any(Option::is_some))
            || (!matches!(
                self.recipient_owner,
                RecipientOwner::Sm { .. } | RecipientOwner::Bosh { .. }
            ) && [
                self.identities.sm_session_id.get(),
                self.identities.mix_delivery_id.get(),
                self.identities.mix_old_token.get(),
                self.identities.mix_new_token.get(),
            ]
            .iter()
            .any(Option::is_some))
        {
            return Err(Rejection::IdentityBinding);
        }
        if matches!(self.recipient_owner, RecipientOwner::None {})
            && self.identities.native_claim_id.get().is_some()
        {
            return Err(Rejection::IdentityBinding);
        }
        match &self.drive {
            Drive::Complete {} => {}
            Drive::DropDirectCommit { frame_id }
            | Drive::DropRearm { frame_id }
            | Drive::DropNativeAckCommit { frame_id } => {
                if !self
                    .originals
                    .iter()
                    .any(|original| original.frame_id == *frame_id)
                {
                    return Err(Rejection::IdentityBinding);
                }
                if matches!(self.drive, Drive::DropNativeAckCommit { .. })
                    && !matches!(&self.recipient_owner, RecipientOwner::Native { frame_id: owner_frame, .. } if owner_frame == frame_id)
                {
                    return Err(Rejection::IdentityBinding);
                }
            }
            Drive::DropSmCheckpointCommit { frame_id } => {
                if !matches!(&self.recipient_owner, RecipientOwner::Sm { frame_id: owner, .. } if owner == frame_id)
                {
                    return Err(Rejection::IdentityBinding);
                }
            }
            Drive::ReplaceBeforeOldAckRead { frame_id } => {
                if !matches!(&self.recipient_owner, RecipientOwner::NativeReplacement { frame_id: owner, .. } if owner == frame_id)
                {
                    return Err(Rejection::IdentityBinding);
                }
            }
            Drive::DropBoshBindCommit { frame_id } => {
                if !matches!(&self.recipient_owner, RecipientOwner::Bosh { frame_id: owner, .. } if owner == frame_id)
                {
                    return Err(Rejection::IdentityBinding);
                }
            }
        }
        Ok(())
    }
}
