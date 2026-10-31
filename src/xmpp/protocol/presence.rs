use super::{Action, ProtocolSession};
use crate::services::xml_util::{set_to, stanza_error};
use crate::xmpp::xml_builder::XmlElement;
use anyhow::Result;
use northstar_roster_application::presence::{PresenceRepository, PresenceService};
use northstar_roster_application::privacy::PrivacyStanzaKind;
use northstar_roster_core::PresenceAccount;
use northstar_roster_xmpp::presence::{
    announced_priority, announced_show, broadcast_presence, deliver_service_messages,
    directed_presence_gate, inject_vcard_avatar_hash, route_directed_presence, PresenceGate,
};
use roxmltree::Node;
use std::sync::{atomic::Ordering, Arc};

mod availability;
mod session;

pub(crate) use northstar_presence_core::directed_recipient_matches;

impl ProtocolSession {
    pub(crate) async fn presence(&mut self, root: Node<'_, '_>, raw: &str) -> Result<Action> {
        if self.authenticated.is_none() {
            return Ok(Action::Send(stanza_error(root, "auth", "not-authorized")));
        }
        let Some(from) = self.full_jid.clone() else {
            return Ok(Action::None);
        };
        let kind = root.attribute("type").unwrap_or("available");
        if let Some(raw_to) = root.attribute("to") {
            let target_jid = match northstar_xmpp_types::jid::CanonicalJid::parse(raw_to) {
                Ok(target) => target,
                Err(_) => return Ok(Action::Send(stanza_error(root, "modify", "jid-malformed"))),
            };
            if let PresenceGate::Closed(reply) =
                directed_presence_gate(&*self, root, &target_jid, kind, &from).await?
            {
                return Ok(reply.map_or(Action::None, Action::Send));
            }
            if let Some(action) = self.try_mix_presence(root, raw).await? {
                return Ok(action);
            }
            if target_jid.resourcepart().is_none()
                && target_jid.localpart().is_none()
                && target_jid.domainpart() == self.pubsub_domain()
            {
                return self.pubsub_presence(kind, &from).await;
            }
            if target_jid.domainpart() == self.muc_domain() {
                if kind == "available" {
                    let user = self.authenticated.as_ref().expect("authenticated session");
                    let avatar_hash = self.state.presence_service().avatar_hash(user.id).await?;
                    let injected = inject_vcard_avatar_hash(raw, root, avatar_hash.as_deref());
                    let document = roxmltree::Document::parse(&injected)?;
                    return self.muc_presence(document.root_element(), &injected).await;
                }
                return self.muc_presence(root, raw).await;
            }
            let reply =
                route_directed_presence(&*self, root, raw, &target_jid, kind, &from).await?;
            return Ok(reply.map_or(Action::None, Action::Send));
        }

        // MIX presence is an account/resource epoch, not a best-effort
        // side effect. Serialize the database projection with the exact
        // in-memory availability/generation transition, then release the
        // per-resource gate before roster, federation and replay work.
        let mix_presence_epoch = Arc::clone(&self.presence.mix_presence_gate)
            .lock_owned()
            .await;
        if !super::mix::mix_presence_route_is_current(
            &self.state,
            &from,
            self.connection_id,
            &self.presence.mix_presence_gate,
            false,
        ) {
            return Ok(Action::None);
        }
        let advertised_mix_capability = self.advertised_mix_capability(root, &from);
        self.forward_presence_to_mix_channels(kind, advertised_mix_capability, raw)
            .await?;
        if matches!(kind, "available" | "unavailable") {
            // A broadcast transition supersedes every earlier directed
            // per-channel suppression for this resource.
            self.presence.mix_presence_fallback_suppressed.clear();
        }
        let user = self.authenticated.as_ref().expect("authenticated session");
        let now_available = kind == "available";
        let was_available = self
            .available
            .as_ref()
            .is_some_and(|available| available.load(Ordering::Acquire));
        let first_available = now_available && !was_available;
        let previous_priority = self.priority.load(Ordering::Relaxed);
        let availability_generation = if was_available != now_available {
            self.presence
                .availability_generation
                .fetch_add(1, Ordering::AcqRel)
                + 1
        } else {
            self.presence
                .availability_generation
                .load(Ordering::Acquire)
        };
        if let Some(available) = &self.available {
            available.store(now_available, Ordering::Release);
        }
        self.commit_caps_observation(root, &from);
        drop(mix_presence_epoch);
        let show = announced_show(root, kind);
        self.show.store(show, Ordering::Relaxed);
        let priority = announced_priority(root, kind);
        self.priority.store(priority, Ordering::Relaxed);
        // XEP-0160 delivers the offline queue on the first available
        // presence whose priority is nonnegative. A resource is allowed
        // to announce priority -1 first and later raise it without an
        // intervening unavailable presence, so availability alone is not
        // sufficient to identify this transition.
        let newly_offline_eligible = northstar_presence_core::offline_replay_became_eligible(
            was_available,
            previous_priority,
            now_available,
            priority,
        );
        // Capture the PostgreSQL clock at the actual XEP-0160
        // availability transition. Roster/presence fanout below may wait
        // on a degraded cluster control plane; a later replay worker must
        // not absorb messages inserted during those waits.
        let offline_replay_cutoff = if newly_offline_eligible && !self.bind2_mam_catchup {
            Some(self.state.presence_service().replay_cutoff().await?)
        } else {
            None
        };

        broadcast_presence(&*self, root, raw, kind, &from, first_available).await?;

        if first_available {
            deliver_service_messages(&*self, &from).await?;
            let replay_service = self.state.replay_service().clone();
            let outbound = self.outbound.clone();
            let active_privacy_list = self
                .privacy_active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            let available = self
                .available
                .as_ref()
                .expect("a bound resource has availability state")
                .clone();
            let generation = self.presence.availability_generation.clone();
            let recipient_id = user.id;
            let full_jid = from.clone();
            let account = format!("{}@{}", user.username, self.state.local_domain());
            let bind2_mam_catchup = self.bind2_mam_catchup;
            let include_offline = priority >= 0 && !bind2_mam_catchup;
            self.defer_after_transport("available-offline-replay", async move {
                super::replay::replay_newly_available_resource(
                    replay_service,
                    outbound,
                    recipient_id,
                    account,
                    full_jid,
                    active_privacy_list,
                    bind2_mam_catchup,
                    include_offline,
                    available,
                    generation,
                    availability_generation,
                    offline_replay_cutoff,
                )
                .await;
            })?;
            // The generic PubSub service advertises last-published, so a
            // subscriber's first broadcast available presence must
            // trigger the same bounded replay as directed presence to the
            // service. The worker starts only after this presence action
            // reaches the transport and applies awaited backpressure.
            let _ = self.pubsub_presence("available", &from).await?;
        } else if newly_offline_eligible && !self.bind2_mam_catchup {
            let replay_service = self.state.replay_service().clone();
            let outbound = self.outbound.clone();
            let active_privacy_list = self
                .privacy_active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            let available = self
                .available
                .as_ref()
                .expect("a bound resource has availability state")
                .clone();
            let generation = self.presence.availability_generation.clone();
            let recipient_id = user.id;
            let full_jid = from.clone();
            let offline_replay_cutoff = offline_replay_cutoff
                .expect("newly eligible legacy replay captured a database cutoff");
            self.defer_after_transport("nonnegative-offline-replay", async move {
                super::replay::replay_newly_nonnegative_resource(
                    replay_service,
                    outbound,
                    recipient_id,
                    full_jid,
                    active_privacy_list,
                    available,
                    generation,
                    availability_generation,
                    offline_replay_cutoff,
                )
                .await;
            })?;
        }
        Ok(Action::None)
    }
}
