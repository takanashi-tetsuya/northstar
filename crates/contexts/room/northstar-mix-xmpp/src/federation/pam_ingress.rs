use super::*;
use northstar_room_application::mix_service::{
    MixReflectionKind, PamDeliveryQuery, ReflectedMixArchiveOutcome, VerifiedMixReflection,
};
use northstar_room_core::mix::{
    MixChannelAddress, MixRealJid, MixRelayAddress, MixStableParticipantId,
};

#[allow(clippy::too_many_arguments)]
pub(super) async fn admit_reflected_message(
    state: &Arc<impl MixHost>,
    authenticated_domain: &str,
    raw: String,
    from: &str,
    to: &str,
    kind: &str,
    encrypted: bool,
    reflected_identity: Result<()>,
    reflected_stanza_id: Result<Uuid>,
    verified_target: Option<Uuid>,
) -> Result<bool> {
    if kind != "groupchat" {
        return Ok(false);
    }
    reflected_identity?;
    let authoritative_stanza_id = reflected_stanza_id?;
    let from_jid = northstar_xmpp_types::jid::CanonicalJid::parse(from)?;
    let participant_id = from_jid
        .resourcepart()
        .context("reflected MIX message requires a stable participant resource")?;
    let participant_id = MixStableParticipantId::parse(participant_id)
        .context("invalid reflected MIX stable participant id")?;
    anyhow::ensure!(
        from_jid.localpart().is_some(),
        "reflected MIX message requires a channel localpart"
    );
    anyhow::ensure!(
        authenticated_mix_service(from_jid.domainpart(), authenticated_domain),
        "forged federated MIX channel message"
    );
    let channel = MixChannelAddress::parse(&from_jid.bare())?;
    let to_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(to)?;
    if to_jid.localpart().is_none() {
        return Ok(false);
    }
    let recipient = MixRealJid::parse(to)?;
    let kind = if let Some(target_id) = verified_target {
        let query = PamDeliveryQuery {
            recipient: &recipient,
            channel: &channel,
        };
        let Some(owner_id) = pam_delivery_account(state.as_ref(), query, NODE_MESSAGES).await?
        else {
            return Ok(true);
        };
        MixReflectionKind::Retraction {
            owner_id,
            target_id,
            source_participant: &participant_id,
        }
    } else {
        MixReflectionKind::Original {
            recipient: &recipient,
        }
    };
    let admission = state
        .mix_service()
        .archive_verified_mix_reflection(VerifiedMixReflection {
            personal_archive_id: Uuid::new_v4(),
            channel: &channel,
            authoritative_stanza_id,
            stanza: &raw,
            encrypted,
            kind,
        })
        .await?;
    let account_id = match kind {
        MixReflectionKind::Original { .. } => admission.stored_original_account(),
        MixReflectionKind::Retraction { owner_id, .. } => matches!(
            admission,
            ReflectedMixArchiveOutcome::Archived(SourceArchiveAdmission::Stored(_))
        )
        .then_some(owner_id),
    };
    if let Some(account_id) = account_id {
        send_reflection(state.as_ref(), account_id, &to_jid, &raw);
    }
    Ok(true)
}

pub(super) async fn handle_reflected_presence(
    state: &Arc<impl MixHost>,
    authenticated_domain: &str,
    raw: String,
    from_jid: &CanonicalJid,
    to: &str,
    kind: &str,
    reflected_identity: Result<()>,
) -> Result<bool> {
    anyhow::ensure!(
        authenticated_mix_service(from_jid.domainpart(), authenticated_domain),
        "federated MIX presence domain is not authenticated"
    );
    let class = ReflectedPresence::classify(kind);
    let (channel, target) = match class {
        ReflectedPresence::Error => {
            let channel = if from_jid.resourcepart().is_some()
                && from_jid
                    .localpart()
                    .is_some_and(|localpart| localpart.contains('#'))
            {
                MixRelayAddress::parse_bare(&from_jid.bare()).map(|relay| relay.channel().clone())
            } else {
                MixChannelAddress::parse(&from_jid.bare())
            };
            let Ok(channel) = channel else {
                return Ok(true);
            };
            (channel, CanonicalJid::parse(to)?)
        }
        ReflectedPresence::Reflection => {
            let _ = presence_children(&raw)?;
            if from_jid.resourcepart().is_none() {
                return Ok(false);
            }
            reflected_identity?;
            let relay = MixRelayAddress::parse_bare(&from_jid.bare())?;
            (relay.channel().clone(), CanonicalJid::parse_bare(to)?)
        }
    };
    if target.localpart().is_none() {
        return Ok(class == ReflectedPresence::Error);
    }
    let recipient = MixRealJid::parse(to)?;
    let query = PamDeliveryQuery {
        recipient: &recipient,
        channel: &channel,
    };
    let Some(account_id) = pam_delivery_account(state.as_ref(), query, NODE_PRESENCE).await? else {
        return Ok(true);
    };
    send_reflection(state.as_ref(), account_id, &target, &raw);
    Ok(true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReflectedPresence {
    Error,
    Reflection,
}

impl ReflectedPresence {
    fn classify(kind: &str) -> Self {
        if kind == "error" {
            Self::Error
        } else {
            Self::Reflection
        }
    }
}

pub(super) async fn pam_delivery_account(
    state: &impl MixHost,
    query: PamDeliveryQuery<'_>,
    node: &str,
) -> Result<Option<Uuid>> {
    Ok(state
        .mix_service()
        .pam_delivery_view(query)
        .await?
        .and_then(|authority| authority.receiving_account(node)))
}

fn send_reflection(state: &impl MixHost, account_id: Uuid, target: &CanonicalJid, raw: &str) {
    for (_, session) in reflection_routes(state, account_id, target) {
        let _ = session.sender().try_send(raw.to_owned());
    }
}

pub(super) fn reflection_routes<'a, H: MixHost>(
    state: &'a H,
    account_id: Uuid,
    target: &CanonicalJid,
) -> impl Iterator<Item = (String, H::Session)> + 'a {
    let exact = target.resourcepart().is_some();
    let target = target.to_string();
    state
        .session_entries_for(&target)
        .into_iter()
        .filter(move |(jid, session)| {
            let matches_target = if exact {
                jid == &target
            } else {
                jid.split_once('/')
                    .is_some_and(|(bare, _)| bare == target.as_str())
            };
            matches_target
                && session.user_id() == account_id
                && state.session_mix_capability(jid) == MixSessionCapability::Supported
        })
}

#[cfg(test)]
mod tests;
