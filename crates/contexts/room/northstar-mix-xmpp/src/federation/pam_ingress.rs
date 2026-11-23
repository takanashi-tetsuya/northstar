use super::*;
use northstar_room_application::mix_service::{
    MixReflectionKind, ReflectedMixArchiveOutcome, VerifiedMixReflection,
};

#[allow(clippy::needless_return, clippy::too_many_arguments)]
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
    anyhow::ensure!(
        northstar_room_application::mix_service::valid_stable_participant_id(participant_id),
        "invalid reflected MIX stable participant id"
    );
    anyhow::ensure!(
        from_jid.localpart().is_some(),
        "reflected MIX message requires a channel localpart"
    );
    anyhow::ensure!(
        authenticated_mix_service(from_jid.domainpart(), authenticated_domain),
        "forged federated MIX channel message"
    );
    let channel = from_jid.bare();
    let to_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(to)?;
    let Some(username) = to_jid.localpart() else {
        return Ok(false);
    };
    let Some(user) = state.mix_service().find_enabled_user(username).await? else {
        return Ok(true);
    };
    if !state
        .mix_service()
        .pam_membership(user.id, &channel)
        .await?
        .is_some_and(|membership| pam_membership_receives(&membership, NODE_MESSAGES))
    {
        return Ok(true);
    }
    if state.mix_service().is_blocked(user.id, &channel).await? {
        return Ok(true);
    }
    let kind = verified_target.map_or(MixReflectionKind::Original, |target_id| {
        MixReflectionKind::Retraction {
            target_id,
            source_participant: participant_id,
        }
    });
    let admission = state
        .mix_service()
        .archive_verified_mix_reflection(VerifiedMixReflection {
            personal_archive_id: Uuid::new_v4(),
            owner_id: user.id,
            channel_jid: &channel,
            authoritative_stanza_id,
            stanza: &raw,
            encrypted,
            kind,
        })
        .await?;
    if !matches!(
        admission,
        ReflectedMixArchiveOutcome::Archived(SourceArchiveAdmission::Stored(_))
    ) {
        return Ok(true);
    }
    for (jid, session) in state.session_entries_for(&to_jid.to_string()) {
        if state.session_mix_capability(&jid) == MixSessionCapability::Supported {
            let _ = session.sender().try_send(raw.clone());
        }
    }
    return Ok(true);
}

#[allow(clippy::needless_return)]
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
    if kind == "error" {
        for (_, session) in state.session_entries_for(to) {
            let _ = session.sender().try_send(raw.clone());
        }
        return Ok(true);
    }
    let _ = presence_children(&raw)?;
    if from_jid.resourcepart().is_none() {
        return Ok(false);
    }
    reflected_identity?;
    let (_participant_id, channel_jid) = decode_participant_jid(&from_jid.bare())?;
    let to_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(to)?;
    let Some(username) = to_jid.localpart() else {
        return Ok(false);
    };
    let Some(user) = state.mix_service().find_enabled_user(username).await? else {
        return Ok(true);
    };
    if !state
        .mix_service()
        .pam_membership(user.id, &channel_jid)
        .await?
        .is_some_and(|membership| pam_membership_receives(&membership, NODE_PRESENCE))
        || state
            .mix_service()
            .is_blocked(user.id, &channel_jid)
            .await?
    {
        return Ok(true);
    }
    for (jid, session) in state.session_entries_for(&to_jid.to_string()) {
        if state.session_mix_capability(&jid) == MixSessionCapability::Supported {
            let _ = session.sender().try_send(raw.clone());
        }
    }
    return Ok(true);
}
