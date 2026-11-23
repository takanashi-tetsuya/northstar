//! Federated MUC message handling for remote room actors.

use super::*;
use crate::ports::Occupant;
use northstar_room_core::MucRequestFacts;
use northstar_xmpp_types::jid::CanonicalJid;

pub(crate) mod archive_eligibility;
mod decline;
mod groupchat;
mod invitation;
mod private;
mod validate;
mod voice;

enum MessageStep<T> {
    Next(T),
    Done(Option<String>),
}

struct MessageAddress<'a> {
    from: &'a str,
    to: &'a str,
    actor_full_jid: String,
    actor_bare_jid: String,
    to_jid: CanonicalJid,
    room_jid: String,
    facts: MucRequestFacts,
}

struct RoomOccupancy<S: MucHost> {
    own: Occupant<S>,
    room: MucRoom,
}

/// Handle messages from a remote room actor. Authorization is bound to the
/// occupant endpoint, not merely to a claimed room nickname.
pub fn federated_muc_message<'a>(
    state: &'a impl MucHost,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
    root: Node<'_, '_>,
    raw: &str,
) -> impl std::future::Future<Output = Result<Option<String>>> + Send + 'a {
    let authenticated_domain = authenticated_domain.to_owned();
    let facts = state.muc_time_sources().prepare_request();
    let request =
        FederatedMessageRequest::from_node(root, raw, state.validate_routed_message(root));
    async move {
        federated_muc_message_owned(state, &authenticated_domain, connection_id, request, facts)
            .await
    }
}

async fn federated_muc_message_owned(
    state: &impl MucHost,
    authenticated_domain: &str,
    connection_id: uuid::Uuid,
    request: FederatedMessageRequest,
    facts: MucRequestFacts,
) -> Result<Option<String>> {
    let address = match validate::validate_message(state, authenticated_domain, &request, facts)? {
        MessageStep::Next(address) => address,
        MessageStep::Done(value) => return Ok(value),
    };
    if let MessageStep::Done(value) =
        decline::handle_invitation_decline(state, &request, &address).await?
    {
        return Ok(value);
    }
    if let MessageStep::Done(value) =
        validate::dispatch_addressed(state, authenticated_domain, &request, &address).await?
    {
        return Ok(value);
    }
    let validate::OccupantLookup {
        occupancy,
        voice_form,
    } = match validate::lookup_occupant(state, authenticated_domain, &request, &address).await? {
        MessageStep::Next(lookup) => lookup,
        MessageStep::Done(value) => return Ok(value),
    };
    if let MessageStep::Done(value) = voice::handle_voice_form(
        state,
        authenticated_domain,
        &connection_id,
        &request,
        &address,
        &occupancy,
        voice_form,
    )
    .await?
    {
        return Ok(value);
    }
    if let MessageStep::Done(value) = invitation::handle_non_groupchat(
        state,
        authenticated_domain,
        &connection_id,
        &request,
        &address,
        &occupancy,
    )
    .await?
    {
        return Ok(value);
    }
    let groupchat::GroupchatAuthority {
        local_authority_guard,
        occupancy: refreshed,
        cluster_target,
    } = match groupchat::recheck_groupchat_authority(
        state,
        authenticated_domain,
        &request,
        &address,
        &occupancy,
    )
    .await?
    {
        MessageStep::Next(authority) => authority,
        MessageStep::Done(value) => return Ok(value),
    };
    let (mut reflection, admission) = match groupchat::prepare_groupchat(
        state,
        authenticated_domain,
        &request,
        &address,
        &refreshed,
        cluster_target,
    )? {
        MessageStep::Next(prepared) => prepared,
        MessageStep::Done(value) => return Ok(value),
    };
    if let MessageStep::Done(value) = groupchat::admit_groupchat(
        state,
        &connection_id,
        &request,
        &address,
        &refreshed,
        &mut reflection,
        admission,
    )
    .await?
    {
        return Ok(value);
    }
    groupchat::fan_out_groupchat(
        state,
        &address,
        &refreshed,
        &reflection,
        local_authority_guard,
    )
    .await
}
