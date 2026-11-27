//! Effects for a leased durable SM snapshot. The lease owner finalizes only
//! after this renderer has completed every required post-commit effect.

use super::unavailable::{SessionCleanupUnavailable, SessionCleanupUnavailablePorts};
use crate::local_routes::sm_teardown::SmTeardownLocalEffects;
use northstar_room_application::muc_service::SerializableMucOccupant;
use northstar_session_application::sm_teardown_presence::{
    SmTeardownPresenceRepository, TerminalOwner, TerminalPresenceRepository,
    TerminalPresenceRequest,
};
use northstar_session_core::SmMucMembership;
use std::{collections::HashSet, future::Future};
use uuid::Uuid;

/// The committed state needed to render teardown, borrowed from its lease owner.
pub struct SmTeardownSnapshot<'a> {
    pub session_id: Uuid,
    pub presence_deadline: std::time::Instant,
    pub user_id: Uuid,
    pub full_jid: &'a str,
    pub available: bool,
    pub active_privacy_list: Option<&'a str>,
    pub joined_rooms: &'a [SmMucMembership],
    pub directed_presence: &'a [String],
}

/// Exact session fencing and MUC effects supplied by the node.
pub trait SmTeardownPorts: Send + Sync {
    fn fence_and_notify(
        &self,
        full_jid: &str,
        sm_session_id: Uuid,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    fn occupant(
        &self,
        sm_session_id: Uuid,
        user_id: Uuid,
        full_jid: &str,
        room_jid: &str,
        nick: &str,
    ) -> impl Future<Output = anyhow::Result<SerializableMucOccupant>> + Send;

    fn send_sm_muc_teardown(
        &self,
        room_jid: &str,
        sm_session_id: Uuid,
        occupant: &SerializableMucOccupant,
    ) -> impl Future<Output = anyhow::Result<()>> + Send;

    fn teardown_exact(
        &self,
        sm_session_id: Uuid,
        occupant: &SerializableMucOccupant,
    ) -> impl Future<Output = anyhow::Result<usize>> + Send;
}

pub struct SmTeardownRuntime<R, U, P> {
    unavailable: SessionCleanupUnavailable<R, U>,
    local: SmTeardownLocalEffects,
    ports: P,
}

impl<R, U, P> SmTeardownRuntime<R, U, P>
where
    R: SmTeardownPresenceRepository + TerminalPresenceRepository,
    U: SessionCleanupUnavailablePorts,
    P: SmTeardownPorts,
{
    pub fn new(
        unavailable: SessionCleanupUnavailable<R, U>,
        local: SmTeardownLocalEffects,
        ports: P,
    ) -> Self {
        Self {
            unavailable,
            local,
            ports,
        }
    }

    pub async fn teardown_snapshot(&self, snapshot: &SmTeardownSnapshot<'_>) -> anyhow::Result<()> {
        let Ok(full_jid) = northstar_xmpp_types::jid::canonical_session_key(snapshot.full_jid)
        else {
            tracing::warn!(sm_session_id = %snapshot.session_id, "discarded invalid durable SM teardown JID");
            anyhow::bail!("invalid durable SM teardown JID");
        };
        let audience = self
            .unavailable
            .capture(TerminalPresenceRequest {
                owner_id: snapshot.user_id,
                owner: TerminalOwner::Suspended {
                    session_id: snapshot.session_id,
                    deadline: snapshot.presence_deadline,
                },
                full_jid: &full_jid,
                active_privacy_list: snapshot.active_privacy_list,
                available: snapshot.available,
                directed: snapshot.directed_presence,
                local_domain: "",
            })
            .await;
        self.ports
            .fence_and_notify(&full_jid, snapshot.session_id)
            .await?;

        let mut first_error = None;

        let mut memberships = HashSet::new();
        for membership in snapshot.joined_rooms {
            let Ok(room_jid) = northstar_xmpp_types::jid::canonicalize_bare(&membership.room_jid)
            else {
                continue;
            };
            let Ok(nick) = northstar_room_core::stanza::prepare_muc_nick(&membership.nick) else {
                continue;
            };
            if !memberships.insert((room_jid.clone(), nick.clone())) {
                continue;
            }
            let occupant = self
                .ports
                .occupant(
                    snapshot.session_id,
                    snapshot.user_id,
                    &full_jid,
                    &room_jid,
                    &nick,
                )
                .await?;
            if let Err(error) = self
                .ports
                .send_sm_muc_teardown(&room_jid, snapshot.session_id, &occupant)
                .await
            {
                tracing::warn!(?error, %room_jid, "failed to publish clustered SM MUC teardown");
                first_error.get_or_insert(error);
            }
            if let Err(error) = self
                .ports
                .teardown_exact(snapshot.session_id, &occupant)
                .await
            {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        // Complete required durable effects first so their retry cannot
        // resend presence that already reached a transport.
        let presence = match audience {
            Ok(Some(audience)) => self.unavailable.publish(audience).await,
            Ok(None) => Ok(()),
            Err(error) => Err(error),
        };
        if let Err(error) = presence {
            tracing::warn!(?error, sm_session_id = %snapshot.session_id, "SM teardown presence requires refresh");
        }
        self.local.finish_suspended_session(snapshot.session_id);
        Ok(())
    }
}
