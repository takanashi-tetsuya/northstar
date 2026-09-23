//! Effects for a leased durable SM snapshot. The lease owner finalizes only
//! after this renderer has completed every required post-commit effect.

use super::{
    attr_escape, cluster_listener_sm_muc_teardown::ClusterListenerSmMucTeardown,
    session_cleanup_unavailable::SessionCleanupUnavailable,
    sm_teardown_local::SmTeardownLocalEffects, sm_teardown_muc_projection::SmTeardownMucProjection,
    sm_teardown_session::SmTeardownSessionEffects, AppState,
};
use crate::{cluster::ClusterSmMucTeardown, db};
use std::collections::HashSet;

pub(crate) struct SmTeardownRuntime {
    session: SmTeardownSessionEffects,
    unavailable: SessionCleanupUnavailable,
    local: SmTeardownLocalEffects,
    muc_projection: SmTeardownMucProjection,
    muc_cluster: ClusterSmMucTeardown,
    muc_local: ClusterListenerSmMucTeardown,
}

impl AppState {
    pub(crate) fn sm_teardown_runtime(&self) -> SmTeardownRuntime {
        SmTeardownRuntime {
            session: self.sm_teardown_session_effects(),
            unavailable: self.session_cleanup_unavailable(),
            local: self.sm_teardown_local_effects(),
            muc_projection: self.sm_teardown_muc_projection(),
            muc_cluster: self.sm_teardown_muc_cluster(),
            muc_local: self.cluster_listener_sm_muc_teardown(),
        }
    }
}

impl SmTeardownRuntime {
    pub(crate) async fn teardown_snapshot(
        &self,
        snapshot: &db::SmTeardownSnapshot,
    ) -> anyhow::Result<()> {
        let Ok(full_jid) = crate::jid::canonical_session_key(&snapshot.full_jid) else {
            tracing::warn!(sm_session_id = %snapshot.session_id, "discarded invalid durable SM teardown JID");
            anyhow::bail!("invalid durable SM teardown JID");
        };
        self.session
            .fence_and_notify(&full_jid, snapshot.session_id)
            .await?;

        let mut first_error = None;

        if snapshot.available {
            let unavailable = format!(
                "<presence xmlns='jabber:client' from='{}' type='unavailable'/>",
                attr_escape(&full_jid)
            );
            let mut routed = HashSet::new();
            let roster = self
                .unavailable
                .roster_subscribers(snapshot.user_id)
                .await?;
            for jid in roster {
                if routed.insert(jid.clone()) {
                    if let Err(error) = self
                        .unavailable
                        .route_with_policy(
                            snapshot.user_id,
                            snapshot.active_privacy_list.as_deref(),
                            &full_jid,
                            &unavailable,
                            &jid,
                        )
                        .await
                    {
                        first_error.get_or_insert(error);
                    }
                }
            }

            // Other resources of the same account are part of the same
            // presence session audience, independent of roster privacy.
            if let Err(error) = self
                .unavailable
                .route_siblings_unchecked(&full_jid, &unavailable)
                .await
            {
                first_error.get_or_insert(error);
            }

            for target in &snapshot.directed_presence {
                if routed.insert(target.clone()) {
                    if let Err(error) = self
                        .unavailable
                        .route_with_policy(
                            snapshot.user_id,
                            snapshot.active_privacy_list.as_deref(),
                            &full_jid,
                            &unavailable,
                            target,
                        )
                        .await
                    {
                        first_error.get_or_insert(error);
                    }
                }
            }
        }

        let mut memberships = HashSet::new();
        for membership in &snapshot.joined_rooms {
            let Ok(room_jid) = crate::jid::canonicalize_bare(&membership.room_jid) else {
                continue;
            };
            let Ok(nick) = crate::xmpp::xml_util::prepare_muc_nick(&membership.nick) else {
                continue;
            };
            if !memberships.insert((room_jid.clone(), nick.clone())) {
                continue;
            }
            let occupant = self
                .muc_projection
                .occupant(
                    snapshot.session_id,
                    snapshot.user_id,
                    &full_jid,
                    &room_jid,
                    &nick,
                )
                .await?;
            if let Err(error) = self
                .muc_cluster
                .send_sm_muc_teardown(&room_jid, snapshot.session_id, &occupant)
                .await
            {
                tracing::warn!(?error, %room_jid, "failed to publish clustered SM MUC teardown");
                first_error.get_or_insert(error);
            }
            if let Err(error) = self
                .muc_local
                .teardown_exact(snapshot.session_id, &occupant)
                .await
            {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        self.local.finish_suspended_session(snapshot.session_id);
        Ok(())
    }
}
