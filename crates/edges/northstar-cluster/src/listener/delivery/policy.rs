use super::{active_privacy_list, ClusterAdapters, ClusterListenerMessagePolicy};
use northstar_stream::local_routes::session::OnlineSession;

pub(super) async fn permits_direct_delivery<A: ClusterAdapters>(
    message_policy: &ClusterListenerMessagePolicy<A>,
    session: &OnlineSession,
    jid: &str,
    privacy_peer_kind: &Option<(String, northstar_xep_0016::PrivacyStanzaKind)>,
    blocklist_requested_only: bool,
    roster_requested_only: bool,
    privacy_requested_only: bool,
) -> bool {
    if !blocklist_requested_only && !roster_requested_only && !privacy_requested_only {
        if let Some((peer, kind)) = privacy_peer_kind.as_ref() {
            match message_policy
                .privacy_allows_session(
                    session.user_id,
                    session.connection_id,
                    active_privacy_list(&session.privacy_active).as_deref(),
                    peer,
                    *kind,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => return false,
                Err(error) => {
                    // Delivery policy reads are fail closed.
                    // A database outage must never turn a deny
                    // list into an allow list on another node.
                    tracing::warn!(?error, %jid, "privacy policy lookup failed during clustered delivery");
                    return false;
                }
            }
        }
    }
    true
}
