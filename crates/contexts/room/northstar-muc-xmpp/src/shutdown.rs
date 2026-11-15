//! XEP-0045 system-shutdown notices to this node's live MUC endpoints.

use northstar_federation_core::FederationRoute;
use northstar_room_application::cluster_muc_receipt_claim::ClusterMucReceiptClaimRepository;
use northstar_room_application::muc_delivery::MucDeliveryRepository;
use northstar_room_application::muc_service::SerializableMucOccupant;
use northstar_room_core::ClusterMucOutboxDelivery;
use northstar_stream::local_routes::muc::MucOccupantEndpoint;
use northstar_stream::muc_delivery::MucDeliveryContext;

/// Fixed concurrency keeps one slow transport from blocking other shutdown
/// notices without spawning tasks or increasing the root's total deadline.
pub async fn count_shutdown_notification_completions<I, F>(notifications: I) -> usize
where
    I: IntoIterator<Item = F>,
    F: std::future::Future<Output = bool>,
{
    use futures::StreamExt;
    futures::stream::iter(notifications)
        .buffer_unordered(16)
        .fold(0, |confirmed, written| async move {
            confirmed + usize::from(written)
        })
        .await
}

/// Give live locally-owned MUC endpoints XEP-0045 system-shutdown status.
/// Count only completed TCP/WS writes or BOSH client response ACKs; SM
/// persistence alone cannot satisfy this process-local completion. The
/// root supervises the whole loop under one bounded, cancellable window.
pub async fn notify_muc_system_shutdown<R, C, F>(delivery: &MucDeliveryContext<R, C, F>) -> usize
where
    R: MucDeliveryRepository,
    C: ClusterMucReceiptClaimRepository<Delivery = ClusterMucOutboxDelivery>,
    F: FederationRoute,
{
    let occupants = delivery
        .muc_occupants
        .iter()
        .filter(|entry| matches!(&entry.value().endpoint, MucOccupantEndpoint::Local(_)))
        .map(|entry| entry.value().clone())
        .collect::<Vec<_>>();
    count_shutdown_notification_completions(occupants.into_iter().map(|occupant| async move {
        let serialized = SerializableMucOccupant::from(&occupant);
        let stanza = northstar_room_core::stanza::muc_presence_stanza_with_status(
            &serialized,
            &occupant.full_jid,
            true,
            true,
            false,
            None,
            true,
            Some(332),
            None,
            None,
        );
        let (receipt, mut received) = tokio::sync::mpsc::unbounded_channel();
        delivery
            .deliver_to_muc_occupant_inner(&occupant, stanza, None, Some(receipt))
            .await
            && received.recv().await.is_some()
    }))
    .await
}
