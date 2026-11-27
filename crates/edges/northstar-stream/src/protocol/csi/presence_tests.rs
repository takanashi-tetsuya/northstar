use super::{defer_stanza, CSI_EVICTIONS};
use crate::outbound::{OutboundItem, PresenceDelivery};
use northstar_xep_0352::{CsiPolicyConfig, DeferredQueue};
use std::sync::atomic::Ordering;

#[test]
fn csi_reports_probe_and_status_eviction_at_the_edge() {
    let mut queue = DeferredQueue::new(CsiPolicyConfig {
        max_deferred_stanzas: 1,
        ..CsiPolicyConfig::default()
    });
    let mut status = OutboundItem::plain(
        "<presence from='alice@example.test/phone'><show>away</show></presence>".into(),
    );
    status.presence_delivery = Some(PresenceDelivery::Status {
        source_epoch: Some(1),
    });
    let mut probe = OutboundItem::plain("<presence from='alice@example.test/phone'/>".into());
    probe.presence_delivery = Some(PresenceDelivery::ProbeReply);
    let before = CSI_EVICTIONS.load(Ordering::Relaxed);
    assert!(defer_stanza(&mut queue, status).is_none());
    assert!(defer_stanza(&mut queue, probe.clone()).is_none());
    assert!(CSI_EVICTIONS.load(Ordering::Relaxed) > before);
    assert_eq!(queue.drain_all()[0].stanza, probe.stanza);
}
