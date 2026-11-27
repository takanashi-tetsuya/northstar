// From src/xmpp/protocol/presence.rs.
use crate::presence::{announced_priority, announced_show, PreparedBroadcastPresence};
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use roxmltree::Node;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_BROADCAST_EPOCH: AtomicU64 = AtomicU64::new(1);

pub(super) struct StagedAvailability {
    pub(super) now_available: bool,
    pub(super) was_available: bool,
    pub(super) first_available: bool,
    pub(super) previous_priority: i16,
    pub(super) priority: i16,
    pub(super) availability_generation: u64,
}

pub(super) fn commit_availability<H: SessionHost>(
    session: &mut ProtocolSession<H>,
    root: Node<'_, '_>,
    kind: &str,
    from: &str,
    prepared: &mut PreparedBroadcastPresence,
) -> StagedAvailability {
    let mut last_presence = session
        .last_presence
        .write()
        .unwrap_or_else(|error| error.into_inner());
    let now_available = kind == "available";
    let was_available = session
        .available
        .as_ref()
        .is_some_and(|available| available.load(Ordering::Acquire));
    let first_available = now_available && !was_available;
    let previous_priority = session.priority.load(Ordering::Relaxed);
    let availability_generation = if was_available != now_available {
        session
            .presence
            .availability_generation
            .fetch_add(1, Ordering::AcqRel)
            + 1
    } else {
        session
            .presence
            .availability_generation
            .load(Ordering::Acquire)
    };
    let priority = announced_priority(root, kind);
    let show = announced_show(root, kind);
    session.commit_caps_observation(root, from);
    *last_presence = prepared.cached.take();
    session.show.store(show, Ordering::Relaxed);
    session.priority.store(priority, Ordering::Relaxed);
    session.presence.broadcast_presence_epoch = Some(
        NEXT_BROADCAST_EPOCH
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |epoch| {
                epoch.checked_add(1)
            })
            .expect("local presence epoch exhausted"),
    );
    if let Some(available) = &session.available {
        available.store(now_available, Ordering::Release);
    }
    StagedAvailability {
        now_available,
        was_available,
        first_available,
        previous_priority,
        priority,
        availability_generation,
    }
}
