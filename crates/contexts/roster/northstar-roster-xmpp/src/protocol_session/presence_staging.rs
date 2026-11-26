// From src/xmpp/protocol/presence.rs.
use crate::presence::{announced_priority, announced_show};
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use roxmltree::Node;
use std::sync::atomic::Ordering;

pub(super) struct StagedAvailability {
    pub(super) now_available: bool,
    pub(super) was_available: bool,
    pub(super) first_available: bool,
    pub(super) previous_priority: i16,
    pub(super) availability_generation: u64,
}

pub(super) fn stage_availability<H: SessionHost>(
    session: &ProtocolSession<H>,
    root: Node<'_, '_>,
    kind: &str,
    from: &str,
) -> StagedAvailability {
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
    if let Some(available) = &session.available {
        available.store(now_available, Ordering::Release);
    }
    session.commit_caps_observation(root, from);
    StagedAvailability {
        now_available,
        was_available,
        first_available,
        previous_priority,
        availability_generation,
    }
}

pub(super) fn stage_show_and_priority<H: SessionHost>(
    session: &ProtocolSession<H>,
    root: Node<'_, '_>,
    kind: &str,
) -> i16 {
    let show = announced_show(root, kind);
    session.show.store(show, Ordering::Relaxed);
    let priority = announced_priority(root, kind);
    session.priority.store(priority, Ordering::Relaxed);
    priority
}
