use northstar_room_core::{MucRequestFacts, MucTimeSources};
use uuid::Uuid;

pub(crate) fn prepare_join_ids(facts: MucRequestFacts, sources: &MucTimeSources) -> (Uuid, Uuid) {
    (facts.id, sources.new_uuid())
}

#[cfg(test)]
mod tests;
