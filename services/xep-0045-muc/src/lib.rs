//! XEP-0045 Multi-User Chat (MUC) microservice.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 6, 7, 8, 19.2, 20.2, Appendix B.1).

use foundation_contracts::adapters::common::ErrorDetail;
use foundation_eventing::memory::InMemoryOutbox;
use foundation_eventing::OutboxEvent;
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Affiliation {
    Owner,
    Admin,
    Member,
    None,
    Outcast,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    Moderator,
    Participant,
    Visitor,
    None,
}

#[derive(Debug, Clone)]
pub struct Occupant {
    pub full_jid: String,
    pub bare_jid: String,
    pub nick: String,
    pub affiliation: Affiliation,
    pub role: Role,
}

pub struct RoomActor {
    pub room_jid: String,
    pub occupants: HashMap<String, Occupant>, // nick -> Occupant
    pub affiliations: HashMap<String, Affiliation>, // bare_jid -> Affiliation
    pub message_sequence: u64,
}

impl RoomActor {
    pub fn new(room_jid: impl Into<String>, creator_bare_jid: impl Into<String>) -> Self {
        let mut affiliations = HashMap::new();
        affiliations.insert(creator_bare_jid.into(), Affiliation::Owner);
        Self {
            room_jid: room_jid.into(),
            occupants: HashMap::new(),
            affiliations,
            message_sequence: 0,
        }
    }
}

pub struct MucService {
    rooms: RwLock<HashMap<String, RoomActor>>, // room_jid -> RoomActor
    outbox: InMemoryOutbox,
}

impl Default for MucService {
    fn default() -> Self {
        Self::new()
    }
}

impl MucService {
    pub fn new() -> Self {
        Self {
            rooms: RwLock::new(HashMap::new()),
            outbox: InMemoryOutbox::new(),
        }
    }

    pub fn join_room(
        &self,
        room_jid: &str,
        full_jid: &str,
        bare_jid: &str,
        nick: &str,
    ) -> Result<Occupant, ErrorDetail> {
        let mut rooms = self.rooms.write().unwrap();
        let room = rooms
            .entry(room_jid.to_string())
            .or_insert_with(|| RoomActor::new(room_jid, bare_jid));

        // Check if user is outcast
        if let Some(Affiliation::Outcast) = room.affiliations.get(bare_jid) {
            return Err(ErrorDetail::new(
                "NOT_AUTHORIZED",
                "User is banned from this room",
            ));
        }

        // Check nick conflict
        if let Some(existing) = room.occupants.get(nick) {
            if existing.full_jid != full_jid {
                return Err(ErrorDetail::new(
                    "CONFLICT",
                    "Nick is already in use by another occupant",
                ));
            }
        }

        let affiliation = room
            .affiliations
            .get(bare_jid)
            .cloned()
            .unwrap_or(Affiliation::None);

        let role = match affiliation {
            Affiliation::Owner | Affiliation::Admin => Role::Moderator,
            Affiliation::Member | Affiliation::None => Role::Participant,
            Affiliation::Outcast => Role::None,
        };

        let occupant = Occupant {
            full_jid: full_jid.to_string(),
            bare_jid: bare_jid.to_string(),
            nick: nick.to_string(),
            affiliation,
            role,
        };

        room.occupants.insert(nick.to_string(), occupant.clone());

        // Stage membership event in Outbox
        let event = OutboxEvent::new(
            "room",
            room_jid,
            room.message_sequence,
            "muc.membership.joined.v1",
            format!("{bare_jid}:{nick}").into_bytes(),
        );
        self.outbox.stage(event);

        Ok(occupant)
    }

    pub fn leave_room(&self, room_jid: &str, nick: &str) -> bool {
        let mut rooms = self.rooms.write().unwrap();
        if let Some(room) = rooms.get_mut(room_jid) {
            if room.occupants.remove(nick).is_some() {
                let event = OutboxEvent::new(
                    "room",
                    room_jid,
                    room.message_sequence,
                    "muc.membership.left.v1",
                    nick.as_bytes().to_vec(),
                );
                self.outbox.stage(event);
                return true;
            }
        }
        false
    }

    pub fn broadcast_message(
        &self,
        room_jid: &str,
        sender_nick: &str,
        stanza: &[u8],
    ) -> Result<u64, ErrorDetail> {
        let mut rooms = self.rooms.write().unwrap();
        let Some(room) = rooms.get_mut(room_jid) else {
            return Err(ErrorDetail::new("ITEM_NOT_FOUND", "Room does not exist"));
        };

        let Some(occupant) = room.occupants.get(sender_nick) else {
            return Err(ErrorDetail::new(
                "NOT_AUTHORIZED",
                "Sender is not an occupant in the room",
            ));
        };

        if occupant.role == Role::Visitor {
            return Err(ErrorDetail::new(
                "NOT_ALLOWED",
                "Visitors cannot send messages to this room",
            ));
        }

        room.message_sequence += 1;
        let seq = room.message_sequence;

        let event = OutboxEvent::new(
            "room",
            room_jid,
            seq,
            "muc.message.broadcast.v1",
            stanza.to_vec(),
        );
        self.outbox.stage(event);

        Ok(seq)
    }

    pub fn occupant_count(&self, room_jid: &str) -> usize {
        self.rooms
            .read()
            .unwrap()
            .get(room_jid)
            .map(|r| r.occupants.len())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn muc_room_join_broadcast_leave_lifecycle() {
        let muc = MucService::new();
        let room = "northstar-chat@muc.example.com";

        // 1. First user joins as creator/owner
        let alice = muc.join_room(
            room,
            "alice@example.com/phone",
            "alice@example.com",
            "Alice",
        );
        assert!(alice.is_ok());
        let alice_occ = alice.unwrap();
        assert_eq!(alice_occ.affiliation, Affiliation::Owner);
        assert_eq!(alice_occ.role, Role::Moderator);

        // 2. Second user joins
        let bob = muc.join_room(room, "bob@example.com/desktop", "bob@example.com", "Bob");
        assert!(bob.is_ok());
        assert_eq!(muc.occupant_count(room), 2);

        // 3. Nick collision fails
        let eve = muc.join_room(room, "eve@example.com/laptop", "eve@example.com", "Alice");
        assert!(eve.is_err());
        assert_eq!(eve.unwrap_err().code, "CONFLICT");

        // 4. Broadcast message advances room sequence
        let seq = muc.broadcast_message(room, "Alice", b"<message>Hello room</message>");
        assert_eq!(seq.unwrap(), 1);

        // 5. Leave room
        assert!(muc.leave_room(room, "Bob"));
        assert_eq!(muc.occupant_count(room), 1);
    }
}
