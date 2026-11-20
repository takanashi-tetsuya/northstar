use super::*;
use northstar_archive_core::{
    FederatedMamAdmissionOutcome, FederatedMamMetadataCommand, FederatedMamStreamPage,
    FederatedMamStreamRequest, MamMetadataResult, MamRoomAccessOutcome, MamRoomReadAuthority,
};
use northstar_delivery_core::{node_delivery::NodeDeliveryReceipt, DurableDelivery};
use northstar_message_core::{DirectPostCommitMode, OfflineDeliveryLimits};
use northstar_room_application::mix_service::MixService;
use northstar_room_application::muc_service::MucService;
use northstar_room_core::occupancy::*;
use northstar_room_core::telemetry::{FederatedMucTelemetry, MucTelemetry};
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::outbound::OutboundSender;
use std::collections::{HashMap, HashSet};

macro_rules! unused_ports {
    ($(fn $name:ident(&self $(, $arg:ident: $ty:ty)*) $(-> $out:ty)?;)+) => {
        $(fn $name(&self $(, $arg: $ty)*) $(-> $out)? {
            $(let _ = $arg;)*
            panic!("unexpected host call: {}", stringify!($name));
        })+
    };
}

macro_rules! unused_async_ports {
    ($(fn $name:ident(&self $(, $arg:ident: $ty:ty)*) $(-> $out:ty)?;)+) => {
        $(async fn $name(&self $(, $arg: $ty)*) $(-> $out)? {
            $(let _ = $arg;)*
            panic!("unexpected host call: {}", stringify!($name));
        })+
    };
}

pub(super) struct Host {
    pub state: Arc<State>,
    pub service: MucService<repository::Repository>,
    pub clustered: bool,
    pub federated: bool,
}

impl MucHost for Host {
    type Repository = repository::Repository;
    type MixRepository = repository::UnusedMix;
    type Outbound = OutboundSender;
    type SuspendedEndpoint = ();
    type Session = OnlineSession;

    fn muc_service(&self) -> &MucService<Self::Repository> {
        &self.service
    }
    fn local_domain(&self) -> &str {
        "local.test"
    }
    fn muc_pg_authority_enabled(&self) -> bool {
        self.clustered
    }
    fn muc_cluster_node_id(&self) -> &str {
        "node-original"
    }
    fn archive_requires_encryption(&self) -> bool {
        false
    }
    fn muc_mam_retention_days(&self) -> i64 {
        7
    }
    fn muc_redis_transport_enabled(&self) -> bool {
        true
    }
    fn xmpp_extension_enabled(&self, id: northstar_xep_core::XepId) -> bool {
        assert_eq!(id, northstar_xep_0045::XEP_ID);
        self.state.record(Event::ProtocolPolicy);
        true
    }

    fn validated_local_muc_occupant(
        &self,
        full_jid: &str,
        connection_id: Uuid,
        room_jid: &str,
        membership: &northstar_session_core::JoinedMucMembership,
    ) -> Option<Occupant<Self>> {
        assert_eq!(
            (full_jid, connection_id, room_jid),
            (SENDER, CONNECTION_ID, ROOM_JID)
        );
        assert_eq!(membership.nick, "Alice");
        assert_eq!(membership.cluster_epoch, OCCUPANT_EPOCH);
        self.state.record(Event::Validate);
        Some(occupant("Alice", SENDER))
    }

    async fn publish_muc_cluster_stanza(
        &self,
        room: &str,
        stanza: &str,
        real_sender: Option<&str>,
    ) -> Result<()> {
        self.state.record(Event::Cluster(
            room.to_owned(),
            stanza.to_owned(),
            real_sender.map(str::to_owned),
        ));
        // Tests poll manually, so this wait needs no scheduler or clock.
        futures::future::poll_fn(|_| {
            if self.state.cluster_pending.load(Ordering::Relaxed) {
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(())
            }
        })
        .await;
        Ok(())
    }

    fn muc_occupants_for(&self, room_jid: &str) -> Vec<(String, Occupant<Self>)> {
        assert_eq!(room_jid, ROOM_JID);
        self.state.record(Event::Recipients);
        let mut occupants = vec![("Bob".to_owned(), occupant("Bob", "bob@local.test/phone"))];
        if self.federated {
            let mut remote = occupant("Alice", REMOTE_SENDER);
            remote.endpoint = MucOccupantEndpoint::Federated {
                authenticated_domain: "remote.test".to_owned(),
                connection_id: CONNECTION_ID,
            };
            occupants.push(("Alice".to_owned(), remote));
        }
        occupants
    }

    async fn blocked_muc_recipient_accounts(
        &self,
        occupants: &[Occupant<Self>],
        stanza_senders: &[String],
    ) -> HashSet<String> {
        let sender = if self.federated {
            REMOTE_SENDER
        } else {
            SENDER
        };
        assert_eq!(occupants.len(), if self.federated { 2 } else { 1 });
        assert_eq!(occupants[0].full_jid, "bob@local.test/phone");
        assert_eq!(
            stanza_senders,
            &[format!("{ROOM_JID}/Alice"), sender.to_owned()]
        );
        self.state.record(Event::Privacy);
        HashSet::new()
    }

    async fn deliver_to_muc_occupant_unchecked(
        &self,
        recipient: &Occupant<Self>,
        stanza: String,
    ) -> bool {
        self.state
            .record(Event::Deliver(recipient.full_jid.clone(), stanza));
        futures::future::poll_fn(|_| {
            if self.state.delivery_pending.load(Ordering::Relaxed) {
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(())
            }
        })
        .await;
        true
    }

    async fn wake_committed_muc_operation(&self, operation_id: Uuid) -> Result<()> {
        self.state.record(Event::Wake(operation_id));
        Ok(())
    }

    fn muc_telemetry(&self) -> MucTelemetry<'_> {
        let counters = &self.state.counters;
        MucTelemetry::new(
            &counters[0],
            &counters[1],
            &counters[2],
            &counters[3],
            &counters[4],
            &counters[5],
            &counters[6],
        )
    }

    fn federated_muc_pg_authority_enabled(&self) -> bool {
        assert!(self.federated);
        false
    }

    fn federated_muc_telemetry(&self) -> FederatedMucTelemetry<'_> {
        assert!(self.federated);
        let counters = &self.state.counters;
        FederatedMucTelemetry::new(
            &counters[0],
            &counters[1],
            &counters[2],
            &counters[3],
            &counters[4],
            &counters[5],
        )
    }

    fn validate_routed_message(&self, _root: Node<'_, '_>) -> Result<(), &'static str> {
        assert!(self.federated);
        Ok(())
    }

    async fn federated_muc_publish_room_message(
        &self,
        room_jid: &str,
        stanza: &str,
        real_sender: Option<&str>,
    ) -> Result<()> {
        assert!(self.federated);
        self.publish_muc_cluster_stanza(room_jid, stanza, real_sender)
            .await
    }

    async fn admit_federated_room_stream<F>(
        &self,
        request: FederatedMamStreamRequest<'_>,
        render: F,
    ) -> Result<FederatedMamAdmissionOutcome>
    where
        F: FnOnce(&FederatedMamStreamPage) -> Result<Vec<String>> + Send,
    {
        let _ = (request, render);
        panic!("unexpected federated archive stream");
    }

    unused_ports! {
        fn mix_service(&self) -> &MixService<Self::MixRepository>;
        fn session_entries_for(&self, jid: &str) -> Vec<(String, Self::Session)>;
        fn message_direct_mode(&self) -> DirectPostCommitMode;
        fn federation_outbox_policy(&self) -> northstar_federation_core::S2sOutboxPolicy;
        fn wake_federation_outbox(&self);
        fn admit_muc_pg_mutation(&self) -> Result<()>;
        fn federated_muc_admit_mutation(&self) -> Result<()>;
        fn federated_muc_occupants_for_closed_connection(&self, authenticated_domain: &str, connection_id: Uuid) -> Vec<Occupant<Self>>;
        fn federated_muc_owner_node_id(&self) -> &str;
        fn federated_muc_redis_transport_enabled(&self) -> bool;
        fn local_muc_occupant_by_nick(&self, room_jid: &str, nick: &str) -> Option<Occupant<Self>>;
        fn local_muc_occupant_exact(&self, identity: LocalMucOccupantIdentity<'_>) -> Option<Occupant<Self>>;
        fn mix_muc_mirror_enabled(&self) -> bool;
        fn move_local_muc_nickname_exact(&self, old: LocalMucOccupantIdentity<'_>, renamed: &Occupant<Self>, cluster_committed: bool) -> LocalMucNicknameMove;
        fn offline_delivery_limits(&self) -> OfflineDeliveryLimits;
        fn publish_local_muc_join_if_vacant(&self, joining: &Occupant<Self>) -> LocalMucJoinPublication;
        fn rebind_local_federated_muc_occupant_exact(&self, old: &Occupant<Self>, new_connection_id: Uuid) -> Option<Occupant<Self>>;
        fn record_muc_cluster_control_plane_failure(&self, error: &anyhow::Error);
        fn refresh_local_muc_policy_exact(&self, identity: LocalMucOccupantIdentity<'_>, moderated: Option<bool>, non_anonymous: Option<bool>) -> Option<(Occupant<Self>, bool)>;
        fn refresh_local_muc_presence_exact(&self, prepared: &Occupant<Self>, apply_policy: bool) -> Option<Occupant<Self>>;
        fn remove_live_muc_membership(&self, occupant: &SerializableMucOccupant) -> bool;
        fn remove_local_muc_occupant_exact(&self, identity: LocalMucOccupantIdentity<'_>) -> Option<Occupant<Self>>;
        fn server_name(&self) -> &str;
        fn set_local_muc_affiliation_exact(&self, identity: LocalMucOccupantIdentity<'_>, affiliation: &str, moderated: bool, only_if_none: bool, expected_affiliation: Option<&str>) -> Option<Occupant<Self>>;
        fn set_local_muc_role_exact(&self, identity: LocalMucOccupantIdentity<'_>, expected_role: &str, role: &str, non_anonymous: Option<bool>) -> Option<Occupant<Self>>;
        fn xmpp_external_route_domain_allowed(&self, domain: &str) -> bool;
    }

    unused_async_ports! {
        fn rearm_unrouted_live_direct(&self, recipient_id: Uuid, message_id: Uuid, claim_id: &mut Option<Uuid>);
        fn send_received_carbons(&self, recipient: &str, delivered: Option<&str>, forwarded: &str);
        fn send_federated(&self, target_domain: &str, stanza: String, bounce_to: Option<String>) -> bool;
        fn federated_mam_room_visible(&self, localpart: &str, viewer_full_jid: &str) -> Result<bool>;
        fn authorize_federated_room(&self, localpart: &str, authority: &MamRoomReadAuthority) -> Result<MamRoomAccessOutcome>;
        fn execute_federated_mam_metadata(&self, command: FederatedMamMetadataCommand) -> Result<MamMetadataResult>;
        fn cache_committed_muc_join(&self, occupant: &SerializableMucOccupant, capacity: usize) -> Result<MucJoinCacheAttempt>;
        fn cached_muc_cluster_occupants(&self, room: &str) -> Result<HashMap<String, String>>;
        fn change_cluster_muc_affiliation_exact(&self, room: &str, occupant: &SerializableMucOccupant, affiliation: &str, role: &str) -> Result<MucRoleChange>;
        fn change_cluster_muc_role_exact(&self, room: &str, occupant: &SerializableMucOccupant, role: &str) -> Result<MucRoleChange>;
        fn deliver_muc_primary_to_remote_node(&self, target: &str, stanza: &str, durable: Option<DurableDelivery>) -> Option<NodeDeliveryReceipt>;
        fn deliver_to_muc_occupant(&self, occupant: &Occupant<Self>, stanza: String) -> bool;
        fn dispatch_push_notification(&self, recipient_id: Uuid) -> Result<()>;
        fn evict_cluster_muc_occupant(&self, occupant: &SerializableMucOccupant, status: u16, actor_nick: Option<&str>, reason: Option<&str>) -> Result<()>;
        fn federated_muc_change_occupant_affiliation(&self, room_jid: &str, occupant: &SerializableMucOccupant, affiliation: &str, role: &str) -> Result<MucRoleChange>;
        fn federated_muc_change_occupant_policy(&self, room_jid: &str, occupant: &SerializableMucOccupant, role: &str, room_non_anonymous: bool) -> Result<MucRoleChange>;
        fn federated_muc_change_occupant_role(&self, room_jid: &str, occupant: &SerializableMucOccupant, role: &str) -> Result<MucRoleChange>;
        fn federated_muc_evict_occupant(&self, occupant: &SerializableMucOccupant, status: u16, actor_nick: Option<&str>, reason: Option<&str>) -> Result<bool>;
        fn federated_muc_global_occupants(&self, room_jid: &str) -> Result<HashMap<String, String>>;
        fn federated_muc_join_room(&self, room_jid: &str) -> Result<()>;
        fn federated_muc_leave_room(&self, room_jid: &str) -> Result<()>;
        fn federated_muc_publish_nickname_change(&self, room_jid: &str, old_occupant: &SerializableMucOccupant, new_occupant: &SerializableMucOccupant, id: Option<&str>) -> Result<()>;
        fn federated_muc_publish_presence(&self, room_jid: &str, occupant: &SerializableMucOccupant, unavailable: bool, created: bool, id: Option<&str>) -> Result<()>;
        fn federated_muc_publish_private_message(&self, room_jid: &str, target_nick: &str, stanza: &str, real_sender: &str) -> Result<()>;
        fn federated_muc_publish_removal_presence(&self, room_jid: &str, occupant: &SerializableMucOccupant, status: Option<u16>, actor_nick: Option<&str>, reason: Option<&str>) -> Result<()>;
        fn federated_muc_register_occupant(&self, room_jid: &str, nick: &str, json: &str) -> Result<bool>;
        fn federated_muc_rename_occupant(&self, room_jid: &str, old_nick: &str, new_nick: &str, expected_epoch: Uuid, old_json: &str, new_json: &str) -> Result<MucRename>;
        fn join_cluster_muc_room(&self, room: &str) -> Result<()>;
        fn leave_cluster_muc_room(&self, room: &str) -> Result<()>;
        fn publish_muc_cluster_nickname_change(&self, room: &str, before: &SerializableMucOccupant, after: &SerializableMucOccupant, id: Option<&str>) -> Result<()>;
        fn publish_muc_cluster_presence(&self, publication: MucPresencePublication<'_>) -> Result<()>;
        fn publish_muc_cluster_presence_with_id(&self, room: &str, occupant: &SerializableMucOccupant, unavailable: bool, created: bool, id: Option<&str>) -> Result<()>;
        fn publish_muc_cluster_private_message(&self, room: &str, nick: &str, stanza: &str, real_sender: &str) -> Result<()>;
        fn register_cluster_muc_occupant(&self, room: &str, nick: &str, json: &str) -> Result<bool>;
        fn remove_exact_muc_soft_state(&self, occupant: &Occupant<Self>) -> Result<bool>;
        fn rename_cluster_muc_occupant_exact(&self, room: &str, old_nick: &str, new_nick: &str, expected_epoch: Uuid, old_json: &str, new_json: &str) -> Result<MucRename>;
        fn revoke_cluster_muc_occupant_exact(&self, occupant: &SerializableMucOccupant, status: u16, actor_nick: Option<&str>, reason: Option<&str>) -> Result<bool>;
        fn route_federated_muc_account_message_remote(&self, target_jid: &str, stanza: &str, delivery: Option<DurableDelivery>) -> Option<FederatedMucAccountRoute>;
    }
}
