macro_rules! ports {
    () => {
        async fn refresh_muc_occupant_activity(
            _session: &ProtocolSession<Self>,
            _room_jid: &str,
            _nick: &str,
        ) -> Result<bool>
        where
            Self: SessionHost,
        {
            panic!("unexpected host call: refresh_muc_occupant_activity")
        }

        async fn occupant_iq_view(
            _session: &ProtocolSession<Self>,
            _room_jid: &str,
            _target_nick: &str,
        ) -> Result<northstar_room_application::muc_service::MucOccupantIqView>
        where
            Self: SessionHost,
        {
            panic!("unexpected host call: occupant_iq_view")
        }

        fn local_muc_occupant_exact(
            &self,
            _identity: LocalMucOccupantIdentity<'_>,
        ) -> Option<MucOccupant> {
            panic!("unexpected host call: local_muc_occupant_exact")
        }
    };
}

pub(super) use ports;
