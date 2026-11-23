use northstar_room_application::mix_service::{
    MixRelayProfileQuery, MixRelayReturnRepository, RelayProfileSnapshot,
};

impl MixRelayReturnRepository for super::UnusedPorts {
    async fn relay_profile_with_incarnation(
        &self,
        _query: MixRelayProfileQuery,
    ) -> anyhow::Result<RelayProfileSnapshot> {
        panic!("unexpected repository call: relay_profile_with_incarnation")
    }
}
