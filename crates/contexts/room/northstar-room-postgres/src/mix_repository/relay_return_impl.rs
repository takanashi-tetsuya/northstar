use super::*;

impl<E: RoomEffects> MixRelayReturnRepository for PostgresMixRepository<E> {
    async fn relay_profile_with_incarnation(
        &self,
        query: MixRelayProfileQuery,
    ) -> Result<RelayProfileSnapshot> {
        relay_profile_snapshot::read_with_incarnation(&self.pool, &self.effects, query).await
    }
}
