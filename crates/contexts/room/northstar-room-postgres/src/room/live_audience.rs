use super::*;

impl<E: RoomEffects> MucLiveAudienceRepository for PostgresMucRepository<E> {
    async fn admit_live_discussion(&self, command: &MucDiscussion) -> Result<DiscussionCommit> {
        crate::muc::admit_muc_discussion_live(&self.pool, discussion_to_db(command), None).await
    }

    async fn commit_live_retraction(
        &self,
        mutation: MucRetractionMutation<'_>,
    ) -> Result<RetractionCommit> {
        let (outcome, audience) =
            crate::muc::retract_muc_message_live(&self.pool, retraction_mutation_as_db(&mutation))
                .await?;
        Ok(RetractionCommit {
            outcome: outcome.into(),
            audience,
        })
    }
}
