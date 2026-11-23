use super::*;

impl MucLiveAudienceRepository for Repository {
    async fn admit_live_discussion(&self, command: &MucDiscussion) -> Result<DiscussionCommit> {
        let outcome = self.admit_discussion(command).await?;
        Ok(DiscussionCommit {
            outcome,
            audience: None,
        })
    }

    async fn commit_live_retraction(
        &self,
        mutation: MucRetractionMutation<'_>,
    ) -> Result<RetractionCommit> {
        let outcome = self
            .retract_local_message_and_archive_action(mutation)
            .await?;
        Ok(RetractionCommit {
            outcome,
            audience: None,
        })
    }
}
