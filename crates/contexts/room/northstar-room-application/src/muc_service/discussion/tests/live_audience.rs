use super::*;

impl MucLiveAudienceRepository for Repository {
    unused_ports! {
        admit_live_discussion(command: &MucDiscussion) -> DiscussionCommit;
        commit_live_retraction(mutation: MucRetractionMutation<'_>) -> RetractionCommit;
    }
}
