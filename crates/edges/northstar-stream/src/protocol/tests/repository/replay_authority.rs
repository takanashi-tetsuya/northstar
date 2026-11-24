use super::UnusedRepository;
use anyhow::Result;
use northstar_session_application::replay::*;

impl ReplayAuthorityRepository for UnusedRepository {
    async fn claim_current_page(
        &self,
        session: &ReplaySession,
        authority: ReplayPageAuthority<'_>,
        bind2: bool,
        ttl: i64,
    ) -> Result<AuthorizedReplayClaim> {
        assert!((authority.is_current)());
        match self
            .claim_page(session, authority.active_privacy_list, bind2, ttl)
            .await?
        {
            ReplayPageOutcome::Empty => Ok(AuthorizedReplayClaim::Empty),
            outcome => panic!("unexpected replay result: {outcome:?}"),
        }
    }

    async fn prepare_current_message(
        &self,
        _: &ReplaySession,
        _: ReplayMessageAuthority<'_>,
    ) -> Result<ReplayPreparation> {
        panic!("unexpected replay preparation")
    }
}
