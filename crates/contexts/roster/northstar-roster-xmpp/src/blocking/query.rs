use super::mutation::patterns_from_jids;
use crate::fanout::{resynchronize_blocklist, run_blocklist_observer};
use crate::{RosterSessionHost, SessionIdentity};
use anyhow::Result;
use northstar_roster_application::blocklist_revisions::BlocklistRevisionRepository;
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use northstar_stream::transport::Action;
use northstar_xep_0191::BlockingCommand;
use northstar_xml_builder::stanza::{iq_error, iq_result};
use roxmltree::Node;
use std::sync::{atomic::Ordering, Arc};

/// Answers an XEP-0191 blocklist request.
pub async fn blocklist<H: SessionHost + RosterSessionHost>(
    session: &mut ProtocolSession<H>,
    id: &str,
    root: Node<'_, '_>,
) -> Result<Action> {
    let Some(actor) = session.roster_actor() else {
        return Ok(Action::Send(iq_error(id, "not-authorized")));
    };
    if !matches!(
        northstar_xep_0191::parse_iq(root),
        Ok(BlockingCommand::GetBlocklist)
    ) {
        return Ok(Action::Send(iq_error(id, "bad-request")));
    }
    let host = Arc::clone(session.host());
    let routes = host.policy_sessions();
    let Some(epoch) = routes.with_exact_policy_session(&actor, |current| {
        let epoch = current.blocklist_observation.begin_snapshot();
        current.blocklist_requested.store(true, Ordering::Release);
        epoch
    }) else {
        return Ok(Action::Send(iq_error(id, "not-authorized")));
    };
    let snapshot: Result<_> = async {
        let snapshot = host
            .blocking_service()
            .revisions()
            .blocklist_snapshot(&actor)
            .await?;
        snapshot
            .map(|snapshot| {
                let patterns = patterns_from_jids(&snapshot.patterns)?;
                Ok((
                    snapshot.revision,
                    northstar_xep_0191::build_blocklist_result(&patterns),
                ))
            })
            .transpose()
    }
    .await;
    let (revision, payload) = match snapshot {
        Ok(Some(snapshot)) => snapshot,
        outcome => {
            resynchronize_blocklist(&routes, &actor, epoch);
            return outcome.map(|_| Action::Send(iq_error(id, "not-authorized")));
        }
    };
    let observer_routes = routes.clone();
    let observer_actor = actor.clone();
    if let Err(error) = session.defer_after_transport("blocklist-initial-sync", async move {
        let finish = observer_routes
            .with_exact_policy_session(&observer_actor, |current| {
                current
                    .blocklist_observation
                    .finish_snapshot(epoch, revision)
                    .then(|| {
                        (
                            current.blocklist_observation.subscribe(),
                            current.disconnect.clone(),
                        )
                    })
            })
            .flatten();
        if let Some((wake, disconnect)) = finish {
            tokio::select! {
                () = disconnect.cancelled() => {},
                () = run_blocklist_observer(
                    host.blocking_service().revisions(),
                    &observer_routes,
                    &observer_actor,
                    epoch,
                    wake,
                    host.post_accept_failure_telemetry(),
                ) => {},
            }
        }
    }) {
        resynchronize_blocklist(&routes, &actor, epoch);
        return Err(error);
    }
    Ok(Action::Send(iq_result(id, &payload)))
}
