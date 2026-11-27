use super::{RosterFanoutRoutes, BLOCKING_PUSH_TIMEOUT};
use crate::blocking::push::journal_payload;
use crate::PostAcceptFailureTelemetry;
use northstar_roster_application::blocklist_revisions::{
    BlocklistJournal, BlocklistRevisionRepository,
};
use northstar_roster_application::SystemRosterEvents;
use northstar_roster_core::{RosterActor, RosterEventSource};
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::local_routes::session_table::LocalSessionTable;
use northstar_xml_builder::rewrite::set_to;
use northstar_xml_builder::XmlElement;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::{mpsc::error::TrySendError, watch};
use uuid::Uuid;

const BLOCKLIST_RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

pub fn blocking_push_stanza(target: &str, payload: &str, id: Uuid) -> String {
    XmlElement::namespaced("iq", "jabber:client")
        .attr("to", target)
        .attr("type", "set")
        .attr("id", format!("block-{}", id.as_u128()))
        .validated_fragment(payload)
        .expect("blocking payload was constructed structurally")
        .finish()
}

pub async fn push_blocklist_change(
    routes: &impl RosterFanoutRoutes,
    repository: &impl BlocklistRevisionRepository,
    actor: &RosterActor,
) {
    let owner = actor.bare_jid();
    let table = routes.policy_sessions();
    let targets = table.session_entries_for(owner);
    let mut journal = match repository.blocklist_journal(actor, None).await {
        Ok(Some(journal)) => journal,
        Ok(None) => return,
        Err(error) => {
            routes.record_fanout_failure();
            tracing::warn!(?error, %owner, "could not read blocklist journal head for push");
            return;
        }
    };
    let Some(change) = journal
        .changes
        .pop()
        .filter(|change| change.revision == journal.revision)
    else {
        return;
    };
    for (jid, sampled) in targets {
        let target = policy_target(actor, jid, &sampled);
        table.with_exact_policy_session(&target, |current| {
            if current.blocklist_requested.load(Ordering::Acquire)
                && !current.signal_blocklist_revision(change.revision)
            {
                routes.record_fanout_failure();
            }
        });
    }
    match routes
        .remote_blocklist_push(actor, change.revision, || {
            let payload = journal_payload(&change)
                .ok_or_else(|| anyhow::anyhow!("invalid blocklist delta"))?;
            Ok(blocking_push_stanza(
                owner,
                &payload,
                SystemRosterEvents.new_protocol_id(),
            ))
        })
        .await
    {
        Ok(failures) => {
            for failure in failures {
                routes.record_fanout_failure();
                tracing::warn!(error=?failure.error, node_id=%failure.node_id,
                    "failed clustered XEP-0191 push");
            }
        }
        Err(error) => {
            routes.record_fanout_failure();
            tracing::warn!(?error, %owner, revision = change.revision, "blocklist fanout failed");
        }
    }
}

pub async fn push_privacy_change(
    routes: &impl RosterFanoutRoutes,
    actor: &RosterActor,
    name: &str,
    base: &str,
) -> Option<String> {
    let account = actor.bare_jid();
    let table = routes.policy_sessions();
    let mut current_push = None;
    for (jid, sampled) in table.session_entries_for(account) {
        let target = policy_target(actor, jid, &sampled);
        table.with_exact_policy_session(&target, |current| {
            if !current.privacy_requested.load(Ordering::Acquire) {
                return;
            }
            let push = set_to(base, &target.full_jid);
            if target.connection_id == actor.connection_id && target.full_jid == actor.full_jid {
                current_push = Some(push);
            } else if let Err(error) = current.sender.try_send(push) {
                disconnect_policy_session(current);
                routes.record_fanout_failure();
                tracing::warn!(jid = %target.full_jid, list = %name, ?error,
                    "XEP-0016 privacy-list push queue was unavailable; disconnecting stale resource");
            }
        });
    }
    match routes.remote_privacy_push(actor, base).await {
        Ok(failures) => {
            for failure in failures {
                routes.record_fanout_failure();
                tracing::warn!(
                    error = ?failure.error,
                    node_id = %failure.node_id,
                    list = %name,
                    "clustered XEP-0016 push failed"
                );
            }
        }
        Err(error) => {
            routes.record_fanout_failure();
            tracing::warn!(?error, list = %name, "could not enumerate nodes for XEP-0016 push");
        }
    }
    current_push.filter(|_| {
        table.with_exact_policy_session(actor, |current| {
            current.privacy_requested.load(Ordering::Acquire)
        }) == Some(true)
    })
}

fn policy_target(actor: &RosterActor, full_jid: String, sampled: &OnlineSession) -> RosterActor {
    RosterActor {
        account_id: actor.account_id,
        auth_generation: actor.auth_generation,
        connection_id: sampled.connection_id,
        full_jid,
    }
}

fn disconnect_policy_session(current: &OnlineSession) {
    current.sender.disconnect_backpressured_transport();
    current.disconnect.cancel();
}

pub(crate) fn resynchronize_blocklist(
    routes: &LocalSessionTable,
    actor: &RosterActor,
    epoch: u64,
) -> bool {
    routes.with_exact_policy_session(actor, |current| {
        current
            .blocklist_observation
            .fail_snapshot(epoch, || disconnect_policy_session(current))
    }) == Some(true)
}

pub(crate) async fn run_blocklist_observer(
    repository: &impl BlocklistRevisionRepository,
    routes: &LocalSessionTable,
    actor: &RosterActor,
    epoch: u64,
    mut wake: watch::Receiver<()>,
    telemetry: PostAcceptFailureTelemetry,
) {
    loop {
        let Some(after) = routes
            .with_exact_policy_session(actor, |current| current.blocklist_observation.cursor(epoch))
            .flatten()
        else {
            return;
        };
        match deliver_journal_batch(repository, routes, actor, epoch, after).await {
            Ok(Some(true)) => continue,
            Ok(Some(false)) => {}
            Ok(None) => return,
            Err(error) => {
                if resynchronize_blocklist(routes, actor, epoch) {
                    telemetry.record_failure();
                    tracing::warn!(jid = %actor.full_jid, after, ?error,
                        "could not deliver the next blocklist revision; forcing resynchronization");
                }
                return;
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(BLOCKLIST_RECONCILE_INTERVAL) => {},
            result = wake.changed() => if result.is_err() { return; },
        }
    }
}

async fn deliver_journal_batch(
    repository: &impl BlocklistRevisionRepository,
    routes: &LocalSessionTable,
    actor: &RosterActor,
    epoch: u64,
    after: i64,
) -> anyhow::Result<Option<bool>> {
    let BlocklistJournal {
        revision: head,
        changes,
    } = repository
        .blocklist_journal(actor, Some(after))
        .await?
        .ok_or_else(|| anyhow::anyhow!("stale blocklist owner"))?;
    let mut cursor = after;
    for change in &changes {
        anyhow::ensure!(
            cursor.checked_add(1) == Some(change.revision),
            "blocklist journal gap"
        );
        cursor = change.revision;
    }
    anyhow::ensure!(
        cursor <= head && (after == head || !changes.is_empty()),
        "blocklist journal gap"
    );
    for change in changes {
        let payload =
            journal_payload(&change).ok_or_else(|| anyhow::anyhow!("invalid blocklist delta"))?;
        let stanza = blocking_push_stanza(
            &actor.full_jid,
            &payload,
            SystemRosterEvents.new_protocol_id(),
        );
        if !tokio::time::timeout(
            BLOCKING_PUSH_TIMEOUT,
            send_blocklist_revision(routes, actor, epoch, change.revision, stanza),
        )
        .await??
        {
            return Ok(None);
        }
    }
    Ok(Some(cursor < head))
}

async fn send_blocklist_revision(
    routes: &LocalSessionTable,
    actor: &RosterActor,
    epoch: u64,
    revision: i64,
    mut stanza: String,
) -> anyhow::Result<bool> {
    loop {
        let result = routes
            .with_exact_policy_session(actor, |current| {
                current
                    .blocklist_observation
                    .enqueue_next(epoch, revision, |fence| {
                        current.sender.try_send_snapshot_push(stanza, fence)
                    })
            })
            .flatten();
        match result {
            Some(Ok(())) => return Ok(true),
            Some(Err(TrySendError::Full(refused))) => stanza = refused,
            Some(Err(TrySendError::Closed(_))) => anyhow::bail!("blocklist push queue closed"),
            None => return Ok(false),
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[cfg(test)]
mod tests;
