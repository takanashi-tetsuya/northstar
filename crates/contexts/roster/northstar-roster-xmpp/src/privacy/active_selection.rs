use super::codec::parse_optional_name_control;
use super::{PrivacySession, PrivacySetControl};
use crate::{RosterSessionHost, SessionIdentity};
use anyhow::Result;
use northstar_roster_application::privacy::PrivacySelectionOutcome;
use northstar_roster_core::RosterActor;
use northstar_stream::protocol::{ProtocolSession, SessionHost};
use northstar_xml_builder::stanza::iq_error;
use roxmltree::Node;
use std::future::Future;
use std::ops::ControlFlow;

/// The activation adapter couples an exact route's lease to its optional durable SM selector.
pub trait PrivacySelectionHost: SessionHost {
    fn commit_privacy_selection(
        &self,
        session: &ProtocolSession<Self>,
        actor: &RosterActor,
        name: Option<&str>,
    ) -> impl Future<Output = Result<PrivacySelectionOutcome>> + Send;

    fn publish_privacy_selection(
        &self,
        session: &ProtocolSession<Self>,
        actor: &RosterActor,
        name: Option<&str>,
    ) -> bool;
}

pub(super) async fn select_active<H: RosterSessionHost + PrivacySelectionHost>(
    session: &ProtocolSession<H>,
    id: &str,
    control: Node<'_, '_>,
) -> Result<PrivacySetControl> {
    let Ok(name) = parse_optional_name_control(control, "active") else {
        return Ok(ControlFlow::Break((iq_error(id, "bad-request"), None)));
    };
    let Some(actor) = session.roster_actor() else {
        return Ok(ControlFlow::Break((iq_error(id, "not-authorized"), None)));
    };
    let host = session.host();
    let outcome = publish_after_commit(
        host.commit_privacy_selection(session, &actor, name.as_deref()),
        || host.publish_privacy_selection(session, &actor, name.as_deref()),
        || async {
            session.disconnect.cancel();
            *session
                .privacy_active
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = name.clone();
            session
                .privacy_service()
                .clear_active_session(actor.account_id, actor.connection_id)
                .await
        },
    )
    .await?;
    match outcome {
        PrivacySelectionOutcome::Updated => Ok(ControlFlow::Continue(Ok(()))),
        PrivacySelectionOutcome::Missing => {
            Ok(ControlFlow::Break((iq_error(id, "item-not-found"), None)))
        }
        PrivacySelectionOutcome::Conflict => {
            Ok(ControlFlow::Break((iq_error(id, "conflict"), None)))
        }
    }
}

async fn publish_after_commit<F: Future<Output = Result<()>>>(
    commit: impl Future<Output = Result<PrivacySelectionOutcome>>,
    publish: impl FnOnce() -> bool,
    compensate: impl FnOnce() -> F,
) -> Result<PrivacySelectionOutcome> {
    let outcome = commit.await?;
    if outcome == PrivacySelectionOutcome::Updated && !publish() {
        compensate().await?;
        anyhow::bail!("committed privacy selection lost its exact live route");
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests;
