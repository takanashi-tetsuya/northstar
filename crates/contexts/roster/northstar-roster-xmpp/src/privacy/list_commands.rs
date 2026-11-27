use super::codec::{parse_list, parse_name_control};
use super::{PrivacySession, PrivacySetControl};
use anyhow::Result;
use northstar_roster_application::privacy::commands::{ActorOutcome, PolicyCommandRepository};
use northstar_roster_application::privacy::{PrivacyListMutationOutcome, PrivacySelectionOutcome};
use northstar_xml_builder::stanza::iq_error;
use roxmltree::Node;
use std::ops::ControlFlow;

pub(super) async fn select_default<S: PrivacySession>(
    session: &S,
    id: &str,
    control: Node<'_, '_>,
) -> Result<PrivacySetControl> {
    let Some(actor) = session.roster_actor() else {
        return Ok(ControlFlow::Break((iq_error(id, "not-authorized"), None)));
    };
    let Ok(name) = parse_name_control(control, "default") else {
        return Ok(ControlFlow::Break((iq_error(id, "bad-request"), None)));
    };
    let result = match session
        .privacy_commands()
        .select_default_privacy_list(&actor, name.as_ref())
        .await?
    {
        ActorOutcome::Current((PrivacySelectionOutcome::Updated, _)) => Ok(()),
        ActorOutcome::Current((PrivacySelectionOutcome::Missing, _)) => Err("item-not-found"),
        ActorOutcome::Current((PrivacySelectionOutcome::Conflict, _)) => Err("conflict"),
        ActorOutcome::Stale => Err("not-authorized"),
    };
    Ok(ControlFlow::Continue(result))
}

pub(super) async fn edit_list<S: PrivacySession>(
    session: &S,
    id: &str,
    control: Node<'_, '_>,
    changed_list: &mut Option<String>,
) -> Result<PrivacySetControl> {
    let Some(actor) = session.roster_actor() else {
        return Ok(ControlFlow::Break((iq_error(id, "not-authorized"), None)));
    };
    let Ok((name, items)) = parse_list(control) else {
        return Ok(ControlFlow::Break((iq_error(id, "bad-request"), None)));
    };
    let result = if items.is_empty() {
        match session
            .privacy_commands()
            .remove_privacy_list(&actor, &name)
            .await?
        {
            ActorOutcome::Current((PrivacyListMutationOutcome::Removed, _)) => {
                *changed_list = Some(name.into_inner());
                Ok(())
            }
            ActorOutcome::Current((PrivacyListMutationOutcome::Missing, _)) => {
                Err("item-not-found")
            }
            ActorOutcome::Current((PrivacyListMutationOutcome::Conflict, _)) => Err("conflict"),
            ActorOutcome::Stale => Err("not-authorized"),
            ActorOutcome::Current((
                PrivacyListMutationOutcome::Stored | PrivacyListMutationOutcome::QuotaExceeded,
                _,
            )) => {
                unreachable!("remove-list returned a replace outcome")
            }
        }
    } else {
        match session
            .privacy_commands()
            .replace_privacy_list(&actor, &name, &items)
            .await?
        {
            ActorOutcome::Current(PrivacyListMutationOutcome::Stored) => {
                *changed_list = Some(name.into_inner());
                Ok(())
            }
            ActorOutcome::Current(PrivacyListMutationOutcome::QuotaExceeded) => {
                Err("resource-constraint")
            }
            ActorOutcome::Stale => Err("not-authorized"),
            ActorOutcome::Current(
                PrivacyListMutationOutcome::Removed
                | PrivacyListMutationOutcome::Missing
                | PrivacyListMutationOutcome::Conflict,
            ) => {
                unreachable!("replace-list returned a remove outcome")
            }
        }
    };
    Ok(ControlFlow::Continue(result))
}
