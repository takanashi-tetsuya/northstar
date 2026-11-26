use super::codec::{parse_list, parse_optional_name_control};
use super::{PrivacySession, PrivacySetControl};
use anyhow::Result;
use northstar_roster_application::privacy::{PrivacyListMutationOutcome, PrivacySelectionOutcome};
use northstar_roster_core::PresenceAccount;
use northstar_xml_builder::stanza::iq_error;
use roxmltree::Node;
use std::ops::ControlFlow;

pub(super) async fn select_default<S: PrivacySession>(
    session: &S,
    id: &str,
    user: &PresenceAccount,
    control: Node<'_, '_>,
) -> Result<PrivacySetControl> {
    let Ok(name) = parse_optional_name_control(control, "default") else {
        return Ok(ControlFlow::Break((iq_error(id, "bad-request"), None)));
    };
    let account = format!("{}@{}", user.username, session.session_local_domain());
    let remote_resource_exists = session.privacy_has_remote_resources(&account).await?;
    let result = match session
        .privacy_service()
        .select_default(
            user.id,
            name.as_deref(),
            session.privacy_local_resources(&account),
            remote_resource_exists,
        )
        .await?
    {
        PrivacySelectionOutcome::Updated => Ok(()),
        PrivacySelectionOutcome::Missing => Err("item-not-found"),
        PrivacySelectionOutcome::Conflict => Err("conflict"),
    };
    Ok(ControlFlow::Continue(result))
}

pub(super) async fn edit_list<S: PrivacySession>(
    session: &S,
    id: &str,
    user: &PresenceAccount,
    control: Node<'_, '_>,
    changed_list: &mut Option<String>,
) -> Result<PrivacySetControl> {
    let Ok(list) = parse_list(control) else {
        return Ok(ControlFlow::Break((iq_error(id, "bad-request"), None)));
    };
    let result = if list.items.is_empty() {
        let active_somewhere = session.privacy_list_active_locally(
            &format!("{}@{}", user.username, session.session_local_domain()),
            &list.name,
        );
        match session
            .privacy_service()
            .remove_list(user.id, &list.name, active_somewhere)
            .await?
        {
            PrivacyListMutationOutcome::Removed => {
                *changed_list = Some(list.name.clone());
                Ok(())
            }
            PrivacyListMutationOutcome::Missing => Err("item-not-found"),
            PrivacyListMutationOutcome::Conflict => Err("conflict"),
            PrivacyListMutationOutcome::Stored | PrivacyListMutationOutcome::QuotaExceeded => {
                unreachable!("remove-list returned a replace outcome")
            }
        }
    } else {
        match session
            .privacy_service()
            .replace_list(user.id, &list)
            .await?
        {
            PrivacyListMutationOutcome::Stored => {
                *changed_list = Some(list.name.clone());
                Ok(())
            }
            PrivacyListMutationOutcome::QuotaExceeded => Err("resource-constraint"),
            PrivacyListMutationOutcome::Removed
            | PrivacyListMutationOutcome::Missing
            | PrivacyListMutationOutcome::Conflict => {
                unreachable!("replace-list returned a remove outcome")
            }
        }
    };
    Ok(ControlFlow::Continue(result))
}
