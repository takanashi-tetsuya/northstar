use super::codec::parse_optional_name_control;
use super::{PrivacySession, PrivacySetControl};
use anyhow::Result;
use northstar_roster_application::privacy::PrivacySelectionOutcome;
use northstar_roster_core::PresenceAccount;
use northstar_xml_builder::stanza::iq_error;
use roxmltree::Node;
use std::ops::ControlFlow;

pub(super) async fn select_active<S: PrivacySession>(
    session: &S,
    id: &str,
    user: &PresenceAccount,
    control: Node<'_, '_>,
) -> Result<PrivacySetControl> {
    let Ok(name) = parse_optional_name_control(control, "active") else {
        return Ok(ControlFlow::Break((iq_error(id, "bad-request"), None)));
    };
    match session
        .privacy_service()
        .select_active(user.id, session.privacy_connection_id(), name.as_deref())
        .await?
    {
        PrivacySelectionOutcome::Updated => {}
        PrivacySelectionOutcome::Missing => {
            return Ok(ControlFlow::Break((iq_error(id, "item-not-found"), None)));
        }
        PrivacySelectionOutcome::Conflict => {
            unreachable!("active-list selection has no resource conflict")
        }
    }
    session.privacy_set_active_list(name);
    Ok(ControlFlow::Continue(Ok(())))
}
