use crate::{FederatedPresenceHandoff, FederatedPresenceOwnerHost};
use anyhow::Result;
use northstar_roster_core::PresenceAccount;

pub(super) async fn dispatch_ordinary_presence(
    state: &impl FederatedPresenceOwnerHost,
    recipient: &PresenceAccount,
    handoff: FederatedPresenceHandoff<'_>,
) -> Result<()> {
    let routes = state
        .capture_federated_presence(handoff.target, recipient)
        .await?;
    state
        .handoff_federated_presence(recipient, handoff, &routes)
        .await?;
    Ok(())
}
