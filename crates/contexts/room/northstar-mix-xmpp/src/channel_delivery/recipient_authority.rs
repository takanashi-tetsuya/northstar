use super::*;

pub(super) async fn resolve_recipient_authority(
    context: &impl MixOutboxPort,
    source: northstar_delivery_core::MixDelivery,
    recipient: &CanonicalJid,
) -> Result<MixDeliveryRecipientAuthority> {
    let address = MixRealJid::parse(&recipient.bare())
        .map_err(|error| permanent_mix_delivery_error("invalid-recipient", error.to_string()))?;
    if same_jid_domain(recipient.domainpart(), context.local_domain()) {
        let account_id = context
            .service()
            .outbox_claimed_recipient_account(source, &address)
            .await?
            .ok_or_else(|| {
                permanent_mix_delivery_error(
                    "account-unavailable",
                    "local MIX recipient account is unbound or no longer enabled at this address",
                )
            })?;
        Ok(MixDeliveryRecipientAuthority::Local {
            address,
            account_id,
        })
    } else {
        Ok(MixDeliveryRecipientAuthority::Remote(address))
    }
}

pub(super) fn check_route_account(
    authority: Option<&MixDeliveryRecipientAuthority>,
    account: Uuid,
) -> Result<()> {
    match authority {
        Some(MixDeliveryRecipientAuthority::Local { account_id, .. }) if *account_id != account => {
            Err(permanent_mix_delivery_error(
                "account-unavailable",
                "local MIX recipient account no longer matches the delivery",
            ))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests;
