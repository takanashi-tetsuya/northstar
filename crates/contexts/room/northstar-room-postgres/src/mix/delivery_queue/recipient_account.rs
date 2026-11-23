use super::*;
use northstar_room_core::mix::MixRealJid;

pub async fn claimed_recipient_account(
    pool: &PgPool,
    source: northstar_delivery_core::MixDelivery,
    address: &MixRealJid,
) -> Result<Option<Uuid>> {
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT account.id
           FROM mix_delivery_recipients AS recipient
           LEFT JOIN users AS account ON account.id = recipient.recipient_local_user_id
            AND account.username = split_part(recipient.recipient_jid, '@', 1)
            AND NOT account.is_disabled
          WHERE recipient.delivery_id=$1 AND recipient.lease_token=$2 AND recipient.recipient_jid=$3
            AND recipient.lease_until>clock_timestamp()",
    )
    .bind(source.delivery_id)
    .bind(source.lease_token)
    .bind(address.as_str())
    .fetch_optional(pool)
    .await?
    .context("MIX recipient is no longer owned by the routing lease")
}
