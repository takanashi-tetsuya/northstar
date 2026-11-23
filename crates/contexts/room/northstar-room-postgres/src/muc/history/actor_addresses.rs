use anyhow::Result;
use northstar_xmpp_types::CanonicalJid;

pub(super) struct HistoryActorAddresses {
    pub(super) actor: CanonicalJid,
    pub(super) sender: CanonicalJid,
}

impl HistoryActorAddresses {
    pub(super) fn parse(actor_scope: &str, sender_jid: &str) -> Result<Self> {
        Ok(Self {
            actor: parse_history_actor(actor_scope)?,
            sender: parse_history_sender(sender_jid)?,
        })
    }
}

pub(super) fn parse_history_actor(actor_scope: &str) -> Result<CanonicalJid> {
    anyhow::ensure!(
        !actor_scope.is_empty() && actor_scope.len() <= 3071,
        "MUC history actor scope must contain 1 to 3071 bytes"
    );
    let actor = CanonicalJid::parse_bare(actor_scope)?;
    anyhow::ensure!(
        actor.localpart().is_some(),
        "MUC history actor scope must be a user bare JID"
    );
    anyhow::ensure!(
        actor.to_string() == actor_scope,
        "MUC history actor scope must already be canonical"
    );
    Ok(actor)
}

pub(super) fn parse_history_sender(sender_jid: &str) -> Result<CanonicalJid> {
    anyhow::ensure!(
        !sender_jid.is_empty() && sender_jid.len() <= 3071,
        "MUC history sender JID must contain 1 to 3071 bytes"
    );
    let sender = CanonicalJid::parse(sender_jid)?;
    anyhow::ensure!(
        sender.to_string() == sender_jid,
        "MUC history sender JID must already be canonical"
    );
    Ok(sender)
}
