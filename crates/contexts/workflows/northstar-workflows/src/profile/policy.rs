use super::RosterAudienceEntry;
use anyhow::{bail, Result};
use northstar_xep_0016::{
    list_denies, PrivacyAction, PrivacyItem, PrivacyList, PrivacyMatchType, PrivacyStanzaKind,
};
use sqlx::{postgres::PgRow, Row};

pub(super) enum OwnerPrivacyPolicy {
    Unselected,
    Unavailable,
    Selected(PrivacyList),
}

impl OwnerPrivacyPolicy {
    pub(super) fn denies_message(
        &self,
        candidate: &str,
        roster: Option<&RosterAudienceEntry>,
    ) -> bool {
        match self {
            Self::Unselected => false,
            Self::Unavailable => true,
            Self::Selected(list) => list_denies(
                list,
                candidate,
                roster.map(|entry| entry.subscription.as_str()),
                roster.map_or(&[], |entry| entry.groups.as_slice()),
                PrivacyStanzaKind::Message,
            ),
        }
    }
}

pub(super) fn decode_list(name: String, rows: &[PgRow]) -> Result<OwnerPrivacyPolicy> {
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let action = match row.try_get::<&str, _>("action")? {
            "allow" => PrivacyAction::Allow,
            "deny" => PrivacyAction::Deny,
            _ => bail!("invalid privacy action"),
        };
        let match_type = match row.try_get::<Option<&str>, _>("match_type")? {
            None => None,
            Some("jid") => Some(PrivacyMatchType::Jid),
            Some("group") => Some(PrivacyMatchType::Group),
            Some("subscription") => Some(PrivacyMatchType::Subscription),
            Some(_) => bail!("invalid privacy match type"),
        };
        let item = PrivacyItem {
            order: u32::try_from(row.try_get::<i64, _>("item_order")?)?,
            action,
            match_type,
            match_value: row.try_get("match_value")?,
            message: row.try_get("filter_message")?,
            iq: row.try_get("filter_iq")?,
            presence_in: row.try_get("filter_presence_in")?,
            presence_out: row.try_get("filter_presence_out")?,
        };
        anyhow::ensure!(
            item.match_type.is_some() == item.match_value.is_some(),
            "incomplete privacy matcher"
        );
        items.push(item);
    }
    Ok(OwnerPrivacyPolicy::Selected(PrivacyList { name, items }))
}
