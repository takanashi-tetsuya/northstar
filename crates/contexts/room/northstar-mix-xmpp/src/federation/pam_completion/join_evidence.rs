use super::*;
use northstar_room_application::mix_service::RemotePamJoinEvidence;
use northstar_room_core::mix::{MixParticipantNick, MixStableParticipantId};

pub(super) struct ParsedJoin {
    participant: MixStableParticipantId,
    subscriptions: Vec<String>,
    nick: Option<MixParticipantNick>,
    anonymous_profile: bool,
    preference: Option<MixParticipantPreference>,
}

impl ParsedJoin {
    pub(super) fn evidence(&self) -> RemotePamJoinEvidence<'_> {
        RemotePamJoinEvidence {
            participant: &self.participant,
            subscriptions: &self.subscriptions,
            nick: self.nick.as_ref(),
            anonymous_profile: self.anonymous_profile,
            preference: self.preference.as_ref(),
        }
    }
}

pub(super) fn parse_join_evidence(
    raw: &str,
    channel: &MixChannelAddress,
) -> Result<Option<ParsedJoin>> {
    let Some(join) = parse_remote_pam_success(raw, channel.as_str())? else {
        return Ok(None);
    };
    let document = Document::parse(raw)?;
    let element = document
        .root_element()
        .children()
        .find(Node::is_element)
        .context("validated MIX join result lost its payload")?;
    let anonymous_profile = element.tag_name().namespace() == Some(ANON_NS);
    let preference = if anonymous_profile {
        let form = element.children().find(|node| {
            node.has_tag_name(("jabber:x:data", "x")) && node.attribute("type") == Some("result")
        });
        let fields = form.map(crate::forms::parse_fields).transpose()?;
        fields
            .as_ref()
            .filter(|fields| {
                ["JID Visibility", "Private Messages", "vCard", "Presence"]
                    .iter()
                    .all(|name| fields.get(*name).is_some_and(|values| values.len() == 1))
            })
            .map(|fields| crate::forms::parse_preference_submission(fields, None))
            .transpose()?
    } else {
        None
    };
    Ok(Some(ParsedJoin {
        participant: MixStableParticipantId::parse(&join.participant_id)?,
        subscriptions: join.subscriptions,
        nick: join
            .nick
            .as_deref()
            .map(MixParticipantNick::parse)
            .transpose()?,
        anonymous_profile,
        preference,
    }))
}
