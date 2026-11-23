use super::*;
use northstar_room_core::mix::{MixAllowBlock, MixJidVisibilityPreference, MixRelayAddress};

const ANON_NS: &str = "urn:xmpp:mix:anon:0";

#[derive(Debug, Eq, PartialEq)]
pub struct RemotePamJoinOptions {
    anonymous_profile: bool,
    preference: Option<(
        MixJidVisibilityPreference,
        MixAllowBlock,
        MixAllowBlock,
        bool,
    )>,
}

impl RemotePamJoinOptions {
    pub fn new(
        anonymous_profile: bool,
        preference: Option<&MixParticipantPreference>,
    ) -> Result<Self> {
        anyhow::ensure!(
            anonymous_profile || preference.is_none(),
            "MIX preferences require ANON join"
        );
        let preference = preference
            .map(|preference| -> Result<_> {
                Ok((
                    MixJidVisibilityPreference::parse(&preference.jid_visibility)?,
                    MixAllowBlock::parse(&preference.private_messages)?,
                    MixAllowBlock::parse(&preference.vcard)?,
                    preference.share_presence,
                ))
            })
            .transpose()?;
        Ok(Self {
            anonymous_profile,
            preference,
        })
    }

    fn suffix(&self) -> String {
        match self.preference {
            Some((visibility, messages, vcard, presence)) => {
                format!("anon:{visibility}:{messages}:{vcard}:{presence}")
            }
            None if self.anonymous_profile => "anon".to_owned(),
            None => String::new(),
        }
    }

    pub fn request_id(&self, nonce: Uuid) -> String {
        if self.anonymous_profile {
            format!("{nonce}:{}", self.suffix())
        } else {
            nonce.to_string()
        }
    }

    pub fn verify_result(&self, request_id: &str) -> Result<(), HostedMixRefusal> {
        let Some(expected) = Self::expected_profile(request_id) else {
            return Ok(());
        };
        if self.anonymous_profile && (expected == "anon" || expected == self.suffix()) {
            Ok(())
        } else {
            Err(HostedMixRefusal::RemoteJoinOptionsNotHonoured)
        }
    }

    pub fn expected_profile(request_id: &str) -> Option<&str> {
        request_id
            .split_once(':')
            .map(|(_, suffix)| suffix)
            .filter(|suffix| *suffix == "anon" || suffix.starts_with("anon:"))
    }

    pub fn submission_form(&self) -> Option<XmlElement> {
        let (visibility, messages, vcard, presence) = self.preference?;
        let field = |name: &'static str, value: &str| {
            XmlElement::new("field")
                .attr("var", name)
                .child(XmlElement::new("value").text(value))
        };
        Some(
            XmlElement::namespaced("x", "jabber:x:data")
                .attr("type", "submit")
                .child(field("FORM_TYPE", ANON_NS).attr("type", "hidden"))
                .child(field("JID Visibility", visibility.as_str()))
                .child(field("Private Messages", messages.as_str()))
                .child(field("vCard", vcard.as_str()))
                .child(field(
                    "Presence",
                    if presence { "share" } else { "not share" },
                )),
        )
    }
}

impl RemotePamJoinEvidence<'_> {
    pub fn render_anon_result(
        &self,
        addressed: &RemotePamResponse<'_>,
        result: PamJoinResult<'_>,
    ) -> Result<String> {
        let participant = MixRelayAddress::new(
            addressed.channel.clone(),
            MixParticipantId::Remote(self.participant.clone()),
            None,
        )?;
        let mut join = XmlElement::namespaced("join", ANON_NS).attr("jid", participant.as_str());
        for node in result.subscriptions {
            join.push_child(XmlElement::new("subscribe").attr("node", node));
        }
        if let Some(nick) = result.nick {
            join.push_child(XmlElement::new("nick").text(nick));
        }
        if let Some(preference) = self.preference {
            join = join.validated_fragment(&super::super::payloads::mix_preference_result_form(
                preference,
            ))?;
        }
        Ok(XmlElement::namespaced("iq", "jabber:client")
            .attr("type", "result")
            .attr("from", result.actor_bare)
            .attr("to", result.requester_full_jid)
            .attr("id", result.client_request_id)
            .child(XmlElement::namespaced("client-join", "urn:xmpp:mix:pam:2").child(join))
            .finish())
    }
}
