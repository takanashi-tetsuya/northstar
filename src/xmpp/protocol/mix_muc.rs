//! XEP-0408 MIX/MUC co-existence discovery.
//!
//! Version 0.2.0 of XEP-0408 is Deferred and defines three deployment models
//! plus disco data forms.  It does **not** define stanza conversion, shadow
//! occupants, or a server-to-server bridge marker.  Northstar therefore uses
//! the partial-mirror model only for explicitly linked local entities and does
//! not invent an unsafe message/presence relay that could loop or disclose a
//! semi-anonymous MUC occupant's real JID.

use crate::{services::mix::MixMucLinkOutcome, state::AppState, xmpp::xml_builder::XmlElement};
use anyhow::Result;

pub(crate) const MIRROR_NS: &str = "urn:xmpp:mix:muc:0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MirrorDirection {
    /// A MIX service/channel points clients at its MUC counterpart.
    Muc,
    /// A MUC service/room points clients at its MIX counterpart.
    Mix,
}

/// XEP-0408 advertises a mirror through an extended disco result, not through
/// a `<feature/>`. Keeping this in one serializer makes it difficult to
/// accidentally advertise the forbidden counterpart protocol feature on a
/// separate-domain service.
pub(crate) fn mirror_discovery_form(direction: MirrorDirection, service_jid: &str) -> String {
    let (form_type, field, label) = match direction {
        MirrorDirection::Muc => (
            format!("{MIRROR_NS}#muc-mirror"),
            "muc-mirror",
            "Location of MUC mirror service",
        ),
        MirrorDirection::Mix => (
            format!("{MIRROR_NS}#mix-mirror"),
            "mix-mirror",
            "Location of MIX mirror service",
        ),
    };
    XmlElement::namespaced("x", "jabber:x:data")
        .attr("type", "result")
        .child(
            XmlElement::new("field")
                .attr("var", "FORM_TYPE")
                .attr("type", "hidden")
                .child(XmlElement::new("value").text(form_type)),
        )
        .child(
            XmlElement::new("field")
                .attr("var", field)
                .attr("type", "jid-single")
                .attr("label", label)
                .child(XmlElement::new("value").text(service_jid.to_owned())),
        )
        .finish()
}

pub(crate) fn conditional_mirror_discovery_form(
    enabled: bool,
    linked: bool,
    direction: MirrorDirection,
    service_jid: &str,
) -> String {
    if enabled && linked {
        mirror_discovery_form(direction, service_jid)
    } else {
        String::new()
    }
}

/// Opportunistically associates a just-created entity with an existing
/// same-localpart counterpart. Failure to prove common ownership is a normal,
/// non-mutating outcome: an attacker cannot cause two other owners' entities
/// to become associated merely by choosing the same address.
pub(crate) async fn maybe_link_local_mirror(
    state: &AppState,
    localpart: &str,
    actor_bare_jid: &str,
) -> Result<MixMucLinkOutcome> {
    if !state.config.mix_muc_mirror_enabled {
        return Ok(MixMucLinkOutcome::MissingCounterpart);
    }
    let outcome = state
        .mix_service()
        .link_local_muc_mirror(
            &format!("mix.{}", state.config.domain),
            localpart,
            actor_bare_jid,
            &state.config.domain,
        )
        .await?;
    if matches!(outcome, MixMucLinkOutcome::Linked) {
        tracing::info!(
            localpart,
            actor = actor_bare_jid,
            "linked XEP-0408 MIX/MUC mirror"
        );
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::{mirror_discovery_form, MirrorDirection};

    #[test]
    fn mirror_forms_use_the_exact_xep_0408_types_without_protocol_features() {
        let muc = mirror_discovery_form(MirrorDirection::Muc, "conference.example.test");
        assert!(muc.contains("urn:xmpp:mix:muc:0#muc-mirror"));
        assert!(muc.contains("var='muc-mirror'"));
        assert!(!muc.contains("<feature"));

        let mix = mirror_discovery_form(MirrorDirection::Mix, "mix.example.test");
        assert!(mix.contains("urn:xmpp:mix:muc:0#mix-mirror"));
        assert!(mix.contains("var='mix-mirror'"));
        assert!(!mix.contains("<feature"));
    }

    #[test]
    fn mirror_forms_escape_operator_controlled_domains() {
        let hostile = "mix.example.test' bad='1</value><feature var='evil'/>&🙂";
        let form = mirror_discovery_form(MirrorDirection::Mix, hostile);
        let document = roxmltree::Document::parse(&form).unwrap();
        let values = document
            .descendants()
            .filter(|node| node.is_element() && node.tag_name().name() == "value")
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 2);
        assert_eq!(values[1].text(), Some(hostile));
        assert_eq!(
            document
                .descendants()
                .filter(|node| node.is_element() && node.tag_name().name() == "feature")
                .count(),
            0
        );
    }

    #[test]
    fn mirror_advertisement_requires_both_operator_opt_in_and_a_durable_link() {
        assert!(super::conditional_mirror_discovery_form(
            false,
            true,
            MirrorDirection::Mix,
            "mix.example.test",
        )
        .is_empty());
        assert!(super::conditional_mirror_discovery_form(
            true,
            false,
            MirrorDirection::Mix,
            "mix.example.test",
        )
        .is_empty());
        assert!(!super::conditional_mirror_discovery_form(
            true,
            true,
            MirrorDirection::Mix,
            "mix.example.test",
        )
        .is_empty());
    }
}
