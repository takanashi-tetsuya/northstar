//! Channel presence processing, verified presence publication and route currency.

use super::*;

pub(super) fn presence_children(raw: &str) -> Result<(String, bool)> {
    let document = Document::parse(raw).context("malformed MIX presence")?;
    let root = document.root_element();
    anyhow::ensure!(root.tag_name().name() == "presence", "not a MIX presence");
    let unavailable = root.attribute("type") == Some("unavailable");
    anyhow::ensure!(
        matches!(
            root.attribute("type"),
            None | Some("available" | "unavailable")
        ),
        "unsupported MIX presence type"
    );
    let mut children = String::new();
    for child in root.children().filter(Node::is_element) {
        if child.tag_name().name() == "mix" && child.tag_name().namespace() == Some(PRESENCE_NS) {
            continue;
        }
        children.push_str(&raw[child.range()]);
    }
    Ok((children, unavailable))
}

pub(super) async fn process_channel_presence(
    state: &Arc<AppState>,
    actor_bare: &str,
    actor_full: &str,
    raw: &str,
) -> Result<Option<String>> {
    let document = Document::parse(raw).context("malformed MIX presence")?;
    let root = document.root_element();
    let to = root.attribute("to").unwrap_or_default();
    let id = root.attribute("id").unwrap_or_default();
    let target = CanonicalJid::parse_bare(to)?;
    let mix_domain = local_mix_domain(state);
    let Some(channel_localpart) = target.localpart() else {
        return Ok(Some(presence_error(
            id,
            to,
            actor_full,
            "modify",
            "jid-malformed",
        )));
    };
    if target.domainpart() != mix_domain {
        return Ok(None);
    }
    let Some(channel) = state
        .mix_service()
        .mix_channel(&mix_domain, channel_localpart)
        .await?
    else {
        return Ok(Some(presence_error(
            id,
            to,
            actor_full,
            "cancel",
            "item-not-found",
        )));
    };
    let (children, unavailable) = presence_children(raw)?;
    match state
        .mix_service()
        .store_mix_presence(channel.id, actor_bare, actor_full, &children, unavailable)
        .await?
    {
        PresenceOutcome::NotParticipant => Ok(Some(presence_error(
            id,
            &channel.jid(),
            actor_full,
            "auth",
            "forbidden",
        ))),
        PresenceOutcome::NotSharing => Ok(None),
        PresenceOutcome::Unchanged => Ok(None),
        PresenceOutcome::Published | PresenceOutcome::Retracted => Ok(None),
    }
}

/// A first presence may arrive before the advertised XEP-0115 hash has been
/// verified. Once capability verification succeeds, publish a conservative
/// available state so a fresh cache or server restart does not permanently
/// omit that resource from MIX. Later presence updates replace this item.
pub(crate) async fn publish_verified_mix_presence_with(
    context: &MixPresenceRecoveryContext,
    actor_full: &str,
    expected_connection_id: Uuid,
    expected_caps_generation: u64,
) -> Result<()> {
    let actor = crate::jid::CanonicalJid::parse(actor_full)?;
    let actor_full = actor.to_string();
    // Snapshot only the epoch identity and its shared gate. The authoritative
    // route is deliberately re-read after the async lock acquisition; using a
    // cloned pre-lock session here would let a delayed caps job act on a
    // removed or SM-replaced resource.
    let Some(mix_presence_gate) = context.routes().gate(&actor_full, expected_connection_id) else {
        return Ok(());
    };
    let expected_mix_presence_gate = Arc::clone(&mix_presence_gate);
    let Some(username) = actor.localpart() else {
        return Ok(());
    };
    let Some(user) = context.find_enabled_user(username).await? else {
        return Ok(());
    };
    let actor_bare = actor.bare();
    // A verified MIX-capable resource makes an already-persisted delivery
    // head eligible immediately. This is deliberately separate from the
    // presence projection below: a MAM/archive write or presence update never
    // acknowledges the durable recipient row.
    context.wake_delivery_recipient(&actor_bare).await?;
    let available = XmlElement::namespaced("presence", "jabber:client")
        .attr("from", &actor_full)
        .finish();
    for membership in context.pam_memberships(user.id).await? {
        if !pam_membership_receives(&membership, NODE_PRESENCE) {
            continue;
        }
        let Ok(channel) = CanonicalJid::parse_bare(&membership.channel_jid) else {
            tracing::warn!(channel = %membership.channel_jid, "ignored malformed persisted MIX membership JID");
            continue;
        };
        let domain = channel.domainpart();
        let directed = crate::services::xml_util::set_to(&available, &membership.channel_jid);
        // Hold the epoch for only one durable projection. User/membership
        // discovery above is intentionally outside it. Explicit presence or
        // teardown can therefore make progress between channels, and every
        // iteration revalidates the exact route before applying an effect.
        let mix_presence_epoch = Arc::clone(&mix_presence_gate).lock_owned().await;
        let Some((epoch_is_current, fallback_suppressed)) = context.routes().epoch_state(
            &actor_full,
            expected_connection_id,
            expected_caps_generation,
            &expected_mix_presence_gate,
            &membership.channel_jid,
        ) else {
            break;
        };
        if !epoch_is_current {
            break;
        }
        if fallback_suppressed {
            continue;
        }
        if domain == context.local_mix_domain() {
            let Some(channel) = context
                .mix_channel(
                    domain,
                    channel
                        .localpart()
                        .expect("joined MIX channel has a localpart"),
                )
                .await?
            else {
                continue;
            };
            let _ = context
                .ensure_presence(channel.id, &actor_bare, &actor_full)
                .await?;
        } else if context.federation_domain_allowed(domain) {
            context
                .send_federated(domain, directed, Some(actor_bare.clone()))
                .await;
        }
        drop(mix_presence_epoch);
    }
    Ok(())
}

pub(crate) fn mix_presence_route_is_current(
    state: &AppState,
    full_jid: &str,
    expected_connection_id: Uuid,
    expected_gate: &Arc<tokio::sync::Mutex<()>>,
    require_available: bool,
) -> bool {
    state.local_mix_presence_route_is_current(
        full_jid,
        expected_connection_id,
        expected_gate,
        require_available,
    )
}

pub(super) fn presence_error(
    id: &str,
    from: &str,
    to: &str,
    error_type: &str,
    condition: &str,
) -> String {
    let condition = XmlElement::dynamic(condition)
        .unwrap_or_else(|_| XmlElement::new("undefined-condition"))
        .attr("xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
    XmlElement::namespaced("presence", "jabber:client")
        .attr("type", "error")
        .attr("from", from)
        .attr("to", to)
        .attr("id", id)
        .child(
            XmlElement::new("error")
                .attr("type", error_type)
                .child(condition),
        )
        .finish()
}
