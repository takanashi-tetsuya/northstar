use super::{directed_grant, message_route, render};
use crate::listener::ListenerTurn;
use crate::presence_routing::FederatedPresenceRequest;
use crate::{
    ClusterControlOutcome, ExactControl, ExactControlKind, EXACT_CONTROL_DELIVERY_VERSION,
};
use anyhow::{Context, Result};
use northstar_federation_core::FederationRoute;
use northstar_roster_application::presence::{PresenceRepository, PresenceService};
use northstar_roster_application::probe_decision::{
    PresenceRoute, ProbeCandidate, ProbeDecision, ProbeQuery, ProbeStatus,
};
use northstar_roster_application::PolicyDirection;
use northstar_roster_core::{ExactPresenceRoute, PresenceAccount};
use northstar_session_application::replay::{
    pending_presence::{PendingPresenceAuthority, PendingPresenceRepository},
    PendingPresenceCursor, PendingPresenceReplay, ReplayRoute, ReplayService,
};
use northstar_stream::local_routes::{
    pending_subscription::deliver_pending_subscription, session::OnlineSession,
    session_table::LocalSessionTable,
};
use northstar_time::DateTime;
use northstar_xml_builder::{rewrite::set_to, XmlElement};
use northstar_xmpp_types::jid::CanonicalJid;
use roxmltree::Document;
use serde_json::Value;
use std::sync::atomic::Ordering;

pub(in crate::listener) fn is_federated_presence_control(json: &Value) -> bool {
    let control = &json["exact_control"];
    json["federated_inbound_presence"].as_bool() == Some(true)
        || control["kind"].as_str() == Some("federated_inbound_presence")
        || (!control["remote_peer"].is_null()
            && matches!(
                control["kind"].as_str(),
                Some("current_presence_replay" | "probe_response")
            ))
}

pub(in crate::listener) async fn handle_federated_presence(
    owner: &FederatedPresenceOwner<
        '_,
        impl PresenceRepository,
        impl PendingPresenceRepository,
        impl FederationRoute,
    >,
    json: &Value,
    turn: &mut ListenerTurn,
) {
    match deliver_control(owner, json).await {
        Ok(delivery) => {
            turn.delivered = delivery.delivered;
            turn.control_outcome = delivery.status.map(|status| match status {
                ProbeStatus::Silent => ClusterControlOutcome::PresenceSilent,
                ProbeStatus::Unsubscribed => ClusterControlOutcome::PresenceUnsubscribed,
                ProbeStatus::Unavailable => ClusterControlOutcome::PresenceUnavailable,
                ProbeStatus::Available => ClusterControlOutcome::PresenceAvailable,
            });
            turn.control_processed = Some(true);
        }
        Err(error) => {
            tracing::warn!(?error, "federated presence control rejected");
            turn.control_processed = Some(false);
        }
    }
}

pub(crate) async fn deliver_control(
    owner: &FederatedPresenceOwner<
        '_,
        impl PresenceRepository,
        impl PendingPresenceRepository,
        impl FederationRoute,
    >,
    json: &Value,
) -> Result<FederatedPresenceDelivery> {
    anyhow::ensure!(
        json["protocol_version"].as_str() == Some(EXACT_CONTROL_DELIVERY_VERSION)
            && [
                "federated_inbound_presence",
                "current_presence_replay",
                "presence_probe",
                "probe_response",
                "presence_subscription",
            ]
            .into_iter()
            .all(|field| json
                .get(field)
                .is_none_or(|value| value.as_bool() == Some(false))),
        "federated presence requires a v15 exact control"
    );
    let control: ExactControl = serde_json::from_value(json["exact_control"].clone())?;
    let request = FederatedPresenceRequest {
        target: json["target"].as_str().context("missing presence target")?,
        sender: json["sender"].as_str().context("missing presence sender")?,
        stanza: json["stanza"].as_str().context("missing presence stanza")?,
        remote_peer: control
            .remote_peer
            .as_deref()
            .context("missing remote peer")?,
        kind: control.kind,
        pending_created_at_micros: serde_json::from_value(
            json["pending_created_at_micros"].clone(),
        )?,
    };
    owner.deliver(request, &control).await
}

#[derive(Debug, Default)]
pub(crate) struct FederatedPresenceDelivery {
    pub(crate) delivered: usize,
    pub(crate) status: Option<ProbeStatus>,
}

/// Local effects shared by ingress and by the signed cluster listener.
pub struct FederatedPresenceOwner<'a, P, R, F> {
    sessions: LocalSessionTable,
    pub(crate) presence: &'a PresenceService<P>,
    replay: &'a ReplayService<R>,
    federation: &'a F,
    local_domain: &'a str,
}

impl<'a, P, R, F> FederatedPresenceOwner<'a, P, R, F>
where
    P: PresenceRepository,
    R: PendingPresenceRepository,
    F: FederationRoute,
{
    pub fn new(
        sessions: LocalSessionTable,
        presence: &'a PresenceService<P>,
        replay: &'a ReplayService<R>,
        federation: &'a F,
        local_domain: &'a str,
    ) -> Self {
        Self {
            sessions,
            presence,
            replay,
            federation,
            local_domain,
        }
    }

    pub(crate) async fn deliver(
        &self,
        request: FederatedPresenceRequest<'_>,
        control: &ExactControl,
    ) -> Result<FederatedPresenceDelivery> {
        anyhow::ensure!(
            request.stanza.len() <= northstar_stream::MAX_XMPP_FRAME_BYTES,
            "federated presence stanza exceeds frame limit"
        );
        let document = Document::parse(request.stanza)?;
        crate::validate_exact_control(control, request.target, &document)?;
        let root = document.root_element();
        let kind = root.attribute("type");
        let (from, sender, target, addressed) = (
            CanonicalJid::parse(root.attribute("from").context("missing presence from")?)?,
            CanonicalJid::parse(request.sender)?,
            CanonicalJid::parse(request.target)?,
            CanonicalJid::parse(root.attribute("to").context("missing presence to")?)?,
        );
        let subscription = crate::is_presence_subscription_stanza(&document);
        let endpoints_match = if subscription {
            from.resourcepart().is_none()
                && from.to_bare() == sender.to_bare()
                && target.resourcepart().is_none()
                && addressed.to_bare() == target
        } else {
            from == sender && addressed == target
        };
        anyhow::ensure!(
            control.remote_peer.as_deref() == Some(request.remote_peer)
                && control.sequence.is_none()
                && matches!(
                    control.kind,
                    ExactControlKind::FederatedInboundPresence
                        | ExactControlKind::ProbeResponse
                        | ExactControlKind::CurrentPresenceReplay
                )
                && target.domainpart() == self.local_domain
                && from.domainpart() == request.remote_peer
                && from.domainpart() != self.local_domain
                && endpoints_match
                && sender.to_string() == request.sender
                && (control.kind != ExactControlKind::CurrentPresenceReplay
                    || (target.resourcepart().is_none() && sender.resourcepart().is_none()))
                && (request.pending_created_at_micros.is_some() == (kind == Some("subscribe"))),
            "invalid federated presence effect or endpoints"
        );
        let username = target.localpart().context("missing local account name")?;
        let account = PresenceAccount {
            id: control.account_id,
            auth_generation: control.auth_generation,
            username: username.to_owned(),
        };
        let directed_probe =
            control.kind == ExactControlKind::ProbeResponse && target.resourcepart().is_some();
        let candidates = self.candidates(control, directed_probe.then_some(request.sender));
        match control.kind {
            ExactControlKind::FederatedInboundPresence => {
                anyhow::ensure!(
                    kind != Some("probe"),
                    "federated probe requires its own effect"
                );
                let pending = request
                    .pending_created_at_micros
                    .map(|micros| {
                        Ok::<_, anyhow::Error>(PendingPresenceReplay {
                            requester: sender.bare(),
                            requester_auth_generation: None,
                            stanza: Some(request.stanza.to_owned()),
                            cursor: PendingPresenceCursor {
                                key: sender.bare(),
                                source: 1,
                                created_at: DateTime::from_timestamp_micros(micros)
                                    .context("invalid pending request timestamp")?,
                            },
                        })
                    })
                    .transpose()?;
                let available_only = target.resourcepart().is_none() || subscription;
                let roster_only = subscription && kind != Some("subscribe");
                self.forward(
                    request,
                    &candidates,
                    available_only,
                    roster_only,
                    pending.as_ref(),
                )
                .await
            }
            ExactControlKind::CurrentPresenceReplay if kind == Some("unavailable") => {
                self.revoke(request, &candidates).await?;
                Ok(FederatedPresenceDelivery::default())
            }
            ExactControlKind::CurrentPresenceReplay | ExactControlKind::ProbeResponse => {
                let explicit = control.kind == ExactControlKind::ProbeResponse;
                self.reply(request, &account, &candidates, explicit).await
            }
            _ => unreachable!("federated presence effect validated above"),
        }
    }

    fn candidates(
        &self,
        control: &ExactControl,
        directed_requester: Option<&str>,
    ) -> Vec<ProbeCandidate> {
        control
            .expected_connections
            .iter()
            .filter_map(|(jid, connection_id)| {
                let exact = ExactPresenceRoute {
                    account_id: control.account_id,
                    auth_generation: control.auth_generation,
                    connection_id: *connection_id,
                    full_jid: jid.clone(),
                    node_id: None,
                };
                self.sessions
                    .with_exact_message_route(&message_route(&exact), |session| {
                        (session.lifecycle.load(Ordering::Acquire) == 0).then(|| ProbeCandidate {
                            route: PresenceRoute {
                                exact,
                                active_list: session.privacy_active_snapshot(),
                            },
                            available: session.available.load(Ordering::Acquire),
                            directed: directed_requester
                                .is_some_and(|sender| directed_grant(session, sender)),
                        })
                    })
                    .flatten()
            })
            .collect()
    }

    async fn forward(
        &self,
        request: FederatedPresenceRequest<'_>,
        candidates: &[ProbeCandidate],
        available_only: bool,
        roster_only: bool,
        pending: Option<&PendingPresenceReplay>,
    ) -> Result<FederatedPresenceDelivery> {
        let mut delivered = 0;
        for candidate in candidates
            .iter()
            .filter(|candidate| !available_only || candidate.available)
        {
            let route = &candidate.route;
            let exact = message_route(&route.exact);
            let epoch = self.sessions.with_exact_message_route(&exact, |session| {
                session.availability_generation.load(Ordering::Acquire)
            });
            let Some(epoch) = epoch else { continue };
            if !self
                .presence
                .read_communication_policy(&route.policy(request.sender, PolicyDirection::Inbound))
                .await?
                .allows()
            {
                continue;
            }
            if let Some(pending) = pending {
                let replay_route = ReplayRoute {
                    recipient_id: exact.account_id,
                    auth_generation: exact.auth_generation,
                    connection_id: exact.connection_id,
                    full_jid: exact.full_jid.clone(),
                };
                if !self
                    .replay
                    .pending_presence_is_current(
                        PendingPresenceAuthority {
                            route: &replay_route,
                            expects_active: route.active_list.is_some(),
                        },
                        pending,
                    )
                    .await?
                {
                    continue;
                }
            }
            let stanza = if pending.is_some() || roster_only {
                set_to(request.stanza, &exact.full_jid)
            } else {
                request.stanza.to_owned()
            };
            let accepted = self.sessions.with_exact_message_route(&exact, |session| {
                if !current_selection(session, route)
                    || (available_only && !session.available.load(Ordering::Acquire))
                    || (roster_only && !session.roster_requested.load(Ordering::Acquire))
                {
                    return false;
                }
                if let Some(pending) = pending {
                    deliver_pending_subscription(session, epoch, (&pending.cursor).into(), || {
                        session.sender.try_send(stanza).is_ok()
                    })
                } else {
                    session.sender.try_send(stanza).is_ok()
                }
            });
            delivered += usize::from(accepted == Some(true));
        }
        Ok(FederatedPresenceDelivery {
            delivered,
            status: None,
        })
    }

    async fn reply(
        &self,
        request: FederatedPresenceRequest<'_>,
        account: &PresenceAccount,
        candidates: &[ProbeCandidate],
        explicit: bool,
    ) -> Result<FederatedPresenceDelivery> {
        let decision = self
            .presence
            .decide_probe(ProbeQuery {
                owner: account,
                target: request.target,
                requester: request.sender,
                candidates,
                recipients: &[],
                explicit,
            })
            .await?;
        let mut status = decision.status();
        let mut failed = false;
        let availability_only = explicit && request.target.contains('/');
        let namespace = if explicit {
            "jabber:server"
        } else {
            "jabber:client"
        };
        match decision {
            ProbeDecision::Available(deliveries) => {
                // One avatar read per reply; a failed read omits the photo.
                let hash = if availability_only {
                    Ok(None)
                } else {
                    self.presence.avatar_hash(account.id).await
                };
                let hash = hash.as_ref().map(|hash| hash.as_deref()).ok();
                for delivery in deliveries {
                    let route = &candidates[delivery.owner].route;
                    let reply = self
                        .sessions
                        .with_exact_message_route(&message_route(&route.exact), |session| {
                            (current_selection(session, route)
                                && session.available.load(Ordering::Acquire)
                                && (!delivery.directed || directed_grant(session, request.sender)))
                            .then(|| {
                                session.current_presence().map(|cached| {
                                    render(
                                        cached,
                                        &route.exact.full_jid,
                                        request.sender,
                                        availability_only,
                                        hash,
                                        namespace,
                                    )
                                })
                            })
                            .flatten()
                        })
                        .flatten();
                    if let Some(reply) = reply {
                        failed |= !self.federation.send(request.remote_peer, reply, None).await;
                    }
                }
            }
            ProbeDecision::Unavailable {
                directed: Some(index),
            } => {
                let route = &candidates[index].route;
                if self
                    .sessions
                    .with_exact_message_route(&message_route(&route.exact), |session| {
                        current_selection(session, route) && directed_grant(session, request.sender)
                    })
                    != Some(true)
                {
                    status = ProbeStatus::Silent;
                }
            }
            _ => {}
        }
        anyhow::ensure!(
            !failed,
            "federated presence reply could not be admitted to the outbox"
        );
        Ok(FederatedPresenceDelivery {
            delivered: 0,
            status: explicit.then_some(status),
        })
    }

    async fn revoke(
        &self,
        request: FederatedPresenceRequest<'_>,
        candidates: &[ProbeCandidate],
    ) -> Result<()> {
        let mut failed = false;
        for candidate in candidates.iter().filter(|candidate| candidate.available) {
            let route = &candidate.route;
            let mut policy = route.policy(request.sender, PolicyDirection::Outbound);
            // Revocation still withdraws prior visibility when a block is in place.
            policy.check_owner_block = false;
            if !self
                .presence
                .read_communication_policy(&policy)
                .await?
                .allows()
            {
                continue;
            }
            let current =
                self.sessions
                    .with_exact_message_route(&message_route(&route.exact), |session| {
                        current_selection(session, route)
                            && session.available.load(Ordering::Acquire)
                    });
            if current == Some(true) {
                let stanza = XmlElement::namespaced("presence", "jabber:client")
                    .attr("from", &route.exact.full_jid)
                    .attr("to", request.sender)
                    .attr("type", "unavailable")
                    .finish();
                failed |= !self
                    .federation
                    .send(request.remote_peer, stanza, None)
                    .await;
            }
        }
        anyhow::ensure!(
            !failed,
            "federated unavailable could not be admitted to the outbox"
        );
        Ok(())
    }
}

fn current_selection(session: &OnlineSession, route: &PresenceRoute) -> bool {
    session.lifecycle.load(Ordering::Acquire) == 0
        && session.privacy_active_snapshot() == route.active_list
}
