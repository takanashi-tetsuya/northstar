//! Parsing of client MIX IQ requests into channel operations.

use super::*;

#[derive(Clone, Debug)]
pub(super) struct OwnedIq {
    pub(super) id: String,
    pub(super) kind: String,
    pub(super) from: Option<String>,
    pub(super) to: Option<String>,
    pub(super) operation: IqOperation,
}

#[derive(Clone, Debug)]
pub(super) struct MixDiscoInfoRequest {
    pub(super) id: String,
    pub(super) from: String,
    pub(super) to: String,
    pub(super) node: Option<String>,
    pub(super) error: Option<&'static str>,
}

pub(super) fn parse_mix_disco_info(raw: &str) -> Result<Option<MixDiscoInfoRequest>> {
    let document = Document::parse(raw).context("malformed MIX disco IQ")?;
    let root = document.root_element();
    if root.tag_name().name() != "iq" {
        return Ok(None);
    }
    let elements = root.children().filter(Node::is_element).collect::<Vec<_>>();
    let Some(query) = elements.first().copied().filter(|query| {
        query.tag_name().name() == "query"
            && query.tag_name().namespace() == Some("http://jabber.org/protocol/disco#info")
    }) else {
        return Ok(None);
    };
    let id = root.attribute("id").unwrap_or_default().to_owned();
    let from = root.attribute("from").unwrap_or_default().to_owned();
    let to = root.attribute("to").unwrap_or_default().to_owned();
    let node = query.attribute("node").map(str::to_owned);
    let error = if root.attribute("type") != Some("get")
        || elements.len() != 1
        || id.is_empty()
        || from.is_empty()
        || to.is_empty()
        || query
            .attributes()
            .any(|attribute| attribute.namespace().is_some() || attribute.name() != "node")
        || query.children().any(|child| child.is_element())
        || query
            .children()
            .filter(|child| child.is_text())
            .any(|child| child.text().is_some_and(|text| !text.trim().is_empty()))
        || node.as_deref().is_some_and(|node| {
            node.is_empty() || node.len() > 1_024 || node.chars().any(char::is_control)
        }) {
        Some("bad-request")
    } else {
        None
    };
    Ok(Some(MixDiscoInfoRequest {
        id,
        from,
        to,
        node,
        error,
    }))
}

#[derive(Clone, Debug)]
pub(super) enum IqOperation {
    Create {
        channel: Option<String>,
    },
    Destroy {
        channel: String,
    },
    Join(JoinData),
    Leave,
    SetNick(String),
    UpdateSubscription {
        subscribe: Vec<String>,
        unsubscribe: Vec<String>,
    },
    PamJoin {
        channel: String,
        join: JoinData,
    },
    PamLeave {
        channel: String,
    },
    PubSubGet {
        node: String,
        max: i64,
    },
    PubSubPublish {
        node: String,
        item_count: usize,
        item_ids: Vec<String>,
        fields: BTreeMap<String, Vec<String>>,
        payloads: Vec<String>,
    },
    PubSubRetract {
        node: String,
        item_ids: Vec<String>,
    },
    Mam(super::super::mam::ParsedMamQuery),
    MamForm,
    MamMetadata,
    MamError(&'static str),
    Ping,
    RegisterNick(Option<String>),
    UserPreferenceGet,
    UserPreferenceSet(BTreeMap<String, Vec<String>>),
    Invite {
        invitee: String,
    },
    /// An IQ result/error whose payload is empty or not otherwise a MIX
    /// request. Used only to correlate federated PAM replies.
    Response,
}

#[derive(Clone, Debug)]
pub(super) struct JoinData {
    pub(super) nodes: Vec<String>,
    pub(super) nick: Option<String>,
    pub(super) invitation: Option<MixInvitationProof>,
    pub(super) preference: Option<MixParticipantPreference>,
    pub(super) anonymous_profile: bool,
}

pub(super) fn parse_iq(raw: &str) -> Result<Option<OwnedIq>> {
    let document = Document::parse(raw).context("malformed MIX IQ")?;
    let root = document.root_element();
    if root.tag_name().name() != "iq" {
        return Ok(None);
    }
    let kind = root.attribute("type").unwrap_or_default().to_owned();
    anyhow::ensure!(
        matches!(kind.as_str(), "get" | "set" | "result" | "error"),
        "invalid MIX IQ type"
    );
    let id = root.attribute("id").unwrap_or_default();
    anyhow::ensure!(
        !id.is_empty() && id.len() <= 1_024 && !id.chars().any(char::is_control),
        "invalid MIX IQ id"
    );
    let elements = root.children().filter(Node::is_element).collect::<Vec<_>>();
    match kind.as_str() {
        "get" | "set" => anyhow::ensure!(elements.len() == 1, "invalid MIX IQ payload count"),
        "result" => anyhow::ensure!(elements.len() <= 1, "invalid MIX IQ result payload count"),
        "error" => {
            anyhow::ensure!(
                (1..=2).contains(&elements.len())
                    && elements
                        .iter()
                        .filter(|node| node.tag_name().name() == "error")
                        .count()
                        == 1,
                "invalid MIX IQ error payload"
            );
        }
        _ => unreachable!(),
    }
    let child = elements.first().copied();
    let operation = if matches!(kind.as_str(), "result" | "error") {
        IqOperation::Response
    } else {
        match child.map(|child| (child, child.tag_name().name(), child.tag_name().namespace())) {
            Some((child, "create", Some(CORE_NS))) => {
                anyhow::ensure!(
                    !child.children().any(|node| node.is_element()),
                    "invalid MIX create"
                );
                IqOperation::Create {
                    channel: child.attribute("channel").map(str::to_owned),
                }
            }
            Some((child, "destroy", Some(CORE_NS))) => {
                anyhow::ensure!(
                    !child.children().any(|node| node.is_element()),
                    "invalid MIX destroy"
                );
                let channel = child.attribute("channel").unwrap_or_default();
                anyhow::ensure!(!channel.is_empty(), "MIX destroy is missing channel");
                IqOperation::Destroy {
                    channel: channel.to_owned(),
                }
            }
            Some((child, "join", Some(CORE_NS | ANON_NS | MISC_NS))) => {
                IqOperation::Join(parse_join(child)?)
            }
            Some((child, "leave", Some(CORE_NS))) => {
                anyhow::ensure!(
                    !child.children().any(|node| node.is_element()),
                    "invalid MIX leave"
                );
                IqOperation::Leave
            }
            Some((child, "setnick", Some(CORE_NS))) => {
                let nick = child
                    .children()
                    .filter(Node::is_element)
                    .collect::<Vec<_>>();
                anyhow::ensure!(
                    nick.len() == 1
                        && nick[0].tag_name().name() == "nick"
                        && nick[0].tag_name().namespace() == Some(CORE_NS)
                        && !nick[0].children().any(|node| node.is_element()),
                    "invalid MIX setnick"
                );
                IqOperation::SetNick(crate::services::mix::prepare_mix_nick(
                    nick[0].text().unwrap_or_default(),
                )?)
            }
            Some((child, "update-subscription", Some(CORE_NS))) => {
                let (subscribe, unsubscribe) = parse_subscription_changes(child)?;
                IqOperation::UpdateSubscription {
                    subscribe,
                    unsubscribe,
                }
            }
            Some((child, "client-join", Some(PAM_NS))) => {
                let channel = child.attribute("channel").unwrap_or_default().to_owned();
                let children = child
                    .children()
                    .filter(Node::is_element)
                    .collect::<Vec<_>>();
                anyhow::ensure!(
                    children.len() == 1
                        && children[0].tag_name().name() == "join"
                        && matches!(children[0].tag_name().namespace(), Some(CORE_NS | ANON_NS)),
                    "invalid MIX-PAM client-join"
                );
                IqOperation::PamJoin {
                    channel,
                    join: parse_join(children[0])?,
                }
            }
            Some((child, "client-leave", Some(PAM_NS))) => {
                let children = child
                    .children()
                    .filter(Node::is_element)
                    .collect::<Vec<_>>();
                anyhow::ensure!(
                    children.len() == 1
                        && children[0].tag_name().name() == "leave"
                        && children[0].tag_name().namespace() == Some(CORE_NS)
                        && !children[0].children().any(|node| node.is_element()),
                    "invalid MIX-PAM client-leave"
                );
                IqOperation::PamLeave {
                    channel: child.attribute("channel").unwrap_or_default().to_owned(),
                }
            }
            Some((child, "pubsub", Some(PUBSUB_NS))) => parse_pubsub(child, raw)?,
            Some((child, "register", Some(MISC_NS))) => {
                let children = child
                    .children()
                    .filter(Node::is_element)
                    .collect::<Vec<_>>();
                anyhow::ensure!(children.len() <= 1, "invalid MIX nick registration");
                let nick = match children.as_slice() {
                    [] => None,
                    [nick]
                        if nick.tag_name().name() == "nick"
                            && nick.tag_name().namespace() == Some(MISC_NS)
                            && !nick.children().any(|node| node.is_element()) =>
                    {
                        Some(crate::services::mix::prepare_mix_nick(
                            nick.text().unwrap_or_default(),
                        )?)
                    }
                    _ => anyhow::bail!("invalid MIX nick registration"),
                };
                IqOperation::RegisterNick(nick)
            }
            Some((child, "user-preference", Some(ANON_NS))) => {
                let forms = child
                    .children()
                    .filter(|node| is_xdata(*node))
                    .collect::<Vec<_>>();
                anyhow::ensure!(forms.len() <= 1, "invalid MIX preference form count");
                if kind == "get" {
                    anyhow::ensure!(forms.is_empty(), "MIX preference get must be empty");
                    IqOperation::UserPreferenceGet
                } else {
                    anyhow::ensure!(forms.len() == 1, "MIX preference set needs a form");
                    IqOperation::UserPreferenceSet(parse_fields(forms[0])?)
                }
            }
            Some((child, "invite", Some(MISC_NS))) if kind == "get" => {
                let invitees = child
                    .children()
                    .filter(Node::is_element)
                    .collect::<Vec<_>>();
                anyhow::ensure!(
                    invitees.len() == 1
                        && invitees[0].tag_name().name() == "invitee"
                        && invitees[0].tag_name().namespace() == Some(MISC_NS)
                        && !invitees[0].children().any(|node| node.is_element()),
                    "invalid MIX invitation request"
                );
                IqOperation::Invite {
                    invitee: northstar_xmpp_types::jid::canonicalize_bare(
                        invitees[0].text().unwrap_or_default(),
                    )?,
                }
            }
            Some((child, "query", Some(MAM_NS))) if kind == "get" => {
                if child.attributes().len() == 0
                    && !child.children().any(|node| node.is_element())
                    && child.text().is_none_or(|text| text.trim().is_empty())
                {
                    IqOperation::MamForm
                } else {
                    IqOperation::MamError("bad-request")
                }
            }
            Some((child, "query", Some(MAM_NS))) if kind == "set" => {
                match super::super::mam::parse_mam_query(child) {
                    Ok(query) => IqOperation::Mam(query),
                    Err(condition) => IqOperation::MamError(condition),
                }
            }
            Some((child, "metadata", Some(MAM_NS))) if kind == "get" => {
                if child.attributes().len() == 0
                    && !child.children().any(|node| node.is_element())
                    && child.text().is_none_or(|text| text.trim().is_empty())
                {
                    IqOperation::MamMetadata
                } else {
                    IqOperation::MamError("bad-request")
                }
            }
            Some((child, "ping", Some(northstar_xep_0199::NAMESPACE))) => {
                northstar_xep_0199::parse_ping_element(child)
                    .map_err(|error| anyhow::anyhow!("invalid MIX ping: {error}"))?;
                IqOperation::Ping
            }
            _ => return Ok(None),
        }
    };
    Ok(Some(OwnedIq {
        id: id.to_owned(),
        kind,
        from: root.attribute("from").map(str::to_owned),
        to: root.attribute("to").map(str::to_owned),
        operation,
    }))
}

pub(super) fn mix_iq_route_candidate(raw: &str, mix_domain: &str) -> bool {
    let Ok(document) = Document::parse(raw) else {
        return false;
    };
    let root = document.root_element();
    if root.tag_name().name() != "iq" {
        return false;
    }
    // PAM requests are addressed to the user's own bare JID rather than the
    // MIX service. Their exact target is checked after the full parse.
    if root
        .children()
        .find(Node::is_element)
        .is_some_and(|child| child.tag_name().namespace() == Some(PAM_NS))
    {
        return true;
    }
    // Everything else owned by the MIX parser is addressed to the MIX
    // service. In particular, a general-purpose PubSub <create/><configure/>
    // request to pubsub.example must never be parsed as a malformed MIX
    // PubSub operation merely because both protocols use the PubSub namespace.
    root.attribute("to")
        .and_then(|to| CanonicalJid::parse(to).ok())
        .is_some_and(|target| target.domainpart() == mix_domain)
}

pub(super) fn parse_join(node: Node<'_, '_>) -> Result<JoinData> {
    let mut nodes = Vec::new();
    let mut nick = None;
    let mut invitation = None;
    let mut preference = None;
    let anonymous_profile = node.tag_name().namespace() == Some(ANON_NS);
    for child in node.children().filter(Node::is_element) {
        match (child.tag_name().name(), child.tag_name().namespace()) {
            ("subscribe", Some(CORE_NS | ANON_NS | MISC_NS)) => {
                anyhow::ensure!(
                    !child.children().any(|node| node.is_element()),
                    "invalid MIX subscribe payload"
                );
                nodes.push(
                    child
                        .attribute("node")
                        .context("MIX subscribe missing node")?
                        .to_owned(),
                );
            }
            ("nick", Some(CORE_NS | ANON_NS | MISC_NS)) => {
                anyhow::ensure!(nick.is_none(), "duplicate MIX nick");
                anyhow::ensure!(
                    !child.children().any(|node| node.is_element()),
                    "invalid MIX nick payload"
                );
                nick = Some(crate::services::mix::prepare_mix_nick(
                    child.text().unwrap_or_default(),
                )?);
            }
            ("invitation", Some(MISC_NS)) => {
                anyhow::ensure!(invitation.is_none(), "duplicate MIX invitation");
                let mut values = BTreeMap::new();
                for field in child.children().filter(Node::is_element) {
                    anyhow::ensure!(
                        field.tag_name().namespace() == Some(MISC_NS)
                            && matches!(
                                field.tag_name().name(),
                                "inviter" | "invitee" | "channel" | "token"
                            )
                            && !field.children().any(|node| node.is_element()),
                        "invalid MIX invitation"
                    );
                    anyhow::ensure!(
                        values
                            .insert(
                                field.tag_name().name().to_owned(),
                                field.text().unwrap_or_default().to_owned(),
                            )
                            .is_none(),
                        "duplicate MIX invitation field"
                    );
                }
                invitation = Some(MixInvitationProof {
                    inviter_jid: values.remove("inviter").context("missing MIX inviter")?,
                    invitee_jid: values.remove("invitee").context("missing MIX invitee")?,
                    channel_jid: values.remove("channel").context("missing MIX channel")?,
                    token: values
                        .remove("token")
                        .context("missing MIX invitation token")?,
                });
            }
            ("x", Some("jabber:x:data")) if anonymous_profile => {
                anyhow::ensure!(preference.is_none(), "duplicate MIX preference form");
                let fields = parse_fields(child)?;
                preference = Some(parse_preference_submission(&fields, None)?);
            }
            _ => anyhow::bail!("unknown MIX join child"),
        }
    }
    let nodes = crate::services::mix::valid_join_nodes(&nodes)?;
    Ok(JoinData {
        nodes,
        nick,
        invitation,
        preference,
        anonymous_profile,
    })
}

pub(super) fn parse_subscription_changes(node: Node<'_, '_>) -> Result<(Vec<String>, Vec<String>)> {
    let mut subscribe = Vec::new();
    let mut unsubscribe = Vec::new();
    for child in node.children().filter(Node::is_element) {
        let target = match (child.tag_name().name(), child.tag_name().namespace()) {
            ("subscribe", Some(CORE_NS)) => &mut subscribe,
            ("unsubscribe", Some(CORE_NS)) => &mut unsubscribe,
            _ => anyhow::bail!("unknown MIX subscription child"),
        };
        anyhow::ensure!(
            !child.children().any(|node| node.is_element()),
            "invalid MIX subscription payload"
        );
        target.push(
            child
                .attribute("node")
                .context("MIX subscription missing node")?
                .to_owned(),
        );
    }
    Ok((
        crate::services::mix::valid_join_nodes(&subscribe)?,
        crate::services::mix::valid_join_nodes(&unsubscribe)?,
    ))
}

pub(super) fn parse_pubsub(pubsub: Node<'_, '_>, raw: &str) -> Result<IqOperation> {
    let actions = pubsub
        .children()
        .filter(Node::is_element)
        .collect::<Vec<_>>();
    anyhow::ensure!(actions.len() == 1, "invalid MIX PubSub action count");
    let action = actions[0];
    anyhow::ensure!(
        action.tag_name().namespace() == Some(PUBSUB_NS),
        "invalid MIX PubSub action namespace"
    );
    let node = action.attribute("node").unwrap_or_default().to_owned();
    match action.tag_name().name() {
        "items" => {
            anyhow::ensure!(
                !action.children().any(|node| node.is_element()),
                "MIX item selection is not supported"
            );
            let max = action
                .attribute("max_items")
                .map(str::parse::<i64>)
                .transpose()
                .context("invalid MIX max_items")?
                .unwrap_or(MAX_ITEMS_PAGE)
                .clamp(1, MAX_ITEMS_PAGE);
            Ok(IqOperation::PubSubGet { node, max })
        }
        "publish" => {
            let children = action
                .children()
                .filter(Node::is_element)
                .collect::<Vec<_>>();
            anyhow::ensure!(children.len() == 1, "invalid MIX publish payload");
            let items = if children[0].tag_name().name() == "item"
                && children[0].tag_name().namespace() == Some(PUBSUB_NS)
            {
                vec![children[0]]
            } else if children[0].tag_name().name() == "items"
                && children[0].tag_name().namespace() == Some(PUBSUB_NS)
            {
                let items = children[0]
                    .children()
                    .filter(Node::is_element)
                    .collect::<Vec<_>>();
                anyhow::ensure!(
                    items.iter().all(|item| {
                        item.tag_name().name() == "item"
                            && item.tag_name().namespace() == Some(PUBSUB_NS)
                    }),
                    "invalid MIX publish item"
                );
                items
            } else {
                anyhow::bail!("invalid MIX publish payload")
            };
            anyhow::ensure!(
                !items.is_empty() && items.len() <= 64,
                "invalid MIX publish item count"
            );
            let item_ids = items
                .iter()
                .filter_map(|item| item.attribute("id").map(str::to_owned))
                .collect::<Vec<_>>();
            let forms = items
                .iter()
                .flat_map(|item| item.descendants().filter(|node| is_xdata(*node)))
                .collect::<Vec<_>>();
            anyhow::ensure!(forms.len() <= 1, "multiple MIX publish forms");
            Ok(IqOperation::PubSubPublish {
                node,
                item_count: items.len(),
                item_ids,
                fields: forms
                    .first()
                    .copied()
                    .map(parse_fields)
                    .transpose()?
                    .unwrap_or_default(),
                payloads: items
                    .iter()
                    .map(|item| {
                        item.children()
                            .filter(Node::is_element)
                            .map(|child| raw[child.range()].to_owned())
                            .collect::<String>()
                    })
                    .collect(),
            })
        }
        "retract" => {
            let items = action
                .children()
                .filter(Node::is_element)
                .collect::<Vec<_>>();
            anyhow::ensure!(
                !items.is_empty()
                    && items.len() <= 64
                    && items.iter().all(|item| {
                        item.tag_name().name() == "item"
                            && item.tag_name().namespace() == Some(PUBSUB_NS)
                            && item.attribute("id").is_some_and(|id| !id.is_empty())
                            && !item.children().any(|node| node.is_element())
                    }),
                "invalid MIX retract item count"
            );
            let item_ids = items
                .iter()
                .map(|item| item.attribute("id").unwrap_or_default().to_owned())
                .collect::<Vec<_>>();
            Ok(IqOperation::PubSubRetract { node, item_ids })
        }
        _ => anyhow::bail!("unsupported MIX PubSub operation"),
    }
}
