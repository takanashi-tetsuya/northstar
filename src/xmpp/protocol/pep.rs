use super::{Action, ProtocolSession};
use crate::xmpp::xml_util::*;
use crate::{
    db,
    state::{attr_escape, bare_jid, jid_domain, localpart},
};
use anyhow::Result;
use roxmltree::Node;
use std::collections::HashSet;

const NS_PUBSUB: &str = "http://jabber.org/protocol/pubsub";
const NS_PUBSUB_EVENT: &str = "http://jabber.org/protocol/pubsub#event";
const NS_XDATA: &str = "jabber:x:data";
const NS_OMEMO2: &str = "urn:xmpp:omemo:2";
const OMEMO_DEVICES: &str = "urn:xmpp:omemo:2:devices";
const OMEMO_BUNDLES: &str = "urn:xmpp:omemo:2:bundles";

impl ProtocolSession {
    pub(crate) async fn pep_publish(
        &self,
        id: &str,
        pubsub: Node<'_, '_>,
        raw: &str,
    ) -> Result<Action> {
        let Some(user) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        if let Some(retract) = pubsub.children().find(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(NS_PUBSUB)
                && node.tag_name().name() == "retract"
        }) {
            return self.pep_retract(id, user, retract).await;
        }
        let Some(publish) = pubsub.children().find(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(NS_PUBSUB)
                && node.tag_name().name() == "publish"
        }) else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        let Some(node) = publish.attribute("node") else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        if node.is_empty() || node.len() > 512 {
            return Ok(Action::Send(iq_error(id, "not-acceptable")));
        }
        let items: Vec<_> = publish
            .children()
            .filter(|child| {
                child.is_element()
                    && child.tag_name().namespace() == Some(NS_PUBSUB)
                    && child.tag_name().name() == "item"
            })
            .collect();
        if items.is_empty() {
            return Ok(Action::Send(pep_error(
                id,
                None,
                "modify",
                "bad-request",
                Some("item-required"),
            )));
        }
        if items.len() > db::PEP_MAX_ITEMS as usize {
            return Ok(Action::Send(pep_error(
                id,
                None,
                "modify",
                "not-allowed",
                Some("max-items-exceeded"),
            )));
        }

        let options = match publish_options(pubsub, node) {
            Ok(options) => options,
            Err(()) => {
                return Ok(Action::Send(pep_error(
                    id,
                    None,
                    "modify",
                    "bad-request",
                    Some("precondition-not-met"),
                )))
            }
        };
        let mut normalized = Vec::with_capacity(items.len());
        let mut assigned_ids = Vec::new();
        let mut unique_ids = HashSet::new();
        for item in items {
            let generated = item.attribute("id").is_none();
            let item_id = item
                .attribute("id")
                .map(str::to_owned)
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            if item_id.is_empty()
                || item_id.len() > 1024
                || !unique_ids.insert(item_id.clone())
                || !valid_pep_payload(node, &item_id, item)
            {
                return Ok(Action::Send(pep_error(
                    id,
                    None,
                    "modify",
                    "bad-request",
                    Some("invalid-payload"),
                )));
            }
            let range = item.range();
            let item_xml = normalized_pep_item(&raw[range], &item_id, generated);
            if item_xml.len() > 512 * 1024 {
                return Ok(Action::Send(pep_error(
                    id,
                    None,
                    "modify",
                    "not-acceptable",
                    Some("payload-too-big"),
                )));
            }
            normalized.push((item_id.clone(), item_xml));
            if generated {
                assigned_ids.push(item_id);
            }
        }
        if normalized.len() > options.config.max_items as usize {
            return Ok(Action::Send(pep_error(
                id,
                None,
                "modify",
                "not-allowed",
                Some("max-items-exceeded"),
            )));
        }
        let borrowed = normalized
            .iter()
            .map(|(item_id, payload)| (item_id.as_str(), payload.as_str()))
            .collect::<Vec<_>>();
        if !db::publish_pep_items(
            &self.state.pool,
            user.id,
            node,
            options.config,
            options.explicit,
            &borrowed,
        )
        .await?
        {
            return Ok(Action::Send(pep_error(
                id,
                None,
                "cancel",
                "conflict",
                Some("precondition-not-met"),
            )));
        }

        let payload = normalized
            .iter()
            .map(|(_, payload)| payload.as_str())
            .collect::<String>();
        self.fan_out_pep_event(node, &payload).await?;
        self.state.metrics.pep_items_published_total.fetch_add(
            normalized.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

        if assigned_ids.is_empty() {
            Ok(Action::Send(iq_result(id, "")))
        } else {
            let items = assigned_ids
                .iter()
                .map(|item_id| format!("<item id='{}'/>", attr_escape(item_id)))
                .collect::<String>();
            Ok(Action::Send(iq_result(
                id,
                &format!(
                    "<pubsub xmlns='{NS_PUBSUB}'><publish node='{}'>{items}</publish></pubsub>",
                    attr_escape(node),
                ),
            )))
        }
    }

    async fn pep_retract(
        &self,
        id: &str,
        user: &db::User,
        retract: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(node) = retract.attribute("node") else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        if node.is_empty() || node.len() > 512 {
            return Ok(Action::Send(iq_error(id, "not-acceptable")));
        }
        let item_ids = retract
            .children()
            .filter(|child| {
                child.is_element()
                    && child.tag_name().namespace() == Some(NS_PUBSUB)
                    && child.tag_name().name() == "item"
            })
            .map(|item| item.attribute("id"))
            .collect::<Option<Vec<_>>>();
        let Some(item_ids) = item_ids.filter(|ids| {
            !ids.is_empty()
                && ids.len() <= db::PEP_MAX_ITEMS as usize
                && ids
                    .iter()
                    .all(|item_id| !item_id.is_empty() && item_id.len() <= 1024)
        }) else {
            return Ok(Action::Send(pep_error(
                id,
                None,
                "modify",
                "bad-request",
                Some("item-required"),
            )));
        };
        let Some(retracted) =
            db::retract_pep_items(&self.state.pool, user.id, node, &item_ids).await?
        else {
            return Ok(Action::Send(iq_error(id, "item-not-found")));
        };
        let notify = retract.attribute("notify") != Some("false")
            && retract.attribute("notify") != Some("0");
        if notify && retracted > 0 {
            let payload = item_ids
                .iter()
                .map(|item_id| format!("<retract id='{}'/>", attr_escape(item_id)))
                .collect::<String>();
            self.fan_out_pep_event(node, &payload).await?;
        }
        self.state
            .metrics
            .pep_items_retracted_total
            .fetch_add(retracted, std::sync::atomic::Ordering::Relaxed);
        Ok(Action::Send(iq_result(id, "")))
    }

    async fn fan_out_pep_event(&self, node: &str, payload: &str) -> Result<()> {
        let user = self
            .authenticated
            .as_ref()
            .expect("PEP event fan-out requires an authenticated owner");
        let owner = format!("{}@{}", user.username, self.state.config.domain);
        let event_for = |recipient: &str| {
            format!(
                "<message xmlns='jabber:client' from='{}' to='{}' type='headline'><event xmlns='{NS_PUBSUB_EVENT}'><items node='{}'>{payload}</items></event></message>",
                attr_escape(&owner),
                attr_escape(recipient),
                attr_escape(node),
            )
        };
        let own_event = event_for(&owner);
        for target in self.state.sessions_for(&owner) {
            let _ = target.sender.try_send(own_event.clone());
        }
        for (contact, _, subscription, _) in db::roster(&self.state.pool, user.id).await? {
            if !matches!(subscription.as_str(), "from" | "both")
                || db::is_blocked(&self.state.pool, user.id, &contact).await?
            {
                continue;
            }
            let remote_domain = jid_domain(&contact)
                .filter(|domain| !domain.eq_ignore_ascii_case(&self.state.config.domain));
            if remote_domain.is_none() {
                if let Some(recipient) =
                    db::find_user(&self.state.pool, localpart(&contact)).await?
                {
                    if db::is_blocked(&self.state.pool, recipient.id, &owner).await? {
                        continue;
                    }
                }
            }
            let event = event_for(&contact);
            if let Some(domain) = remote_domain {
                if self.state.config.federation_domain_allowed(domain) {
                    self.state.federation.send(domain, event, None);
                }
            } else {
                for target in self.state.sessions_for(&contact) {
                    let _ = target.sender.try_send(event.clone());
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn pep_get(
        &self,
        id: &str,
        iq: Node<'_, '_>,
        pubsub: Node<'_, '_>,
    ) -> Result<Action> {
        let Some(requester) = &self.authenticated else {
            return Ok(Action::Send(iq_error(id, "not-authorized")));
        };
        let Some(items) = pubsub.children().find(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(NS_PUBSUB)
                && node.tag_name().name() == "items"
        }) else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        let Some(node) = items.attribute("node") else {
            return Ok(Action::Send(iq_error(id, "bad-request")));
        };
        let owner_name = iq
            .attribute("to")
            .map(localpart)
            .unwrap_or(&requester.username)
            .to_ascii_lowercase();
        let Some(owner) = db::find_user(&self.state.pool, &owner_name).await? else {
            return Ok(Action::Send(iq_error(id, "item-not-found")));
        };
        let from = iq.attribute("to");
        if db::pep_node(&self.state.pool, owner.id, node)
            .await?
            .is_none()
        {
            return Ok(Action::Send(if let Some(from) = from {
                iq_error_from(id, from, "item-not-found")
            } else {
                iq_error(id, "item-not-found")
            }));
        }
        let requester_jid = format!("{}@{}", requester.username, self.state.config.domain);
        if !pep_access_allowed(
            &self.state.pool,
            &owner,
            &self.state.config.domain,
            node,
            &requester_jid,
        )
        .await?
        {
            return Ok(Action::Send(pep_error(
                id,
                from,
                "auth",
                "not-authorized",
                Some("presence-subscription-required"),
            )));
        }
        let requested_id = items
            .children()
            .find(|node| {
                node.is_element()
                    && node.tag_name().namespace() == Some(NS_PUBSUB)
                    && node.tag_name().name() == "item"
            })
            .and_then(|node| node.attribute("id"));
        let stored = db::pep_items(&self.state.pool, owner.id, node, requested_id, 100).await?;
        if stored.is_empty() {
            return Ok(Action::Send(if let Some(from) = from {
                iq_error_from(id, from, "item-not-found")
            } else {
                iq_error(id, "item-not-found")
            }));
        }
        let mut payload = format!(
            "<pubsub xmlns='{NS_PUBSUB}'><items node='{}'>",
            attr_escape(node)
        );
        for (_, item) in stored {
            payload.push_str(&item);
        }
        payload.push_str("</items></pubsub>");
        self.state
            .metrics
            .pep_retrievals_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some(from) = from {
            Ok(Action::Send(iq_result_from(id, from, &payload)))
        } else {
            Ok(Action::Send(iq_result(id, &payload)))
        }
    }
}

pub(crate) async fn pep_access_allowed(
    pool: &sqlx::PgPool,
    owner: &db::User,
    domain: &str,
    node: &str,
    requester_jid: &str,
) -> Result<bool> {
    let owner_jid = format!("{}@{domain}", owner.username);
    if bare_jid(requester_jid).eq_ignore_ascii_case(&owner_jid) {
        return Ok(true);
    }
    let Some(config) = db::pep_node(pool, owner.id, node).await? else {
        return Ok(false);
    };
    if db::is_blocked(pool, owner.id, bare_jid(requester_jid)).await? {
        return Ok(false);
    }
    if config.access_model == "open" {
        return Ok(true);
    }
    Ok(db::roster_item(pool, owner.id, bare_jid(requester_jid))
        .await?
        .is_some_and(|(_, _, subscription, _)| matches!(subscription.as_str(), "from" | "both")))
}

struct PublishOptions {
    config: db::PepNodeConfig,
    explicit: bool,
}

fn publish_options(pubsub: Node<'_, '_>, node: &str) -> std::result::Result<PublishOptions, ()> {
    let mut config = db::default_pep_node_config(node);
    let Some(options) = pubsub.children().find(|child| {
        child.is_element()
            && child.tag_name().namespace() == Some(NS_PUBSUB)
            && child.tag_name().name() == "publish-options"
    }) else {
        return Ok(PublishOptions {
            config,
            explicit: false,
        });
    };
    let form = options
        .children()
        .find(|child| {
            child.is_element()
                && child.tag_name().namespace() == Some(NS_XDATA)
                && child.tag_name().name() == "x"
                && child.attribute("type") == Some("submit")
        })
        .ok_or(())?;
    if xdata_field(form, "FORM_TYPE") != Some("http://jabber.org/protocol/pubsub#publish-options") {
        return Err(());
    }
    for field in form.children().filter(|child| {
        child.is_element()
            && child.tag_name().namespace() == Some(NS_XDATA)
            && child.tag_name().name() == "field"
    }) {
        match field.attribute("var").ok_or(())? {
            "FORM_TYPE" => {}
            "pubsub#access_model" => {
                let value = child_text(field, "value").ok_or(())?;
                if !matches!(value, "open" | "presence") {
                    return Err(());
                }
                config.access_model = value.to_owned();
            }
            "pubsub#max_items" => {
                let value = child_text(field, "value").ok_or(())?;
                config.max_items = if value == "max" {
                    db::PEP_MAX_ITEMS
                } else {
                    value.parse().map_err(|_| ())?
                };
                if !(1..=db::PEP_MAX_ITEMS).contains(&config.max_items) {
                    return Err(());
                }
            }
            _ => return Err(()),
        }
    }
    Ok(PublishOptions {
        config,
        explicit: true,
    })
}

fn valid_pep_payload(node: &str, item_id: &str, item: Node<'_, '_>) -> bool {
    let payloads = item
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    if payloads.len() != 1 {
        return false;
    }
    let payload = payloads[0];
    match node {
        OMEMO_DEVICES => {
            if payload.tag_name().name() != "devices"
                || payload.tag_name().namespace() != Some(NS_OMEMO2)
            {
                return false;
            }
            let mut ids = HashSet::new();
            payload
                .children()
                .filter(|child| child.is_element())
                .all(|device| {
                    device.tag_name().name() == "device"
                        && device.tag_name().namespace() == Some(NS_OMEMO2)
                        && device
                            .attribute("id")
                            .and_then(parse_positive_i32)
                            .is_some_and(|id| ids.insert(id))
                })
        }
        OMEMO_BUNDLES => {
            parse_positive_i32(item_id).is_some()
                && payload.tag_name().name() == "bundle"
                && payload.tag_name().namespace() == Some(NS_OMEMO2)
                && valid_omemo_bundle(payload)
        }
        _ => true,
    }
}

fn valid_omemo_bundle(bundle: Node<'_, '_>) -> bool {
    let required = ["spk", "spks", "ik", "prekeys"];
    if required.iter().any(|name| {
        !bundle.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == *name
                && child.tag_name().namespace() == Some(NS_OMEMO2)
        })
    }) {
        return false;
    }
    let Some(spk) = bundle.children().find(|child| {
        child.is_element()
            && child.tag_name().name() == "spk"
            && child.tag_name().namespace() == Some(NS_OMEMO2)
    }) else {
        return false;
    };
    if spk.attribute("id").and_then(parse_positive_i32).is_none()
        || spk.text().is_none_or(str::is_empty)
    {
        return false;
    }
    let Some(prekeys) = bundle.children().find(|child| {
        child.is_element()
            && child.tag_name().name() == "prekeys"
            && child.tag_name().namespace() == Some(NS_OMEMO2)
    }) else {
        return false;
    };
    let mut ids = HashSet::new();
    let keys = prekeys
        .children()
        .filter(|child| child.is_element())
        .collect::<Vec<_>>();
    !keys.is_empty()
        && keys.len() <= 1000
        && keys.iter().all(|key| {
            key.tag_name().name() == "pk"
                && key.tag_name().namespace() == Some(NS_OMEMO2)
                && key.text().is_some_and(|text| !text.is_empty())
                && key
                    .attribute("id")
                    .and_then(parse_positive_i32)
                    .is_some_and(|id| ids.insert(id))
        })
}

fn parse_positive_i32(value: &str) -> Option<i32> {
    value.parse::<i32>().ok().filter(|value| *value > 0)
}

fn pep_error(
    id: &str,
    from: Option<&str>,
    error_type: &str,
    condition: &str,
    pubsub_condition: Option<&str>,
) -> String {
    let from = from
        .map(|value| format!(" from='{}'", attr_escape(value)))
        .unwrap_or_default();
    let extension = pubsub_condition
        .map(|value| format!("<{value} xmlns='http://jabber.org/protocol/pubsub#errors'/>"))
        .unwrap_or_default();
    format!(
        "<iq xmlns='jabber:client' type='error'{from} id='{}'><error type='{}'><{} xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>{extension}</error></iq>",
        attr_escape(id),
        attr_escape(error_type),
        condition,
    )
}

fn normalized_pep_item(item_xml: &str, item_id: &str, generated: bool) -> String {
    if !generated {
        return item_xml.to_owned();
    }
    let Some(tag_end) = item_xml.find('>') else {
        return item_xml.to_owned();
    };
    let insert_at = item_xml[..tag_end]
        .rfind('/')
        .filter(|slash| item_xml[*slash..tag_end].trim() == "/")
        .unwrap_or(tag_end);
    let mut normalized = item_xml.to_owned();
    normalized.insert_str(insert_at, &format!(" id='{}'", attr_escape(item_id)));
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn generated_pep_id_is_inserted_into_stored_item() {
        assert_eq!(
            normalized_pep_item("<item><value/></item>", "generated", true),
            "<item id='generated'><value/></item>"
        );
        assert_eq!(
            normalized_pep_item("<item/>", "generated", true),
            "<item id='generated'/>"
        );
    }

    #[test]
    fn omemo_device_list_rejects_duplicate_or_invalid_ids() {
        let valid = Document::parse(
            "<item xmlns='http://jabber.org/protocol/pubsub' id='current'><devices xmlns='urn:xmpp:omemo:2'><device id='1'/><device id='2'/></devices></item>",
        )
        .unwrap();
        assert!(valid_pep_payload(
            OMEMO_DEVICES,
            "current",
            valid.root_element()
        ));
        for xml in [
            "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'><device id='1'/><device id='1'/></devices></item>",
            "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'><device id='0'/></devices></item>",
            "<item xmlns='http://jabber.org/protocol/pubsub'><devices xmlns='urn:xmpp:omemo:2'/><extra/></item>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(!valid_pep_payload(
                OMEMO_DEVICES,
                "current",
                document.root_element()
            ));
        }
    }

    #[test]
    fn publish_options_apply_omemo_defaults_and_reject_unknown_fields() {
        let xml = "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:omemo:2:bundles'/><publish-options><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field><field var='pubsub#access_model'><value>open</value></field><field var='pubsub#max_items'><value>max</value></field></x></publish-options></pubsub>";
        let document = Document::parse(xml).unwrap();
        let options = publish_options(document.root_element(), OMEMO_BUNDLES).unwrap();
        assert!(options.explicit);
        assert_eq!(options.config.access_model, "open");
        assert_eq!(options.config.max_items, db::PEP_MAX_ITEMS);

        let invalid = xml.replace("pubsub#max_items", "pubsub#unknown");
        let document = Document::parse(&invalid).unwrap();
        assert!(publish_options(document.root_element(), OMEMO_BUNDLES).is_err());
    }
}
