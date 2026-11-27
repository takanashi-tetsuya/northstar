//! XEP-0016 privacy lists.

use crate::SessionIdentity;
use anyhow::Result;
use northstar_roster_application::privacy::commands::PolicyCommandRepository;
use northstar_roster_application::privacy::{PrivacyRepository, PrivacyService};
use northstar_xml_builder::stanza::{iq_error, iq_result};
use roxmltree::Node;
use std::ops::ControlFlow;

mod active_selection;
mod codec;
mod list_commands;
mod push;
mod queries;

use codec::{element_children, valid_query_shell};
use push::push_privacy_list_change;

pub use active_selection::PrivacySelectionHost;
pub use queries::privacy_get;

const PRIVACY_NS: &str = northstar_xep_0016::NAMESPACE;
const MAX_PRIVACY_QUERY_BYTES: usize = 64 * 1024;

type PrivacySetControl = ControlFlow<(String, Option<String>), Result<(), &'static str>>;

/// What a client session provides to the XEP-0016 handlers.
pub trait PrivacySession: crate::SessionIdentity {
    /// The session's bound full JID, or `None` before resource binding.
    fn privacy_full_jid(&self) -> Option<&str>;
    /// The id of the session's connection.
    fn privacy_connection_id(&self) -> uuid::Uuid;
    /// The privacy service, over the repository the composition root binds.
    fn privacy_service(&self) -> &PrivacyService<impl PrivacyRepository>;
    /// The account-fenced command repository for privacy and blocklist IQs.
    fn privacy_commands(&self) -> &impl PolicyCommandRepository;
    /// Records that this session asked for privacy lists, which makes it a target of later pushes.
    fn privacy_mark_requested(&self);
    /// The name of the session's active list.
    fn privacy_active_list(&self) -> Option<String>;
    /// How many resources of `account` are connected to this node.
    fn privacy_local_resources(&self, account: &str) -> usize;
    /// Whether a resource of `account` is connected to another node.
    fn privacy_has_remote_resources(
        &self,
        account: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    /// Whether a resource of `account` on this node has the list `name` active.
    fn privacy_list_active_locally(&self, account: &str, name: &str) -> bool;
    /// Delivers the push `base`, addressed to `account`, to every other resource of the account
    /// that asked for privacy lists, on this node and on the others. Returns the push for this
    /// session when it asked for them, for the caller to send after its reply.
    fn privacy_push_change(
        &self,
        account: &str,
        name: &str,
        base: &str,
    ) -> impl std::future::Future<Output = Option<String>> + Send;
}

/// Handles a privacy-list query IQ set request, returning the reply and an optional push.
pub async fn privacy_set<H: crate::RosterSessionHost + PrivacySelectionHost>(
    session: &northstar_stream::protocol::ProtocolSession<H>,
    id: &str,
    root: Node<'_, '_>,
    query: Node<'_, '_>,
) -> Result<(String, Option<String>)> {
    let Some(user) = session.session_account() else {
        return Ok((iq_error(id, "not-authorized"), None));
    };
    if !privacy_iq_addressed_to_account(root, session.privacy_full_jid())
        || !valid_query_shell(query)
        || query.document().input_text().len() > MAX_PRIVACY_QUERY_BYTES
    {
        return Ok((iq_error(id, "bad-request"), None));
    }
    let children = element_children(query);
    if children.len() != 1 {
        return Ok((iq_error(id, "bad-request"), None));
    }
    let control = children[0];
    let mut changed_list = None;
    let result = match control.tag_name().name() {
        "active" => active_selection::select_active(session, id, control).await?,
        "default" => list_commands::select_default(session, id, control).await?,
        "list" => list_commands::edit_list(session, id, control, &mut changed_list).await?,
        _ => return Ok((iq_error(id, "bad-request"), None)),
    };
    let result = match result {
        ControlFlow::Continue(result) => result,
        ControlFlow::Break(reply) => return Ok(reply),
    };
    let response = match result {
        Ok(()) => iq_result(id, ""),
        Err(condition) => return Ok((iq_error(id, condition), None)),
    };
    let Some(name) = changed_list else {
        return Ok((response, None));
    };
    let current_push = push_privacy_list_change(session, &user.username, &name).await?;
    Ok((response, current_push))
}

fn privacy_iq_addressed_to_account(root: Node<'_, '_>, full_jid: Option<&str>) -> bool {
    match root.attribute("to") {
        None => true,
        Some(to) => full_jid
            .and_then(|jid| northstar_xmpp_types::jid::canonical_bare_key(jid).ok())
            .is_some_and(|owner| {
                northstar_xmpp_types::jid::canonical_bare_key(to).is_ok_and(|to| to == owner)
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::codec::{parse_list, render_list};
    use super::push::privacy_push_stanza;
    use super::PRIVACY_NS;
    use northstar_roster_application::privacy::{
        PrivacyAction, PrivacyItem, PrivacyList, PrivacyMatchType,
    };
    use roxmltree::{Document, Node};

    fn parse(xml: &str) -> PrivacyList {
        let document = Document::parse(xml).unwrap();
        let (name, items) = parse_list(document.root_element()).unwrap();
        PrivacyList {
            name: name.into_inner(),
            items,
        }
    }

    #[test]
    fn parses_canonical_bounded_ordered_rules() {
        let list = parse(
            "<list xmlns='jabber:iq:privacy' name='work'>\
             <item type='jid' value='ALICE@Example.test/Phone' action='deny' order='20'><message/><presence-in/></item>\
             <item action='allow' order='30'/></list>",
        );
        assert_eq!(
            list.items[0].match_value.as_deref(),
            Some("alice@example.test/Phone")
        );
        assert!(list.items[0].message && list.items[0].presence_in);
        assert_eq!(list.items[1].match_type, None);
    }

    #[test]
    fn rejects_ambiguous_duplicate_and_unknown_controls() {
        for xml in [
            "<list xmlns='jabber:iq:privacy' name='x'><item action='deny' order='1'/><item action='allow' order='1'/></list>",
            "<list xmlns='jabber:iq:privacy' name='x'><item type='jid' action='deny' order='1'/></list>",
            "<list xmlns='jabber:iq:privacy' name='x'><item action='deny' order='1'><message/><message/></item></list>",
            "<list xmlns='jabber:iq:privacy' name='x'><item action='deny' order='1'><unknown/></item></list>",
            "<list xmlns='jabber:iq:privacy' name='x'><foreign/></list>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(
                parse_list(document.root_element()).is_err(),
                "accepted {xml}"
            );
        }
    }

    #[test]
    fn rendering_is_stable_and_escapes_values() {
        let list = PrivacyList {
            name: "a'b".to_owned(),
            items: vec![PrivacyItem {
                order: 1,
                action: PrivacyAction::Deny,
                match_type: Some(PrivacyMatchType::Group),
                match_value: Some("R&D".to_owned()),
                message: true,
                iq: false,
                presence_in: false,
                presence_out: false,
            }],
        };
        let xml = render_list(&list.name, &list.items);
        assert!(Document::parse(&xml).is_ok());
        assert!(xml.contains("a&apos;b") && xml.contains("R&amp;D"));
    }

    #[test]
    fn accepts_full_xs_unsigned_int_order_range() {
        let list = parse(
            "<list xmlns='jabber:iq:privacy' name='x'><item action='deny' order='4294967295'/></list>",
        );
        assert_eq!(list.items[0].order, u32::MAX);
        let document = Document::parse(
            "<list xmlns='jabber:iq:privacy' name='x'><item action='deny' order='4294967296'/></list>",
        )
        .unwrap();
        assert!(parse_list(document.root_element()).is_err());
    }

    #[test]
    fn privacy_push_is_a_strict_addressed_iq_set() {
        let push = privacy_push_stanza(
            "alice@example.test",
            "alice@example.test/Phone",
            "privacy-1",
            "<query xmlns='jabber:iq:privacy'><list name='work'/></query>",
        )
        .unwrap();
        let document = Document::parse(&push).unwrap();
        let root = document.root_element();
        assert_eq!(root.attribute("type"), Some("set"));
        assert_eq!(root.attribute("from"), Some("alice@example.test"));
        assert_eq!(root.attribute("to"), Some("alice@example.test/Phone"));
        assert_eq!(
            root.children()
                .find(Node::is_element)
                .unwrap()
                .tag_name()
                .namespace(),
            Some(PRIVACY_NS)
        );
    }

    #[test]
    fn default_change_conflicts_with_any_other_connected_resource() {
        assert!(!northstar_roster_application::privacy::default_change_conflicts(1, false));
        assert!(northstar_roster_application::privacy::default_change_conflicts(2, false));
        assert!(northstar_roster_application::privacy::default_change_conflicts(1, true));
    }
}

#[cfg(test)]
mod command_tests;
