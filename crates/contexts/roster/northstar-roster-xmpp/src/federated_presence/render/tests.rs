use super::*;
use roxmltree::Document;

#[test]
fn auto_replies_use_subscription_types_and_preserve_optional_id() {
    for (kind, spelling) in [
        (SubscriptionReply::Subscribed, "subscribed"),
        (SubscriptionReply::Unsubscribed, "unsubscribed"),
    ] {
        for id in [None, Some("request'&1")] {
            let stanza = subscription_reply("alice@local.test", "bob&carol@remote.test", kind, id);
            let document = Document::parse(&stanza).unwrap();
            let root = document.root_element();
            assert_eq!(root.tag_name().namespace(), Some("jabber:server"));
            assert_eq!(root.attribute("from"), Some("alice@local.test"));
            assert_eq!(root.attribute("to"), Some("bob&carol@remote.test"));
            assert_eq!(root.attribute("type"), Some(spelling));
            assert_eq!(root.attribute("id"), id);
        }
    }
}
