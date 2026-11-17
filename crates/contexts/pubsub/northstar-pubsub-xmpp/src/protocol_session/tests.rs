use super::*;
use std::sync::Mutex;

#[derive(Default)]
struct RecordingPubSubHandlers {
    addresses: Mutex<Vec<String>>,
}

impl PubSubHandlers for RecordingPubSubHandlers {
    async fn pubsub_iq_get(&self, _: &str, _: Node<'_, '_>) -> Result<Action> {
        unreachable!()
    }

    async fn pubsub_iq_set(&self, id: &str, child: Node<'_, '_>, to: &str) -> Result<Action> {
        assert_eq!(id, "pubsub-set");
        assert_eq!(child.tag_name().name(), "pubsub");
        self.addresses.lock().unwrap().push(to.to_owned());
        Ok(Action::None)
    }

    async fn pubsub_owner_get(&self, _: &str, _: Node<'_, '_>) -> Result<Action> {
        unreachable!()
    }

    async fn pubsub_owner_set(&self, _: &str, _: Node<'_, '_>) -> Result<Action> {
        unreachable!()
    }

    async fn pubsub_request(&self, _: &str, _: &str, _: Node<'_, '_>) -> Result<Action> {
        unreachable!()
    }

    async fn pubsub_authorization_response(&self, _: Node<'_, '_>) -> Result<bool> {
        unreachable!()
    }

    async fn pubsub_authorization_response_unless_busy(&self, _: Node<'_, '_>) -> Result<bool> {
        unreachable!()
    }

    async fn pubsub_presence(&mut self, _: &str, _: &str) -> Result<Action> {
        unreachable!()
    }
}

#[tokio::test]
async fn pubsub_iq_set_normalizes_missing_empty_and_explicit_to() {
    let handlers = RecordingPubSubHandlers::default();
    for (iq, expected) in [
        ("<iq><pubsub/></iq>", ""),
        ("<iq to=''><pubsub/></iq>", ""),
        (
            "<iq to='pubsub.example.test'><pubsub/></iq>",
            "pubsub.example.test",
        ),
    ] {
        let doc = roxmltree::Document::parse(iq).unwrap();
        let stanza = doc.root_element();
        let action = handlers
            .pubsub_iq_set_with_optional_to(
                "pubsub-set",
                stanza.first_element_child().unwrap(),
                stanza.attribute("to"),
            )
            .await
            .unwrap();
        assert!(matches!(action, Action::None));
        assert_eq!(
            *handlers.addresses.lock().unwrap(),
            vec![expected.to_owned()]
        );
        handlers.addresses.lock().unwrap().clear();
    }
}
