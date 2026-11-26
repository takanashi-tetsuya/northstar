use super::*;

#[test]
fn blocklist_push_samples_ids_for_local_and_lazy_remote_stanzas() {
    run(async {
        let owner = "alice@example.test";
        let target = "alice@example.test/phone";
        let (session, mut receiver) = session("phone");
        session.blocklist_requested.store(true, Ordering::Release);
        let routes = Routes {
            sessions: vec![(target.into(), session)],
            request_push: true,
            ..Routes::default()
        };
        let counter = AtomicU64::new(42);
        let payload =
            northstar_xml_builder::XmlElement::namespaced("unblock", "urn:xmpp:blocking").finish();
        let new_id = || Uuid::from_u128(u128::from(counter.fetch_add(1, Ordering::Relaxed)));
        push_blocklist_change(&Routes::default(), owner, &payload, new_id).await;
        assert_eq!(counter.load(Ordering::Relaxed), 42);
        push_blocklist_change(&routes, owner, &payload, new_id).await;
        let local = receiver.try_recv().unwrap().stanza;
        let remote = routes.remote_pushes.lock().unwrap();
        for (xml, id) in [
            (local.as_str(), "block-42"),
            (remote[0].as_str(), "block-43"),
        ] {
            let document = roxmltree::Document::parse(xml).unwrap();
            assert_eq!(document.root_element().attribute("id"), Some(id));
        }
        assert_eq!(counter.load(Ordering::Relaxed), 44);
    });
}
