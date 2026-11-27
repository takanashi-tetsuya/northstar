use super::*;

#[test]
fn service_forms_and_pep_events_keep_their_source_scope() {
    let domain = "example.test";
    let service = "pubsub.example.test";
    let publisher = "alice@example.test";
    assert!(matches!(
        source(service, domain, false),
        Some(NotificationSource::Service(value)) if value == service
    ));
    assert!(matches!(
        source(publisher, domain, true),
        Some(NotificationSource::PepPublisher(value)) if value == publisher
    ));
    assert!(source(publisher, domain, false).is_none());
    assert!(source("alice@remote.test", domain, true).is_none());
    assert!(source("alice@example.test/phone", domain, true).is_none());
}
