//! Handler trait and future types for IQ request routing.
//!
//! Provides [`IqHandler`] and [`HandlerFuture`] used by session handlers
//! to process inbound IQ request stanzas asynchronously.

use std::future::Future;
use std::pin::Pin;

use crate::iq::IqRequest;

/// The future a handler returns; it borrows the session and the request for `'a`.
pub type HandlerFuture<'a, R> = Pin<Box<dyn Future<Output = anyhow::Result<R>> + Send + 'a>>;

/// Handles the IQ requests of the routes it is registered for.
pub trait IqHandler<S: ?Sized, R>: Send + Sync {
    /// Handles an inbound IQ request borrowing the session and the request.
    fn handle<'a>(&'a self, session: &'a mut S, request: IqRequest<'a>) -> HandlerFuture<'a, R>;
}

/// Blanket implementation of [`IqHandler`] for functions and closures.
impl<S: ?Sized, R, F> IqHandler<S, R> for F
where
    F: for<'a> Fn(&'a mut S, IqRequest<'a>) -> HandlerFuture<'a, R> + Send + Sync,
{
    fn handle<'a>(&'a self, session: &'a mut S, request: IqRequest<'a>) -> HandlerFuture<'a, R> {
        self(session, request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iq::{IqKind, IqRequest, IqRoute, IqRouter};

    struct Session {
        counter: usize,
    }

    type SessionHandler = for<'a> fn(&'a mut Session, IqRequest<'a>) -> HandlerFuture<'a, String>;

    fn handle_roster<'a>(
        session: &'a mut Session,
        request: IqRequest<'a>,
    ) -> HandlerFuture<'a, String> {
        Box::pin(async move {
            session.counter += 1;
            Ok(format!("roster:{}", request.id))
        })
    }

    fn handle_ping<'a>(
        session: &'a mut Session,
        request: IqRequest<'a>,
    ) -> HandlerFuture<'a, String> {
        Box::pin(async move {
            session.counter += 1;
            Ok(format!("ping:{}", request.id))
        })
    }

    #[test]
    fn plain_fn_handlers_dispatch_iq() {
        let mut session = Session { counter: 0 };
        let mut router: IqRouter<SessionHandler> = IqRouter::new();

        let route_roster = IqRoute::new("query", "jabber:iq:roster", IqKind::Get);
        let route_ping = IqRoute::new("ping", "urn:xmpp:ping", IqKind::Get);

        router.register(route_roster, handle_roster).unwrap();
        router.register(route_ping, handle_ping).unwrap();

        let xml = r#"<iq id="req-roster" type="get"><query xmlns="jabber:iq:roster"/></iq>"#;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let stanza = doc.root_element();
        let payload = stanza.first_element_child().unwrap();
        let request = IqRequest {
            id: stanza.attribute("id").unwrap(),
            kind: IqKind::parse(stanza.attribute("type").unwrap()).unwrap(),
            stanza,
            payload,
            raw: xml,
        };

        let handler = router
            .route(
                payload.tag_name().name(),
                payload.tag_name().namespace().unwrap(),
                request.kind,
            )
            .unwrap();

        let result =
            futures::executor::block_on(IqHandler::handle(handler, &mut session, request)).unwrap();
        assert_eq!(result, "roster:req-roster");
        assert_eq!(session.counter, 1);

        let xml_ping = r#"<iq id="req-ping" type="get"><ping xmlns="urn:xmpp:ping"/></iq>"#;
        let doc_ping = roxmltree::Document::parse(xml_ping).unwrap();
        let stanza_ping = doc_ping.root_element();
        let payload_ping = stanza_ping.first_element_child().unwrap();
        let request_ping = IqRequest {
            id: stanza_ping.attribute("id").unwrap(),
            kind: IqKind::parse(stanza_ping.attribute("type").unwrap()).unwrap(),
            stanza: stanza_ping,
            payload: payload_ping,
            raw: xml_ping,
        };

        let handler_ping = router
            .route(
                payload_ping.tag_name().name(),
                payload_ping.tag_name().namespace().unwrap(),
                request_ping.kind,
            )
            .unwrap();

        let result_ping = futures::executor::block_on(IqHandler::handle(
            handler_ping,
            &mut session,
            request_ping,
        ))
        .unwrap();
        assert_eq!(result_ping, "ping:req-ping");
        assert_eq!(session.counter, 2);
    }

    fn as_handler<F>(f: F) -> F
    where
        F: for<'a> Fn(&'a mut Session, IqRequest<'a>) -> HandlerFuture<'a, String> + Send + Sync,
    {
        f
    }

    #[test]
    fn closure_handler_dispatches_iq() {
        let mut session = Session { counter: 0 };
        let closure = as_handler(|session, request| {
            Box::pin(async move {
                session.counter += 1;
                Ok(format!("closure:{}", request.id))
            })
        });

        let mut router = IqRouter::new();
        let route = IqRoute::new("query", "jabber:iq:roster", IqKind::Get);
        router.register(route, closure).unwrap();

        let xml = r#"<iq id="req-closure" type="get"><query xmlns="jabber:iq:roster"/></iq>"#;
        let doc = roxmltree::Document::parse(xml).unwrap();
        let stanza = doc.root_element();
        let payload = stanza.first_element_child().unwrap();
        let request = IqRequest {
            id: stanza.attribute("id").unwrap(),
            kind: IqKind::parse(stanza.attribute("type").unwrap()).unwrap(),
            stanza,
            payload,
            raw: xml,
        };

        let handler = router
            .route(
                payload.tag_name().name(),
                payload.tag_name().namespace().unwrap(),
                request.kind,
            )
            .unwrap();

        let result =
            futures::executor::block_on(IqHandler::handle(handler, &mut session, request)).unwrap();
        assert_eq!(result, "closure:req-closure");
        assert_eq!(session.counter, 1);
    }
}
