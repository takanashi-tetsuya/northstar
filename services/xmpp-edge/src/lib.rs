//! XMPP C2S Edge Connection Gateway microservice.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 5.1, 6, 19.1, 19.5).

use foundation_contracts::common::AuthContext;
use foundation_contracts::delivery::DeliveryServerMessage;
use foundation_contracts::identity::{AuthenticateRequest, AuthenticateResponse};
use foundation_contracts::ingress::SubmitMessageRequest;
use foundation_contracts::session::{BindSessionRequest, BindSessionResponse};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPhase {
    PreAuth,
    Authenticating,
    Binding,
    Authenticated,
    Closed,
}

pub struct EdgeConnectionActor {
    pub connection_id: String,
    pub edge_instance_id: String,
    pub phase: SessionPhase,
    pub auth: Option<AuthContext>,
    pub full_jid: Option<String>,
    pub session_epoch: Option<u64>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
}

impl EdgeConnectionActor {
    pub fn new(edge_instance_id: impl Into<String>, outbound_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            connection_id: Uuid::new_v4().to_string(),
            edge_instance_id: edge_instance_id.into(),
            phase: SessionPhase::PreAuth,
            auth: None,
            full_jid: None,
            session_epoch: None,
            outbound_tx,
        }
    }

    /// Handles authentication step against Identity service.
    pub fn handle_auth_response(&mut self, res: AuthenticateResponse) -> bool {
        if res.success && res.auth_context.is_some() {
            self.auth = res.auth_context;
            self.phase = SessionPhase::Binding;
            true
        } else {
            self.phase = SessionPhase::PreAuth;
            false
        }
    }

    /// Handles binding step against Session Directory service.
    pub fn handle_bind_response(&mut self, res: BindSessionResponse) -> bool {
        if res.success {
            self.full_jid = Some(res.full_jid);
            self.session_epoch = Some(res.session_epoch);
            self.phase = SessionPhase::Authenticated;
            true
        } else {
            false
        }
    }

    /// Delivers an outbound stanza from delivery-router to the client socket.
    pub async fn deliver_to_socket(
        &self,
        msg: DeliveryServerMessage,
    ) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.outbound_tx.send(msg.stanza).await
    }

    /// Builds an authentication request for the Identity microservice.
    pub fn build_auth_request(
        &self,
        username: &str,
        mechanism: &str,
        password_bytes: &[u8],
    ) -> AuthenticateRequest {
        AuthenticateRequest {
            username: username.to_string(),
            mechanism: mechanism.to_string(),
            auth_payload: password_bytes.to_vec(),
            trace: None,
        }
    }

    /// Builds a resource binding request for the Session Directory microservice.
    pub fn build_bind_request(&self, desired_resource: &str) -> Option<BindSessionRequest> {
        self.auth.as_ref().map(|auth| BindSessionRequest {
            auth: auth.clone(),
            desired_resource: desired_resource.to_string(),
            edge_instance_id: self.edge_instance_id.clone(),
            connection_id: self.connection_id.clone(),
            trace: None,
        })
    }

    /// Builds a message submission request for the Message Ingress microservice.
    pub fn build_ingress_request(
        &self,
        to_jid: &str,
        stanza_id: &str,
        raw_stanza: &[u8],
    ) -> Option<SubmitMessageRequest> {
        let full_jid = self.full_jid.as_ref()?;
        let auth = self.auth.as_ref()?;
        Some(SubmitMessageRequest {
            from_full_jid: full_jid.clone(),
            to_jid: to_jid.to_string(),
            stanza_id: stanza_id.to_string(),
            message_type: "chat".to_string(),
            raw_stanza: raw_stanza.to_vec(),
            auth: auth.clone(),
            trace: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn edge_connection_lifecycle_flow() {
        let (tx, mut rx) = mpsc::channel(16);
        let mut actor = EdgeConnectionActor::new("edge-east-1", tx);
        assert_eq!(actor.phase, SessionPhase::PreAuth);

        // 1. Authenticate
        let auth_res = AuthenticateResponse {
            success: true,
            auth_context: Some(AuthContext::new("acc-1", "alice@example.com", 1, "local")),
            challenge_or_response: Vec::new(),
            error: None,
        };
        let authed = actor.handle_auth_response(auth_res);
        assert!(authed);
        assert_eq!(actor.phase, SessionPhase::Binding);

        // 2. Bind
        let bind_req = actor.build_bind_request("phone").unwrap();
        assert_eq!(bind_req.desired_resource, "phone");

        let bind_res = BindSessionResponse {
            success: true,
            full_jid: "alice@example.com/phone".to_string(),
            session_epoch: 1,
            error: None,
        };
        let bound = actor.handle_bind_response(bind_res);
        assert!(bound);
        assert_eq!(actor.phase, SessionPhase::Authenticated);
        assert_eq!(actor.full_jid.as_deref(), Some("alice@example.com/phone"));

        // 3. Receive message from delivery router and push to client socket
        let delivery = DeliveryServerMessage {
            delivery_id: "deliv-1".to_string(),
            target_connection_id: actor.connection_id.clone(),
            target_full_jid: "alice@example.com/phone".to_string(),
            stanza: b"<message>hello</message>".to_vec(),
            trace: None,
        };

        actor.deliver_to_socket(delivery).await.unwrap();
        let received = rx.recv().await.unwrap();
        assert_eq!(received, b"<message>hello</message>");
    }
}
