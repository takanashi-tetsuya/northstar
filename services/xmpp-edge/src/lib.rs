//! XMPP C2S Edge Connection Gateway microservice.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Sections 5.1, 6, 19.1, 19.5).

use foundation_contracts::adapters::assertions::AuthGrant;
use foundation_contracts::adapters::common::AuthContext;
use foundation_contracts::adapters::delivery::DeliveryServerMessage;
use foundation_contracts::adapters::identity::{
    AuthenticateResponse, ContinueAuthenticationResponse, StartAuthenticationRequest,
};
use foundation_contracts::adapters::ingress::SubmitMessageRequest;
use foundation_contracts::adapters::session::{BindSessionRequest, BindSessionResponse};
use foundation_security::SecretBytes;
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
    pub auth_grant: Option<AuthGrant>,
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
            auth_grant: None,
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

    /// Completes the password-free SCRAM exchange. Binding is allowed only
    /// after the Identity service returns an assertion for this connection.
    pub fn handle_continue_authentication_response(
        &mut self,
        res: ContinueAuthenticationResponse,
    ) -> bool {
        let Some(grant) = res.auth_grant.filter(|_| res.success) else {
            self.phase = SessionPhase::PreAuth;
            return false;
        };
        self.auth = Some(
            AuthContext::new(
                &grant.account_id,
                &grant.bare_jid,
                grant.credential_generation,
                "unknown",
            )
            .with_role("user"),
        );
        self.auth_grant = Some(grant);
        self.phase = SessionPhase::Binding;
        true
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

    /// Builds the first leg of SCRAM without carrying a clear-text password.
    pub fn build_start_authentication_request(
        &self,
        username: &str,
        mechanism: &str,
        client_first: &[u8],
        channel_binding: Option<String>,
        channel_binding_data: Option<&[u8]>,
    ) -> StartAuthenticationRequest {
        StartAuthenticationRequest {
            username: username.to_string(),
            mechanism: mechanism.to_string(),
            client_first: SecretBytes::new(client_first.to_vec()),
            channel_binding,
            channel_binding_data: channel_binding_data.map(|data| SecretBytes::new(data.to_vec())),
            trace: None,
        }
    }

    /// Builds a resource binding request for the Session Directory microservice.
    pub fn build_bind_request(&self, desired_resource: &str) -> Option<BindSessionRequest> {
        self.auth.as_ref().map(|auth| BindSessionRequest {
            auth: auth.clone(),
            auth_grant: self.auth_grant.clone(),
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
            idempotency_key: None,
            session_assertion: None,
            canonical_input: None,
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
            auth_grant: None,
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
            assertion: None,
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
            server_message_id: "srv-1".to_owned(),
            delivery_attempt: 1,
            session_epoch: 1,
        };

        actor.deliver_to_socket(delivery).await.unwrap();
        let received = rx.recv().await.unwrap();
        assert_eq!(received, b"<message>hello</message>");
    }
}
