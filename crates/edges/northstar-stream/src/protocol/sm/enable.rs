//! Stream management enablement and resumability policy.

use super::sm_resume_token_hash;
use crate::protocol::{ProtocolSession, SessionHost};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use northstar_session_application::sm::{SmSessionCreationOutcome, SmSessionCreationRequest};
use northstar_xep_0198::resumability_allowed;
use rand::RngCore;
use zeroize::Zeroizing;

impl<H: SessionHost> ProtocolSession<H> {
    /// A fatal or explicit terminal transport outcome cannot leave this
    /// connection eligible for stream resumption.
    pub(crate) fn forbid_sm_resume(&mut self) {
        self.sm.resume_allowed = false;
    }

    pub(crate) fn has_sm_session(&self) -> bool {
        self.sm.db_id.is_some()
    }

    /// Enables XEP-0198 as an inline Bind 2 feature and returns the exact XML
    /// that belongs inside `<bound/>`. Resume tokens are 256-bit random
    /// bearers; PostgreSQL receives only SHA-256(token).
    pub(crate) async fn enable_sm_inline(
        &mut self,
        resume: bool,
        requested_max: Option<u64>,
    ) -> std::result::Result<String, &'static str> {
        if self.full_jid.is_none() || self.sm.enabled {
            return Err("unexpected-request");
        }
        // XEP-0388 supplies a stable user-agent UUID, while legacy SASL has no
        // standard way to prove device continuity.  Under the strict policy,
        // negotiate ordinary stream management for an unidentifiable legacy
        // client instead of issuing a bearer that the claim authority must
        // later reject.  Operators can explicitly disable the policy when
        // legacy resumption is an intended compatibility boundary.
        let resume = resumability_allowed(
            resume,
            self.sm_runtime_policy.session.require_same_device,
            self.user_agent_id.is_some(),
        );
        self.sm.enabled = true;
        self.sm.resume_allowed = resume;
        self.sm.inbound_h = 0;
        self.sm.outbound_h = 0;
        self.sm.acked_h = 0;
        self.sm.unacked.clear();
        self.sm.db_id = None;

        let Some(user) = self.authenticated.as_ref() else {
            self.reset_sm();
            return Err("not-authorized");
        };
        let full_jid = self.full_jid.clone().expect("checked above");
        let Ok(parsed_full_jid) = northstar_xmpp_types::jid::CanonicalJid::parse(&full_jid) else {
            self.reset_sm();
            return Err("unexpected-request");
        };
        let Some(resource) = parsed_full_jid.resourcepart() else {
            self.reset_sm();
            return Err("unexpected-request");
        };
        let server_max = self.sm_runtime_policy.session.resume_timeout_seconds;
        let negotiated_max = if resume {
            requested_max.unwrap_or(server_max).min(server_max).max(1)
        } else {
            // Non-resumable SM still needs a database owner for durable
            // delivery fences until the client advances `h`.  Its random
            // bearer is never emitted, and Drop revokes the row immediately;
            // this TTL is only a crash-recovery ceiling.
            server_max.max(1)
        };
        let mut token = Zeroizing::new([0_u8; 32]);
        rand::thread_rng().fill_bytes(&mut *token);
        let resume_id = Zeroizing::new(URL_SAFE_NO_PAD.encode(token.as_ref()));
        // The client proves the exact base64url text emitted in `id`. Hashing
        // the pre-encoding random bytes would create an unreachable row: no
        // conforming wire client ever sends those raw bytes back.
        let token_hash = sm_resume_token_hash(resume_id.as_str());
        let snapshot = self.sm_snapshot();
        let snapshot_bytes = snapshot.resident_bytes().ok_or("resource-constraint")?;
        if snapshot_bytes > self.sm_runtime_policy.buffer.max_snapshot_bytes {
            self.reset_sm();
            return Err("resource-constraint");
        }
        let capacity = match self
            .host
            .sm_memory_governor()
            .try_reserve_live(snapshot_bytes)
        {
            Ok(capacity) => capacity,
            Err(_) => {
                self.host.sm_session_telemetry().capacity_rejected();
                self.reset_sm();
                return Err("resource-constraint");
            }
        };
        self.sm.capacity = Some(capacity);
        match self
            .live_session_ownership
            .attempt(
                self.host
                    .sm_service()
                    .create_session(SmSessionCreationRequest {
                        token_hash: &token_hash,
                        user_id: user.id,
                        auth_generation: user.auth_generation,
                        full_jid: &full_jid,
                        resource,
                        server_domain: self.host.local_domain(),
                        connection_id: self.connection_id,
                        snapshot: &snapshot,
                        ttl_seconds: negotiated_max,
                        live_lease_seconds: self.sm_runtime_policy.session.live_lease_seconds,
                        max_per_account: self.sm_runtime_policy.session.max_per_account,
                        max_global: self.sm_runtime_policy.session.max_global,
                    }),
            )
            .await
        {
            Ok(SmSessionCreationOutcome::Created { id, ownership }) => {
                self.sm.db_id = Some(id);
                self.apply_sm_ownership_resolution(&ownership);
                *self
                    .sm
                    .session_id_shared
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(id);
                self.host
                    .associate_local_muc_sm_session(
                        &full_jid,
                        self.connection_id,
                        id,
                        &self.joined_rooms,
                    )
                    .await;
                self.sm.resume_timeout_seconds = negotiated_max;
                if resume {
                    Ok(northstar_xep_0198::build_enabled(
                        Some(resume_id.as_str()),
                        true,
                        Some(
                            u32::try_from(negotiated_max)
                                .expect("validated SM timeout fits into u32"),
                        ),
                        None,
                    ))
                } else {
                    Ok(northstar_xep_0198::build_enabled(None, false, None, None))
                }
            }
            Ok(SmSessionCreationOutcome::CapacityExhausted) => {
                self.host.sm_session_telemetry().capacity_rejected();
                self.reset_sm();
                Err("resource-constraint")
            }
            Err(error) => {
                tracing::error!(?error, "could not create durable XEP-0198 resume state");
                self.reset_sm();
                Err("resource-constraint")
            }
        }
    }
}
