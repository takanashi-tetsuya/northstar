//! Runtime bridge for a lazy frame-owned ordinary MIX message. Registration
//! and retirement share a synchronous lock; absence is selected by the frame.

pub use crate::mix::{
    Observation, PreparedIngress, Rejected, ReplayRequest, StoreRequest, Summary, TerminalReason,
};
pub use northstar_room_core::mix::{Ingress, StoreCommand};
use std::sync::Mutex;

#[derive(Default)]
struct SlotState {
    observation: Option<Observation>,
    terminal: Option<TerminalReason>,
}

#[derive(Default)]
pub struct MixForegroundSlot(Mutex<SlotState>);

impl MixForegroundSlot {
    pub fn register(&self, prepared: &PreparedIngress) -> Result<Observation, Rejected> {
        let mut slot = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if slot.terminal.is_some() {
            return Err(Rejected::Retired);
        }
        if let Some(observation) = &slot.observation {
            if observation.snapshot().terminal.is_some() {
                return Err(Rejected::Retired);
            }
            if !observation.is_for(prepared) {
                return Err(Rejected::Input);
            }
            return Ok(observation.clone());
        }
        let observation = Observation::new(prepared.clone());
        slot.observation = Some(observation.clone());
        Ok(observation)
    }

    pub fn retire(&self, reason: TerminalReason) -> Option<Summary> {
        let mut slot = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let reason = *slot.terminal.get_or_insert(reason);
        slot.observation
            .as_ref()
            .map(|observation| observation.retire(reason))
    }
}

pub fn effect_error(error: crate::mix::EffectError<anyhow::Error>) -> anyhow::Error {
    match error {
        crate::mix::EffectError::Observation(error) => error.into(),
        crate::mix::EffectError::Repository(error) => error,
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod fixture {
    use super::*;
    use crate::mix::{admit_observed, commit_observed, CommitError, Completion};
    use northstar_room_core::mix::{
        Admission, DeliveryProjection, Existing, Outcome, Participant, RecipientProjection,
        ReplayIdentity, Stored,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uuid::Uuid;

    #[derive(Clone, Copy)]
    pub enum Cut {
        Return,
        BeforeCommit,
        DuringCommit,
        AfterReceipt,
        FailAfterReceipt,
        PanicAfterReceipt,
    }

    #[derive(Default)]
    pub struct Calls {
        pub repository: AtomicUsize,
        pub commit: AtomicUsize,
        pub membership: AtomicUsize,
        pub wake: AtomicUsize,
    }

    pub fn prepared(identity: bool) -> PreparedIngress {
        PreparedIngress::new(Ingress {
            channel_id: Uuid::from_u128(71),
            channel_jid: "room@mix.local.test".into(),
            actor_bare: "alice@local.test".into(),
            actor_full: "alice@local.test/phone".into(),
            children: "<body>ordinary message</body>".into(),
            encrypted: false,
            identity: identity.then(|| ReplayIdentity {
                client_id: "origin-71".into(),
                canonical_semantics: vec![7, 1],
            }),
        })
    }
    pub fn command(identity: bool) -> StoreCommand {
        let prepared = prepared(identity);
        let input = prepared.ingress();
        StoreCommand {
            channel_id: input.channel_id,
            actor: input.actor_bare.clone(),
            item_id: Uuid::from_u128(72),
            payload: "<message from='room@mix.local.test'><body>ordinary message</body></message>"
                .into(),
            identity: input.identity.clone(),
            delivery_payload: input.children.clone(),
            visible_jid: None,
            encrypted: false,
        }
    }
    pub fn participant() -> Participant {
        Participant {
            participant_id: Uuid::from_u128(73),
            jid: "bob@local.test".into(),
            nick: Some("Bob".into()),
        }
    }
    pub fn stored(audience: bool) -> Stored {
        Stored {
            authoritative_id: Uuid::from_u128(72),
            storage_id: Uuid::from_u128(74),
            channel_id: Uuid::from_u128(71),
            channel_jid: "room@mix.local.test".into(),
            projection: audience.then(|| DeliveryProjection {
                event_id: Uuid::from_u128(72),
                channel_id: Uuid::from_u128(71),
                channel_jid: "room@mix.local.test".into(),
                stanza_template:
                    "<message to='bob@local.test'><body>ordinary message</body></message>".into(),
                authoritative_stanza_id: Some(Uuid::from_u128(72)),
                archive: true,
                encrypted: false,
                recipients: vec![RecipientProjection {
                    participant: participant(),
                    delivery_id: Uuid::from_u128(75),
                    sequence: 812,
                }],
            }),
        }
    }
    pub fn returned(audience: bool) -> Admission {
        Admission {
            outcome: Outcome::Stored(Uuid::from_u128(72)),
            recipients: if audience {
                vec![participant()]
            } else {
                vec![]
            },
        }
    }
    pub fn existing() -> Existing {
        Existing {
            authoritative_id: Uuid::from_u128(70),
            semantic_key_id: "fixture".into(),
            semantic_mac: vec![19; 32],
            target_id: None,
        }
    }
    pub async fn admit(
        request: &StoreRequest,
        cut: Cut,
        audience: bool,
        calls: &Calls,
    ) -> anyhow::Result<Completion> {
        admit_observed(request, "mix.local.test", async {
            calls.repository.fetch_add(1, Ordering::Relaxed);
            if matches!(cut, Cut::BeforeCommit) {
                std::future::pending::<()>().await;
            }
            commit_observed(
                async {
                    calls.commit.fetch_add(1, Ordering::Relaxed);
                    if matches!(cut, Cut::DuringCommit) {
                        std::future::pending::<()>().await;
                    }
                    Ok::<(), anyhow::Error>(())
                },
                request,
                stored(audience),
            )
            .await
            .map_err(|error| match error {
                CommitError::Observation(error) => anyhow::Error::from(error),
                CommitError::Commit(error) => error,
            })?;
            match cut {
                Cut::AfterReceipt => std::future::pending::<()>().await,
                Cut::FailAfterReceipt => anyhow::bail!("MIX receipt-before-return backend failure"),
                Cut::PanicAfterReceipt => std::panic::panic_any("MIX receipt-before-return panic"),
                _ => {}
            }
            Ok(returned(audience))
        })
        .await
        .map_err(effect_error)
    }
}
