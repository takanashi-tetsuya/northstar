//! Independent per-item native writer call bounds.
//! These counters never consult Recorder, so semantic observation loss cannot
//! disable the actual per-item write/flush caps.
use crate::stage4_replay as wire;

pub(super) const MAX_WRITES: u8 = 32;
pub(super) const MAX_FLUSHES: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PlanError {
    ZeroChunk,
    TooManyWrites { required: usize },
}
pub(super) fn preflight(
    actual_stanza: &str,
    script: &wire::WriteScript,
) -> Result<usize, PlanError> {
    required_writes(
        actual_stanza.len(),
        script.chunk_limit as usize,
        script.fail_after_accepted_bytes.get().map(|n| *n as usize),
    )
    .and_then(|required| {
        if required > usize::from(MAX_WRITES) {
            Err(PlanError::TooManyWrites { required })
        } else {
            Ok(required)
        }
    })
}
fn required_writes(
    bytes: usize,
    chunk: usize,
    fail_after: Option<usize>,
) -> Result<usize, PlanError> {
    if chunk == 0 {
        return Err(PlanError::ZeroChunk);
    }
    Ok(match fail_after {
        Some(fail_after) if fail_after < bytes => fail_after.div_ceil(chunk) + 1,
        _ => bytes.div_ceil(chunk),
    })
}
#[derive(Default)]
pub(super) struct Counters {
    pub(super) writes: u8,
    pub(super) flushes: u8,
}
impl Counters {
    pub(super) fn enter_write(&mut self) -> bool {
        if self.writes == MAX_WRITES {
            return false;
        }
        self.writes += 1;
        true
    }
    pub(super) fn enter_flush(&mut self) -> bool {
        if self.flushes == MAX_FLUSHES {
            return false;
        }
        self.flushes += 1;
        true
    }
    pub(super) fn last_write_would_be_nonterminal(
        &self,
        offered: usize,
        accepted: usize,
        scripted_failure: bool,
    ) -> bool {
        self.writes == MAX_WRITES && !scripted_failure && accepted < offered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preflight_counts_the_scripted_failure_call_and_uses_actual_bytes() {
        assert_eq!(required_writes(33, 1, Some(31)), Ok(32));
        assert_eq!(required_writes(33, 1, Some(32)), Ok(33));
        assert_eq!(required_writes(33, 1, Some(0)), Ok(1));
        assert_eq!(required_writes(33, 2, Some(33)), Ok(17));
        assert_eq!(required_writes(33, 2, Some(34)), Ok(17));
        assert_eq!(required_writes(33, 2, None), Ok(17));
        assert_eq!(required_writes(0, 1, Some(0)), Ok(0));
        assert_eq!(required_writes(0, 1, None), Ok(0));
        assert_eq!(required_writes(1, 0, None), Err(PlanError::ZeroChunk));
        let script = wire::WriteScript {
            chunk_limit: 1,
            fail_after_accepted_bytes: wire::Nullable::Value(32),
            flush: wire::FlushReply::Ok,
        };
        assert_eq!(
            preflight(&"x".repeat(33), &script),
            Err(PlanError::TooManyWrites { required: 33 })
        );
        // Count materialized UTF-8 bytes, never scalar characters or raw
        // input before set_to/control rendering expands it.
        assert_eq!(
            preflight(
                "🙂",
                &wire::WriteScript {
                    chunk_limit: 1,
                    fail_after_accepted_bytes: wire::Nullable::Null(()),
                    flush: wire::FlushReply::Ok
                }
            ),
            Ok(4)
        );
    }
    #[test]
    fn independent_counters_reject_call33_flush2_and_identify_nonterminal32() {
        let mut c = Counters::default();
        for _ in 0..31 {
            assert!(c.enter_write());
        }
        assert!(c.enter_write());
        assert_eq!(c.writes, 32);
        assert!(c.last_write_would_be_nonterminal(2, 1, false));
        assert!(!c.last_write_would_be_nonterminal(1, 1, false));
        assert!(!c.last_write_would_be_nonterminal(2, 0, true));
        assert!(!c.enter_write());
        assert_eq!(c.writes, 32);
        assert!(c.enter_flush());
        assert!(!c.enter_flush());
        assert_eq!(c.flushes, 1);
    }
}
