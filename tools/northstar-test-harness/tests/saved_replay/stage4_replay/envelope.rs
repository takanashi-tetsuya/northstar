use super::case_validation::require;
use super::{
    decode, snapshot_key, Empty, Envelope, Fact, Hex, IdentityMap, Introduction, LabelContext,
    List, Loss, NativeFact, Nullable, ObservationStatus, PollSite, Rejection, Sha256, Text,
    ValidatedCase, Walk, ENTRY, EVIDENCE_SCHEMA, FRAME_TAG, MAX_FRAME, MAX_INPUT,
    MAX_OWNER_SNAPSHOTS, MAX_POLLS,
};
use std::collections::BTreeMap;

pub(crate) fn sha256(bytes: &[u8]) -> Sha256 {
    use sha2::Digest;
    Hex(sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
impl Envelope {
    pub(crate) fn rejected(input: &[u8], rejection: Rejection) -> Result<Self, Rejection> {
        if input.len() > MAX_INPUT {
            return Err(Rejection::TooLarge);
        }
        Ok(Self {
            schema: Text::new(EVIDENCE_SCHEMA)?,
            entry: Text::new(ENTRY)?,
            input_sha256: sha256(input),
            rejection: Nullable::Value(rejection),
            execution: Nullable::Null(()),
            resource_stop: Nullable::Null(()),
            identity_map: List::new(vec![])?,
            facts: List::new(vec![])?,
            observation_status: ObservationStatus::Complete(Empty {}),
        })
    }
}
struct CappedWriter {
    bytes: Vec<u8>,
    overflow: bool,
}
impl std::io::Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_FRAME.saturating_sub(self.bytes.len()) {
            self.overflow = true;
            return Err(std::io::Error::other("Stage4 evidence cap"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(crate) fn encode_frame(envelope: &Envelope) -> Result<Vec<u8>, Loss> {
    let mut payload = CappedWriter {
        bytes: Vec::new(),
        overflow: false,
    };
    if serde_json::to_writer(&mut payload, envelope).is_err() {
        return Err(if payload.overflow {
            Loss::FrameOverflow
        } else {
            Loss::EncodingFailure
        });
    }
    let header = format!("\x1e{FRAME_TAG} {}\n", payload.bytes.len());
    let trailer = b"\n\x1eEND\n";
    if header.len() + payload.bytes.len() + trailer.len() > MAX_FRAME {
        return Err(Loss::FrameOverflow);
    }
    let mut frame = header.into_bytes();
    frame.extend(payload.bytes);
    frame.extend_from_slice(trailer);
    Ok(frame)
}
pub(crate) fn decode_frame(frame: &[u8]) -> Result<Envelope, Rejection> {
    if frame.len() > MAX_FRAME {
        return Err(Rejection::TooLarge);
    }
    let newline = frame
        .iter()
        .position(|b| *b == b'\n')
        .ok_or(Rejection::Encoding)?;
    let header = std::str::from_utf8(&frame[..newline]).map_err(|_| Rejection::Encoding)?;
    let count = header
        .strip_prefix(&format!("\x1e{FRAME_TAG} "))
        .ok_or(Rejection::Schema)?;
    require(
        !count.is_empty()
            && count.bytes().all(|c| c.is_ascii_digit())
            && (count == "0" || !count.starts_with('0')),
    )?;
    let count: usize = count.parse().map_err(|_| Rejection::Bound)?;
    let end = (newline + 1).checked_add(count).ok_or(Rejection::Bound)?;
    require(end <= frame.len() && &frame[end..] == b"\n\x1eEND\n")?;
    let envelope: Envelope =
        serde_json::from_slice(&frame[newline + 1..end]).map_err(|_| Rejection::Json)?;
    require(envelope.schema.as_str() == EVIDENCE_SCHEMA && envelope.entry.as_str() == ENTRY)
        .map_err(|_| Rejection::Schema)?;
    let canonical = serde_json::to_vec(&envelope).map_err(|_| Rejection::Encoding)?;
    if canonical.as_slice() != &frame[newline + 1..end] {
        return Err(Rejection::Encoding);
    }
    Ok(envelope)
}
/// Structural encoding/identity validation only. Unsafe but well-typed domain
/// histories are retained for the independent semantic oracle, not rejected here.
pub(crate) fn validate_envelope(
    envelope: &Envelope,
    input: &[u8],
    case: Option<&ValidatedCase>,
) -> Result<(), Loss> {
    if envelope.input_sha256 != sha256(input) {
        return Err(Loss::EncodingFailure);
    }
    if let Some(reason) = envelope.rejection.get() {
        if envelope.execution.get().is_some()
            || envelope.resource_stop.get().is_some()
            || !envelope.facts.is_empty()
            || !envelope.identity_map.is_empty()
            || case.is_some()
        {
            return Err(Loss::EncodingFailure);
        }
        if decode(input).err().as_ref() != Some(reason)
            || !matches!(envelope.observation_status, ObservationStatus::Complete(_))
        {
            return Err(Loss::EncodingFailure);
        }
        return Ok(());
    }
    let case = case.ok_or(Loss::EncodingFailure)?;
    if case.input_sha256 != sha256(input) {
        return Err(Loss::EncodingFailure);
    }
    match envelope.resource_stop.get() {
        Some(stop) => {
            stop.validate().map_err(|_| Loss::EncodingFailure)?;
            if envelope.execution.get().is_some() {
                return Err(Loss::EncodingFailure);
            }
        }
        None => {
            if envelope.execution.get().is_none() {
                return Err(Loss::EncodingFailure);
            }
        }
    }
    // A valid resource_stop means incomplete/nonqualifying, before fixture
    // matching. This structural function does not qualify anything, including
    // a mutant (whose intentional qualified=false alone is not this distinction).
    let mut map = IdentityMap {
        fixed: case.fixed_ids.clone(),
        reading_wire: true,
        ..IdentityMap::default()
    };
    let mut counts = BTreeMap::new();
    let mut io_counts = BTreeMap::new();
    let mut polls = 0;
    for (index, record) in envelope.facts.as_slice().iter().enumerate() {
        if record.seq != index as u32 + 1 {
            return Err(Loss::NoncontiguousSequence);
        }
        if let Fact::Driver(poll) = &record.fact {
            PollSite::new(poll.owner, poll.owner_ordinal).map_err(|_| Loss::EncodingFailure)?;
            polls += 1;
            if polls > MAX_POLLS {
                return Err(Loss::PollOverflow);
            }
        }
        if let Some(key) = snapshot_key(&record.fact) {
            let n = counts.entry(key).or_insert(0);
            *n += 1;
            if *n > MAX_OWNER_SNAPSHOTS {
                return Err(Loss::OwnerSnapshotOverflow);
            }
        }
        let io_key = match &record.fact {
            Fact::Native(NativeFact::Write(x)) => Some(((0, x.item_ordinal), 32)),
            Fact::Native(NativeFact::Flush(x)) => Some(((1, x.item_ordinal), 1)),
            _ => None,
        };
        if let Some((key, limit)) = io_key {
            let n = io_counts.entry(key).or_insert(0);
            *n += 1;
            if *n > limit {
                return Err(Loss::FactOverflow);
            }
        }
        let mut fact = record.fact.clone();
        fact.walk(
            &mut LabelContext {
                identities: &mut map,
                seq: record.seq,
            },
            Introduction::UnexpectedObservedIdentity,
        )?;
    }
    if map.introductions.as_slice() != envelope.identity_map.as_slice() {
        return Err(Loss::NoncanonicalIdentity);
    }
    if let ObservationStatus::Lost(lost) = &envelope.observation_status {
        if lost.after_seq != envelope.facts.len() as u32 {
            return Err(Loss::NoncontiguousSequence);
        }
    }
    Ok(())
}
