use super::super::{Envelope, Loss, Rejection, ENTRY, EVIDENCE_SCHEMA, MAX_FRAME};
use super::canonical::{compare_with_limits, Mode, Output};
use super::identities::Identities;
use super::parser::{lexical, parse, Budget, Limits};
use super::scalars::{hex_bound, lower_hex};
use super::Closed;

pub(in crate::stage4_replay) const TAG: &str = "NORTHSTAR_STAGE4_COMPOSITION_V2";
const MARKER: &str = "northstar-stage4-composition-compact-v2";

pub(super) const END: &[u8] = b"\n\x1eEND\n";

fn schema(envelope: &Envelope, budget: &mut Budget) -> Result<(), Rejection> {
    budget.visits(2)?;
    if !budget.equal(
        envelope.schema.as_str().as_bytes(),
        EVIDENCE_SCHEMA.as_bytes(),
    )? || !budget.equal(envelope.entry.as_str().as_bytes(), ENTRY.as_bytes())?
    {
        return Err(Rejection::Schema);
    }
    Ok(())
}
fn payload(
    envelope: &Envelope,
    expanded: usize,
    digest: &[u8; 32],
    budget: &mut Budget,
    node_cost: usize,
) -> Result<Vec<u8>, Rejection> {
    let identities = Identities::new(envelope.identity_map.as_slice(), budget)?;
    let digest = lower_hex(digest, budget)?;
    let mut out = Output::compact(budget, node_cost);
    out.node(0)?;
    out.put(b"[")?;
    out.node(0)?;
    out.string(MARKER)?;
    out.put(b",")?;
    out.node(0)?;
    out.integer(expanded as i128)?;
    out.put(b",")?;
    out.node(0)?;
    out.string(&digest)?;
    out.put(b",")?;
    envelope.emit(&mut out, &identities, Mode::Compact, Envelope::REF)?;
    out.put(b"]")?;
    out.data.ok_or(Rejection::Encoding)
}
pub(super) fn frame(payload: &[u8], budget: &mut Budget) -> Result<Vec<u8>, Rejection> {
    let digits = if payload.is_empty() {
        1
    } else {
        payload.len().ilog10() as usize + 1
    };
    let header_len = 1 + TAG.len() + 1 + digits + 1;
    let size = header_len
        .checked_add(payload.len())
        .and_then(|n| n.checked_add(END.len()))
        .ok_or(Rejection::Bound)?;
    if size > MAX_FRAME {
        return Err(Rejection::TooLarge);
    }
    budget.bytes(header_len)?;
    let mut header = [0u8; 64];
    if header_len > header.len() {
        return Err(Rejection::Bound);
    }
    header[0] = 0x1e;
    header[1..1 + TAG.len()].copy_from_slice(TAG.as_bytes());
    header[1 + TAG.len()] = b' ';
    let mut number = payload.len();
    for index in (header_len - 1 - digits..header_len - 1).rev() {
        header[index] = b'0' + (number % 10) as u8;
        number /= 10;
    }
    header[header_len - 1] = b'\n';
    // Framing emission plus the explicit buffer concatenation/copy. Both the
    // stack header and final Vec have fixed capacity, so neither can grow-copy.
    budget.bytes(header_len + END.len())?;
    budget.bytes(size)?;
    let mut result = Vec::with_capacity(size);
    result.extend_from_slice(&header[..header_len]);
    result.extend_from_slice(payload);
    result.extend_from_slice(END);
    Ok(result)
}
pub(super) fn encode_with_limits(
    envelope: &Envelope,
    limits: Limits,
) -> Result<(Vec<u8>, usize, usize), Rejection> {
    let mut budget = Budget::new(limits);
    schema(envelope, &mut budget)?;
    let mut named = Output::expanded(&mut budget, 2);
    envelope.emit(
        &mut named,
        &Identities::default(),
        Mode::Named,
        Envelope::REF,
    )?;
    let (expanded, digest) = named.summary()?;
    let compact = payload(envelope, expanded, &digest, &mut budget, 1)?;
    let frame = frame(&compact, &mut budget)?;
    Ok((frame, budget.visits, budget.bytes))
}
pub(in crate::stage4_replay) fn encode(envelope: &Envelope) -> Result<Vec<u8>, Loss> {
    encode_with_limits(envelope, Limits::default())
        .map(|(frame, _, _)| frame)
        .map_err(|error| {
            if error == Rejection::TooLarge {
                Loss::FrameOverflow
            } else {
                Loss::EncodingFailure
            }
        })
}
pub(super) fn extract<'a>(frame: &'a [u8], budget: &mut Budget) -> Result<&'a [u8], Rejection> {
    if frame.len() > MAX_FRAME {
        return Err(Rejection::TooLarge);
    }
    let prefix = b"\x1eNORTHSTAR_STAGE4_COMPOSITION_V2 ";
    let actual = frame.get(..prefix.len()).unwrap_or(frame);
    if !budget.equal(actual, prefix)? {
        return Err(Rejection::Schema);
    }
    let mut newline = None;
    for (position, byte) in frame[prefix.len()..].iter().enumerate() {
        budget.bytes(1)?;
        if *byte == b'\n' {
            newline = Some(prefix.len() + position);
            break;
        }
    }
    let newline = newline.ok_or(Rejection::Encoding)?;
    let digits = &frame[prefix.len()..newline];
    if !(1..=6).contains(&digits.len()) {
        return Err(Rejection::Encoding);
    }
    budget.bytes(digits.len())?;
    if !digits.iter().all(u8::is_ascii_digit) || (digits.len() > 1 && digits[0] == b'0') {
        return Err(Rejection::Encoding);
    }
    budget.bytes(digits.len())?;
    let mut count = 0usize;
    for &digit in digits {
        count = count
            .checked_mul(10)
            .and_then(|n| n.checked_add(usize::from(digit - b'0')))
            .ok_or(Rejection::Encoding)?;
    }
    let end = newline
        .checked_add(1)
        .and_then(|n| n.checked_add(count))
        .ok_or(Rejection::Bound)?;
    if end > frame.len() || !budget.equal(&frame[end..], END)? {
        return Err(Rejection::Encoding);
    }
    Ok(&frame[newline + 1..end])
}
pub(super) fn decode_with_limits(
    frame: &[u8],
    limits: Limits,
) -> Result<(Envelope, usize, usize), Rejection> {
    let mut budget = Budget::new(limits);
    let raw = extract(frame, &mut budget)?;
    lexical(raw, &mut budget)?;
    // One bounded, duplicate-checking JSON parse, after lexical preflight.
    let compact = parse(raw, &mut budget)?;
    let wrapper = compact.array(4)?;
    let marker = wrapper[0].string()?;
    budget.scalar(marker)?;
    if !budget.equal(marker.as_bytes(), MARKER.as_bytes())? {
        return Err(Rejection::Schema);
    }
    let declared = usize::try_from(wrapper[1].integer()?).map_err(|_| Rejection::Bound)?;
    if declared > budget.limits.expanded {
        return Err(Rejection::Bound);
    }
    let declared_hash = wrapper[2].string()?;
    hex_bound(declared_hash, 32, true, &mut budget)?;
    let mut named = Output::expanded(&mut budget, 3);
    // Original bounds/type validation and canonical hashing are fused with
    // construction. All three expanded visits are nevertheless reserved first.
    let envelope = Envelope::read(
        &wrapper[3],
        &mut named,
        &Identities::default(),
        Mode::Compact,
        Envelope::REF,
    )?;
    let (expanded, digest) = named.summary()?;
    schema(&envelope, &mut budget)?;
    let digest_text = lower_hex(&digest, &mut budget)?;
    if expanded != declared || !budget.equal(digest_text.as_bytes(), declared_hash.as_bytes())? {
        return Err(Rejection::Encoding);
    }
    // Parse already reserved the two compact passes. Every expanded node also
    // prepaid the re-projection pass; identity-index inspections are additional.
    let canonical = payload(&envelope, expanded, &digest, &mut budget, 0).map_err(|e| {
        if e == Rejection::TooLarge {
            Rejection::Encoding
        } else {
            e
        }
    })?;
    if !budget.equal(&canonical, raw)? {
        return Err(Rejection::Encoding);
    }
    Ok((envelope, budget.visits, budget.bytes))
}
pub(in crate::stage4_replay) fn decode(frame: &[u8]) -> Result<Envelope, Rejection> {
    decode_with_limits(frame, Limits::default()).map(|(envelope, _, _)| envelope)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::stage4_replay) enum RoundtripFailure {
    Decode(Rejection),
    Compare(Rejection),
}
/// Verify the same captured Envelope against its decoded V2 representation.
/// The decoder and the complete paired comparison each retain their own
/// operation-wide budgets. No owner is run and no frame is repaired/retried.
pub(in crate::stage4_replay) fn verify_frame_roundtrip(
    original: &Envelope,
    frame: &[u8],
) -> Result<(), RoundtripFailure> {
    let restored = decode(frame).map_err(RoundtripFailure::Decode)?;
    compare_with_limits(original, &restored, Limits::default())
        .map_err(RoundtripFailure::Compare)?;
    Ok(())
}
