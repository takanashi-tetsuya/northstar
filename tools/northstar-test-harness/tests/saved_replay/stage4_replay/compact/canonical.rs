use super::super::{Envelope, Rejection, MAX_FRAME};
use super::identities::Identities;
use super::parser::{Budget, Limits};
use super::Closed;
use sha2::{Digest, Sha256 as Hash};

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Mode {
    Named,
    Compact,
}
pub(super) struct Output<'a> {
    pub(super) budget: &'a mut Budget,
    pub(super) data: Option<Vec<u8>>,
    hash: Option<Hash>,
    pub(super) len: usize,
    pub(super) cap: usize,
    node_cost: usize,
    overflow: Rejection,
    wire: Option<(usize, bool, bool)>,
}
impl<'a> Output<'a> {
    pub(super) fn expanded(budget: &'a mut Budget, node_cost: usize) -> Self {
        let cap = budget.limits.expanded;
        Self {
            budget,
            data: None,
            hash: Some(Hash::new()),
            len: 0,
            cap,
            node_cost,
            overflow: Rejection::Bound,
            wire: None,
        }
    }
    pub(super) fn compact(budget: &'a mut Budget, node_cost: usize) -> Self {
        Self {
            budget,
            data: Some(Vec::with_capacity(MAX_FRAME)),
            hash: None,
            len: 0,
            cap: MAX_FRAME,
            node_cost,
            overflow: Rejection::TooLarge,
            wire: Some((0, false, false)),
        }
    }
    pub(super) fn node(&mut self, depth: usize) -> Result<(), Rejection> {
        self.budget.depth(depth)?;
        self.budget.visits(self.node_cost)
    }
    pub(super) fn put(&mut self, bytes: &[u8]) -> Result<(), Rejection> {
        let next = self.len.checked_add(bytes.len()).ok_or(Rejection::Bound)?;
        if next > self.cap {
            return Err(self.overflow);
        }
        self.budget.bytes(bytes.len())?;
        // Incremental wire-depth scan reserves its own pass before bytes can
        // enter the compact output buffer. Quoted brackets never count.
        if let Some((depth, quoted, escaped)) = &mut self.wire {
            self.budget.bytes(bytes.len())?;
            for &c in bytes {
                if *quoted {
                    if *escaped {
                        *escaped = false;
                    } else if c == b'\\' {
                        *escaped = true;
                    } else if c == b'"' {
                        *quoted = false;
                    }
                } else if c == b'"' {
                    *quoted = true;
                } else if c == b'[' || c == b'{' {
                    *depth = depth.checked_add(1).ok_or(Rejection::Bound)?;
                    self.budget.depth(*depth)?;
                } else if c == b']' || c == b'}' {
                    *depth = depth.checked_sub(1).ok_or(Rejection::Encoding)?;
                }
            }
        }
        if self.hash.is_some() {
            self.budget.bytes(bytes.len())?;
        }
        if let Some(hash) = &mut self.hash {
            hash.update(bytes);
        }
        if let Some(data) = &mut self.data {
            self.budget.bytes(bytes.len())?;
            data.extend_from_slice(bytes);
        }
        self.len = next;
        Ok(())
    }
    pub(super) fn string(&mut self, text: &str) -> Result<(), Rejection> {
        self.budget.scalar(text)?;
        self.put(b"\"")?;
        for (position, c) in text.char_indices() {
            match c {
                '"' => self.put(b"\\\"")?,
                '\\' => self.put(b"\\\\")?,
                '\u{8}' => self.put(b"\\b")?,
                '\u{c}' => self.put(b"\\f")?,
                '\n' => self.put(b"\\n")?,
                '\r' => self.put(b"\\r")?,
                '\t' => self.put(b"\\t")?,
                c if c < '\u{20}' => {
                    let n = c as u8;
                    let h = b"0123456789abcdef";
                    self.put(&[
                        b'\\',
                        b'u',
                        b'0',
                        b'0',
                        h[usize::from(n >> 4)],
                        h[usize::from(n & 15)],
                    ])?;
                }
                c => self.put(&text.as_bytes()[position..position + c.len_utf8()])?,
            }
        }
        self.put(b"\"")
    }
    pub(super) fn integer(&mut self, value: i128) -> Result<(), Rejection> {
        // Stack-only exact decimal conversion, including signed minima.
        let mut buffer = [0u8; 40];
        let mut at = buffer.len();
        let mut n = value.unsigned_abs();
        loop {
            at -= 1;
            buffer[at] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        if value < 0 {
            at -= 1;
            buffer[at] = b'-';
        }
        self.put(&buffer[at..])
    }
    pub(super) fn summary(self) -> Result<(usize, [u8; 32]), Rejection> {
        Ok((
            self.len,
            self.hash.ok_or(Rejection::Encoding)?.finalize().into(),
        ))
    }
}

// Two reusable nonrecursive leaf buffers. The largest named leaf is
// Text<16384> containing JSON-escaped control scalars: 6*16384+2 bytes.
// These are not full expanded Envelope buffers or a peak-memory quota.
pub(super) const MAX_CANONICAL_LEAF: usize = 6 * 16_384 + 2;
pub(super) struct Comparison {
    pub(super) budget: Budget,
    pub(super) left: Vec<u8>,
    pub(super) right: Vec<u8>,
    pub(super) left_bytes: usize,
    pub(super) right_bytes: usize,
}
impl Comparison {
    pub(super) fn new(limits: Limits) -> Self {
        Self {
            budget: Budget::new(limits),
            left: Vec::with_capacity(MAX_CANONICAL_LEAF),
            right: Vec::with_capacity(MAX_CANONICAL_LEAF),
            left_bytes: 0,
            right_bytes: 0,
        }
    }
    pub(super) fn node(&mut self, depth: usize) -> Result<(), Rejection> {
        self.budget.depth(depth)?;
        self.budget.visits(2)
    }
    pub(super) fn literal(&mut self, bytes: &[u8]) -> Result<(), Rejection> {
        let left = self
            .left_bytes
            .checked_add(bytes.len())
            .ok_or(Rejection::Bound)?;
        let right = self
            .right_bytes
            .checked_add(bytes.len())
            .ok_or(Rejection::Bound)?;
        if left > self.budget.limits.expanded || right > self.budget.limits.expanded {
            return Err(Rejection::Bound);
        }
        // Both canonical streams emit their fixed punctuation. The immutable
        // literal is borrowed; no retained byte-buffer copy occurs here.
        self.budget
            .bytes(bytes.len().checked_mul(2).ok_or(Rejection::Bound)?)?;
        if !self.budget.equal(bytes, bytes)? {
            return Err(Rejection::Encoding);
        }
        self.left_bytes = left;
        self.right_bytes = right;
        Ok(())
    }
    pub(super) fn key(&mut self, key: &'static str) -> Result<(), Rejection> {
        // Only frozen ASCII Rust field identifiers reach this method.
        self.literal(b"\"")?;
        self.literal(key.as_bytes())?;
        self.literal(b"\":")
    }
    fn pair(
        &mut self,
        depth: usize,
        left: impl FnOnce(&mut Output<'_>) -> Result<(), Rejection>,
        right: impl FnOnce(&mut Output<'_>) -> Result<(), Rejection>,
    ) -> Result<(), Rejection> {
        self.node(depth)?;
        let left_cap = MAX_CANONICAL_LEAF.min(
            self.budget
                .limits
                .expanded
                .checked_sub(self.left_bytes)
                .ok_or(Rejection::Bound)?,
        );
        let right_cap = MAX_CANONICAL_LEAF.min(
            self.budget
                .limits
                .expanded
                .checked_sub(self.right_bytes)
                .ok_or(Rejection::Bound)?,
        );
        self.left.clear();
        self.right.clear();
        let mut out = Output {
            budget: &mut self.budget,
            data: Some(std::mem::take(&mut self.left)),
            hash: None,
            len: 0,
            cap: left_cap,
            node_cost: 0,
            overflow: Rejection::Bound,
            wire: None,
        };
        left(&mut out)?;
        self.left = out.data.ok_or(Rejection::Encoding)?;
        let mut out = Output {
            budget: &mut self.budget,
            data: Some(std::mem::take(&mut self.right)),
            hash: None,
            len: 0,
            cap: right_cap,
            node_cost: 0,
            overflow: Rejection::Bound,
            wire: None,
        };
        right(&mut out)?;
        self.right = out.data.ok_or(Rejection::Encoding)?;
        self.left_bytes = self
            .left_bytes
            .checked_add(self.left.len())
            .ok_or(Rejection::Bound)?;
        self.right_bytes = self
            .right_bytes
            .checked_add(self.right.len())
            .ok_or(Rejection::Bound)?;
        if !self.budget.equal(&self.left, &self.right)? {
            return Err(Rejection::Encoding);
        }
        Ok(())
    }
    pub(super) fn leaf<T: Closed>(
        &mut self,
        left: &T,
        right: &T,
        depth: usize,
    ) -> Result<(), Rejection> {
        self.pair(
            depth,
            |out| left.emit(out, &Identities::default(), Mode::Named, depth),
            |out| right.emit(out, &Identities::default(), Mode::Named, depth),
        )
    }
    pub(super) fn strings(
        &mut self,
        left: &str,
        right: &str,
        depth: usize,
    ) -> Result<(), Rejection> {
        self.pair(depth, |out| out.string(left), |out| out.string(right))
    }
}

pub(super) fn compare_with_limits(
    left: &Envelope,
    right: &Envelope,
    limits: Limits,
) -> Result<(usize, usize, usize), Rejection> {
    let mut pair = Comparison::new(limits);
    left.compare(right, &mut pair, Envelope::REF)?;
    if pair.left_bytes != pair.right_bytes {
        return Err(Rejection::Encoding);
    }
    Ok((pair.left_bytes, pair.budget.visits, pair.budget.bytes))
}
