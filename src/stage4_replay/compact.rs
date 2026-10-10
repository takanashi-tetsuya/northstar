//! Closed output-only positional V2. The 231 adapters below are the frozen
//! Envelope closure, not a selectable schema or a compact Case parser.
#![cfg(test)]
use super::*;
use sha2::{Digest, Sha256 as Hash};

pub(super) const TAG: &str = "NORTHSTAR_STAGE4_COMPOSITION_V2";
const MARKER: &str = "northstar-stage4-composition-compact-v2";
const EXPANDED_LIMIT: usize = 4_194_304;
const VISIT_LIMIT: usize = 262_144;
const BYTE_LIMIT: usize = 33_554_432;
const DEPTH_LIMIT: usize = 48;
const END: &[u8] = b"\n\x1eEND\n";

#[derive(Clone, Copy)]
struct Limits {
    expanded: usize,
    visits: usize,
    bytes: usize,
    depth: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            expanded: EXPANDED_LIMIT,
            visits: VISIT_LIMIT,
            bytes: BYTE_LIMIT,
            depth: DEPTH_LIMIT,
        }
    }
}
struct Budget {
    limits: Limits,
    visits: usize,
    bytes: usize,
}
impl Budget {
    fn new(limits: Limits) -> Self {
        Self {
            limits,
            visits: 0,
            bytes: 0,
        }
    }
    fn visits(&mut self, n: usize) -> Result<(), Rejection> {
        let next = self.visits.checked_add(n).ok_or(Rejection::Bound)?;
        if next > self.limits.visits {
            return Err(Rejection::Bound);
        }
        self.visits = next;
        Ok(())
    }
    fn bytes(&mut self, n: usize) -> Result<(), Rejection> {
        let next = self.bytes.checked_add(n).ok_or(Rejection::Bound)?;
        if next > self.limits.bytes {
            return Err(Rejection::Bound);
        }
        self.bytes = next;
        Ok(())
    }
    fn depth(&self, depth: usize) -> Result<(), Rejection> {
        if depth > self.limits.depth {
            Err(Rejection::Bound)
        } else {
            Ok(())
        }
    }
    // The first charged scan determines the exact scalar count. The second
    // reserves 4*codepoints BEFORE its scalar/UTF-8-length preflight. Rust str
    // cannot contain surrogates; the raw JSON parser rejects lone escapes.
    fn scalar(&mut self, text: &str) -> Result<usize, Rejection> {
        self.bytes(text.len())?;
        let count = text.chars().count();
        self.bytes(count.checked_mul(4).ok_or(Rejection::Bound)?)?;
        let mut len = 0usize;
        for c in text.chars() {
            len = len.checked_add(c.len_utf8()).ok_or(Rejection::Bound)?;
        }
        Ok(len)
    }
    fn equal(&mut self, a: &[u8], b: &[u8]) -> Result<bool, Rejection> {
        self.bytes(a.len().checked_add(b.len()).ok_or(Rejection::Bound)?)?;
        Ok(a == b)
    }
}

// The parse tree is bounded by raw wire/depth before parsing; its two compact
// visits are reserved before each node is constructed. No expanded JSON tree
// or expanded JSON byte buffer is materialized.
#[derive(Debug)]
enum Node {
    Null,
    Bool(bool),
    Int(i128),
    Str(String),
    Array(Vec<Node>),
    Object(Vec<(String, Node)>),
}
impl Node {
    fn array(&self, n: usize) -> Result<&[Node], Rejection> {
        match self {
            Self::Array(v) if v.len() == n => Ok(v),
            _ => Err(Rejection::Json),
        }
    }
    fn string(&self) -> Result<&str, Rejection> {
        match self {
            Self::Str(v) => Ok(v),
            _ => Err(Rejection::Json),
        }
    }
    fn integer(&self) -> Result<i128, Rejection> {
        match self {
            Self::Int(v) => Ok(*v),
            _ => Err(Rejection::Json),
        }
    }
}

fn lexical(raw: &[u8], budget: &mut Budget) -> Result<(), Rejection> {
    budget.bytes(raw.len())?;
    std::str::from_utf8(raw).map_err(|_| Rejection::Json)?;
    budget.bytes(raw.len())?;
    let mut stack = [0u8; DEPTH_LIMIT];
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut primitive = 0usize;
    let mut token_start = None;
    for (position, &c) in raw.iter().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                quoted = false;
            } else if c < 0x20 {
                return Err(Rejection::Json);
            }
            continue;
        }
        if matches!(
            c,
            b'"' | b'[' | b'{' | b']' | b'}' | b',' | b':' | b' ' | b'\r' | b'\n' | b'\t'
        ) {
            if let Some(start) = token_start.take() {
                integer_preflight(&raw[start..position], budget)?;
            }
        } else if token_start.is_none() {
            token_start = Some(position);
        }
        match c {
            b'"' => {
                quoted = true;
                primitive = 0;
            }
            b'[' | b'{' => {
                depth = depth.checked_add(1).ok_or(Rejection::Bound)?;
                budget.depth(depth)?;
                if depth > stack.len() {
                    return Err(Rejection::Bound);
                }
                stack[depth - 1] = c;
                primitive = 0;
            }
            b']' | b'}' => {
                if depth == 0 || stack[depth - 1] != if c == b']' { b'[' } else { b'{' } {
                    return Err(Rejection::Json);
                }
                depth -= 1;
                primitive = 0;
            }
            b',' | b':' | b' ' | b'\r' | b'\n' | b'\t' => primitive = 0,
            _ => {
                primitive += 1;
                if primitive > 20 {
                    return Err(Rejection::Bound);
                }
            }
        }
    }
    if quoted || escaped || depth != 0 {
        return Err(Rejection::Json);
    }
    if let Some(start) = token_start {
        integer_preflight(&raw[start..], budget)?;
    }
    Ok(())
}

// serde_json owns JSON syntax, UTF-8 escape decoding and surrogate handling.
// These visitors only retain bounded nodes, reject duplicate keys and reserve
// work. No arbitrary serializer/deserializer framework or source schema is used.
struct NodeSeed<'a> {
    budget: &'a mut Budget,
    failure: &'a mut Option<Rejection>,
}
fn parse_error<E: serde::de::Error>(failure: &mut Option<Rejection>, error: Rejection) -> E {
    if failure.is_none() {
        *failure = Some(error);
    }
    E::custom("invalid compact evidence")
}
impl<'de> serde::de::DeserializeSeed<'de> for NodeSeed<'_> {
    type Value = Node;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Node, D::Error> {
        self.budget
            .visits(2)
            .map_err(|e| parse_error(self.failure, e))?;
        deserializer.deserialize_any(self)
    }
}
impl<'de> serde::de::Visitor<'de> for NodeSeed<'_> {
    type Value = Node;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a bounded compact JSON value")
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Node, E> {
        Ok(Node::Null)
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Node, E> {
        Ok(Node::Bool(value))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Node, E> {
        Ok(Node::Int(i128::from(value)))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Node, E> {
        Ok(Node::Int(i128::from(value)))
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Node, E> {
        Err(parse_error(self.failure, Rejection::Json))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Node, E> {
        self.budget
            .scalar(value)
            .map_err(|e| parse_error(self.failure, e))?;
        self.budget
            .bytes(value.len())
            .map_err(|e| parse_error(self.failure, e))?;
        Ok(Node::Str(value.to_owned()))
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Node, E> {
        self.budget
            .scalar(&value)
            .map_err(|e| parse_error(self.failure, e))?;
        Ok(Node::Str(value))
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut access: A) -> Result<Node, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = access.next_element_seed(NodeSeed {
            budget: self.budget,
            failure: self.failure,
        })? {
            values.push(value);
        }
        Ok(Node::Array(values))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut access: A) -> Result<Node, A::Error> {
        let mut fields: Vec<(String, Node)> = Vec::new();
        while let Some(key) = access.next_key_seed(KeySeed {
            budget: self.budget,
            failure: self.failure,
        })? {
            // The unchanged identity introduction has the maximum three keys.
            if fields.len() == 3 {
                return Err(parse_error(self.failure, Rejection::Json));
            }
            for (old, _) in &fields {
                if self
                    .budget
                    .equal(old.as_bytes(), key.as_bytes())
                    .map_err(|e| parse_error(self.failure, e))?
                {
                    return Err(parse_error(self.failure, Rejection::Json));
                }
            }
            let value = access.next_value_seed(NodeSeed {
                budget: self.budget,
                failure: self.failure,
            })?;
            fields.push((key, value));
        }
        Ok(Node::Object(fields))
    }
}
struct KeySeed<'a> {
    budget: &'a mut Budget,
    failure: &'a mut Option<Rejection>,
}
impl<'de> serde::de::DeserializeSeed<'de> for KeySeed<'_> {
    type Value = String;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<String, D::Error> {
        deserializer.deserialize_str(self)
    }
}
impl<'de> serde::de::Visitor<'de> for KeySeed<'_> {
    type Value = String;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a scalar compact object key")
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<String, E> {
        self.budget
            .scalar(value)
            .map_err(|e| parse_error(self.failure, e))?;
        self.budget
            .bytes(value.len())
            .map_err(|e| parse_error(self.failure, e))?;
        Ok(value.to_owned())
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<String, E> {
        self.budget
            .scalar(&value)
            .map_err(|e| parse_error(self.failure, e))?;
        Ok(value)
    }
}
fn parse(raw: &[u8], budget: &mut Budget) -> Result<Node, Rejection> {
    use serde::de::DeserializeSeed;
    // Exactly one bounded generic parse. Its temporary allocations are limited
    // by raw wire/depth preflight, never the untrusted expanded declaration.
    budget.bytes(raw.len())?;
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let mut failure = None;
    let result = NodeSeed {
        budget,
        failure: &mut failure,
    }
    .deserialize(&mut deserializer);
    let value = result.map_err(|_| failure.unwrap_or(Rejection::Json))?;
    deserializer.end().map_err(|_| Rejection::Json)?;
    Ok(value)
}
fn integer_preflight(token: &[u8], budget: &mut Budget) -> Result<(), Rejection> {
    if token
        .first()
        .is_none_or(|c| *c != b'-' && !c.is_ascii_digit())
    {
        return Ok(());
    }
    budget.bytes(token.len())?;
    if token.iter().any(|c| matches!(c, b'.' | b'e' | b'E')) {
        return Err(Rejection::Json);
    }
    let digits = token.strip_prefix(b"-").unwrap_or(token);
    budget.bytes(digits.len())?;
    if digits.is_empty()
        || !digits.iter().all(u8::is_ascii_digit)
        || (digits.len() > 1 && digits[0] == b'0')
    {
        return Err(Rejection::Json);
    }
    if token == b"-0" {
        return Err(Rejection::Encoding);
    }
    budget.bytes(token.len())?;
    let text = std::str::from_utf8(token).map_err(|_| Rejection::Json)?;
    budget.bytes(token.len())?;
    let value = text.parse::<i128>().map_err(|_| Rejection::Bound)?;
    // Out-of-global-domain integers are Bound before
    // positional context. All in-domain unknown sum codes remain Json.
    if value < i128::from(i64::MIN) || value > i128::from(u64::MAX) {
        return Err(Rejection::Bound);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Named,
    Compact,
}
struct Output<'a> {
    budget: &'a mut Budget,
    data: Option<Vec<u8>>,
    hash: Option<Hash>,
    len: usize,
    cap: usize,
    node_cost: usize,
    overflow: Rejection,
    wire: Option<(usize, bool, bool)>,
}
impl<'a> Output<'a> {
    fn expanded(budget: &'a mut Budget, node_cost: usize) -> Self {
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
    fn compact(budget: &'a mut Budget, node_cost: usize) -> Self {
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
    fn node(&mut self, depth: usize) -> Result<(), Rejection> {
        self.budget.depth(depth)?;
        self.budget.visits(self.node_cost)
    }
    fn put(&mut self, bytes: &[u8]) -> Result<(), Rejection> {
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
    fn string(&mut self, text: &str) -> Result<(), Rejection> {
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
    fn integer(&mut self, value: i128) -> Result<(), Rejection> {
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
    fn summary(self) -> Result<(usize, [u8; 32]), Rejection> {
        Ok((
            self.len,
            self.hash.ok_or(Rejection::Encoding)?.finalize().into(),
        ))
    }
}

// Deliberately private, closed adapters. Only the frozen output DTOs implement
// this trait. No runtime type name, schema selection, pool, or fallback exists.
trait Closed: Sized {
    const REF: usize = 0;
    fn emit(
        &self,
        out: &mut Output<'_>,
        ids: &Identities,
        mode: Mode,
        depth: usize,
    ) -> Result<(), Rejection>;
    fn read(
        node: &Node,
        out: &mut Output<'_>,
        ids: &Identities,
        mode: Mode,
        depth: usize,
    ) -> Result<Self, Rejection>;
    // The default is used only by primitive named representations. Every
    // container in the frozen closure overrides it with paired traversal.
    fn compare(&self, other: &Self, pair: &mut Comparison, depth: usize) -> Result<(), Rejection> {
        pair.leaf(self, other, depth)
    }
}

// Two reusable nonrecursive leaf buffers. The largest named leaf is
// Text<16384> containing JSON-escaped control scalars: 6*16384+2 bytes.
// These are not full expanded Envelope buffers or a peak-memory quota.
const MAX_CANONICAL_LEAF: usize = 6 * 16_384 + 2;
struct Comparison {
    budget: Budget,
    left: Vec<u8>,
    right: Vec<u8>,
    left_bytes: usize,
    right_bytes: usize,
}
impl Comparison {
    fn new(limits: Limits) -> Self {
        Self {
            budget: Budget::new(limits),
            left: Vec::with_capacity(MAX_CANONICAL_LEAF),
            right: Vec::with_capacity(MAX_CANONICAL_LEAF),
            left_bytes: 0,
            right_bytes: 0,
        }
    }
    fn node(&mut self, depth: usize) -> Result<(), Rejection> {
        self.budget.depth(depth)?;
        self.budget.visits(2)
    }
    fn literal(&mut self, bytes: &[u8]) -> Result<(), Rejection> {
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
    fn key(&mut self, key: &'static str) -> Result<(), Rejection> {
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
    fn leaf<T: Closed>(&mut self, left: &T, right: &T, depth: usize) -> Result<(), Rejection> {
        self.pair(
            depth,
            |out| left.emit(out, &Identities::default(), Mode::Named, depth),
            |out| right.emit(out, &Identities::default(), Mode::Named, depth),
        )
    }
    fn strings(&mut self, left: &str, right: &str, depth: usize) -> Result<(), Rejection> {
        self.pair(depth, |out| out.string(left), |out| out.string(right))
    }
}

fn named_fields<'a>(
    node: &'a Node,
    names: &[&str],
    budget: &mut Budget,
) -> Result<Vec<&'a Node>, Rejection> {
    let Node::Object(fields) = node else {
        return Err(Rejection::Json);
    };
    if fields.len() != names.len() {
        return Err(Rejection::Json);
    }
    for (key, _) in fields {
        budget.scalar(key)?;
    }
    let mut ordered = Vec::with_capacity(names.len());
    for name in names {
        let mut found = None;
        for (key, value) in fields {
            if budget.equal(key.as_bytes(), name.as_bytes())? {
                found = Some(value);
                break;
            }
        }
        ordered.push(found.ok_or(Rejection::Json)?);
    }
    Ok(ordered)
}
// Synthetic parser controls only; these constructors do not run owners.
trait Example: Closed + Serialize + Eq + std::fmt::Debug {
    fn example() -> Self;
    fn mapping_controls() {
        adapter_roundtrip(&Self::example());
    }
}
macro_rules! closed_object {
    ($name:ty {}) => {
        impl Example for $name { fn example() -> Self { Self {} } }
        impl Closed for $name {
            const REF: usize = 1;
            fn emit(&self, out: &mut Output<'_>, _: &Identities, mode: Mode, depth: usize) -> Result<(), Rejection> {
                out.node(depth)?; out.put(if mode == Mode::Named { b"{}" } else { b"[]" })
            }
            fn read(node: &Node, out: &mut Output<'_>, _: &Identities, mode: Mode, depth: usize) -> Result<Self, Rejection> {
                out.node(depth)?;
                if mode == Mode::Named { named_fields(node, &[], out.budget)?; } else { node.array(0)?; }
                out.put(b"{}")?; Ok(Self {})
            }
            fn compare(&self, _: &Self, pair: &mut Comparison, depth: usize) -> Result<(), Rejection> {
                pair.node(depth)?; pair.literal(b"{}")
            }
        }
    };
    ($name:ty { $($field:ident: $kind:ty),+ $(,)? }) => {
        impl Example for $name { fn example() -> Self { Self { $($field: <$kind>::example()),* } } }
        impl Closed for $name {
            const REF: usize = 1;
            fn emit(&self, out: &mut Output<'_>, ids: &Identities, mode: Mode, depth: usize) -> Result<(), Rejection> {
                out.node(depth)?; out.put(if mode == Mode::Named { b"{" } else { b"[" })?;
                let mut first = true;
                $(if !first { out.put(b",")?; } first = false;
                if mode == Mode::Named { out.string(stringify!($field))?; out.put(b":")?; }
                self.$field.emit(out, ids, mode, depth + 1 + <$kind>::REF)?;)*
                let _ = (first, ids);
                out.put(if mode == Mode::Named { b"}" } else { b"]" })
            }
            fn read(node: &Node, out: &mut Output<'_>, ids: &Identities, mode: Mode, depth: usize) -> Result<Self, Rejection> {
                out.node(depth)?;
                let names = &[$(stringify!($field)),*];
                let named;
                let fields: &[&Node] = if mode == Mode::Named { named = named_fields(node, names, out.budget)?; &named } else { named = node.array(names.len())?.iter().collect::<Vec<_>>(); &named };
                let mut next = fields.iter(); out.put(b"{")?; let mut first = true;
                $(if !first { out.put(b",")?; } first = false;
                out.string(stringify!($field))?; out.put(b":")?;
                let $field = <$kind>::read(next.next().copied().ok_or(Rejection::Json)?, out, ids, mode, depth + 1 + <$kind>::REF)?;)*
                let _ = (&mut next, first, ids);
                out.put(b"}")?;
                Ok(Self { $($field),* })
            }
            fn compare(&self, other: &Self, pair: &mut Comparison, depth: usize) -> Result<(), Rejection> {
                pair.node(depth)?; pair.literal(b"{")?; let mut first = true;
                $(if !first { pair.literal(b",")?; } first = false;
                pair.key(stringify!($field))?;
                self.$field.compare(&other.$field, pair, depth + 1 + <$kind>::REF)?;)*
                let _ = first; pair.literal(b"}")
            }
        }
    };
}
macro_rules! closed_enum {
    ($name:ty { $first:ident $(, $variant:ident)* $(,)? }) => {
        impl Example for $name {
            fn example() -> Self { Self::$first }
            fn mapping_controls() { adapter_roundtrip(&Self::$first); $(adapter_roundtrip(&Self::$variant);)* }
        }
        closed_enum_impl!($name { $first $(, $variant)* });
    };
}
macro_rules! closed_enum_impl {
    ($name:ty { $($variant:ident),+ $(,)? }) => {
        impl Closed for $name {
            const REF: usize = 1;
            fn emit(&self, out: &mut Output<'_>, _: &Identities, _: Mode, depth: usize) -> Result<(), Rejection> {
                out.node(depth)?; out.string(match self { $(Self::$variant => stringify!($variant)),+ })
            }
            fn read(node: &Node, out: &mut Output<'_>, _: &Identities, _: Mode, depth: usize) -> Result<Self, Rejection> {
                out.node(depth)?; let text = node.string()?; out.budget.scalar(text)?;
                let value = match text { $(stringify!($variant) => Self::$variant,)+ _ => return Err(Rejection::Json) };
                out.string(text)?; Ok(value)
            }
        }
    };
}
macro_rules! closed_sum {
    ($name:ty { $first_code:literal => $first:ident($first_kind:ty) $(, $code:literal => $variant:ident($kind:ty))* $(,)? }) => {
        impl Example for $name {
            fn example() -> Self { Self::$first(<$first_kind>::example()) }
            fn mapping_controls() {
                adapter_roundtrip(&Self::$first(<$first_kind>::example()));
                $(adapter_roundtrip(&Self::$variant(<$kind>::example()));)*
            }
        }
        closed_sum_impl!($name { $first_code => $first($first_kind) $(, $code => $variant($kind))* });
    };
}
macro_rules! closed_sum_impl {
    ($name:ty { $($code:literal => $variant:ident($kind:ty)),+ $(,)? }) => {
        impl Closed for $name {
            const REF: usize = 1;
            fn emit(&self, out: &mut Output<'_>, ids: &Identities, mode: Mode, depth: usize) -> Result<(), Rejection> {
                out.node(depth)?;
                match self { $(Self::$variant(value) => {
                    if mode == Mode::Named { out.put(b"{\"kind\":")?; out.node(depth)?; out.string(stringify!($variant))?; out.put(b",\"data\":")?; }
                    else { out.put(b"[")?; out.node(depth)?; out.integer($code)?; out.put(b",")?; }
                    value.emit(out, ids, mode, depth + 1 + <$kind>::REF)?;
                    out.put(if mode == Mode::Named { b"}" } else { b"]" })
                }),+ }
            }
            fn read(node: &Node, out: &mut Output<'_>, ids: &Identities, mode: Mode, depth: usize) -> Result<Self, Rejection> {
                out.node(depth)?;
                let (code, data) = if mode == Mode::Named {
                    let fields = named_fields(node, &["kind", "data"], out.budget)?;
                    let tag = fields[0].string()?; out.budget.scalar(tag)?;
                    (match tag { $(stringify!($variant) => $code,)+ _ => return Err(Rejection::Json) }, fields[1])
                } else { let fields = node.array(2)?; (fields[0].integer()?, &fields[1]) };
                match code { $($code => {
                    out.put(b"{\"kind\":")?; out.node(depth)?; out.string(stringify!($variant))?; out.put(b",\"data\":")?;
                    let value = <$kind>::read(data, out, ids, mode, depth + 1 + <$kind>::REF)?;
                    out.put(b"}")?; Ok(Self::$variant(value))
                }),+ _ => Err(Rejection::Json) }
            }
            fn compare(&self, other: &Self, pair: &mut Comparison, depth: usize) -> Result<(), Rejection> {
                pair.node(depth)?; pair.literal(b"{\"kind\":")?;
                let left = match self { $(Self::$variant(_) => stringify!($variant)),+ };
                let right = match other { $(Self::$variant(_) => stringify!($variant)),+ };
                pair.strings(left, right, depth)?; pair.literal(b",\"data\":")?;
                match (self, other) {
                    $((Self::$variant(left), Self::$variant(right)) => left.compare(right, pair, depth + 1 + <$kind>::REF)?,)+
                    _ => return Err(Rejection::Encoding),
                }
                pair.literal(b"}")
            }
        }
    };
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum IdentityKey {
    Fixed(u128),
    Opaque(u8),
}
#[derive(Default)]
struct Identities {
    first: BTreeMap<IdentityKey, usize>,
    labels: Vec<IdentityLabel>,
}
impl Identities {
    fn key(label: &IdentityLabel, budget: &mut Budget) -> Result<IdentityKey, Rejection> {
        // Extra terminal inspection: object, kind, payload object, leaf. UUID
        // keys are integer values; ordered-map comparisons inspect no strings.
        budget.visits(4)?;
        Ok(match label {
            IdentityLabel::Fixed(v) => {
                budget.bytes(32)?;
                IdentityKey::Fixed(v.uuid.0.as_u128())
            }
            IdentityLabel::Opaque(v) => IdentityKey::Opaque(v.ordinal),
        })
    }
    fn new(introductions: &[IdentityIntroduction], budget: &mut Budget) -> Result<Self, Rejection> {
        budget.visits(1)?;
        if introductions.len() > MAX_IDENTITIES {
            return Err(Rejection::Bound);
        }
        let mut result = Self::default();
        for (index, item) in introductions.iter().enumerate() {
            budget.visits(1)?;
            let key = Self::key(&item.label, budget)?;
            result.first.entry(key).or_insert(index);
            // A bounded typed terminal copy, never a shared expanded JSON node.
            budget.bytes(match key {
                IdentityKey::Fixed(_) => 16,
                IdentityKey::Opaque(_) => 1,
            })?;
            result.labels.push(item.label.clone());
        }
        Ok(result)
    }
    fn index(&self, label: &IdentityLabel, budget: &mut Budget) -> Result<usize, Rejection> {
        let key = Self::key(label, budget)?;
        self.first.get(&key).copied().ok_or(Rejection::Encoding)
    }
}

macro_rules! closed_integer {
    ($($kind:ty),+ $(,)?) => { $(impl Closed for $kind {
        fn emit(&self, out: &mut Output<'_>, _: &Identities, _: Mode, depth: usize) -> Result<(), Rejection> { out.node(depth)?; out.integer(i128::from(*self)) }
        fn read(node: &Node, out: &mut Output<'_>, _: &Identities, _: Mode, depth: usize) -> Result<Self, Rejection> {
            out.node(depth)?; let number = node.integer()?; let value = <$kind>::try_from(number).map_err(|_| Rejection::Bound)?; out.integer(number)?; Ok(value)
        }
    })+ };
}
closed_integer!(u8, u32, u64, i32, i64);
impl Closed for bool {
    fn emit(
        &self,
        out: &mut Output<'_>,
        _: &Identities,
        _: Mode,
        depth: usize,
    ) -> Result<(), Rejection> {
        out.node(depth)?;
        out.put(if *self { b"true" } else { b"false" })
    }
    fn read(
        node: &Node,
        out: &mut Output<'_>,
        ids: &Identities,
        mode: Mode,
        depth: usize,
    ) -> Result<Self, Rejection> {
        let Node::Bool(value) = node else {
            return Err(Rejection::Json);
        };
        value.emit(out, ids, mode, depth)?;
        Ok(*value)
    }
}
impl<const N: usize> Closed for Text<N> {
    fn emit(
        &self,
        out: &mut Output<'_>,
        _: &Identities,
        _: Mode,
        depth: usize,
    ) -> Result<(), Rejection> {
        out.node(depth)?;
        text_bound::<N>(&self.0, out.budget)?;
        out.string(&self.0)
    }
    fn read(
        node: &Node,
        out: &mut Output<'_>,
        _: &Identities,
        _: Mode,
        depth: usize,
    ) -> Result<Self, Rejection> {
        out.node(depth)?;
        let value = node.string()?;
        text_bound::<N>(value, out.budget)?;
        out.string(value)?;
        out.budget.bytes(value.len())?;
        Ok(Text(value.to_owned()))
    }
}
fn text_bound<const N: usize>(text: &str, budget: &mut Budget) -> Result<(), Rejection> {
    if budget.scalar(text)? > N {
        return Err(Rejection::Bound);
    }
    budget.bytes(text.len())?;
    if text.contains('\0') {
        Err(Rejection::Bound)
    } else {
        Ok(())
    }
}
fn hex_bound(text: &str, max: usize, exact: bool, budget: &mut Budget) -> Result<(), Rejection> {
    budget.scalar(text)?;
    let cap = max.checked_mul(2).ok_or(Rejection::Bound)?;
    if text.len() > cap {
        return Err(Rejection::Bound);
    }
    if (exact && text.len() != cap) || !text.len().is_multiple_of(2) {
        return Err(Rejection::Encoding);
    }
    budget.bytes(text.len())?;
    if !text
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Rejection::Encoding);
    }
    Ok(())
}
impl<const N: usize> Closed for Hex<N> {
    fn emit(
        &self,
        out: &mut Output<'_>,
        _: &Identities,
        _: Mode,
        depth: usize,
    ) -> Result<(), Rejection> {
        out.node(depth)?;
        hex_bound(&self.0, N, true, out.budget)?;
        out.string(&self.0)
    }
    fn read(
        node: &Node,
        out: &mut Output<'_>,
        _: &Identities,
        _: Mode,
        depth: usize,
    ) -> Result<Self, Rejection> {
        out.node(depth)?;
        let text = node.string()?;
        hex_bound(text, N, true, out.budget)?;
        out.string(text)?;
        out.budget.bytes(text.len())?;
        Ok(Hex(text.to_owned()))
    }
}
fn unhex(text: &str, budget: &mut Budget) -> Result<Vec<u8>, Rejection> {
    let n = text.len() / 2;
    budget.bytes(text.len().checked_add(n).ok_or(Rejection::Bound)?)?;
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    let mut result = Vec::with_capacity(n);
    for pair in text.as_bytes().chunks_exact(2) {
        result.push((digit(pair[0]) << 4) | digit(pair[1]));
    }
    Ok(result)
}
fn lower_hex(raw: &[u8], budget: &mut Budget) -> Result<String, Rejection> {
    let len = raw.len().checked_mul(2).ok_or(Rejection::Bound)?;
    budget.bytes(raw.len().checked_add(len).ok_or(Rejection::Bound)?)?;
    let mut result = String::with_capacity(len);
    let h = b"0123456789abcdef";
    for &b in raw {
        result.push(h[usize::from(b >> 4)] as char);
        result.push(h[usize::from(b & 15)] as char);
    }
    Ok(result)
}
fn utf8<'a>(raw: &'a [u8], budget: &mut Budget) -> Result<Option<&'a str>, Rejection> {
    budget.bytes(raw.len().checked_mul(2).ok_or(Rejection::Bound)?)?;
    Ok(std::str::from_utf8(raw).ok())
}
impl<const N: usize> Closed for Bytes<N> {
    fn emit(
        &self,
        out: &mut Output<'_>,
        _: &Identities,
        mode: Mode,
        depth: usize,
    ) -> Result<(), Rejection> {
        out.node(depth)?;
        hex_bound(&self.0, N, false, out.budget)?;
        if mode == Mode::Named {
            return out.string(&self.0);
        }
        let bytes = unhex(&self.0, out.budget)?;
        let text = utf8(&bytes, out.budget)?;
        out.put(b"[")?;
        out.node(depth)?;
        out.integer(if text.is_some() { 0 } else { 1 })?;
        out.put(b",")?;
        out.node(depth)?;
        out.string(text.unwrap_or(&self.0))?;
        out.put(b"]")
    }
    fn read(
        node: &Node,
        out: &mut Output<'_>,
        _: &Identities,
        mode: Mode,
        depth: usize,
    ) -> Result<Self, Rejection> {
        out.node(depth)?;
        if mode == Mode::Named {
            let text = node.string()?;
            hex_bound(text, N, false, out.budget)?;
            out.string(text)?;
            out.budget.bytes(text.len())?;
            return Ok(Bytes(text.to_owned()));
        }
        let pair = node.array(2)?;
        let tag = pair[0].integer()?;
        let text = pair[1].string()?;
        let len = out.budget.scalar(text)?;
        match tag {
            0 => {
                if len > N {
                    return Err(Rejection::Bound);
                }
                let encoded_len = len
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(2))
                    .ok_or(Rejection::Bound)?;
                if out.len.checked_add(encoded_len).ok_or(Rejection::Bound)? > out.cap {
                    return Err(Rejection::Bound);
                }
                // Rust str is already scalar UTF-8. This conversion inspects and
                // produces len bytes logically, despite retaining a borrow.
                out.budget
                    .bytes(len.checked_mul(2).ok_or(Rejection::Bound)?)?;
                let hex = lower_hex(text.as_bytes(), out.budget)?;
                out.string(&hex)?;
                Ok(Bytes(hex))
            }
            1 => {
                hex_bound(text, N, false, out.budget)?;
                let encoded_len = text.len().checked_add(2).ok_or(Rejection::Bound)?;
                if out.len.checked_add(encoded_len).ok_or(Rejection::Bound)? > out.cap {
                    return Err(Rejection::Bound);
                }
                let bytes = unhex(text, out.budget)?;
                if utf8(&bytes, out.budget)?.is_some() {
                    return Err(Rejection::Encoding);
                }
                out.string(text)?;
                out.budget.bytes(text.len())?;
                Ok(Bytes(text.to_owned()))
            }
            _ => Err(Rejection::Encoding),
        }
    }
}
impl<T: Closed> Closed for Nullable<T> {
    fn emit(
        &self,
        out: &mut Output<'_>,
        ids: &Identities,
        mode: Mode,
        depth: usize,
    ) -> Result<(), Rejection> {
        out.budget.depth(depth)?;
        match self {
            Self::Null(()) => {
                out.node(depth)?;
                out.put(b"null")
            }
            Self::Value(value) => value.emit(out, ids, mode, depth + 1 + T::REF),
        }
    }
    fn read(
        node: &Node,
        out: &mut Output<'_>,
        ids: &Identities,
        mode: Mode,
        depth: usize,
    ) -> Result<Self, Rejection> {
        out.budget.depth(depth)?;
        if matches!(node, Node::Null) {
            out.node(depth)?;
            out.put(b"null")?;
            Ok(Self::Null(()))
        } else {
            T::read(node, out, ids, mode, depth + 1 + T::REF).map(Self::Value)
        }
    }
    fn compare(&self, other: &Self, pair: &mut Comparison, depth: usize) -> Result<(), Rejection> {
        pair.budget.depth(depth)?;
        match (self, other) {
            (Self::Null(()), Self::Null(())) => {
                pair.node(depth)?;
                pair.literal(b"null")
            }
            (Self::Value(left), Self::Value(right)) => {
                left.compare(right, pair, depth + 1 + T::REF)
            }
            _ => {
                pair.node(depth)?;
                Err(Rejection::Encoding)
            }
        }
    }
}
impl<T: Closed, const N: usize> Closed for List<T, N> {
    fn emit(
        &self,
        out: &mut Output<'_>,
        ids: &Identities,
        mode: Mode,
        depth: usize,
    ) -> Result<(), Rejection> {
        out.node(depth)?;
        if self.len() > N {
            return Err(Rejection::Bound);
        }
        out.put(b"[")?;
        for (i, value) in self.as_slice().iter().enumerate() {
            if i != 0 {
                out.put(b",")?;
            }
            value.emit(out, ids, mode, depth + 1 + T::REF)?;
        }
        out.put(b"]")
    }
    fn read(
        node: &Node,
        out: &mut Output<'_>,
        ids: &Identities,
        mode: Mode,
        depth: usize,
    ) -> Result<Self, Rejection> {
        out.node(depth)?;
        let Node::Array(values) = node else {
            return Err(Rejection::Json);
        };
        if values.len() > N {
            return Err(Rejection::Bound);
        }
        let mut result = Vec::new();
        out.put(b"[")?;
        for (i, value) in values.iter().enumerate() {
            if i != 0 {
                out.put(b",")?;
            }
            result.push(T::read(value, out, ids, mode, depth + 1 + T::REF)?);
        }
        out.put(b"]")?;
        Ok(List(result))
    }
    fn compare(&self, other: &Self, pair: &mut Comparison, depth: usize) -> Result<(), Rejection> {
        pair.node(depth)?;
        if self.len() > N || other.len() > N {
            return Err(Rejection::Bound);
        }
        if self.len() != other.len() {
            return Err(Rejection::Encoding);
        }
        pair.literal(b"[")?;
        for (index, (left, right)) in self.as_slice().iter().zip(other.as_slice()).enumerate() {
            if index != 0 {
                pair.literal(b",")?;
            }
            left.compare(right, pair, depth + 1 + T::REF)?;
        }
        pair.literal(b"]")
    }
}
impl<T: Closed, const N: usize> Closed for [T; N] {
    fn emit(
        &self,
        out: &mut Output<'_>,
        ids: &Identities,
        mode: Mode,
        depth: usize,
    ) -> Result<(), Rejection> {
        out.node(depth)?;
        out.put(b"[")?;
        for (i, value) in self.iter().enumerate() {
            if i != 0 {
                out.put(b",")?;
            }
            value.emit(out, ids, mode, depth + 1 + T::REF)?;
        }
        out.put(b"]")
    }
    fn read(
        node: &Node,
        out: &mut Output<'_>,
        ids: &Identities,
        mode: Mode,
        depth: usize,
    ) -> Result<Self, Rejection> {
        out.node(depth)?;
        let values = node.array(N)?;
        let mut result = Vec::new();
        out.put(b"[")?;
        for (i, value) in values.iter().enumerate() {
            if i != 0 {
                out.put(b",")?;
            }
            result.push(T::read(value, out, ids, mode, depth + 1 + T::REF)?);
        }
        out.put(b"]")?;
        result.try_into().map_err(|_| Rejection::Json)
    }
    fn compare(&self, other: &Self, pair: &mut Comparison, depth: usize) -> Result<(), Rejection> {
        pair.node(depth)?;
        pair.literal(b"[")?;
        for (index, (left, right)) in self.iter().zip(other).enumerate() {
            if index != 0 {
                pair.literal(b",")?;
            }
            left.compare(right, pair, depth + 1 + T::REF)?;
        }
        pair.literal(b"]")
    }
}
impl Closed for Id {
    fn emit(
        &self,
        out: &mut Output<'_>,
        _: &Identities,
        _: Mode,
        depth: usize,
    ) -> Result<(), Rejection> {
        out.node(depth)?;
        out.budget.bytes(16 + 36)?;
        let mut bytes = [0u8; 36];
        out.string(self.0.hyphenated().encode_lower(&mut bytes))
    }
    fn read(
        node: &Node,
        out: &mut Output<'_>,
        _: &Identities,
        _: Mode,
        depth: usize,
    ) -> Result<Self, Rejection> {
        out.node(depth)?;
        let text = node.string()?;
        out.budget.scalar(text)?;
        if text.len() != 36 {
            return Err(Rejection::Encoding);
        }
        out.budget.bytes(36 + 16)?;
        let uuid = Uuid::parse_str(text).map_err(|_| Rejection::Encoding)?;
        out.budget.bytes(16 + 36)?;
        let mut bytes = [0u8; 36];
        let canonical = uuid.hyphenated().encode_lower(&mut bytes);
        if !out.budget.equal(text.as_bytes(), canonical.as_bytes())? {
            return Err(Rejection::Encoding);
        }
        out.string(text)?;
        Ok(Id(uuid))
    }
}
impl Closed for IdentityLabel {
    fn emit(
        &self,
        out: &mut Output<'_>,
        ids: &Identities,
        _: Mode,
        depth: usize,
    ) -> Result<(), Rejection> {
        out.node(depth)?;
        out.put(b"{\"kind\":")?;
        out.node(depth)?;
        match self {
            Self::Fixed(v) => {
                out.string("Fixed")?;
                out.put(b",\"data\":{\"uuid\":")?;
                out.node(depth)?;
                v.uuid.emit(out, ids, Mode::Named, depth)?;
            }
            Self::Opaque(v) => {
                out.string("Opaque")?;
                out.put(b",\"data\":{\"ordinal\":")?;
                out.node(depth)?;
                v.ordinal.emit(out, ids, Mode::Named, depth)?;
            }
        }
        out.put(b"}}")
    }
    fn read(
        node: &Node,
        out: &mut Output<'_>,
        ids: &Identities,
        _: Mode,
        depth: usize,
    ) -> Result<Self, Rejection> {
        let fields = named_fields(node, &["kind", "data"], out.budget)?;
        out.node(depth)?;
        let tag = fields[0].string()?;
        out.budget.scalar(tag)?;
        out.put(b"{\"kind\":")?;
        out.node(depth)?;
        let result = match tag {
            "Fixed" => {
                let data = named_fields(fields[1], &["uuid"], out.budget)?;
                out.string("Fixed")?;
                out.put(b",\"data\":{\"uuid\":")?;
                out.node(depth)?;
                Self::Fixed(FixedIdentity {
                    uuid: Id::read(data[0], out, ids, Mode::Named, depth)?,
                })
            }
            "Opaque" => {
                let data = named_fields(fields[1], &["ordinal"], out.budget)?;
                out.string("Opaque")?;
                out.put(b",\"data\":{\"ordinal\":")?;
                out.node(depth)?;
                Self::Opaque(OpaqueIdentity {
                    ordinal: u8::read(data[0], out, ids, Mode::Named, depth)?,
                })
            }
            _ => return Err(Rejection::Json),
        };
        out.put(b"}}")?;
        Ok(result)
    }
    fn compare(&self, other: &Self, pair: &mut Comparison, depth: usize) -> Result<(), Rejection> {
        pair.node(depth)?;
        pair.literal(b"{\"kind\":")?;
        let tag = |value: &Self| match value {
            Self::Fixed(_) => "Fixed",
            Self::Opaque(_) => "Opaque",
        };
        pair.strings(tag(self), tag(other), depth)?;
        pair.literal(b",\"data\":")?;
        pair.node(depth)?;
        pair.literal(b"{")?;
        match (self, other) {
            (Self::Fixed(left), Self::Fixed(right)) => {
                pair.key("uuid")?;
                left.uuid.compare(&right.uuid, pair, depth)?;
            }
            (Self::Opaque(left), Self::Opaque(right)) => {
                pair.key("ordinal")?;
                left.ordinal.compare(&right.ordinal, pair, depth)?;
            }
            _ => return Err(Rejection::Encoding),
        }
        pair.literal(b"}}")
    }
}
impl Closed for EvidenceId {
    fn emit(
        &self,
        out: &mut Output<'_>,
        ids: &Identities,
        mode: Mode,
        depth: usize,
    ) -> Result<(), Rejection> {
        let Self::Encoded(label) = self else {
            return Err(Rejection::Encoding);
        };
        if mode == Mode::Named {
            label.emit(out, ids, mode, depth)
        } else {
            out.node(depth)?;
            let index = ids.index(label, out.budget)?;
            out.integer(index as i128)
        }
    }
    fn read(
        node: &Node,
        out: &mut Output<'_>,
        ids: &Identities,
        mode: Mode,
        depth: usize,
    ) -> Result<Self, Rejection> {
        if mode == Mode::Named {
            return IdentityLabel::read(node, out, ids, mode, depth).map(Self::Encoded);
        }
        let index = usize::try_from(node.integer()?).map_err(|_| Rejection::Bound)?;
        let label = ids.labels.get(index).ok_or(Rejection::Bound)?;
        // Emits/counts the complete original four-node label at every reference
        // before its independent typed clone is constructed.
        label.emit(out, ids, Mode::Named, depth)?;
        out.budget.bytes(match label {
            IdentityLabel::Fixed(_) => 16,
            IdentityLabel::Opaque(_) => 1,
        })?;
        Ok(Self::Encoded(label.clone()))
    }
    fn compare(&self, other: &Self, pair: &mut Comparison, depth: usize) -> Result<(), Rejection> {
        match (self, other) {
            (Self::Encoded(left), Self::Encoded(right)) => left.compare(right, pair, depth),
            _ => {
                pair.node(depth)?;
                Err(Rejection::Encoding)
            }
        }
    }
}

impl Closed for Envelope {
    const REF: usize = 1;
    fn emit(
        &self,
        out: &mut Output<'_>,
        ids: &Identities,
        mode: Mode,
        depth: usize,
    ) -> Result<(), Rejection> {
        out.node(depth)?;
        out.put(if mode == Mode::Named { b"{" } else { b"[" })?;
        macro_rules! field {
            ($field:ident, $kind:ty, $field_mode:expr, $comma:expr) => {
                if $comma {
                    out.put(b",")?;
                }
                if mode == Mode::Named {
                    out.string(stringify!($field))?;
                    out.put(b":")?;
                }
                self.$field
                    .emit(out, ids, $field_mode, depth + 1 + <$kind>::REF)?;
            };
        }
        field!(schema, Text<64>, mode, false);
        field!(entry, Text<128>, mode, true);
        field!(input_sha256, Hex<32>, mode, true);
        field!(rejection, Nullable<Rejection>, mode, true);
        field!(execution, Nullable<Execution>, mode, true);
        field!(resource_stop, Nullable<ResourceStop>, mode, true);
        field!(identity_map, List<IdentityIntroduction, 64>, Mode::Named, true);
        field!(facts, List<Captured, 256>, mode, true);
        field!(observation_status, ObservationStatus, mode, true);
        out.put(if mode == Mode::Named { b"}" } else { b"]" })
    }
    fn read(
        node: &Node,
        out: &mut Output<'_>,
        ids: &Identities,
        mode: Mode,
        depth: usize,
    ) -> Result<Self, Rejection> {
        out.node(depth)?;
        let names = [
            "schema",
            "entry",
            "input_sha256",
            "rejection",
            "execution",
            "resource_stop",
            "identity_map",
            "facts",
            "observation_status",
        ];
        let fields: Vec<&Node> = if mode == Mode::Named {
            named_fields(node, &names, out.budget)?
        } else {
            node.array(9)?.iter().collect()
        };
        out.put(b"{")?;
        macro_rules! field {
            ($index:literal, $field:ident, $kind:ty, $field_mode:expr, $identities:expr) => {
                if $index != 0 {
                    out.put(b",")?;
                }
                out.string(stringify!($field))?;
                out.put(b":")?;
                let $field = <$kind>::read(
                    fields[$index],
                    out,
                    $identities,
                    $field_mode,
                    depth + 1 + <$kind>::REF,
                )?;
            };
        }
        field!(0, schema, Text<64>, mode, ids);
        field!(1, entry, Text<128>, mode, ids);
        field!(2, input_sha256, Hex<32>, mode, ids);
        field!(3, rejection, Nullable<Rejection>, mode, ids);
        field!(4, execution, Nullable<Execution>, mode, ids);
        field!(5, resource_stop, Nullable<ResourceStop>, mode, ids);
        field!(6, identity_map, List<IdentityIntroduction, 64>, Mode::Named, ids);
        let local_ids = Identities::new(identity_map.as_slice(), out.budget)?;
        field!(7, facts, List<Captured, 256>, mode, &local_ids);
        field!(8, observation_status, ObservationStatus, mode, &local_ids);
        out.put(b"}")?;
        Ok(Self {
            schema,
            entry,
            input_sha256,
            rejection,
            execution,
            resource_stop,
            identity_map,
            facts,
            observation_status,
        })
    }
    fn compare(&self, other: &Self, pair: &mut Comparison, depth: usize) -> Result<(), Rejection> {
        pair.node(depth)?;
        pair.literal(b"{")?;
        pair.key("schema")?;
        self.schema
            .compare(&other.schema, pair, depth + 1 + <Text<64>>::REF)?;
        pair.literal(b",")?;
        pair.key("entry")?;
        self.entry
            .compare(&other.entry, pair, depth + 1 + <Text<128>>::REF)?;
        pair.literal(b",")?;
        pair.key("input_sha256")?;
        self.input_sha256
            .compare(&other.input_sha256, pair, depth + 1 + <Hex<32>>::REF)?;
        pair.literal(b",")?;
        pair.key("rejection")?;
        self.rejection.compare(
            &other.rejection,
            pair,
            depth + 1 + <Nullable<Rejection>>::REF,
        )?;
        pair.literal(b",")?;
        pair.key("execution")?;
        self.execution.compare(
            &other.execution,
            pair,
            depth + 1 + <Nullable<Execution>>::REF,
        )?;
        pair.literal(b",")?;
        pair.key("resource_stop")?;
        self.resource_stop.compare(
            &other.resource_stop,
            pair,
            depth + 1 + <Nullable<ResourceStop>>::REF,
        )?;
        pair.literal(b",")?;
        pair.key("identity_map")?;
        self.identity_map.compare(
            &other.identity_map,
            pair,
            depth + 1 + <List<IdentityIntroduction, 64>>::REF,
        )?;
        pair.literal(b",")?;
        pair.key("facts")?;
        self.facts
            .compare(&other.facts, pair, depth + 1 + <List<Captured, 256>>::REF)?;
        pair.literal(b",")?;
        pair.key("observation_status")?;
        self.observation_status.compare(
            &other.observation_status,
            pair,
            depth + 1 + <ObservationStatus>::REF,
        )?;
        pair.literal(b"}")
    }
}

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
fn frame(payload: &[u8], budget: &mut Budget) -> Result<Vec<u8>, Rejection> {
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
fn encode_with_limits(
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
pub(super) fn encode(envelope: &Envelope) -> Result<Vec<u8>, Loss> {
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
fn extract<'a>(frame: &'a [u8], budget: &mut Budget) -> Result<&'a [u8], Rejection> {
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
fn decode_with_limits(frame: &[u8], limits: Limits) -> Result<(Envelope, usize, usize), Rejection> {
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
pub(super) fn decode(frame: &[u8]) -> Result<Envelope, Rejection> {
    decode_with_limits(frame, Limits::default()).map(|(envelope, _, _)| envelope)
}

fn compare_with_limits(
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RoundtripFailure {
    Decode(Rejection),
    Compare(Rejection),
}
/// Verify the same captured Envelope against its decoded V2 representation.
/// The decoder and the complete paired comparison each retain their own
/// operation-wide budgets. No owner is run and no frame is repaired/retried.
pub(super) fn verify_frame_roundtrip(
    original: &Envelope,
    frame: &[u8],
) -> Result<(), RoundtripFailure> {
    let restored = decode(frame).map_err(RoundtripFailure::Decode)?;
    compare_with_limits(original, &restored, Limits::default())
        .map_err(RoundtripFailure::Compare)?;
    Ok(())
}

// BEGIN FROZEN ADAPTERS
// Source subset SHA-256: 0d28af4728b2a9fb08abf6408d0b5a970442307c69eae93cd225ab436622f7e4
// Slot/code map SHA-256: da17fe738832e1ff90868f4daac9a81b679c1b189c2c20b129bdd76ae3fe67c8
// Root Envelope is implemented explicitly above for its identity_map exception.
closed_enum!(Rejection {
    TooLarge,
    Json,
    Schema,
    Bound,
    Encoding,
    Relationship,
    Unsupported
});
closed_enum!(Execution {
    Complete,
    Cancelled,
    Failed
});
closed_sum!(ResourceStop { 0 => DriverPoll(DriverResourceStop), 1 => NativeWrite(NativeResourceStop), 2 => NativeFlush(NativeResourceStop) });
closed_object!(DriverResourceStop {
    owner: DriverOwner,
    owner_ordinal: u8,
    admitted_calls: u8
});
closed_enum!(DriverOwner {
    Muc,
    Foreground,
    Claim,
    Worker,
    Credential,
    Native,
    Publication,
    Bosh
});
closed_object!(NativeResourceStop {
    item_ordinal: u8,
    admitted_calls: u8
});
closed_object!(IdentityIntroduction {
    label: IdentityLabel,
    first_seq: u32,
    locus: Introduction
});
closed_enum!(Introduction {
    Frame,
    Connection,
    Session,
    CredentialAttempt,
    ConstructedReceipt,
    ReturnedReceipt,
    TransferredReceipt,
    BegunReceipt,
    ControlIdentity,
    ReceiptAssociation,
    ArchiveCandidate,
    StageIdentity,
    SourceIdentity,
    UnexpectedObservedIdentity
});
closed_object!(Captured {
    seq: u32,
    fact: Fact
});
closed_sum!(Fact { 0 => Frame(FrameCapture<EvidenceId>), 1 => Muc(MucFact<EvidenceId>), 2 => Foreground(ForegroundFact<EvidenceId>), 3 => Claim(ClaimFact<EvidenceId>), 4 => Worker(WorkerFact<EvidenceId>), 5 => Credential(CredentialCapture<EvidenceId>), 6 => Control(ControlFact<EvidenceId>), 7 => Native(NativeFact<EvidenceId>), 8 => Bosh(BoshFact<EvidenceId>), 9 => Driver(DriverPoll) });
closed_object!(FrameCapture<EvidenceId> { frame: EvidenceId, cut: Cut, stage: Nullable<FrameStage>, outcome: Nullable<FrameOutcome>, admission_begin: Nullable<AdmissionEvidence<EvidenceId>>, admission_finalize: Nullable<AdmissionEvidence<EvidenceId>> });
closed_enum!(Cut {
    Introduction,
    PortEntry,
    PortReturn,
    BeforePoll,
    AfterPoll,
    ChildDrop,
    AfterRunnerDrop,
    BeforePublish,
    AfterPublish,
    BeforeFinish,
    AfterFinish,
    BeforeTeardown,
    AfterTeardown
});
closed_enum!(FrameStage {
    Validation,
    Handler,
    SmCheckpoint,
    AuthPublication,
    CapsPublication,
    ReplacementNotification,
    MessagePolicy,
    MessageAdmission,
    MessageRouting,
    MessageFollowup,
    MucPolicy,
    MucGateWait,
    MucAuthority,
    MucAdmission,
    MucClusterFanout,
    MucLocalFanout,
    MixPolicy,
    MixAdmission
});
closed_enum!(FrameOutcome {
    Pending,
    Completed,
    BackendFailure,
    TimedOut,
    Cancelled,
    Panicked,
    IntegrityRejected,
    CredentialRejected,
    RouteRejected,
    CompletedWithDeferredNotification
});
closed_object!(AdmissionEvidence<EvidenceId> { correlation: Correlation<EvidenceId>, started: bool, knowledge: AdmissionKnowledge<EvidenceId>, returned: Nullable<AdmissionReturned<EvidenceId>> });
closed_object!(Correlation<EvidenceId> { operation_id: EvidenceId, effect: u64, generation: u64, attempt: u64 });
closed_sum!(AdmissionKnowledge<EvidenceId> { 0 => NoCommitRequested(Empty), 1 => CommitCallEntered(AdmissionCommit<EvidenceId>), 2 => ReceiptKnown(AdmissionCommit<EvidenceId>) });
closed_object!(Empty {});
closed_object!(AdmissionCommit<EvidenceId> { correlation: Correlation<EvidenceId>, scope: EffectScope, fact: AdmissionFact<EvidenceId> });
closed_enum!(EffectScope {
    NewReservation,
    Reclaim,
    ReplayRead,
    PendingRequirement,
    GuardDenial,
    AdmissionFinalize,
    GuardOnlyVerification
});
closed_sum!(AdmissionFact<EvidenceId> { 0 => Reserved(FenceEvidence<EvidenceId>), 1 => ReplayAccepted(Empty), 2 => InProgress(Empty), 3 => Denied(Empty), 4 => Finalized(FinalizedFact<EvidenceId>), 5 => GuardOnly(GuardValue) });
closed_object!(FenceEvidence<EvidenceId> { admission_key: Hex<32>, payload_mac: Hex<32>, lease_token: EvidenceId });
closed_object!(FinalizedFact<EvidenceId> { fence: FenceEvidence<EvidenceId>, result: FinalizeSuccess });
closed_enum!(FinalizeSuccess {
    PendingAccepted,
    AlreadyAccepted
});
closed_object!(GuardValue {
    decision: GuardDecision
});
closed_enum!(GuardDecision { Allowed, Denied });
closed_sum!(AdmissionReturned<EvidenceId> { 0 => Proceed(FenceEvidence<EvidenceId>), 1 => AcceptPending(Empty), 2 => Error(Empty) });
closed_sum!(MucFact<EvidenceId> { 0 => Snapshot(MucCapture<EvidenceId>), 1 => Recipients(MucRecipients<EvidenceId>), 2 => Endpoint(MucEndpoint<EvidenceId>) });
closed_object!(MucCapture<EvidenceId> { frame: EvidenceId, cut: Cut, command: Nullable<MucCommand<EvidenceId>>, requested_class: Nullable<AcceptanceClass>, snapshot: MucSnapshot<EvidenceId> });
closed_object!(MucCommand<EvidenceId> { id: EvidenceId, room_id: EvidenceId, actor_scope: Text<1024>, origin_id: Nullable<Text<256>>, sender_jid: Text<1024>, nick: Text<256>, stanza: Text<4096>, encrypted: bool, archive: bool, retention_days: i64, authority: Authority<EvidenceId> });
closed_object!(Authority<EvidenceId> { clustered: bool, expected_room_epoch: EvidenceId, principal: MucPrincipal<EvidenceId>, actor_scope: Text<1024>, full_jid: Text<1024>, nick: Text<256>, occupant_incarnation: EvidenceId, connection_uuid: EvidenceId, expected_role: Text<256>, expected_affiliation: Text<256>, cluster_target: Nullable<ClusterTarget<EvidenceId>> });
closed_sum!(MucPrincipal<EvidenceId> { 0 => Local(LocalPrincipal<EvidenceId>), 1 => Federated(FederatedPrincipal) });
closed_object!(LocalPrincipal<EvidenceId> { user_id: EvidenceId, local_domain: Text<256> });
closed_object!(FederatedPrincipal { bare_jid: Text<1024>, authenticated_domain: Text<256> });
closed_object!(ClusterTarget<EvidenceId> { room_id: EvidenceId, room_epoch: EvidenceId, occupant_incarnation: EvidenceId, occupancy_epoch: i64, full_jid: Text<1024>, nick: Text<256>, connection_uuid: EvidenceId, connection_epoch: i64 });
closed_enum!(AcceptanceClass {
    ArchiveAndIdentity,
    ArchiveOnly,
    IdentityOnly,
    Volatile
});
closed_object!(MucSnapshot<EvidenceId> { request_issued: bool, repository_started: bool, knowledge: MucKnowledge<EvidenceId>, returned: Nullable<MucReturned<EvidenceId>>, fanout: FanoutPrefix, terminal: Nullable<OwnerTerminal> });
closed_sum!(MucKnowledge<EvidenceId> { 0 => NoCommitRequested(Empty), 1 => CommitCallEntered(MucCommitFact<EvidenceId>), 2 => ReceiptKnown(MucCommitFact<EvidenceId>) });
closed_object!(MucCommitFact<EvidenceId> { outcome: MucOutcome<EvidenceId>, fresh_class: Nullable<AcceptanceClass> });
closed_sum!(MucOutcome<EvidenceId> { 0 => Stored(OneId<EvidenceId>), 1 => Replay(OneId<EvidenceId>), 2 => Unauthorized(Empty), 3 => Stale(Empty) });
closed_object!(OneId<EvidenceId> { id: EvidenceId });
closed_sum!(MucReturned<EvidenceId> { 0 => Outcome(MucOutcome<EvidenceId>), 1 => Error(Empty) });
closed_object!(FanoutPrefix { stage: FanoutStage, recipients: Nullable<u32>, next_recipient: u32, endpoint_pending: bool, blocked: u32, accepted: u32, rejected: u32 });
closed_enum!(FanoutStage {
    Unavailable,
    Ready,
    Started,
    ClusterEntered,
    ClusterReturned,
    PrivacyEntered,
    Delivering,
    Completed
});
closed_enum!(OwnerTerminal {
    Completed,
    BackendFailure,
    TimedOut,
    Cancelled,
    Panicked
});
closed_object!(MucRecipients<EvidenceId> { frame: EvidenceId, recipients: List<RecipientObservation<EvidenceId>, 2> });
closed_object!(RecipientObservation<EvidenceId> { user_id: EvidenceId, full_jid: Text<1024>, connection_id: EvidenceId });
closed_object!(MucEndpoint<EvidenceId> { frame: EvidenceId, ordinal: u8, recipient: RecipientObservation<EvidenceId>, privacy_returned: Nullable<bool>, entered: bool, returned: Nullable<bool>, queued_item: Nullable<QueueItem<EvidenceId>> });
closed_object!(QueueItem<EvidenceId> { item_ordinal: u8, connection_id: EvidenceId, source: Nullable<Source<EvidenceId>>, stanza: Text<16384>, auth_control: Nullable<EvidenceId> });
closed_sum!(Source<EvidenceId> { 0 => C2s(C2sSource<EvidenceId>), 1 => Mix(MixSource<EvidenceId>) });
closed_object!(C2sSource<EvidenceId> { recipient_id: EvidenceId, message_id: EvidenceId, claim_id: Nullable<EvidenceId> });
closed_object!(MixSource<EvidenceId> { delivery_id: EvidenceId, lease_token: EvidenceId });
closed_sum!(ForegroundFact<EvidenceId> { 0 => Snapshot(ForegroundCapture<EvidenceId>), 1 => ProjectionRow(ProjectionRowJoin<EvidenceId>), 2 => InitialRow(InitialRowLoaded<EvidenceId>) });
closed_object!(ForegroundCapture<EvidenceId> { frame: EvidenceId, cut: Cut, ingress: MixIngress<EvidenceId>, command: Nullable<MixStoreCommand<EvidenceId>>, snapshot: ForegroundSnapshot<EvidenceId> });
closed_object!(MixIngress<EvidenceId> { channel_id: EvidenceId, channel_jid: Text<1024>, actor_bare: Text<1024>, actor_full: Text<1024>, children: Text<4096>, encrypted: bool, identity: Nullable<ReplayIdentityInput> });
closed_object!(ReplayIdentityInput { client_id: Text<256>, canonical_semantics: Bytes<4096> });
closed_object!(MixStoreCommand<EvidenceId> { channel_id: EvidenceId, actor: Text<1024>, item_id: EvidenceId, payload: Text<4096>, identity: Nullable<ReplayIdentityInput>, delivery_payload: Text<4096>, visible_jid: Nullable<Text<1024>>, encrypted: bool });
closed_object!(ForegroundSnapshot<EvidenceId> { replay: ReadKnowledge<EvidenceId>, request_issued: bool, repository_started: bool, existing: ExistingKnowledge<EvidenceId>, knowledge: ForegroundKnowledge<EvidenceId>, returned: Nullable<ForegroundReturned<EvidenceId>>, wake: Wake, terminal: Nullable<OwnerTerminal> });
closed_object!(ReadKnowledge<EvidenceId> { issued: bool, started: bool, miss: bool, existing: ExistingKnowledge<EvidenceId>, returned: Nullable<ReadReturned<EvidenceId>> });
closed_object!(ExistingKnowledge<EvidenceId> { raw: Nullable<Existing<EvidenceId>>, authenticated: Nullable<MixReplay<EvidenceId>> });
closed_object!(Existing<EvidenceId> { authoritative_id: EvidenceId, semantic_key_id: Text<256>, semantic_mac: Bytes<64>, target_id: Nullable<EvidenceId> });
closed_sum!(MixReplay<EvidenceId> { 0 => Miss(Empty), 1 => Replay(OneId<EvidenceId>), 2 => Conflict(Empty) });
closed_sum!(ReadReturned<EvidenceId> { 0 => Outcome(MixReplay<EvidenceId>), 1 => Error(Empty) });
closed_sum!(ForegroundKnowledge<EvidenceId> { 0 => NoCommitRequested(Empty), 1 => CommitCallEntered(Stored<EvidenceId>), 2 => ReceiptKnown(Stored<EvidenceId>) });
closed_object!(Stored<EvidenceId> { authoritative_id: EvidenceId, storage_id: EvidenceId, channel_id: EvidenceId, channel_jid: Text<1024>, projection: Nullable<DeliveryProjection<EvidenceId>> });
closed_object!(DeliveryProjection<EvidenceId> { event_id: EvidenceId, channel_id: EvidenceId, channel_jid: Text<1024>, stanza_template: Text<4096>, authoritative_stanza_id: Nullable<EvidenceId>, archive: bool, encrypted: bool, recipients: List<RecipientProjection<EvidenceId>, 2> });
closed_object!(RecipientProjection<EvidenceId> { participant: Participant<EvidenceId>, delivery_id: EvidenceId, sequence: i64 });
closed_object!(Participant<EvidenceId> { participant_id: EvidenceId, jid: Text<1024>, nick: Nullable<Text<256>> });
closed_sum!(ForegroundReturned<EvidenceId> { 0 => AcceptedStored(OneId<EvidenceId>), 1 => Admission(MixAdmission<EvidenceId>), 2 => Error(Empty) });
closed_object!(MixAdmission<EvidenceId> { outcome: MixOutcome<EvidenceId>, recipients: List<Participant<EvidenceId>, 2> });
closed_sum!(MixOutcome<EvidenceId> { 0 => Stored(OneId<EvidenceId>), 1 => Replay(OneId<EvidenceId>), 2 => NotParticipant(Empty), 3 => Conflict(Empty), 4 => TooLarge(Empty) });
closed_enum!(Wake {
    Unavailable,
    Ready,
    Invoked
});
closed_object!(ProjectionRowJoin<EvidenceId> { foreground_frame: EvidenceId, recipient_ordinal: u8, stored_authoritative_id: EvidenceId, row_slot: u8, actual_row: DeliveryRow<EvidenceId> });
closed_object!(DeliveryRow<EvidenceId> { source: MixSource<EvidenceId>, event_id: EvidenceId, channel_id: EvidenceId, channel_jid: Text<1024>, participant_id: EvidenceId, recipient_jid: Text<1024>, recipient_nick: Nullable<Text<256>>, stanza: Text<4096>, authoritative_stanza_id: Nullable<EvidenceId>, archive: bool, encrypted: bool, attempt_count: i32, route_wake_generation: i64 });
closed_object!(InitialRowLoaded<EvidenceId> { input_row_ordinal: u8, row_slot: u8, actual_row: DeliveryRow<EvidenceId> });
closed_sum!(ClaimFact<EvidenceId> { 0 => Snapshot(ClaimCapture<EvidenceId>), 1 => Attempt(ClaimAttemptJoin<EvidenceId>) });
closed_object!(ClaimCapture<EvidenceId> { claim_ordinal: u8, cut: Cut, command: ClaimCommand, snapshot: ClaimSnapshot<EvidenceId> });
closed_object!(ClaimCommand {
    limit: i64,
    max_bytes: i64
});
closed_object!(ClaimSnapshot<EvidenceId> { issued: bool, started: bool, knowledge: ClaimKnowledge<EvidenceId>, returned: Nullable<ClaimReturned<EvidenceId>>, terminal: Nullable<OwnerTerminal> });
closed_sum!(ClaimKnowledge<EvidenceId> { 0 => NoStatementEntered(Empty), 1 => ReadEmpty(Empty), 2 => AutocommitStatementEntered(Empty), 3 => StatementReceipt(Rows<EvidenceId>) });
closed_object!(Rows<EvidenceId> { rows: List<DeliveryRow<EvidenceId>, 1> });
closed_sum!(ClaimReturned<EvidenceId> { 0 => Accepted(CountValue), 1 => Rejected(Rows<EvidenceId>), 2 => Error(Empty) });
closed_object!(CountValue { count: u32 });
closed_object!(ClaimAttemptJoin<EvidenceId> { claim_ordinal: u8, row_ordinal: u8, attempt_ordinal: u8, source: MixSource<EvidenceId>, row: DeliveryRow<EvidenceId>, same_retained_row: Nullable<bool> });
closed_sum!(WorkerFact<EvidenceId> { 0 => Snapshot(WorkerCapture<EvidenceId>), 1 => Archive(ArchiveCall<EvidenceId>), 2 => Lookup(RouteLookup<EvidenceId>), 3 => Candidate(RouteCandidate<EvidenceId>), 4 => LocalQueue(LocalQueueJoin<EvidenceId>), 5 => Handoff(TypedHandoff<EvidenceId>), 6 => ChildDrop(RouteChildDrop<EvidenceId>), 7 => Settlement(SettlementCall<EvidenceId>), 8 => Account(AccountCall<EvidenceId>), 9 => Privacy(PrivacyCall<EvidenceId>) });
closed_object!(WorkerCapture<EvidenceId> { attempt_ordinal: u8, cut: Cut, row: DeliveryRow<EvidenceId>, route_stanza: Nullable<Text<4096>>, snapshot: WorkerSnapshot<EvidenceId> });
closed_object!(WorkerSnapshot<EvidenceId> { route: RoutePhase, route_returned: Nullable<RouteResult>, archive: ArchiveSnapshot<EvidenceId>, local: List<LocalPrefix<EvidenceId>, 2>, cluster: List<ClusterPrefix<EvidenceId>, 2>, transfer: Nullable<TransferFact<EvidenceId>>, lease_lost: bool, aborted: bool, renewal_scope_closed: bool, renewal: RenewalSnapshot, settlement: Nullable<SettlementSnapshot>, terminal: Nullable<OwnerTerminal> });
closed_enum!(RoutePhase {
    Unprepared,
    Prepared,
    Started,
    Returned
});
closed_enum!(RouteResult {
    CompletedByWorker,
    Transferred,
    Pending,
    Permanent,
    Retry,
    Cancelled
});
closed_object!(ArchiveSnapshot<EvidenceId> { issued: bool, started: bool, knowledge: ArchiveKnowledge<EvidenceId>, returned: Nullable<ArchiveReturned<EvidenceId>> });
closed_sum!(ArchiveKnowledge<EvidenceId> { 0 => NoCommitEntered(Empty), 1 => CommitCallEntered(ArchiveResult<EvidenceId>), 2 => ReceiptKnown(ArchiveResult<EvidenceId>) });
closed_sum!(ArchiveResult<EvidenceId> { 0 => Stored(OneId<EvidenceId>), 1 => Replay(OneId<EvidenceId>) });
closed_sum!(ArchiveReturned<EvidenceId> { 0 => Outcome(ArchiveResult<EvidenceId>), 1 => Error(Empty) });
closed_object!(LocalPrefix<EvidenceId> { target: Text<1024>, started: bool, enqueued: bool, returned: Nullable<LocalResult<EvidenceId>> });
closed_sum!(LocalResult<EvidenceId> { 0 => QueueFull(Empty), 1 => QueueClosed(Empty), 2 => HandoffClosed(Empty), 3 => Transferred(TransferBoundary<EvidenceId>) });
closed_sum!(TransferBoundary<EvidenceId> { 0 => SocketFenced(OneId<EvidenceId>), 1 => SmPersisted(OneId<EvidenceId>), 2 => BoshPersisted(OneId<EvidenceId>), 3 => ClusterSocketFenced(Empty), 4 => ClusterSmPersisted(Empty), 5 => ClusterBoshPersisted(Empty) });
closed_object!(ClusterPrefix<EvidenceId> { node: Text<256>, started: bool, returned: bool, handoff: Nullable<TransferBoundary<EvidenceId>> });
closed_object!(TransferFact<EvidenceId> { target: Text<1024>, boundary: TransferBoundary<EvidenceId> });
closed_object!(RenewalSnapshot { issued: u64, started: bool, pending: bool, knowledge: RenewalKnowledge, returned: Nullable<RenewalReturned>, last_receipt: Nullable<RenewalReceipt> });
closed_sum!(RenewalKnowledge { 0 => NotEntered(Empty), 1 => AutocommitStatementEntered(Empty), 2 => StatementReceipt(BoolValue) });
closed_object!(BoolValue { value: bool });
closed_sum!(RenewalReturned { 0 => Outcome(BoolValue), 1 => Error(Empty) });
closed_object!(RenewalReceipt {
    ordinal: u64,
    value: bool
});
closed_object!(SettlementSnapshot { kind: SettlementKind, started: bool, knowledge: SettlementKnowledge, returned: Nullable<SettlementReturned> });
closed_enum!(SettlementKind {
    Ack,
    Defer,
    Retry,
    DeadLetter
});
closed_sum!(SettlementKnowledge { 0 => NotEntered(Empty), 1 => CommitCallEntered(SettlementResult), 2 => AutocommitStatementEntered(Empty), 3 => ReceiptKnown(SettlementResult) });
closed_sum!(SettlementResult { 0 => Ack(BoolValue), 1 => Defer(BoolValue), 2 => Retry(RetryValue), 3 => DeadLetter(BoolValue) });
closed_object!(RetryValue { value: RetryResult });
closed_enum!(RetryResult {
    LeaseLost,
    Retried,
    RouteWokenAtAttemptLimit,
    DeadLettered
});
closed_sum!(SettlementReturned { 0 => Outcome(SettlementResult), 1 => Error(Empty) });
closed_object!(ArchiveCall<EvidenceId> { attempt_ordinal: u8, command: ArchiveCommand<EvidenceId>, returned: Nullable<ArchiveReturned<EvidenceId>> });
closed_object!(ArchiveCommand<EvidenceId> { personal_archive_id: EvidenceId, owner_id: EvidenceId, channel_jid: Text<1024>, authoritative_stanza_id: EvidenceId, stanza: Text<4096>, encrypted: bool, client_stanza_id: Nullable<Text<256>> });
closed_object!(RouteLookup<EvidenceId> { owner: RouteLookupOwner<EvidenceId>, lookup_key: Text<1024>, entries: List<RouteSession<EvidenceId>, 2> });
closed_sum!(RouteLookupOwner<EvidenceId> { 0 => Auth(OneId<EvidenceId>), 1 => Worker(MixItemOwner) });
closed_object!(MixItemOwner {
    attempt_ordinal: u8
});
closed_object!(RouteSession<EvidenceId> { full_jid: Text<1024>, connection_id: EvidenceId, user_id: EvidenceId, auth_generation: i64, user_agent_epoch: Nullable<i64>, caps_observation_generation: u64, routable: bool, disconnected: bool, lifecycle: u8 });
closed_object!(RouteCandidate<EvidenceId> { attempt_ordinal: u8, lookup_key: Text<1024>, full_jid: Text<1024>, connection_id: EvidenceId, user_id: EvidenceId, auth_generation: i64, caps_observation_generation: u64, routable: bool, disconnected: bool, lifecycle: u8, caps_before: Nullable<CapsObservation<EvidenceId>>, caps_after: Nullable<CapsObservation<EvidenceId>>, capability: MixCapability, pending_caps_count_before: u32, pending_caps_count_after: u32 });
closed_object!(CapsObservation<EvidenceId> { owner: CapsOwner<EvidenceId>, key: Nullable<CapsKey>, summary: Nullable<VerifiedCapsSummary> });
closed_sum!(CapsOwner<EvidenceId> { 0 => Local(LocalCapsEpoch<EvidenceId>), 1 => Federated(FederatedCapsOwner<EvidenceId>) });
closed_object!(LocalCapsEpoch<EvidenceId> { connection_id: EvidenceId, generation: u64 });
closed_object!(FederatedCapsOwner<EvidenceId> { connection_id: EvidenceId, observation_id: EvidenceId });
closed_object!(CapsKey { algorithm: Text<256>, node: Text<256>, version: Text<256> });
closed_object!(VerifiedCapsSummary { mix_core: bool, mix_pam: bool, notify_storage: Text<4096>, notify_ranges: List<NotifyRange, 2> });
closed_object!(NotifyRange {
    start: u32,
    end: u32
});
closed_enum!(MixCapability {
    Supported,
    Unsupported,
    Unknown
});
closed_object!(LocalQueueJoin<EvidenceId> { attempt_ordinal: u8, target: Text<1024>, item: QueueItem<EvidenceId> });
closed_object!(TypedHandoff<EvidenceId> { attempt_ordinal: u8, item_ordinal: u8, source: MixSource<EvidenceId>, received: HandoffResult<EvidenceId> });
closed_sum!(HandoffResult<EvidenceId> { 0 => Received(TransferBoundary<EvidenceId>), 1 => Empty(Empty), 2 => Closed(Empty) });
closed_object!(RouteChildDrop<EvidenceId> { attempt_ordinal: u8, disconnected: bool, snapshot: WorkerSnapshot<EvidenceId> });
closed_object!(SettlementCall<EvidenceId> { attempt_ordinal: u8, source: MixSource<EvidenceId>, kind: SettlementKind, command: SettlementCommand, attempt_count: i32, route_wake_generation: i64, at_entry: WorkerSnapshot<EvidenceId>, returned: Nullable<SettlementReturned> });
closed_sum!(SettlementCommand { 0 => Ack(Empty), 1 => Defer(DeferCommand), 2 => Retry(RetryCommand), 3 => DeadLetter(DeadLetterCommand) });
closed_object!(DeferCommand { delay_seconds: i64 });
closed_object!(RetryCommand { error: Text<256> });
closed_object!(DeadLetterCommand { reason: Text<256>, error: Text<256> });
closed_object!(AccountCall<EvidenceId> { attempt_ordinal: u8, username: Text<1024>, returned: Nullable<AccountReturned<EvidenceId>> });
closed_sum!(AccountReturned<EvidenceId> { 0 => Found(AccountIdentity<EvidenceId>), 1 => Absent(Empty), 2 => Error(Empty) });
closed_object!(AccountIdentity<EvidenceId> { id: EvidenceId, username: Text<1024> });
closed_object!(PrivacyCall<EvidenceId> { attempt_ordinal: u8, owner_id: EvidenceId, candidate: Text<1024>, returned: Nullable<PrivacyReturned> });
closed_sum!(PrivacyReturned { 0 => Outcome(BoolValue), 1 => Error(Empty) });
closed_object!(CredentialCapture<EvidenceId> { cut: Cut, snapshot: CredentialSnapshot<EvidenceId>, joins: Nullable<CredentialJoins<EvidenceId>> });
closed_object!(CredentialSnapshot<EvidenceId> { attempt: EvidenceId, frame: EvidenceId, connection: EvidenceId, ordinal: u8, kind: ObservedCredentialKind, service_started: bool, repository_started: bool, begin: CredentialCall, eligibility: Eligibility, transaction_returned: bool, preparation: [PreparationResult; 5], stage_id: Nullable<EvidenceId>, rollback: Nullable<CredentialRollback>, commit: CredentialCall, receipt_constructed: bool, returned: Nullable<CredentialReturned>, return_matches: bool, transferred: bool, handler: Nullable<HandlerReturn>, call_terminal: Nullable<CredentialTerminal>, integrity_failure: bool });
closed_enum!(ObservedCredentialKind {
    Binding,
    UnboundFast,
    Resume
});
closed_enum!(CredentialCall {
    NotEntered,
    Entered,
    Ok,
    Err
});
closed_sum!(Eligibility { 0 => NotEntered(Empty), 1 => Entered(Empty), 2 => Returned(NullableBool), 3 => Err(Empty) });
closed_object!(NullableBool { value: Nullable<bool> });
closed_enum!(PreparationResult {
    NotEntered,
    Entered,
    Present,
    Absent,
    Err
});
closed_object!(CredentialRollback {
    site: CredentialRollbackSite,
    call: CredentialCall
});
closed_enum!(CredentialRollbackSite {
    GenerationRefused,
    FastExpired,
    BindingReservationLost,
    BindingStageMissing,
    BindingFastExpired,
    ResumeStageMissing,
    ResumeClaimLost,
    ResumeFastExpired,
    ResumePrivacyMissing
});
closed_enum!(CredentialReturned {
    Authenticated,
    UnknownCredentials,
    Disabled,
    StaleGeneration,
    ExpiredCredentials,
    ReplayedCredentials,
    IntegrityFailure,
    BackendFailure,
    BindingCommitted,
    BindingCredentialsExpired,
    BindingReservationLost,
    ResumeCommitted,
    ResumeCredentialsExpired,
    ResumeClaimLost,
    ResumePrivacySelectionMissing,
    Error
});
closed_enum!(HandlerReturn {
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    Panicked
});
closed_enum!(CredentialTerminal {
    Returned,
    Cancelled,
    Panicked
});
closed_object!(CredentialJoins<EvidenceId> { owner: CredentialAttemptJoin<EvidenceId>, constructed_receipt: Nullable<EvidenceId>, returned_receipt: Nullable<EvidenceId>, transferred_receipt: Nullable<EvidenceId> });
closed_object!(CredentialAttemptJoin<EvidenceId> { attempt: EvidenceId, frame: EvidenceId, connection: EvidenceId, ordinal: u8, kind: ObservedCredentialKind });
closed_sum!(ControlFact<EvidenceId> { 0 => Holder(ControlCapture<EvidenceId>), 1 => LivePublication(LivePublication<EvidenceId>), 2 => Callback(PublicationCallback<EvidenceId>) });
closed_object!(ControlCapture<EvidenceId> { cut: Cut, actual_xml: Nullable<Text<4096>>, holder: Nullable<ControlJoins<EvidenceId>> });
closed_object!(ControlJoins<EvidenceId> { introduced: Nullable<ControlAssociation<EvidenceId>>, transferred: Nullable<ControlAssociation<EvidenceId>> });
closed_object!(ControlAssociation<EvidenceId> { control: EvidenceId, connection: EvidenceId, frame: Nullable<EvidenceId>, receipt: EvidenceId, length: u32, digest: Hex<32>, publication: PublicationJoins<EvidenceId> });
closed_object!(PublicationJoins<EvidenceId> { control: EvidenceId, frame: Nullable<EvidenceId>, receipt: EvidenceId, credential: Nullable<CredentialAttemptJoin<EvidenceId>>, begun_receipt: Nullable<EvidenceId>, bound_effects: bool, notification_expected: bool });
closed_object!(LivePublication<EvidenceId> { cut: Cut, snapshot: PublicationSnapshot<EvidenceId>, joins: Nullable<PublicationJoins<EvidenceId>> });
closed_object!(PublicationSnapshot<EvidenceId> { control: EvidenceId, frame: Nullable<EvidenceId>, handler: Nullable<HandlerReturn>, sealed: bool, transport: AuthTransport, publication: PublicationKnowledge, service_started: bool, repository_started: bool, rollback: PublicationRollback, returned: Nullable<PublicationReturned>, return_matches: bool, effects: PublicationEffects, terminal: Nullable<PublicationTerminal> });
closed_sum!(AuthTransport { 0 => NotStarted(Empty), 1 => Recording(Empty), 2 => WriteEntered(Empty), 3 => Written(Empty), 4 => BoshExposureEntered(RidValue), 5 => BoshAccepted(RidValue), 6 => BoshRefused(RidValue) });
closed_object!(RidValue { rid: u64 });
closed_sum!(PublicationKnowledge { 0 => NotStarted(Empty), 1 => NotRequired(Empty), 2 => BeforeCommit(Empty), 3 => CommitCallEntered(Empty), 4 => ReceiptKnown(EpochValue) });
closed_object!(EpochValue { epoch: Nullable<i64> });
closed_enum!(PublicationRollback {
    NotRequested,
    CallEntered,
    Returned,
    Failed
});
closed_sum!(PublicationReturned { 0 => Authenticated(EpochValue), 1 => UnknownCredentials(Empty), 2 => Disabled(Empty), 3 => StaleGeneration(Empty), 4 => ExpiredCredentials(Empty), 5 => ReplayedCredentials(Empty), 6 => IntegrityFailure(Empty), 7 => BackendFailure(Empty) });
closed_object!(PublicationEffects { unbound: bool, epoch_applied: bool, route_mapping: Nullable<bool>, route_activation: Nullable<bool>, caps_entered: bool, caps_returned: bool, notification_entered: bool, notification_returned: Nullable<bool> });
closed_enum!(PublicationTerminal {
    Completed,
    DeferredNotification,
    Failed,
    Cancelled,
    Panicked,
    Abandoned,
    ExposedNotAttempted
});
closed_object!(PublicationCallback<EvidenceId> { connection: EvidenceId, session: Nullable<EvidenceId>, rid: Nullable<u64>, invoked_owners: List<ControlAssociation<EvidenceId>, 2>, returned: Nullable<bool> });
closed_sum!(NativeFact<EvidenceId> { 0 => Snapshot(NativeCapture<EvidenceId>), 1 => Dequeue(NativeDequeue<EvidenceId>), 2 => Write(WriteCall), 3 => Flush(FlushCall), 4 => Ack(NativeAckCall<EvidenceId>), 5 => OwnershipReceipt(NativeReceipt), 6 => WriteReceipt(NativeReceipt) });
closed_object!(NativeCapture<EvidenceId> { connection: EvidenceId, item_ordinal: u8, owner: ItemOwner<EvidenceId>, cut: Cut, snapshot: Nullable<NativeSnapshot<EvidenceId>> });
closed_sum!(ItemOwner<EvidenceId> { 0 => Muc(MucItemOwner<EvidenceId>), 1 => Mix(MixItemOwner), 2 => Auth(AuthItemOwner<EvidenceId>) });
closed_object!(MucItemOwner<EvidenceId> { frame: EvidenceId, recipient_ordinal: u8 });
closed_object!(AuthItemOwner<EvidenceId> { frame: EvidenceId, control: EvidenceId });
closed_object!(NativeSnapshot<EvidenceId> { original: Nullable<Source<EvidenceId>>, preparation: NativePreparation, managed_by_sm: Nullable<bool>, fence_entered: bool, returned_fence: Nullable<Source<EvidenceId>>, writer_entered: bool, writer_result: Nullable<WriterResult>, write_decision: Nullable<WriteDecision>, ack: NativeAckKnowledge<EvidenceId>, ack_returned: Nullable<bool>, terminal: Nullable<CallTerminal> });
closed_enum!(NativePreparation {
    NotStarted,
    Recording,
    FenceCallEntered,
    Prepared,
    Superseded,
    Failed
});
closed_enum!(WriterResult { FullWrite, Failed });
closed_enum!(WriteDecision { Withhold, Written });
closed_sum!(NativeAckKnowledge<EvidenceId> { 0 => NotRequested(Empty), 1 => NoCommitRequested(Empty), 2 => CommitCallEntered(NativeAckFact<EvidenceId>), 3 => ReceiptKnown(NativeAckFact<EvidenceId>) });
closed_object!(NativeAckFact<EvidenceId> { source: Source<EvidenceId>, disposition: AckDisposition });
closed_enum!(AckDisposition {
    Deleted,
    AbsentUnclaimed,
    NoMatchingMix
});
closed_enum!(CallTerminal {
    Returned,
    TimedOut,
    Cancelled,
    Panicked
});
closed_object!(NativeDequeue<EvidenceId> { owner: ItemOwner<EvidenceId>, item: QueueItem<EvidenceId> });
closed_object!(WriteCall { item_ordinal: u8, offered_len: u32, offered_sha256: Hex<32>, accepted_bytes_hex: Bytes<4096>, result: IoResult });
closed_enum!(IoResult { Ok, Error, Pending });
closed_object!(FlushCall {
    item_ordinal: u8,
    result: IoResult
});
closed_object!(NativeAckCall<EvidenceId> { item_ordinal: u8, source: Source<EvidenceId>, returned: Nullable<bool> });
closed_object!(NativeReceipt {
    item_ordinal: u8,
    result: ReceiptResult
});
closed_enum!(ReceiptResult {
    Accepted,
    Refused,
    Empty,
    Closed
});
closed_sum!(BoshFact<EvidenceId> { 0 => Snapshot(BoshCapture<EvidenceId>), 1 => Selection(SelectionCapture<EvidenceId>), 2 => Transfer(BoshTransferCall<EvidenceId>), 3 => Bind(BoshBindCall<EvidenceId>), 4 => Renew(BoshRenewCall<EvidenceId>), 5 => Ack(BoshAckCall), 6 => Receiver(BoshResponseReceiver<EvidenceId>), 7 => Cache(CacheCapture<EvidenceId>), 8 => Queue(BoshQueueCapture<EvidenceId>), 9 => TransportReceipt(BoshTransportReceipt<EvidenceId>) });
closed_object!(BoshCapture<EvidenceId> { owner_ordinal: u8, association: BoshAssociation<EvidenceId>, cut: Cut, snapshot: BoshSnapshot<EvidenceId> });
closed_sum!(BoshAssociation<EvidenceId> { 0 => Outbound(QueueItem<EvidenceId>), 1 => Request(BoshRequestAssociation<EvidenceId>) });
closed_object!(BoshRequestAssociation<EvidenceId> { session: EvidenceId, connection: Nullable<EvidenceId>, rid: u64, ack: Nullable<u64>, sid: Nullable<Text<256>>, fingerprint: Hex<32>, request_xml: Text<4096> });
closed_object!(BoshSnapshot<EvidenceId> { scope: BoshScope<EvidenceId>, transfers: List<BoshTransferSnapshot<EvidenceId>, 1>, responses: List<BoshResponseSnapshot<EvidenceId>, 2>, renewals: List<BoshRenewSnapshot<EvidenceId>, 1>, acknowledgements: List<BoshAckSnapshot<EvidenceId>, 1>, terminal: Nullable<CallTerminal>, keep_running: Nullable<bool> });
closed_object!(BoshScope<EvidenceId> { session_id: EvidenceId, ttl_seconds: u64, kind: BoshOperationKind });
closed_enum!(BoshOperationKind {
    Request,
    Outbound,
    HeldResponse
});
closed_object!(BoshTransferSnapshot<EvidenceId> { source: MixSource<EvidenceId>, knowledge: BoshTransferKnowledge<EvidenceId>, returned_source: Nullable<MixSource<EvidenceId>>, return_matches_receipt: bool, local_entered: bool, source_applied: bool, notification_attempted: bool, queue_accepted: Nullable<bool> });
closed_sum!(BoshTransferKnowledge<EvidenceId> { 0 => NoCommitRequested(Empty), 1 => CommitCallEntered(MixSource<EvidenceId>), 2 => ReceiptKnown(MixSource<EvidenceId>) });
closed_object!(BoshResponseSnapshot<EvidenceId> { rid: u64, kind: BoshResponseKind, lineage: List<Nullable<Source<EvidenceId>>, 4>, removed: List<bool, 4>, attempts: List<BoshBindAttempt<EvidenceId>, 4>, construction_restored: u32, exposure_entered: bool, responder_calls: u32, accepted_responders: u32, refused_responders: u32, control_calls: u32, control_accepted: u32, control_refused: u32, empty_cache_evictions: u32, bookkeeping: bool, cached: bool });
closed_enum!(BoshResponseKind {
    Payload,
    TerminalControl,
    EmptyControl
});
closed_object!(BoshBindAttempt<EvidenceId> { selected_end: Nullable<u32>, selected_len: u32, sources: Nullable<List<Source<EvidenceId>, 4>>, knowledge: BoshBindKnowledge<EvidenceId>, returned: Nullable<Membership<EvidenceId>>, return_matches: bool, superseded_message: Nullable<EvidenceId>, restored: bool, restore_matches: bool, removed_indices: List<u32, 4> });
closed_sum!(BoshBindKnowledge<EvidenceId> { 0 => NotRequired(Empty), 1 => NoCommitRequested(Empty), 2 => CommitCallEntered(Membership<EvidenceId>), 3 => ReceiptKnown(Membership<EvidenceId>) });
closed_object!(Membership<EvidenceId> { c2s_message_ids: List<EvidenceId, 2>, mix_delivery_ids: List<EvidenceId, 1> });
closed_object!(BoshRenewSnapshot<EvidenceId> { expected: Nullable<BoshExpected<EvidenceId>>, knowledge: TransactionKnowledge, returned: bool, return_matches: bool, ack_issued: bool, replay_calls: u32, replay_accepted: u32, replay_refused: u32, replay_bookkeeping: bool });
closed_object!(BoshExpected<EvidenceId> { rid: u64, membership: Membership<EvidenceId> });
closed_enum!(TransactionKnowledge {
    NoCommitRequested,
    CommitCallEntered,
    ReceiptKnown
});
closed_object!(BoshAckSnapshot<EvidenceId> { rid: u64, knowledge: TransactionKnowledge, deleted: Nullable<List<DeletedSource<EvidenceId>, 1>>, returned: bool, return_matches: bool, cache_evictions: u32, receipt_calls: u32, receipts_sent: u32, receipts_refused: u32 });
closed_sum!(DeletedSource<EvidenceId> { 0 => C2s(DeletedC2s<EvidenceId>), 1 => Mix(MixSource<EvidenceId>) });
closed_object!(DeletedC2s<EvidenceId> { recipient_id: EvidenceId, message_id: EvidenceId });
closed_object!(SelectionCapture<EvidenceId> { cut: Cut, selection: SelectionSnapshot<EvidenceId> });
closed_object!(SelectionSnapshot<EvidenceId> { session: EvidenceId, rid: u64, fingerprint: Hex<32>, first_validated_connection: Nullable<EvidenceId>, validated_connection: Nullable<EvidenceId>, selected_count: u32, status: SelectionStatus, items: [Nullable<SelectedItem<EvidenceId>>; 4] });
closed_sum!(SelectionStatus { 0 => Complete(Empty), 1 => Incomplete(IncompleteSelection) });
closed_object!(IncompleteSelection {
    omitted_items: u32,
    missing_auth_associations: u32,
    connection_changed: bool
});
closed_object!(SelectedItem<EvidenceId> { ordinal: u32, source: Nullable<Source<EvidenceId>>, utf8_length: u32, sha256: Hex<32>, auth_marker: bool, sealed_association: Nullable<ControlAssociation<EvidenceId>>, holder_joins: Nullable<ControlJoins<EvidenceId>> });
closed_object!(BoshTransferCall<EvidenceId> { owner_ordinal: u8, source: MixSource<EvidenceId>, returned_source: Nullable<MixSource<EvidenceId>> });
closed_object!(BoshBindCall<EvidenceId> { owner_ordinal: u8, rid: u64, sources: List<Source<EvidenceId>, 4>, returned_membership: Nullable<Membership<EvidenceId>> });
closed_object!(BoshRenewCall<EvidenceId> { owner_ordinal: u8, expected: Nullable<BoshExpected<EvidenceId>>, returned: Nullable<bool> });
closed_object!(BoshAckCall { owner_ordinal: u8, rid: u64, returned: Nullable<bool> });
closed_object!(BoshResponseReceiver<EvidenceId> { session: EvidenceId, connection: Nullable<EvidenceId>, owner_ordinal: u8, rid: u64, receiver_ordinal: u8, result: ResponseResult });
closed_sum!(ResponseResult { 0 => Received(BodyBytes), 1 => Empty(Empty), 2 => Closed(Empty) });
closed_object!(BodyBytes { body_hex: Bytes<16384> });
closed_object!(CacheCapture<EvidenceId> { session: EvidenceId, connection: EvidenceId, cut: Cut, entries: List<CacheEntry<EvidenceId>, 2> });
closed_object!(CacheEntry<EvidenceId> { rid: u64, fingerprint: Hex<32>, membership: Membership<EvidenceId>, body_hex: Bytes<16384>, response_bytes: u32, replays: u32, transport_receipt_count: u32 });
closed_object!(BoshQueueCapture<EvidenceId> { session: EvidenceId, connection: EvidenceId, cut: Cut, fifo: List<QueueItem<EvidenceId>, 4>, output_bytes: u32, highest_responded: u64 });
closed_object!(BoshTransportReceipt<EvidenceId> { session: EvidenceId, item_ordinal: u8, result: ReceiptResult });
closed_object!(DriverPoll {
    owner: DriverOwner,
    owner_ordinal: u8,
    result: PollResult
});
closed_enum!(PollResult { Pending, Ready });
closed_sum!(ObservationStatus { 0 => Complete(Empty), 1 => Lost(LostObservation) });
closed_object!(LostObservation {
    reason: Loss,
    after_seq: u32
});
closed_enum!(Loss {
    FactOverflow,
    PollOverflow,
    IdentityOverflow,
    OpaqueOverflow,
    OwnerSnapshotOverflow,
    FrameOverflow,
    UnlabeledIdentity,
    EncodedIdentityAtCapture,
    NoncanonicalIdentity,
    NoncontiguousSequence,
    MissingObservation,
    EncodingFailure
});
// END FROZEN ADAPTERS

// Synthetic parser controls. Samples are
// synthetic DTOs; they are neither saved owner executions nor qualification.
macro_rules! examples { ($($kind:ty => $value:expr),+ $(,)?) => { $(impl Example for $kind { fn example() -> Self { $value } })+ }; }
examples!(u8 => 0, u32 => 0, u64 => 0, i32 => 0, i64 => 0, bool => false, Id => Id(Uuid::nil()));
impl<const N: usize> Example for Text<N> {
    fn example() -> Self {
        Text(String::new())
    }
}
impl<const N: usize> Example for Hex<N> {
    fn example() -> Self {
        Hex("00".repeat(N))
    }
}
impl<const N: usize> Example for Bytes<N> {
    fn example() -> Self {
        Bytes(String::new())
    }
}
impl<T: Example> Example for Nullable<T> {
    fn example() -> Self {
        Self::Null(())
    }
}
impl<T: Example, const N: usize> Example for List<T, N> {
    fn example() -> Self {
        Self(Vec::new())
    }
}
impl<T: Example, const N: usize> Example for [T; N]
where
    [T; N]: Serialize,
{
    fn example() -> Self {
        std::array::from_fn(|_| T::example())
    }
}
impl Example for IdentityLabel {
    fn example() -> Self {
        Self::Fixed(FixedIdentity {
            uuid: Id::example(),
        })
    }
}
impl Example for EvidenceId {
    fn example() -> Self {
        Self::Encoded(IdentityLabel::example())
    }
}
impl Example for Envelope {
    fn example() -> Self {
        Envelope::rejected(b"bad", Rejection::Json).unwrap()
    }
}
fn control_introductions() -> Vec<IdentityIntroduction> {
    vec![
        IdentityIntroduction {
            label: IdentityLabel::example(),
            first_seq: 1,
            locus: Introduction::Frame,
        },
        IdentityIntroduction {
            label: IdentityLabel::Opaque(OpaqueIdentity { ordinal: 1 }),
            first_seq: 2,
            locus: Introduction::CredentialAttempt,
        },
    ]
}
fn adapter_control_prepare(canonical: &[u8]) -> ([u8; 32], Budget, Identities) {
    let expected: [u8; 32] = Hash::digest(canonical).into();
    let mut budget = Budget::new(Limits::default());
    let identities = Identities::new(&control_introductions(), &mut budget).unwrap();
    (expected, budget, identities)
}
fn adapter_control_parse(raw: &[u8]) -> (Budget, Node, Identities) {
    let mut budget = Budget::new(Limits::default());
    lexical(raw, &mut budget).unwrap();
    let node = parse(raw, &mut budget).unwrap();
    let identities = Identities::new(&control_introductions(), &mut budget).unwrap();
    (budget, node, identities)
}
fn assert_adapter_summary(summary: (usize, [u8; 32]), canonical: &[u8], expected: [u8; 32]) {
    assert_eq!(summary, (canonical.len(), expected));
}
fn assert_adapter_bytes(actual: &[u8], expected: &[u8]) {
    assert_eq!(actual, expected);
}
fn assert_adapter_lengths(pair: &Comparison, canonical: &[u8]) {
    assert_eq!(
        (pair.left_bytes, pair.right_bytes),
        (canonical.len(), canonical.len())
    );
}
fn adapter_roundtrip<T: Example>(value: &T) {
    let canonical = serde_json::to_vec(value).unwrap();
    let (expected, mut budget, identities) = adapter_control_prepare(&canonical);
    let mut named = Output::expanded(&mut budget, 2);
    value
        .emit(&mut named, &identities, Mode::Named, T::REF)
        .unwrap();
    assert_adapter_summary(named.summary().unwrap(), &canonical, expected);
    let mut compact = Output::compact(&mut budget, 1);
    value
        .emit(&mut compact, &identities, Mode::Compact, T::REF)
        .unwrap();
    let raw = compact.data.unwrap();
    let (mut budget, node, identities) = adapter_control_parse(&raw);
    let mut expanded = Output::expanded(&mut budget, 3);
    let restored = T::read(&node, &mut expanded, &identities, Mode::Compact, T::REF).unwrap();
    assert_adapter_summary(expanded.summary().unwrap(), &canonical, expected);
    assert_eq!(&restored, value);
    assert_adapter_bytes(&serde_json::to_vec(&restored).unwrap(), &canonical);
    let mut pair = Comparison::new(Limits::default());
    value.compare(&restored, &mut pair, T::REF).unwrap();
    assert_adapter_lengths(&pair, &canonical);
    let mut compact = Output::compact(&mut budget, 0);
    restored
        .emit(&mut compact, &identities, Mode::Compact, T::REF)
        .unwrap();
    assert_adapter_bytes(&compact.data.unwrap(), &raw);
}
fn raw_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = format!("\x1e{TAG} {}\n", payload.len()).into_bytes();
    frame.extend_from_slice(payload);
    frame.extend_from_slice(END);
    frame
}
fn mutate(frame: &[u8], change: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    // Generic Value materialization is confined to these small synthetic
    // malformed-fixture controls, never used by either codec boundary.
    let mut budget = Budget::new(Limits::default());
    let raw = extract(frame, &mut budget).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(raw).unwrap();
    change(&mut value);
    raw_frame(&serde_json::to_vec(&value).unwrap())
}
fn raw_read<T: Closed>(raw: &[u8]) -> Result<T, Rejection> {
    let mut budget = Budget::new(Limits::default());
    lexical(raw, &mut budget)?;
    let node = parse(raw, &mut budget)?;
    let identities = Identities::new(&control_introductions(), &mut budget)?;
    let mut out = Output::expanded(&mut budget, 3);
    T::read(&node, &mut out, &identities, Mode::Compact, T::REF)
}

#[test]
fn compact_v2_expanded_roundtrip_and_explicit_v1_compatibility() {
    let original = Envelope::example();
    let v1 = super::encode_frame(&original).unwrap();
    let v2 = encode(&original).unwrap();
    assert_eq!(super::decode_frame(&v1).unwrap(), original);
    assert_eq!(super::decode_compact_frame(&v2).unwrap(), original);
    assert_eq!(encode(&decode(&v2).unwrap()).unwrap(), v2);
    assert_eq!(super::decode_frame(&v2), Err(Rejection::Schema));
    assert_eq!(decode(&v1), Err(Rejection::Schema));
    assert_eq!(
        serde_json::to_vec(&decode(&v2).unwrap()).unwrap(),
        serde_json::to_vec(&original).unwrap()
    );
}
#[test]
fn compact_v2_scalars_nullable_lists_fixed_arrays_and_all_byte_sites() {
    adapter_roundtrip(&u64::MAX);
    adapter_roundtrip(&i64::MIN);
    adapter_roundtrip(&i64::MAX);
    adapter_roundtrip(&u32::MAX);
    adapter_roundtrip(&i32::MIN);
    adapter_roundtrip(&i32::MAX);
    adapter_roundtrip(&u8::MAX);
    adapter_roundtrip(&true);
    adapter_roundtrip(&false);
    adapter_roundtrip(&Text::<256>::new("café😀\n\t\"\\\u{2028}\u{2029}/e\u{301}").unwrap());
    adapter_roundtrip(&Nullable::<u64>::Value(u64::MAX));
    adapter_roundtrip(&List::<u32, 3>::new(vec![9, 2, 9]).unwrap());
    adapter_roundtrip(&[PreparationResult::example(); 5]);
    for raw in [
        &b""[..],
        &b"\0\x01\x08\x0c\n\r\t\"\\/"[..],
        "雪😀\u{2028}\u{2029}".as_bytes(),
        &b"\xff\xfe\xc0\x80"[..],
    ] {
        adapter_roundtrip(&Bytes::<4096>::of(raw).unwrap());
        adapter_roundtrip(&Bytes::<64>::of(raw).unwrap());
        adapter_roundtrip(&Bytes::<16384>::of(raw).unwrap());
        let mut replay = ReplayIdentityInput::example();
        replay.canonical_semantics = Bytes::of(raw).unwrap();
        adapter_roundtrip(&replay);
        let mut existing = Existing::<EvidenceId>::example();
        existing.semantic_mac = Bytes::of(raw).unwrap();
        adapter_roundtrip(&existing);
        let mut write = WriteCall::example();
        write.accepted_bytes_hex = Bytes::of(raw).unwrap();
        adapter_roundtrip(&write);
        adapter_roundtrip(&BodyBytes {
            body_hex: Bytes::of(raw).unwrap(),
        });
        let mut cache = CacheEntry::<EvidenceId>::example();
        cache.body_hex = Bytes::of(raw).unwrap();
        adapter_roundtrip(&cache);
    }
    adapter_roundtrip(&Bytes::<64>::of(&[b'x'; 64]).unwrap());
    adapter_roundtrip(&Bytes::<4096>::of(&vec![b'x'; 4096]).unwrap());
    adapter_roundtrip(&Bytes::<16384>::of(&vec![b'x'; 16384]).unwrap());
    assert_eq!(raw_read::<Hex<2>>(br#""000000""#), Err(Rejection::Bound));
    assert_eq!(raw_read::<Hex<2>>(br#""00""#), Err(Rejection::Encoding));
    assert_eq!(raw_read::<Hex<2>>(br#""00FF""#), Err(Rejection::Encoding));
    assert_eq!(raw_read::<Bytes<2>>(br#"[0,"abc"]"#), Err(Rejection::Bound));
    assert_eq!(raw_read::<Text<2>>(br#""abc""#), Err(Rejection::Bound));
    assert_eq!(raw_read::<Text<2>>(br#""\u0000""#), Err(Rejection::Bound));
    assert_eq!(raw_read::<u8>(b"256"), Err(Rejection::Bound));
    assert_eq!(
        raw_read::<u64>(b"18446744073709551616"),
        Err(Rejection::Bound)
    );
    assert_eq!(
        raw_read::<i64>(b"-9223372036854775809"),
        Err(Rejection::Bound)
    );
    assert_eq!(raw_read::<u8>(b"true"), Err(Rejection::Json));
    assert_eq!(raw_read::<u8>(b"1.0"), Err(Rejection::Json));
    assert_eq!(raw_read::<u8>(b"1e0"), Err(Rejection::Json));
    assert_eq!(raw_read::<u8>(b"-0"), Err(Rejection::Encoding));
    assert_eq!(
        raw_read::<ObservationStatus>(b"[-1,[]]"),
        Err(Rejection::Json)
    );
    assert_eq!(
        raw_read::<ObservationStatus>(b"[18446744073709551615,[]]"),
        Err(Rejection::Json)
    );
    assert_eq!(
        raw_read::<ObservationStatus>(b"[18446744073709551616,[]]"),
        Err(Rejection::Bound)
    );
    assert_eq!(raw_read::<List<u8, 1>>(b"[0,1]"), Err(Rejection::Bound));
    assert_eq!(raw_read::<[u8; 2]>(b"[0]"), Err(Rejection::Json));
}
#[test]
fn compact_v2_byte_modes_and_unicode_fail_in_controlled_classes() {
    for raw in [
        br#"[2,"ff"]"#.as_slice(),
        br#"[1,"00"]"#,
        br#"[1,"FF"]"#,
        br#"[1,"f"]"#,
        br#"[1,"gg"]"#,
        br#"[1,""]"#,
    ] {
        assert_eq!(raw_read::<Bytes<4>>(raw), Err(Rejection::Encoding));
    }
    for raw in [
        br#"[true,"x"]"#.as_slice(),
        br#"[0.0,"x"]"#,
        br#"["0","x"]"#,
        br#"[0,"x",0]"#,
    ] {
        assert_eq!(raw_read::<Bytes<4>>(raw), Err(Rejection::Json));
    }
    assert_eq!(
        raw_read::<Bytes<4>>(br#"[0,"\ud83d\ude00"]"#).unwrap(),
        Bytes::of("😀".as_bytes()).unwrap()
    );
    for raw in [
        br#"[0,"\ud800"]"#.as_slice(),
        br#"[0,"\udc00"]"#,
        br#"[0,"\ud800x"]"#,
        &[b'[', b'0', b',', b'"', 0xff, b'"', b']'],
    ] {
        assert_eq!(raw_read::<Bytes<4>>(raw), Err(Rejection::Json));
    }
    let mut original = Envelope::example();
    original.schema = Text::new(EVIDENCE_SCHEMA).unwrap();
    let valid = encode(&original).unwrap();
    let mut budget = Budget::new(Limits::default());
    let text = std::str::from_utf8(extract(&valid, &mut budget).unwrap()).unwrap();
    let escaped = text.replacen("northstar", "\\u006eorthstar", 1);
    assert_eq!(
        decode(&raw_frame(escaped.as_bytes())),
        Err(Rejection::Encoding)
    );
}
#[test]
fn compact_v2_malformed_wrapper_framing_and_commitments() {
    let good = encode(&Envelope::example()).unwrap();
    for change in [0usize, 1, 2] {
        let bad = mutate(&good, |v| {
            if change == 0 {
                v.as_array_mut().unwrap().pop();
            } else if change == 1 {
                v[3].as_array_mut().unwrap().pop();
            } else {
                v[3][8][0] = serde_json::json!(200);
            }
        });
        assert_eq!(decode(&bad), Err(Rejection::Json));
    }
    assert_eq!(
        decode(&mutate(&good, |v| v[0] = serde_json::json!("other"))),
        Err(Rejection::Schema)
    );
    assert_eq!(
        decode(&mutate(&good, |v| v[1] = serde_json::json!(EXPANDED_LIMIT + 1))),
        Err(Rejection::Bound)
    );
    assert_eq!(
        decode(&mutate(&good, |v| v[1] = serde_json::json!(EXPANDED_LIMIT))),
        Err(Rejection::Encoding)
    );
    assert_eq!(
        decode(&mutate(&good, |v| v[1] = serde_json::json!(-1))),
        Err(Rejection::Bound)
    );
    assert_eq!(
        decode(&mutate(&good, |v| v[1] = serde_json::json!(1))),
        Err(Rejection::Encoding)
    );
    assert_eq!(
        decode(&mutate(&good, |v| v[2] = serde_json::json!("00".repeat(32)))),
        Err(Rejection::Encoding)
    );
    assert_eq!(
        decode(&mutate(&good, |v| v[3][8][0] = serde_json::json!(-1))),
        Err(Rejection::Json)
    );
    for index in [
        serde_json::json!(true),
        serde_json::json!(0.0),
        serde_json::json!("0"),
    ] {
        assert_eq!(
            decode(&mutate(&good, |v| v[3][8][0] = index)),
            Err(Rejection::Json)
        );
    }
    let long_header = format!("\x1e{TAG} 1234567\n[]\n\x1eEND\n");
    assert_eq!(decode(long_header.as_bytes()), Err(Rejection::Encoding));
    let nonascii_header = format!("\x1e{TAG} é\n[]\n\x1eEND\n");
    assert_eq!(decode(nonascii_header.as_bytes()), Err(Rejection::Encoding));
    assert_eq!(decode(b"wrong tag without newline"), Err(Rejection::Schema));
    let mut broken = good.clone();
    broken.pop();
    assert_eq!(decode(&broken), Err(Rejection::Encoding));
    let mut trailing = good.clone();
    trailing.push(b' ');
    assert_eq!(decode(&trailing), Err(Rejection::Encoding));
    assert_eq!(decode(&vec![0; MAX_FRAME + 1]), Err(Rejection::TooLarge));
    assert_eq!(decode(&raw_frame(b"[")), Err(Rejection::Json));
    assert_eq!(
        decode(&raw_frame(b"[0,123456789012345678901]")),
        Err(Rejection::Bound)
    );
    assert_eq!(raw_read::<IdentityLabel>(br#"{"kind":"Fixed","kind":"Fixed","data":{"uuid":"00000000-0000-0000-0000-000000000000"}}"#), Err(Rejection::Json));
    assert_eq!(
        raw_read::<IdentityLabel>(br#"{"kind":"Opaque","data":{"ordinal":1,"extra":0}}"#),
        Err(Rejection::Json)
    );
}
#[test]
fn compact_v2_identity_indices_are_closed_and_terminal() {
    adapter_roundtrip(&EvidenceId::Encoded(IdentityLabel::Opaque(
        OpaqueIdentity { ordinal: 1 },
    )));
    for raw in [b"-1".as_slice(), b"2", b"18446744073709551615"] {
        assert_eq!(raw_read::<EvidenceId>(raw), Err(Rejection::Bound));
    }
    for raw in [b"true".as_slice(), b"0.0", b"\"0\"", b"[0]", b"{\"ref\":0}"] {
        assert_eq!(raw_read::<EvidenceId>(raw), Err(Rejection::Json));
    }
    assert_eq!(raw_read::<Text<64>>(b"0"), Err(Rejection::Json));
    let mut envelope = Envelope::example();
    envelope.facts = List::new(vec![Captured {
        seq: 1,
        fact: Fact::Frame(FrameCapture {
            frame: EvidenceId::Raw(Uuid::nil()),
            cut: Cut::example(),
            stage: Nullable::Null(()),
            outcome: Nullable::Null(()),
            admission_begin: Nullable::Null(()),
            admission_finalize: Nullable::Null(()),
        }),
    }])
    .unwrap();
    assert_eq!(encode(&envelope), Err(Loss::EncodingFailure));
    if let Fact::Frame(v) = &mut envelope.facts.0[0].fact {
        v.frame = EvidenceId::example();
    }
    assert_eq!(encode(&envelope), Err(Loss::EncodingFailure));
}

fn synthetic_history() -> (Vec<u8>, ValidatedCase, Envelope) {
    let seed = super::tests::input_case();
    let input = serde_json::to_vec(seed.case()).unwrap();
    let case = super::decode(&input).unwrap();
    let mut recorder = Recorder::new(&case);
    let mut capture = CredentialCapture::<EvidenceId>::example();
    capture.snapshot.attempt = EvidenceId::observed(Uuid::from_u128(100));
    capture.snapshot.frame = EvidenceId::observed(Uuid::from_u128(1));
    capture.snapshot.connection = EvidenceId::observed(Uuid::from_u128(2));
    // Intentionally well-typed but causally unsafe. Codec controls must retain
    // this exact value; the independent semantic reader decides its meaning.
    capture.snapshot.receipt_constructed = true;
    capture.snapshot.return_matches = true;
    recorder.capture(Fact::Credential(capture.clone())).unwrap();
    capture.snapshot.ordinal = 1;
    recorder.capture(Fact::Credential(capture)).unwrap();
    let envelope = recorder.finish(Execution::Complete).unwrap();
    (input, case, envelope)
}
#[test]
fn compact_v2_same_typed_slots_and_history_mutants_are_not_repaired() {
    let (input, case, original) = synthetic_history();
    super::validate_envelope(&original, &input, Some(&case)).unwrap();
    let frame = encode(&original).unwrap();
    assert_eq!(decode(&frame).unwrap(), original);
    let mut slot_swap = original.clone();
    if let Fact::Credential(capture) = &mut slot_swap.facts.0[0].fact {
        std::mem::swap(
            &mut capture.snapshot.frame,
            &mut capture.snapshot.connection,
        );
    }
    let restored = decode(&encode(&slot_swap).unwrap()).unwrap();
    assert_eq!(restored, slot_swap);
    assert_ne!(restored, original);
    assert!(super::validate_envelope(&restored, &input, Some(&case)).is_err());
    for kind in 0..7 {
        let mut changed = original.clone();
        match kind {
            0 => {
                changed.identity_map.0[0].first_seq += 1;
            }
            1 => {
                changed.identity_map.0[0].locus = Introduction::ReceiptAssociation;
            }
            2 => {
                changed.identity_map.0.swap(0, 1);
            }
            3 => {
                changed.facts.0.swap(0, 1);
            }
            4 => {
                changed.facts.0.pop();
            }
            5 => {
                changed.facts.0.push(changed.facts.0[0].clone());
            }
            _ => {
                if let Fact::Credential(capture) = &mut changed.facts.0[1].fact {
                    capture.snapshot.return_matches = false;
                }
            }
        }
        // Recompute count/hash by an explicit encode; a stale commitment cannot
        // mask whether the changed, well-typed history survives expansion.
        let restored = decode(&encode(&changed).unwrap()).unwrap();
        assert_eq!(restored, changed);
        assert_ne!(restored, original);
    }
}
#[test]
fn compact_v2_rejected_loss_resource_statuses_survive() {
    let mut value = Envelope::example();
    for reason in [Rejection::Json, Rejection::Bound, Rejection::Unsupported] {
        value.rejection = Nullable::Value(reason);
        assert_eq!(decode(&encode(&value).unwrap()).unwrap(), value);
    }
    value.rejection = Nullable::Null(());
    value.execution = Nullable::Value(Execution::Cancelled);
    value.observation_status = ObservationStatus::Lost(LostObservation {
        reason: Loss::MissingObservation,
        after_seq: 0,
    });
    assert_eq!(decode(&encode(&value).unwrap()).unwrap(), value);
    value.execution = Nullable::Null(());
    value.resource_stop = Nullable::Value(ResourceStop::DriverPoll(DriverResourceStop::example()));
    assert_eq!(decode(&encode(&value).unwrap()).unwrap(), value);
}
#[test]
fn compact_v2_inclusive_budgets_checked_before_work() {
    let value = Envelope::example();
    let (frame, visits, bytes) = encode_with_limits(&value, Limits::default()).unwrap();
    let expanded = serde_json::to_vec(&value).unwrap().len();
    for limit in [
        Limits {
            visits,
            ..Limits::default()
        },
        Limits {
            bytes,
            ..Limits::default()
        },
        Limits {
            expanded,
            ..Limits::default()
        },
    ] {
        assert!(encode_with_limits(&value, limit).is_ok());
    }
    for limit in [
        Limits {
            visits: visits - 1,
            ..Limits::default()
        },
        Limits {
            bytes: bytes - 1,
            ..Limits::default()
        },
        Limits {
            expanded: expanded - 1,
            ..Limits::default()
        },
    ] {
        assert_eq!(encode_with_limits(&value, limit), Err(Rejection::Bound));
    }
    let (_, visits, bytes) = decode_with_limits(&frame, Limits::default()).unwrap();
    for limit in [
        Limits {
            visits,
            ..Limits::default()
        },
        Limits {
            bytes,
            ..Limits::default()
        },
        Limits {
            expanded,
            ..Limits::default()
        },
    ] {
        assert!(decode_with_limits(&frame, limit).is_ok());
    }
    for limit in [
        Limits {
            visits: visits - 1,
            ..Limits::default()
        },
        Limits {
            bytes: bytes - 1,
            ..Limits::default()
        },
        Limits {
            expanded: expanded - 1,
            ..Limits::default()
        },
    ] {
        assert_eq!(decode_with_limits(&frame, limit), Err(Rejection::Bound));
    }
    let mut exact = Budget::new(Limits::default());
    exact.visits(VISIT_LIMIT).unwrap();
    assert_eq!(exact.visits(1), Err(Rejection::Bound));
    exact.bytes(BYTE_LIMIT).unwrap();
    assert_eq!(exact.bytes(1), Err(Rejection::Bound));
    let mut budget = Budget::new(Limits::default());
    budget.visits = usize::MAX;
    assert_eq!(budget.visits(1), Err(Rejection::Bound));
    budget.bytes = usize::MAX;
    assert_eq!(budget.bytes(1), Err(Rejection::Bound));
    for depth in [48usize, 49] {
        let raw = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        let mut budget = Budget::new(Limits::default());
        assert_eq!(
            lexical(raw.as_bytes(), &mut budget),
            if depth == 48 {
                Ok(())
            } else {
                Err(Rejection::Bound)
            }
        );
    }
    let mut out_budget = Budget::new(Limits::default());
    let mut out = Output::compact(&mut out_budget, 1);
    out.node(48).unwrap();
    assert_eq!(out.node(49), Err(Rejection::Bound));
    for _ in 0..48 {
        out.put(b"[").unwrap();
    }
    assert_eq!(out.put(b"["), Err(Rejection::Bound));
}
#[test]
fn compact_v2_whole_frame_limit_remains_exact_and_overflow_is_loss() {
    let header_len = 1 + TAG.len() + 1 + 6 + 1;
    let max_payload = MAX_FRAME - header_len - END.len();
    let mut budget = Budget::new(Limits::default());
    assert_eq!(
        frame(&vec![b' '; max_payload], &mut budget).unwrap().len(),
        MAX_FRAME
    );
    let mut budget = Budget::new(Limits::default());
    assert_eq!(
        frame(&vec![b' '; max_payload + 1], &mut budget),
        Err(Rejection::TooLarge)
    );
    let mut value = Envelope::example();
    value.rejection = Nullable::Null(());
    value.execution = Nullable::Value(Execution::Complete);
    let mut write = WriteCall::example();
    write.accepted_bytes_hex = Bytes::of(&vec![0; 4096]).unwrap();
    value.facts = List::new(
        (1..=10)
            .map(|seq| Captured {
                seq,
                fact: Fact::Native(NativeFact::Write(write.clone())),
            })
            .collect(),
    )
    .unwrap();
    assert_eq!(encode(&value), Err(Loss::FrameOverflow));
    assert!(matches!(
        value.observation_status,
        ObservationStatus::Complete(_)
    ));
    assert_eq!(value.facts.len(), 10);
    assert!(value.resource_stop.get().is_none());
}

#[test]
fn compact_v2_every_frozen_shape_field_and_variant_roundtrips() {
    <Envelope>::mapping_controls();
    <Rejection>::mapping_controls();
    <Execution>::mapping_controls();
    <ResourceStop>::mapping_controls();
    <DriverResourceStop>::mapping_controls();
    <DriverOwner>::mapping_controls();
    <NativeResourceStop>::mapping_controls();
    <IdentityIntroduction>::mapping_controls();
    <Introduction>::mapping_controls();
    <Captured>::mapping_controls();
    <Fact>::mapping_controls();
    <FrameCapture<EvidenceId>>::mapping_controls();
    <Cut>::mapping_controls();
    <FrameStage>::mapping_controls();
    <FrameOutcome>::mapping_controls();
    <AdmissionEvidence<EvidenceId>>::mapping_controls();
    <Correlation<EvidenceId>>::mapping_controls();
    <AdmissionKnowledge<EvidenceId>>::mapping_controls();
    <Empty>::mapping_controls();
    <AdmissionCommit<EvidenceId>>::mapping_controls();
    <EffectScope>::mapping_controls();
    <AdmissionFact<EvidenceId>>::mapping_controls();
    <FenceEvidence<EvidenceId>>::mapping_controls();
    <FinalizedFact<EvidenceId>>::mapping_controls();
    <FinalizeSuccess>::mapping_controls();
    <GuardValue>::mapping_controls();
    <GuardDecision>::mapping_controls();
    <AdmissionReturned<EvidenceId>>::mapping_controls();
    <MucFact<EvidenceId>>::mapping_controls();
    <MucCapture<EvidenceId>>::mapping_controls();
    <MucCommand<EvidenceId>>::mapping_controls();
    <Authority<EvidenceId>>::mapping_controls();
    <MucPrincipal<EvidenceId>>::mapping_controls();
    <LocalPrincipal<EvidenceId>>::mapping_controls();
    <FederatedPrincipal>::mapping_controls();
    <ClusterTarget<EvidenceId>>::mapping_controls();
    <AcceptanceClass>::mapping_controls();
    <MucSnapshot<EvidenceId>>::mapping_controls();
    <MucKnowledge<EvidenceId>>::mapping_controls();
    <MucCommitFact<EvidenceId>>::mapping_controls();
    <MucOutcome<EvidenceId>>::mapping_controls();
    <OneId<EvidenceId>>::mapping_controls();
    <MucReturned<EvidenceId>>::mapping_controls();
    <FanoutPrefix>::mapping_controls();
    <FanoutStage>::mapping_controls();
    <OwnerTerminal>::mapping_controls();
    <MucRecipients<EvidenceId>>::mapping_controls();
    <RecipientObservation<EvidenceId>>::mapping_controls();
    <MucEndpoint<EvidenceId>>::mapping_controls();
    <QueueItem<EvidenceId>>::mapping_controls();
    <Source<EvidenceId>>::mapping_controls();
    <C2sSource<EvidenceId>>::mapping_controls();
    <MixSource<EvidenceId>>::mapping_controls();
    <ForegroundFact<EvidenceId>>::mapping_controls();
    <ForegroundCapture<EvidenceId>>::mapping_controls();
    <MixIngress<EvidenceId>>::mapping_controls();
    <ReplayIdentityInput>::mapping_controls();
    <MixStoreCommand<EvidenceId>>::mapping_controls();
    <ForegroundSnapshot<EvidenceId>>::mapping_controls();
    <ReadKnowledge<EvidenceId>>::mapping_controls();
    <ExistingKnowledge<EvidenceId>>::mapping_controls();
    <Existing<EvidenceId>>::mapping_controls();
    <MixReplay<EvidenceId>>::mapping_controls();
    <ReadReturned<EvidenceId>>::mapping_controls();
    <ForegroundKnowledge<EvidenceId>>::mapping_controls();
    <Stored<EvidenceId>>::mapping_controls();
    <DeliveryProjection<EvidenceId>>::mapping_controls();
    <RecipientProjection<EvidenceId>>::mapping_controls();
    <Participant<EvidenceId>>::mapping_controls();
    <ForegroundReturned<EvidenceId>>::mapping_controls();
    <MixAdmission<EvidenceId>>::mapping_controls();
    <MixOutcome<EvidenceId>>::mapping_controls();
    <Wake>::mapping_controls();
    <ProjectionRowJoin<EvidenceId>>::mapping_controls();
    <DeliveryRow<EvidenceId>>::mapping_controls();
    <InitialRowLoaded<EvidenceId>>::mapping_controls();
    <ClaimFact<EvidenceId>>::mapping_controls();
    <ClaimCapture<EvidenceId>>::mapping_controls();
    <ClaimCommand>::mapping_controls();
    <ClaimSnapshot<EvidenceId>>::mapping_controls();
    <ClaimKnowledge<EvidenceId>>::mapping_controls();
    <Rows<EvidenceId>>::mapping_controls();
    <ClaimReturned<EvidenceId>>::mapping_controls();
    <CountValue>::mapping_controls();
    <ClaimAttemptJoin<EvidenceId>>::mapping_controls();
    <WorkerFact<EvidenceId>>::mapping_controls();
    <WorkerCapture<EvidenceId>>::mapping_controls();
    <WorkerSnapshot<EvidenceId>>::mapping_controls();
    <RoutePhase>::mapping_controls();
    <RouteResult>::mapping_controls();
    <ArchiveSnapshot<EvidenceId>>::mapping_controls();
    <ArchiveKnowledge<EvidenceId>>::mapping_controls();
    <ArchiveResult<EvidenceId>>::mapping_controls();
    <ArchiveReturned<EvidenceId>>::mapping_controls();
    <LocalPrefix<EvidenceId>>::mapping_controls();
    <LocalResult<EvidenceId>>::mapping_controls();
    <TransferBoundary<EvidenceId>>::mapping_controls();
    <ClusterPrefix<EvidenceId>>::mapping_controls();
    <TransferFact<EvidenceId>>::mapping_controls();
    <RenewalSnapshot>::mapping_controls();
    <RenewalKnowledge>::mapping_controls();
    <BoolValue>::mapping_controls();
    <RenewalReturned>::mapping_controls();
    <RenewalReceipt>::mapping_controls();
    <SettlementSnapshot>::mapping_controls();
    <SettlementKind>::mapping_controls();
    <SettlementKnowledge>::mapping_controls();
    <SettlementResult>::mapping_controls();
    <RetryValue>::mapping_controls();
    <RetryResult>::mapping_controls();
    <SettlementReturned>::mapping_controls();
    <ArchiveCall<EvidenceId>>::mapping_controls();
    <ArchiveCommand<EvidenceId>>::mapping_controls();
    <RouteLookup<EvidenceId>>::mapping_controls();
    <RouteLookupOwner<EvidenceId>>::mapping_controls();
    <MixItemOwner>::mapping_controls();
    <RouteSession<EvidenceId>>::mapping_controls();
    <RouteCandidate<EvidenceId>>::mapping_controls();
    <CapsObservation<EvidenceId>>::mapping_controls();
    <CapsOwner<EvidenceId>>::mapping_controls();
    <LocalCapsEpoch<EvidenceId>>::mapping_controls();
    <FederatedCapsOwner<EvidenceId>>::mapping_controls();
    <CapsKey>::mapping_controls();
    <VerifiedCapsSummary>::mapping_controls();
    <NotifyRange>::mapping_controls();
    <MixCapability>::mapping_controls();
    <LocalQueueJoin<EvidenceId>>::mapping_controls();
    <TypedHandoff<EvidenceId>>::mapping_controls();
    <HandoffResult<EvidenceId>>::mapping_controls();
    <RouteChildDrop<EvidenceId>>::mapping_controls();
    <SettlementCall<EvidenceId>>::mapping_controls();
    <SettlementCommand>::mapping_controls();
    <DeferCommand>::mapping_controls();
    <RetryCommand>::mapping_controls();
    <DeadLetterCommand>::mapping_controls();
    <AccountCall<EvidenceId>>::mapping_controls();
    <AccountReturned<EvidenceId>>::mapping_controls();
    <AccountIdentity<EvidenceId>>::mapping_controls();
    <PrivacyCall<EvidenceId>>::mapping_controls();
    <PrivacyReturned>::mapping_controls();
    <CredentialCapture<EvidenceId>>::mapping_controls();
    <CredentialSnapshot<EvidenceId>>::mapping_controls();
    <ObservedCredentialKind>::mapping_controls();
    <CredentialCall>::mapping_controls();
    <Eligibility>::mapping_controls();
    <NullableBool>::mapping_controls();
    <PreparationResult>::mapping_controls();
    <CredentialRollback>::mapping_controls();
    <CredentialRollbackSite>::mapping_controls();
    <CredentialReturned>::mapping_controls();
    <HandlerReturn>::mapping_controls();
    <CredentialTerminal>::mapping_controls();
    <CredentialJoins<EvidenceId>>::mapping_controls();
    <CredentialAttemptJoin<EvidenceId>>::mapping_controls();
    <ControlFact<EvidenceId>>::mapping_controls();
    <ControlCapture<EvidenceId>>::mapping_controls();
    <ControlJoins<EvidenceId>>::mapping_controls();
    <ControlAssociation<EvidenceId>>::mapping_controls();
    <PublicationJoins<EvidenceId>>::mapping_controls();
    <LivePublication<EvidenceId>>::mapping_controls();
    <PublicationSnapshot<EvidenceId>>::mapping_controls();
    <AuthTransport>::mapping_controls();
    <RidValue>::mapping_controls();
    <PublicationKnowledge>::mapping_controls();
    <EpochValue>::mapping_controls();
    <PublicationRollback>::mapping_controls();
    <PublicationReturned>::mapping_controls();
    <PublicationEffects>::mapping_controls();
    <PublicationTerminal>::mapping_controls();
    <PublicationCallback<EvidenceId>>::mapping_controls();
    <NativeFact<EvidenceId>>::mapping_controls();
    <NativeCapture<EvidenceId>>::mapping_controls();
    <ItemOwner<EvidenceId>>::mapping_controls();
    <MucItemOwner<EvidenceId>>::mapping_controls();
    <AuthItemOwner<EvidenceId>>::mapping_controls();
    <NativeSnapshot<EvidenceId>>::mapping_controls();
    <NativePreparation>::mapping_controls();
    <WriterResult>::mapping_controls();
    <WriteDecision>::mapping_controls();
    <NativeAckKnowledge<EvidenceId>>::mapping_controls();
    <NativeAckFact<EvidenceId>>::mapping_controls();
    <AckDisposition>::mapping_controls();
    <CallTerminal>::mapping_controls();
    <NativeDequeue<EvidenceId>>::mapping_controls();
    <WriteCall>::mapping_controls();
    <IoResult>::mapping_controls();
    <FlushCall>::mapping_controls();
    <NativeAckCall<EvidenceId>>::mapping_controls();
    <NativeReceipt>::mapping_controls();
    <ReceiptResult>::mapping_controls();
    <BoshFact<EvidenceId>>::mapping_controls();
    <BoshCapture<EvidenceId>>::mapping_controls();
    <BoshAssociation<EvidenceId>>::mapping_controls();
    <BoshRequestAssociation<EvidenceId>>::mapping_controls();
    <BoshSnapshot<EvidenceId>>::mapping_controls();
    <BoshScope<EvidenceId>>::mapping_controls();
    <BoshOperationKind>::mapping_controls();
    <BoshTransferSnapshot<EvidenceId>>::mapping_controls();
    <BoshTransferKnowledge<EvidenceId>>::mapping_controls();
    <BoshResponseSnapshot<EvidenceId>>::mapping_controls();
    <BoshResponseKind>::mapping_controls();
    <BoshBindAttempt<EvidenceId>>::mapping_controls();
    <BoshBindKnowledge<EvidenceId>>::mapping_controls();
    <Membership<EvidenceId>>::mapping_controls();
    <BoshRenewSnapshot<EvidenceId>>::mapping_controls();
    <BoshExpected<EvidenceId>>::mapping_controls();
    <TransactionKnowledge>::mapping_controls();
    <BoshAckSnapshot<EvidenceId>>::mapping_controls();
    <DeletedSource<EvidenceId>>::mapping_controls();
    <DeletedC2s<EvidenceId>>::mapping_controls();
    <SelectionCapture<EvidenceId>>::mapping_controls();
    <SelectionSnapshot<EvidenceId>>::mapping_controls();
    <SelectionStatus>::mapping_controls();
    <IncompleteSelection>::mapping_controls();
    <SelectedItem<EvidenceId>>::mapping_controls();
    <BoshTransferCall<EvidenceId>>::mapping_controls();
    <BoshBindCall<EvidenceId>>::mapping_controls();
    <BoshRenewCall<EvidenceId>>::mapping_controls();
    <BoshAckCall>::mapping_controls();
    <BoshResponseReceiver<EvidenceId>>::mapping_controls();
    <ResponseResult>::mapping_controls();
    <BodyBytes>::mapping_controls();
    <CacheCapture<EvidenceId>>::mapping_controls();
    <CacheEntry<EvidenceId>>::mapping_controls();
    <BoshQueueCapture<EvidenceId>>::mapping_controls();
    <BoshTransportReceipt<EvidenceId>>::mapping_controls();
    <DriverPoll>::mapping_controls();
    <PollResult>::mapping_controls();
    <ObservationStatus>::mapping_controls();
    <LostObservation>::mapping_controls();
    <Loss>::mapping_controls();
}

#[test]
fn compact_v2_body_membership_counter_and_prefix_mutations_survive_exactly() {
    let mut value = Envelope::example();
    value.rejection = Nullable::Null(());
    value.execution = Nullable::Value(Execution::Complete);
    value.identity_map = List::new(control_introductions()).unwrap();
    let mut cache = CacheCapture::<EvidenceId>::example();
    let mut entry = CacheEntry::<EvidenceId>::example();
    entry.body_hex = Bytes::of(b"<body>A</body>").unwrap();
    entry.response_bytes = 13;
    entry.replays = 2;
    entry.transport_receipt_count = 1;
    entry.membership.c2s_message_ids = List::new(vec![EvidenceId::example()]).unwrap();
    cache.entries = List::new(vec![entry]).unwrap();
    let mut receiver = BoshResponseReceiver::<EvidenceId>::example();
    receiver.result = ResponseResult::Received(BodyBytes {
        body_hex: Bytes::of(b"<body>A</body>").unwrap(),
    });
    let write = WriteCall {
        item_ordinal: 0,
        offered_len: 10,
        offered_sha256: super::sha256(b"0123456789"),
        accepted_bytes_hex: Bytes::of(b"012").unwrap(),
        result: IoResult::example(),
    };
    value.facts = List::new(vec![
        Captured {
            seq: 1,
            fact: Fact::Bosh(BoshFact::Cache(cache.clone())),
        },
        Captured {
            seq: 2,
            fact: Fact::Bosh(BoshFact::Cache(cache)),
        },
        Captured {
            seq: 3,
            fact: Fact::Bosh(BoshFact::Receiver(receiver)),
        },
        Captured {
            seq: 4,
            fact: Fact::Native(NativeFact::Write(write.clone())),
        },
    ])
    .unwrap();
    let original = decode(&encode(&value).unwrap()).unwrap();
    assert_eq!(original, value);
    for mutation in 0..8 {
        let mut changed = value.clone();
        if mutation < 5 {
            if let Fact::Bosh(BoshFact::Cache(cache)) = &mut changed.facts.0[1].fact {
                let entry = &mut cache.entries.0[0];
                match mutation {
                    0 => entry.body_hex = Bytes::of(b"<body>B</body>").unwrap(),
                    1 => entry.response_bytes += 1,
                    2 => entry.replays += 1,
                    3 => entry.transport_receipt_count += 1,
                    _ => entry.membership.c2s_message_ids.0.clear(),
                }
            }
        } else if mutation == 5 {
            if let Fact::Bosh(BoshFact::Receiver(receiver)) = &mut changed.facts.0[2].fact {
                receiver.result = ResponseResult::Received(BodyBytes {
                    body_hex: Bytes::of(b"wrong").unwrap(),
                });
            }
        } else if mutation == 6 {
            if let Fact::Native(NativeFact::Write(call)) = &mut changed.facts.0[3].fact {
                call.accepted_bytes_hex = Bytes::of(b"013").unwrap();
                assert_eq!(call.offered_len, write.offered_len);
                assert_eq!(call.offered_sha256, write.offered_sha256);
            }
        } else {
            if let Fact::Bosh(BoshFact::Receiver(receiver)) = &mut changed.facts.0[2].fact {
                receiver.connection =
                    Nullable::Value(EvidenceId::Encoded(IdentityLabel::Opaque(OpaqueIdentity {
                        ordinal: 1,
                    })));
            }
        }
        let restored = decode(&encode(&changed).unwrap()).unwrap();
        assert_eq!(restored, changed);
        assert_ne!(restored, original);
        assert_eq!(restored.facts.len(), 4);
        assert_eq!(
            serde_json::to_vec(&restored).unwrap(),
            serde_json::to_vec(&changed).unwrap()
        );
    }
}
#[test]
fn compact_v2_identity_introductions_never_replace_chronological_validation() {
    let (input, case, original) = synthetic_history();
    let mut unused = original.clone();
    unused.identity_map.0.push(IdentityIntroduction {
        label: IdentityLabel::Opaque(OpaqueIdentity { ordinal: 2 }),
        first_seq: 2,
        locus: Introduction::ReceiptAssociation,
    });
    let restored = decode(&encode(&unused).unwrap()).unwrap();
    assert_eq!(restored, unused);
    assert_eq!(
        super::validate_envelope(&restored, &input, Some(&case)),
        Err(Loss::NoncanonicalIdentity)
    );
    let mut missing = original.clone();
    missing.identity_map.0.remove(0);
    assert_eq!(encode(&missing), Err(Loss::EncodingFailure));
    let mut reassigned = original.clone();
    if let Fact::Credential(capture) = &mut reassigned.facts.0[1].fact {
        capture.snapshot.attempt = capture.snapshot.connection.clone();
    }
    let restored = decode(&encode(&reassigned).unwrap()).unwrap();
    assert_eq!(restored, reassigned);
    assert_ne!(restored, original);
    // UUID/ordinal values are identity data, not a codec repair policy.
    let fixed = IdentityLabel::Fixed(FixedIdentity {
        uuid: Id(Uuid::from_u128(77)),
    });
    adapter_roundtrip(&fixed);
    let opaque = IdentityLabel::Opaque(OpaqueIdentity { ordinal: 16 });
    adapter_roundtrip(&opaque);
}

#[test]
fn compact_v2_same_capture_gate_requires_actual_canonical_equality() {
    let (_, _, original) = synthetic_history();
    let frame = encode(&original).unwrap();
    assert_eq!(verify_frame_roundtrip(&original, &frame), Ok(()));
    let named = serde_json::to_vec(&original).unwrap();
    let (bytes, visits, work) =
        compare_with_limits(&original, &decode(&frame).unwrap(), Limits::default()).unwrap();
    assert_eq!(bytes, named.len());
    // Count the original named JSON nodes independently in this small synthetic
    // control. Comparison must touch precisely both complete value trees.
    fn nodes(value: &serde_json::Value) -> usize {
        1 + match value {
            serde_json::Value::Array(v) => v.iter().map(nodes).sum(),
            serde_json::Value::Object(v) => v.values().map(nodes).sum(),
            _ => 0,
        }
    }
    let value: serde_json::Value = serde_json::from_slice(&named).unwrap();
    assert_eq!(visits, 2 * nodes(&value));
    for limits in [
        Limits {
            expanded: bytes,
            ..Limits::default()
        },
        Limits {
            visits,
            ..Limits::default()
        },
        Limits {
            bytes: work,
            ..Limits::default()
        },
    ] {
        assert!(compare_with_limits(&original, &original, limits).is_ok());
    }
    for limits in [
        Limits {
            expanded: bytes - 1,
            ..Limits::default()
        },
        Limits {
            visits: visits - 1,
            ..Limits::default()
        },
        Limits {
            bytes: work - 1,
            ..Limits::default()
        },
    ] {
        assert_eq!(
            compare_with_limits(&original, &original, limits),
            Err(Rejection::Bound)
        );
    }
    let mut changed = original.clone();
    if let Fact::Credential(capture) = &mut changed.facts.0[1].fact {
        capture.snapshot.return_matches = false;
    }
    let changed_frame = encode(&changed).unwrap();
    assert_eq!(
        verify_frame_roundtrip(&original, &changed_frame),
        Err(RoundtripFailure::Compare(Rejection::Encoding))
    );
    assert_eq!(verify_frame_roundtrip(&changed, &changed_frame), Ok(()));
    changed.facts.0.pop();
    assert_eq!(
        verify_frame_roundtrip(&original, &encode(&changed).unwrap()),
        Err(RoundtripFailure::Compare(Rejection::Encoding))
    );
    let mut broken = frame.clone();
    broken.pop();
    assert_eq!(
        verify_frame_roundtrip(&original, &broken),
        Err(RoundtripFailure::Decode(Rejection::Encoding))
    );
    assert_eq!(
        verify_frame_roundtrip(&original, &super::encode_frame(&original).unwrap()),
        Err(RoundtripFailure::Decode(Rejection::Schema))
    );
}
#[test]
fn compact_v2_comparison_buffers_cover_true_leaf_bound_without_recursion() {
    let value = Text::<16384>::new("\u{1}".repeat(16384)).unwrap();
    let mut pair = Comparison::new(Limits::default());
    value.compare(&value, &mut pair, 0).unwrap();
    assert_eq!(pair.left_bytes, MAX_CANONICAL_LEAF);
    assert_eq!(pair.right_bytes, MAX_CANONICAL_LEAF);
    assert_eq!(pair.budget.visits, 2);
    assert!(pair.left.capacity() >= MAX_CANONICAL_LEAF);
    assert!(pair.right.capacity() >= MAX_CANONICAL_LEAF);
    let left = pair.left.as_ptr();
    let right = pair.right.as_ptr();
    Text::<16384>::new("short")
        .unwrap()
        .compare(&Text::<16384>::new("short").unwrap(), &mut pair, 0)
        .unwrap();
    assert_eq!(pair.left.as_ptr(), left);
    assert_eq!(pair.right.as_ptr(), right);
    assert_eq!(pair.budget.visits, 4);
    assert_eq!(pair.left_bytes, MAX_CANONICAL_LEAF + 7);
}
