use super::super::Rejection;
use serde::Deserializer;

pub(super) const EXPANDED_LIMIT: usize = 4_194_304;
pub(super) const VISIT_LIMIT: usize = 262_144;
pub(super) const BYTE_LIMIT: usize = 33_554_432;
const DEPTH_LIMIT: usize = 48;

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub(super) expanded: usize,
    pub(super) visits: usize,
    pub(super) bytes: usize,
    pub(super) depth: usize,
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
pub(super) struct Budget {
    pub(super) limits: Limits,
    pub(super) visits: usize,
    pub(super) bytes: usize,
}
impl Budget {
    pub(super) fn new(limits: Limits) -> Self {
        Self {
            limits,
            visits: 0,
            bytes: 0,
        }
    }
    pub(super) fn visits(&mut self, n: usize) -> Result<(), Rejection> {
        let next = self.visits.checked_add(n).ok_or(Rejection::Bound)?;
        if next > self.limits.visits {
            return Err(Rejection::Bound);
        }
        self.visits = next;
        Ok(())
    }
    pub(super) fn bytes(&mut self, n: usize) -> Result<(), Rejection> {
        let next = self.bytes.checked_add(n).ok_or(Rejection::Bound)?;
        if next > self.limits.bytes {
            return Err(Rejection::Bound);
        }
        self.bytes = next;
        Ok(())
    }
    pub(super) fn depth(&self, depth: usize) -> Result<(), Rejection> {
        if depth > self.limits.depth {
            Err(Rejection::Bound)
        } else {
            Ok(())
        }
    }
    // The first charged scan determines the exact scalar count. The second
    // reserves 4*codepoints BEFORE its scalar/UTF-8-length preflight. Rust str
    // cannot contain surrogates; the raw JSON parser rejects lone escapes.
    pub(super) fn scalar(&mut self, text: &str) -> Result<usize, Rejection> {
        self.bytes(text.len())?;
        let count = text.chars().count();
        self.bytes(count.checked_mul(4).ok_or(Rejection::Bound)?)?;
        let mut len = 0usize;
        for c in text.chars() {
            len = len.checked_add(c.len_utf8()).ok_or(Rejection::Bound)?;
        }
        Ok(len)
    }
    pub(super) fn equal(&mut self, a: &[u8], b: &[u8]) -> Result<bool, Rejection> {
        self.bytes(a.len().checked_add(b.len()).ok_or(Rejection::Bound)?)?;
        Ok(a == b)
    }
}

// The parse tree is bounded by raw wire/depth before parsing; its two compact
// visits are reserved before each node is constructed. No expanded JSON tree
// or expanded JSON byte buffer is materialized.
#[derive(Debug)]
pub(super) enum Node {
    Null,
    Bool(bool),
    Int(i128),
    Str(String),
    Array(Vec<Node>),
    Object(Vec<(String, Node)>),
}
impl Node {
    pub(super) fn array(&self, n: usize) -> Result<&[Node], Rejection> {
        match self {
            Self::Array(v) if v.len() == n => Ok(v),
            _ => Err(Rejection::Json),
        }
    }
    pub(super) fn string(&self) -> Result<&str, Rejection> {
        match self {
            Self::Str(v) => Ok(v),
            _ => Err(Rejection::Json),
        }
    }
    pub(super) fn integer(&self) -> Result<i128, Rejection> {
        match self {
            Self::Int(v) => Ok(*v),
            _ => Err(Rejection::Json),
        }
    }
}

pub(super) fn lexical(raw: &[u8], budget: &mut Budget) -> Result<(), Rejection> {
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
pub(super) fn parse(raw: &[u8], budget: &mut Budget) -> Result<Node, Rejection> {
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

pub(super) fn named_fields<'a>(
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
