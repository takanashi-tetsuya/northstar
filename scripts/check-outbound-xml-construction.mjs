import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// This is a monotonic per-file baseline. Every tracked outbound producer has
// moved behind XmlElement/validated-fragment boundaries and therefore has a
// zero raw-literal budget. Static parser literals still require the exact
// allowlist below.
const BASELINE = new Map([
  ['src/xmpp/xml_util.rs', 0],
  ['src/xmpp/protocol.rs', 0],
  ['src/xmpp/protocol/blocking.rs', 0],
  ['src/xmpp/protocol/caps.rs', 0],
  ['src/xmpp/protocol/csi.rs', 0],
  ['src/xmpp/protocol/commands.rs', 0],
  ['src/xmpp/protocol/discovery.rs', 0],
  ['src/xmpp/protocol/extdisco.rs', 0],
  ['src/xmpp/protocol/jingle.rs', 0],
  ['src/xmpp/protocol/mam.rs', 0],
  ['src/xmpp/protocol/mix_muc.rs', 0],
  ['src/xmpp/protocol/private.rs', 0],
  ['src/xmpp/protocol/privacy.rs', 0],
  ['src/xmpp/protocol/presence.rs', 0],
  ['src/xmpp/protocol/retractions.rs', 0],
  ['src/xmpp/protocol/roster.rs', 0],
  ['src/xmpp/protocol/sasl2.rs', 0],
  ['src/xmpp/protocol/upload.rs', 0],
  ['src/xmpp/protocol/vcard.rs', 0],
  ['src/xmpp/protocol/messaging.rs', 0],
  ['src/xmpp/protocol/muc.rs', 0],
  ['src/xmpp/protocol/mix.rs', 0],
  ['src/xmpp/protocol/pubsub.rs', 0],
  ['src/xmpp/protocol/pep.rs', 0],
  ['src/xmpp/protocol/federated_muc.rs', 0],
  ['src/xmpp/protocol/misc.rs', 0],
  ['src/xmpp/protocol/sm.rs', 0],
  ['src/services/mix.rs', 0],
  ['src/db/mix.rs', 0],
  ['src/components.rs', 0],
  ['src/cluster.rs', 0],
  ['src/s2s/inbound.rs', 0],
  ['src/s2s/outbound.rs', 0],
  ['src/xmpp/protocol/ibr.rs', 0],
]);

// Static protocol constants may be exempted only by an exact file, line and
// literal match plus a reason. Exemptions must be parser input, never outbound
// stanzas; the line-bound match deliberately fails closed if moved.
const STATIC_LITERAL_ALLOWLIST = [
  {
    file: 'src/xmpp/protocol/sasl2.rs',
    line: 625,
    literal: '</stream:stream>',
    reason: 'parser-only synthetic close used to validate a stream opening element',
  },
];

const XML_TAG = /<(?:[!?/])?[A-Za-z_][A-Za-z0-9_.:-]*(?:\s|\/?>)/;

function productionSource(source) {
  // Test modules use descriptive names (`legacy_tests`, `security_tests`, …)
  // as well as `tests`; none of their fixture XML is an outbound production
  // construction site. Mask each complete module rather than truncating at
  // the first one: Rust permits production items after a test module and the
  // old truncation hid exactly such an outbound vCard presence constructor.
  const ranges = [];
  const testModule = /^#\[cfg\(test\)\]\s*\r?\nmod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{/gm;
  for (let match; (match = testModule.exec(source)) !== null; ) {
    const open = match.index + match[0].lastIndexOf('{');
    const close = matchingRustBrace(source, open);
    if (close < 0) {
      throw new Error(`unterminated cfg(test) module at line ${lineAt(source, match.index)}`);
    }
    ranges.push([match.index, close + 1]);
    testModule.lastIndex = close + 1;
  }
  let masked = '';
  let cursor = 0;
  for (const [start, end] of ranges) {
    masked += source.slice(cursor, start);
    masked += source.slice(start, end).replace(/[^\r\n]/g, ' ');
    cursor = end;
  }
  return masked + source.slice(cursor);
}

function matchingRustBrace(source, opening) {
  let depth = 1;
  let index = opening + 1;
  while (index < source.length) {
    if (source.startsWith('//', index)) {
      const newline = source.indexOf('\n', index + 2);
      index = newline < 0 ? source.length : newline + 1;
      continue;
    }
    if (source.startsWith('/*', index)) {
      let commentDepth = 1;
      index += 2;
      while (index < source.length && commentDepth > 0) {
        if (source.startsWith('/*', index)) {
          commentDepth += 1;
          index += 2;
        } else if (source.startsWith('*/', index)) {
          commentDepth -= 1;
          index += 2;
        } else {
          index += 1;
        }
      }
      continue;
    }

    const rawPrefix = /^(?:br|rb|r)(#+)?"/.exec(source.slice(index));
    if (rawPrefix) {
      const hashes = rawPrefix[1] ?? '';
      const terminator = `"${hashes}`;
      const end = source.indexOf(terminator, index + rawPrefix[0].length);
      if (end < 0) return -1;
      index = end + terminator.length;
      continue;
    }

    const quoteOffset = source[index] === '"' ? 0 : source.startsWith('b"', index) ? 1 : -1;
    if (quoteOffset >= 0) {
      index += quoteOffset + 1;
      let escaped = false;
      while (index < source.length) {
        const character = source[index++];
        if (escaped) escaped = false;
        else if (character === '\\') escaped = true;
        else if (character === '"') break;
      }
      continue;
    }

    // Skip a real char/byte-char literal, but leave lifetimes such as `'a`
    // in ordinary code. This mirrors the literal scanner below.
    const charContentStart =
      source[index] === "'" ? index + 1 : source.startsWith("b'", index) ? index + 2 : -1;
    if (charContentStart >= 0 && charContentStart < source.length) {
      let cursor = charContentStart;
      if (source[cursor] === '\\') {
        cursor += 2;
        if (source[cursor - 1] === 'u' && source[cursor] === '{') {
          const brace = source.indexOf('}', cursor + 1);
          cursor = brace < 0 ? source.length : brace + 1;
        }
      } else {
        const scalar = source.codePointAt(cursor);
        cursor += scalar !== undefined && scalar > 0xffff ? 2 : 1;
      }
      if (source[cursor] === "'") {
        index = cursor + 1;
        continue;
      }
    }

    if (source[index] === '{') depth += 1;
    else if (source[index] === '}' && --depth === 0) return index;
    index += 1;
  }
  return -1;
}

function lineAt(source, offset) {
  return source.slice(0, offset).split(/\r?\n/).length;
}

// Extract normal, byte and raw Rust string literals without depending on a
// formatter-specific layout. Comments are skipped so examples cannot consume
// the budget. The gate intentionally errs on the side of reporting any XML-
// shaped literal in production code: callers should use XmlElement even for a
// currently-static stanza so future dynamic values cannot reopen interpolation.
function rustStringLiterals(source) {
  const literals = [];
  let index = 0;
  let blockCommentDepth = 0;
  while (index < source.length) {
    if (blockCommentDepth > 0) {
      if (source.startsWith('/*', index)) {
        blockCommentDepth += 1;
        index += 2;
      } else if (source.startsWith('*/', index)) {
        blockCommentDepth -= 1;
        index += 2;
      } else {
        index += 1;
      }
      continue;
    }
    if (source.startsWith('//', index)) {
      const newline = source.indexOf('\n', index + 2);
      index = newline < 0 ? source.length : newline + 1;
      continue;
    }
    if (source.startsWith('/*', index)) {
      blockCommentDepth = 1;
      index += 2;
      continue;
    }

    // Skip Rust character literals before looking for a raw-string `r"`
    // prefix. Without this, the double quote in the perfectly ordinary char
    // literal `'"'` is mistaken for a string opening and desynchronizes the
    // scanner until a later `r"` byte sequence. Lifetimes such as `'a` do not
    // have the required closing quote after one scalar/escape and therefore
    // fall through unchanged.
    const charContentStart =
      source[index] === "'" ? index + 1 : source.startsWith("b'", index) ? index + 2 : -1;
    if (charContentStart >= 0 && charContentStart < source.length) {
      let cursor = charContentStart;
      if (source[cursor] === '\\') {
        cursor += 2;
        if (source[cursor - 1] === 'u' && source[cursor] === '{') {
          const brace = source.indexOf('}', cursor + 1);
          cursor = brace < 0 ? source.length : brace + 1;
        }
      } else {
        const scalar = source.codePointAt(cursor);
        cursor += scalar !== undefined && scalar > 0xffff ? 2 : 1;
      }
      if (source[cursor] === "'") {
        index = cursor + 1;
        continue;
      }
    }

    const rawPrefix = /^(?:br|rb|r)(#+)?"/.exec(source.slice(index));
    if (rawPrefix) {
      const start = index;
      const hashes = rawPrefix[1] ?? '';
      const contentStart = index + rawPrefix[0].length;
      const terminator = `"${hashes}`;
      const end = source.indexOf(terminator, contentStart);
      if (end < 0) throw new Error(`unterminated raw Rust string at line ${lineAt(source, start)}`);
      literals.push({ value: source.slice(contentStart, end), line: lineAt(source, start) });
      index = end + terminator.length;
      continue;
    }

    const quoteOffset = source[index] === '"' ? 0 : source.startsWith('b"', index) ? 1 : -1;
    if (quoteOffset >= 0) {
      const start = index;
      let cursor = index + quoteOffset + 1;
      let value = '';
      let escaped = false;
      for (; cursor < source.length; cursor += 1) {
        const character = source[cursor];
        if (escaped) {
          // Exact decoding is unnecessary: XML tag delimiters are never
          // represented by a Rust escape in protocol literals.
          value += `\\${character}`;
          escaped = false;
        } else if (character === '\\') {
          escaped = true;
        } else if (character === '"') {
          break;
        } else {
          value += character;
        }
      }
      if (cursor >= source.length) {
        throw new Error(`unterminated Rust string at line ${lineAt(source, start)}`);
      }
      literals.push({ value, line: lineAt(source, start) });
      index = cursor + 1;
      continue;
    }
    index += 1;
  }
  return literals;
}

function findings(relativePath, source) {
  return rustStringLiterals(productionSource(source))
    .filter(({ value }) => XML_TAG.test(value))
    .filter(({ line, value }) =>
      !STATIC_LITERAL_ALLOWLIST.some(
        (entry) =>
          entry.file === relativePath && entry.line === line && entry.literal === value,
      ),
    );
}

// Guard the detector itself against the two most important false-negative and
// false-positive classes before inspecting the repository.
if (findings('self-test.rs', 'fn x() { format!("<iq id={}/>", id); }').length !== 1) {
  throw new Error('outbound XML detector self-test did not identify a raw stanza');
}
if (findings('self-test.rs', 'fn x() { format!("{form_type}<"); }').length !== 0) {
  throw new Error('outbound XML detector confused a caps hash delimiter with an XML tag');
}
const splitProductionSelfTest = `
fn before() { format!("<iq/>"); }
#[cfg(test)]
mod fixtures { const XML: &str = r#"<message>{ ignored }</message>"#; }
fn after() { format!("<presence/>"); }
`;
if (findings('self-test.rs', splitProductionSelfTest).length !== 2) {
  throw new Error('outbound XML detector hid production code after a cfg(test) module');
}

let failed = false;
const verbose = process.env.NORTHSTAR_XML_GATE_VERBOSE === '1';
console.log('Raw outbound XML construction baseline:');
for (const [relativePath, maximum] of BASELINE) {
  const source = fs.readFileSync(path.join(root, relativePath), 'utf8');
  const current = findings(relativePath, source);
  console.log(`  ${relativePath}: current=${current.length}, baseline=${maximum}`);
  if (verbose || current.length > maximum) {
    if (current.length > maximum) failed = true;
    for (const finding of current) {
      const preview = finding.value.replace(/\s+/g, ' ').slice(0, 120);
      console.error(`    line ${finding.line}: ${JSON.stringify(preview)}`);
    }
  }
}

if (failed) {
  throw new Error(
    'raw outbound XML construction regressed; use XmlElement or an explicitly validated fragment',
  );
}

console.log('Outbound XML construction gate passed.');
