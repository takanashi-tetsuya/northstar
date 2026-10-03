import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

// Source-shape wiring guard only. Routing, health races, exact delivery tuples
// and acceptance semantics are exercised by direct_route_tests.rs, not proved
// by this lexical check. Keep the inspected production functions small.
export function readFederatedRouteSources() {
  const read = file => fs.readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
  return {
    inbound: read('src/s2s/inbound.rs'),
    adapter: read('src/s2s/inbound/direct_route.rs'),
  };
}

function maskRust(source) {
  // ASCII offsets are used by the scanner; preserve UTF-16 offsets as well.
  const output = source.split('');
  const mask = (start, end) => {
    for (let at = start; at < end; at++) if (output[at] !== '\n') output[at] = ' ';
  };
  for (let at = 0; at < source.length;) {
    let end = at;
    if (source.startsWith('//', at)) {
      end = source.indexOf('\n', at);
      if (end < 0) end = source.length;
    } else if (source.startsWith('/*', at)) {
      let depth = 1;
      end = at + 2;
      while (end < source.length && depth) {
        if (source.startsWith('/*', end)) { depth++; end += 2; }
        else if (source.startsWith('*/', end)) { depth--; end += 2; }
        else end++;
      }
      if (depth) throw new Error('unterminated Rust block comment');
    } else {
      const raw = source.slice(at).match(/^r(#+)?"/);
      if (raw) {
        const close = `"${raw[1] ?? ''}`;
        end = source.indexOf(close, at + raw[0].length);
        if (end < 0) throw new Error('unterminated Rust raw string');
        end += close.length;
      } else if (source[at] === '"') {
        end = at + 1;
        while (end < source.length) {
          if (source[end] === '\\') { end += 2; continue; }
          if (source[end++] === '"') break;
        }
      } else if (source[at] === "'") {
        const literal = source.slice(at).match(/^'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'/);
        if (literal) end = at + literal[0].length;
      }
    }
    if (end > at) { mask(at, end); at = end; }
    else at++;
  }
  return output.join('');
}

function balancedBody(code, open, left = '{', right = '}') {
  if (open < 0 || code[open] !== left) throw new Error('production boundary body missing');
  let depth = 0;
  for (let at = open; at < code.length; at++) {
    if (code[at] === left) depth++;
    if (code[at] === right && --depth === 0) return code.slice(open + 1, at);
  }
  throw new Error('production boundary body unterminated');
}

function functionBody(code, name) {
  const match = new RegExp(`\\bfn\\s+${name}\\s*(?:<[^{}]*>)?\\s*\\(`).exec(code);
  if (!match) throw new Error(`missing production function ${name}`);
  return balancedBody(code, code.indexOf('{', match.index));
}

function requireMatch(code, pattern, message) {
  if (!pattern.test(code)) throw new Error(message);
}

export function verifyFederatedRouteBoundaries(sources) {
  const inbound = maskRust(sources.inbound);
  const adapter = maskRust(sources.adapter);
  requireMatch(inbound, /\bmod\s+direct_route\s*;/, 'S2S route adapter module must stay registered');
  requireMatch(inbound, /\buse\s+direct_route::S2sDirectRoutePort\s*;/, 'S2S caller must import its origin-specific adapter');
  const caller = functionBody(inbound, 'route_inbound_message');
  const invocation = /\bDirectMessageRouter::route_federated\s*\(\s*&S2sDirectRoutePort\s*\(\s*state\s*\)\s*,/.exec(caller);
  if (!invocation || (caller.match(/\bDirectMessageRouter::route_federated\s*\(/g) ?? []).length !== 1) {
    throw new Error('S2S message caller must invoke route_federated once through S2sDirectRoutePort');
  }
  const argumentsBody = balancedBody(caller, caller.indexOf('(', invocation.index), '(', ')');
  requireMatch(argumentsBody, /\bDirectRouteRequest\s*\{/, 'S2S route must use the typed request');
  for (const field of [/\bdelivery\s*,/, /\bsender\s*:\s*from\s*,/, /\brecipient_id\s*:\s*recipient\.id\s*,/, /\bstanza\s*:\s*&annotated\s*,/, /\bapproved_targets\s*:\s*&targets\s*,/, /\benforce_direct_health\s*:\s*true\s*,/]) {
    requireMatch(argumentsBody, field, 'S2S route must keep the approved envelope, targets and health enforcement');
  }
  requireMatch(argumentsBody, /\bhistory_committed\s*,?\s*$/, 'S2S route must preserve independent committed-history input');
  if (/\.\s*(?:try_send(?:_durable)?|route_s2s_message_to_[a-z_]+)\s*\(/.test(caller)) {
    throw new Error('S2S caller regained inline queue/remote routing outside the direct owner');
  }
  requireMatch(caller, /\bDirectRouteOutcome::Routed\s*\{\s*accepted_full_jid\s*\}\s*=>\s*\(\s*true\s*,\s*accepted_full_jid\s*\)/, 'S2S caller must retain the accepted resource for Carbon exclusion');
  requireMatch(caller, /\bSome\(delivered_key\)\s*=\s*delivered_key\.as_deref\(\)/, 'S2S caller must use the optional accepted Carbon exclusion key');

  const compactBody = name => functionBody(adapter, name).replace(/\s+/g, '');
  requireMatch(compactBody('record_local_accept'), /self\.0\.s2s_online_queue_telemetry\(\)\.accepted\(durable\);/, 'S2S local acceptance must retain federation queue telemetry and delivery kind');
  requireMatch(compactBody('post_accept_failed'), /self\.0\.s2s_inbound_delivery_telemetry\(\)\.post_accept_failed\(\);/, 'S2S post-accept failures must retain federation telemetry');
  if (/\bpersonal_message_telemetry\s*\(/.test(adapter)) throw new Error('S2S adapter must not record C2S origin telemetry');
  requireMatch(compactBody('try_local'), /OnlineRoutePort::try_local\(self\.0,session,stanza,delivery\)/, 'S2S adapter must preserve the exact local delivery tuple');
  requireMatch(compactBody('route_available_remote'), /self\.0\.route_s2s_message_to_available_remote_resources\(jid,stanza,delivery\)\.await/, 'S2S fanout must use its federation remote adapter');
  const primary = compactBody('route_remote_primary');
  requireMatch(primary, /self\.0\.route_s2s_message_to_remote_primary\(jid,stanza,delivery\)\.await/, 'S2S primary must use its federation remote adapter');
  requireMatch(primary, /delivered:routed\.delivered,accepted_full_jid:routed\.accepted_full_jid,/, 'S2S remote receipt must preserve acceptance and Carbon exclusion');
  requireMatch(compactBody('rearm_direct_route'), /DirectMessageRoutePort::rearm_direct_route\(self\.0,delivery\)\.await;/, 'S2S rearm must retain the exact delivery claim');
  return { caller: 'route_inbound_message', owner: 'route_federated', adapter: 'S2sDirectRoutePort' };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  verifyFederatedRouteBoundaries(readFederatedRouteSources());
  console.log('federated direct-route caller/adapter source wiring is intact (not a semantic proof)');
}
