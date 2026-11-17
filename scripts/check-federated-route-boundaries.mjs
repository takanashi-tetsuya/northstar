import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { readProductionModule } from './lib/source-module.mjs';

// Source-shape wiring guard only. Routing, health races, exact delivery tuples
// and acceptance semantics are exercised by direct_route_tests.rs, not proved
// by this lexical check. Keep the inspected production functions small.
export function readFederatedRouteSources() {
  const read = file => fs.readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
  return {
    inbound: readProductionModule('crates/contexts/message/northstar-message-xmpp/src/federated_message.rs'),
    adapter: readProductionModule('crates/contexts/message/northstar-message-xmpp/src/federated_message.rs'),
    host: read('src/node/hosts/message.rs'),
    state: read('crates/contexts/message/northstar-message-xmpp/src/lib.rs'),
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
  const host = maskRust(sources.host);
  requireMatch(maskRust(sources.state), /\bpub\s+mod\s+federated_message\s*;/, 'S2S route adapter module must stay registered');
  requireMatch(adapter, /\bstruct\s+FederatedDirectRoute\s*<\s*'a\s*,\s*H\s*>\s*\(\s*&'a\s+H\s*\)\s*;/, 'S2S caller must own its origin-specific adapter');
  const caller = functionBody(inbound, 'route_inbound_message');
  const invocation = /\bDirectMessageRouter::route_federated\s*\(\s*&FederatedDirectRoute\s*\(\s*state\s*\)\s*,/.exec(caller);
  const argumentsBody = balancedBody(caller, caller.indexOf('(', invocation.index), '(', ')');
  requireMatch(argumentsBody, /\bhistory_committed\s*,?\s*$/, 'S2S route must preserve independent committed-history input');
  if (/\.\s*(?:try_send(?:_durable)?|route_s2s_message_to_[a-z_]+)\s*\(/.test(caller)) {
    throw new Error('S2S caller regained inline queue/remote routing outside the direct owner');
  }

  const hostBody = name => functionBody(host, name).replace(/\s+/g, '');
  if (hostBody('record_s2s_online_accept') !== 'northstar_federation_application::telemetry::OnlineQueueAcceptanceTelemetry::new(&self.metrics.online_queue_durable_acceptances_total,&self.metrics.online_queue_volatile_acceptances_total,).accepted(durable);') {
    throw new Error('S2S local acceptance must retain federation queue telemetry and delivery kind');
  }
  if (hostBody('record_s2s_post_accept_failure') !== 'northstar_federation_application::telemetry::InboundDeliveryTelemetry::new(&self.metrics.post_accept_side_effect_failures_total,&self.metrics.messages_routed_total,).post_accept_failed();') {
    throw new Error('S2S post-accept failures must retain federation telemetry');
  }
  if (/\bpersonal_message_telemetry\s*\(/.test(adapter)) throw new Error('S2S adapter must not record C2S origin telemetry');
  const localEntries = [...adapter.matchAll(/\bfn\s+try_local\s*\(/g)];
  if (localEntries.length !== 1) {
    throw new Error('S2S adapter must have one owned local enqueue entry');
  }
  const localStart = localEntries[0].index;
  const localSignature = adapter.slice(localStart, adapter.indexOf('{', localStart)).replace(/\s+/g, '');
  if (localSignature !== 'fntry_local(&self,session:&Self::Session,enqueue:northstar_stream::outbound::RouteEnqueue,)->Result<(),northstar_stream::outbound::RouteSendError>') {
    throw new Error('S2S adapter must accept an owned local enqueue and preserve its refusal type');
  }
  const primary = hostBody('route_s2s_message_to_remote_primary')
    .replace('self.personal_message_telemetry()', hostBody('personal_message_telemetry'));
  requireMatch(primary, /self\.cluster\.route_s2s_message_to_remote_primary\(jid,stanza,delivery,&northstar_message_application::telemetry::PersonalMessageTelemetry::new\([^()]*\),?\)\.await/, 'S2S primary must use its federation remote adapter');
  requireMatch(primary, /delivered:routed\.delivered,accepted_full_jid:routed\.accepted_full_jid,/, 'S2S remote receipt must preserve acceptance and Carbon exclusion');
  return { caller: 'route_inbound_message', owner: 'route_federated', adapter: 'FederatedDirectRoute' };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  verifyFederatedRouteBoundaries(readFederatedRouteSources());
  console.log('federated direct-route caller/adapter source wiring is intact (not a semantic proof)');
}
