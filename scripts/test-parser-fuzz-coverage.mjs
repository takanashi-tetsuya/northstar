import assert from "node:assert/strict";
import path from "node:path";

import { loadParserFuzzModel, validateParserFuzzCoverage } from "./check-parser-fuzz-coverage.mjs";

// Mutate an in-memory repository model: no fixture writes, builds, or fuzz
// execution are needed to prove that normal CI rejects stale coverage claims.
const baseline = loadParserFuzzModel();
assert.deepEqual(validateParserFuzzCoverage(baseline), { violations: [], targetCount: 6 });
let rejected = 0;

function rejects(mutate, message) {
  const model = structuredClone(baseline);
  mutate(model);
  assert.match(validateParserFuzzCoverage(model).violations.join("\n"), message);
  rejected += 1;
}

rejects((model) => {
  model.cargoManifest = model.cargoManifest.replace("[workspace]", "# workspace removed");
}, /independent workspace and lockfile boundary/);

rejects((model) => {
  model.cargoManifest = model.cargoManifest.replace(/^northstar-auth-core = .+$/m, "");
}, /must directly depend on the production crate ..\/crates\/northstar-auth-core/);

rejects((model) => {
  model.cargoManifest = model.cargoManifest.replace(
    'path = "../crates/northstar-xep-0198"', 'path = "shadow-stream-management"',
  );
}, /must directly depend on the production crate ..\/crates\/northstar-xep-0198/);

rejects((model) => {
  model.existingPaths.delete(path.join(model.root, "crates", "northstar-xep-0198", "src", "lib.rs"));
}, /northstar-xep-0198: production crate manifest or library is missing/);

rejects((model) => {
  model.crateManifests.set("northstar-xep-0313", '[package]\nname = "shadow-mam"');
}, /northstar-xep-0313: production crate manifest or library is missing/);

rejects((model) => {
  model.existingPaths.delete(path.join(model.root, "src", "transport_parsing.rs"));
}, /declared production module does not resolve below src/);

rejects((model) => {
  model.sources.set("sasl_sm_state.rs", model.sources.get("sasl_sm_state.rs")
    + '\n#[path = "../../src/xmpp/sm_counter.rs"]\nmod sm_counter;\n');
}, /unregistered source include .*sm_counter/);

rejects((model) => {
  model.sources.set("xml_framing.rs", model.sources.get("xml_framing.rs")
    .replace("use northstar_xml_framing as framing;",
      '#[path = "../../src/xmpp/framing.rs"]\nmod framing;'));
}, /must directly reference production crate northstar-xml-framing/);

rejects((model) => {
  model.sources.set("mam_pubsub_parsing.rs", model.sources.get("mam_pubsub_parsing.rs")
    .replace("northstar_xep_0313::parse_mam_query(node)", "model_mam_query(node)")
    + "\n// northstar_xep_0313::parse_mam_query(node) only appears in a comment.\n");
}, /does not invoke the production MAM query parser/);

rejects((model) => {
  model.sources.set("sasl_sm_state.rs", model.sources.get("sasl_sm_state.rs")
    + "\nmod northstar_xep_0198 {}\n");
}, /production crate namespace northstar_xep_0198 must not be shadowed/);

rejects((model) => {
  model.sources.delete("rest_extractors.rs");
}, /rest_extractors.rs: required parser target is missing/);

rejects((model) => {
  model.cargoManifest = model.cargoManifest.replace('name = "rest_extractors"', 'name = "unused"');
}, /rest_extractors.rs: missing its exact \[\[bin\]\] registration/);

rejects((model) => {
  model.sources.set("shadow_parser.rs", "#![no_main]");
}, /shadow_parser.rs: parser target is not registered/);

rejects((model) => {
  model.sources.set("semantic_stanza.rs", model.sources.get("semantic_stanza.rs")
    + "\nfn parse_stanza() {}\n");
}, /parser-like local function parse_stanza must use a model_ prefix/);

rejects((model) => {
  model.sources.set("semantic_stanza.rs", model.sources.get("semantic_stanza.rs")
    + "\nfn model_parse_stanza() {}\n");
}, /model_parse_stanza needs a nearby comment explaining its differential purpose/);

console.log(`Parser fuzz coverage regression checks passed: ${rejected} invalid coverage models rejected`);
