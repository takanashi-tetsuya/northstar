import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const targetDirectory = path.join(root, "fuzz", "fuzz_targets");
const cargoManifest = fs.readFileSync(path.join(root, "fuzz", "Cargo.toml"), "utf8");

// This manifest deliberately names the production boundary and the entry
// points each fuzz target must execute. A target cannot silently regress into
// testing a hand-written shadow parser while retaining a plausible filename.
const targets = new Map([
  [
    "xml_framing",
    {
      modules: [["framing", "../../src/xmpp/framing.rs"]],
      entryPoints: [
        ["stateful XML entity framer", /\bframing::XmlEntityFramer\b/],
        ["production frame extraction", /\b[A-Za-z_][A-Za-z0-9_]*\.take_frame\s*\(/],
      ],
    },
  ],
  [
    "bosh_ws_framing",
    {
      modules: [
        ["framing", "../../src/xmpp/framing.rs"],
        ["transport_parsing", "../../src/transport_parsing.rs"],
      ],
      entryPoints: [
        ["production BOSH parser", /\btransport_parsing::parse_bosh_frame\s*\(/],
        ["production WebSocket parser", /\btransport_parsing::take_websocket_frame\s*\(/],
      ],
    },
  ],
  [
    "sasl_sm_state",
    {
      modules: [
        ["auth", "../../src/auth.rs"],
        ["sm_counter", "../../src/xmpp/sm_counter.rs"],
      ],
      entryPoints: [
        ["production SASL mechanism", /\b(?:Plain|External|ScramSha256)Mechanism\b/],
        ["production SM acknowledgement counter", /\bsm_counter::acknowledgement_delta\s*\(/],
      ],
    },
  ],
  [
    "semantic_stanza",
    {
      modules: [
        ["framing", "../../src/xmpp/framing.rs"],
        ["stanza_validation", "../../src/xmpp/stanza_validation.rs"],
      ],
      entryPoints: [
        [
          "production frame extraction",
          /\b(?:framing::take_frame|[A-Za-z_][A-Za-z0-9_]*\.take_frame)\s*\(/,
        ],
        [
          "production stanza validator",
          /\bstanza_validation::validate_client_stanza\s*\(/,
        ],
      ],
      forbiddenShadowFunctions: ["exercise_semantics"],
    },
  ],
  [
    "mam_pubsub_parsing",
    {
      modules: [["mam_pubsub_parsing", "../../src/mam_pubsub_parsing.rs"]],
      entryPoints: [
        [
          "production MAM query parser",
          /\bmam_pubsub_parsing::parse_mam_query\s*\(/,
        ],
        [
          "production PubSub envelope parser",
          /\bmam_pubsub_parsing::parse_pubsub_envelope\s*\(/,
        ],
        [
          "production PubSub RSM parser",
          /\bmam_pubsub_parsing::parse_pubsub_rsm\s*\(/,
        ],
      ],
    },
  ],
  [
    "rest_extractors",
    {
      modules: [["extract", "../../src/api/extract.rs"]],
      entryPoints: [
        ["production REST query extractor", /\bextract::ApiQuery\b/],
        ["production REST path extractor", /\bextract::ApiPath\b/],
      ],
    },
  ],
]);

const violations = [];
const expectedFiles = [...targets.keys()].map((name) => `${name}.rs`).sort();
const actualFiles = fs
  .readdirSync(targetDirectory, { withFileTypes: true })
  .filter((entry) => entry.isFile() && entry.name.endsWith(".rs"))
  .map((entry) => entry.name)
  .sort();

for (const missing of expectedFiles.filter((file) => !actualFiles.includes(file))) {
  violations.push(`fuzz/fuzz_targets/${missing}: required parser target is missing`);
}
for (const unregistered of actualFiles.filter((file) => !expectedFiles.includes(file))) {
  violations.push(
    `fuzz/fuzz_targets/${unregistered}: parser target is not registered in the production-coverage gate`,
  );
}

const binSections = cargoManifest.split(/^\s*\[\[bin\]\]\s*$/m).slice(1);
for (const [target, requirement] of targets) {
  const relativeFile = `fuzz/fuzz_targets/${target}.rs`;
  const file = path.join(targetDirectory, `${target}.rs`);
  if (!fs.existsSync(file)) continue;
  const source = fs.readFileSync(file, "utf8");
  const code = source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "");

  const registered = binSections.some(
    (section) =>
      new RegExp(`^\\s*name\\s*=\\s*"${target}"\\s*$`, "m").test(section) &&
      new RegExp(`^\\s*path\\s*=\\s*"fuzz_targets/${target}\\.rs"\\s*$`, "m").test(
        section,
      ),
  );
  if (!registered) {
    violations.push(`${relativeFile}: missing its exact [[bin]] registration in fuzz/Cargo.toml`);
  }

  for (const [moduleName, modulePath] of requirement.modules) {
    const escapedPath = modulePath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const escapedModule = moduleName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const directProductionModule = new RegExp(
      `^\\s*#\\[\\s*path\\s*=\\s*"${escapedPath}"\\s*\\]\\s*(?:pub(?:\\([^)]*\\))?\\s+)?mod\\s+${escapedModule}\\s*;`,
      "m",
    );
    if (!directProductionModule.test(code)) {
      violations.push(
        `${relativeFile}: must directly include production module ${modulePath} as ${moduleName}`,
      );
    }

    const resolvedModule = path.resolve(targetDirectory, modulePath);
    const sourceRoot = `${path.join(root, "src")}${path.sep}`;
    if (!resolvedModule.startsWith(sourceRoot) || !fs.existsSync(resolvedModule)) {
      violations.push(
        `${relativeFile}: declared production module does not resolve below src/: ${modulePath}`,
      );
    }
  }

  for (const [description, pattern] of requirement.entryPoints) {
    if (!pattern.test(code)) {
      violations.push(`${relativeFile}: does not invoke the ${description}`);
    }
  }

  for (const forbidden of requirement.forbiddenShadowFunctions ?? []) {
    const pattern = new RegExp(`^fn\\s+${forbidden}\\b`, "m");
    if (pattern.test(code)) {
      violations.push(
        `${relativeFile}: local shadow parser ${forbidden} must be removed or renamed model_${forbidden}`,
      );
    }
  }

  // Parser-shaped top-level helpers are models, not production coverage. Keep
  // that distinction machine-visible and require a nearby explanation of the
  // differential oracle whenever such a model is intentionally retained.
  const localFunctions = [
    ...source.matchAll(/^(?:pub(?:\([^)]*\))?\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\b/gm),
  ];
  for (const match of localFunctions) {
    const name = match[1];
    if (
      /^(?:parse|validate|extract|decode|frame|scan|tokenize|take)_/.test(name) &&
      !name.startsWith("model_")
    ) {
      violations.push(
        `${relativeFile}: parser-like local function ${name} must use a model_ prefix`,
      );
    }
    if (!name.startsWith("model_")) continue;

    const precedingLines = source.slice(0, match.index).split(/\r?\n/).slice(-5);
    if (!precedingLines.some((line) => /^\s*\/\/[/!]?\s*.*\bdifferential\b/i.test(line))) {
      violations.push(
        `${relativeFile}: ${name} needs a nearby comment explaining its differential purpose`,
      );
    }
  }
}

if (violations.length > 0) {
  throw new Error(
    `parser fuzz targets must execute production parser boundaries directly:\n${violations.join("\n")}`,
  );
}

console.log(
  `Parser fuzz production-coverage gate passed: ${targets.size} targets exercise declared production parsers`,
);
