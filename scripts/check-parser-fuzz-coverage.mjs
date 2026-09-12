import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const repositoryRoot = path.resolve(path.dirname(scriptPath), "..");

// This manifest deliberately names the production boundary and the entry
// points each fuzz target must execute. A target cannot silently regress into
// testing a hand-written shadow parser while retaining a plausible filename.
const targets = new Map([
  [
    "xml_framing",
    {
      modules: [],
      crates: [["northstar-xml-framing", /\buse\s+northstar_xml_framing\s+as\s+framing\s*;/]],
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
        ["transport_parsing", "../../src/transport_parsing.rs"],
      ],
      crates: [["northstar-xml-framing", /\buse\s+northstar_xml_framing\s+as\s+framing\s*;/]],
      entryPoints: [
        ["production BOSH parser", /\btransport_parsing::parse_bosh_frame\s*\(/],
        ["production WebSocket parser", /\btransport_parsing::take_websocket_frame\s*\(/],
      ],
    },
  ],
  [
    "sasl_sm_state",
    {
      modules: [],
      crates: [
        ["northstar-auth-core", /\buse\s+northstar_auth_core\s*::\s*\{/],
        ["northstar-xep-0198", /\bnorthstar_xep_0198::acknowledgement_delta\s*\(/],
      ],
      entryPoints: [
        ["production SASL mechanism", /\b(?:Plain|External|ScramSha256)Mechanism\b/],
        ["production SM acknowledgement counter", /\bnorthstar_xep_0198::acknowledgement_delta\s*\(/],
      ],
    },
  ],
  [
    "semantic_stanza",
    {
      modules: [
        ["stanza_validation", "../../src/xmpp/stanza_validation.rs"],
      ],
      crates: [
        ["northstar-xml-framing", /\buse\s+northstar_xml_framing\s+as\s+framing\s*;/],
        ["northstar-xmpp-types", /\buse\s+northstar_xmpp_types::jid\s*;/],
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
      modules: [],
      crates: [
        ["northstar-xep-0313", /\bnorthstar_xep_0313::parse_mam_query\s*\(/],
        ["northstar-xep-0060", /\bnorthstar_xep_0060::parse_pubsub_envelope\s*\(/],
      ],
      entryPoints: [
        [
          "production MAM query parser",
          /\bnorthstar_xep_0313::parse_mam_query\s*\(/,
        ],
        [
          "production PubSub envelope parser",
          /\bnorthstar_xep_0060::parse_pubsub_envelope\s*\(/,
        ],
        [
          "production PubSub RSM parser",
          /\bnorthstar_xep_0060::parse_rsm_element\s*\(/,
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

const productionCrates = new Set(
  [...targets.values()].flatMap((requirement) => (requirement.crates ?? []).map(([name]) => name)),
);

function escaped(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function loadParserFuzzModel(root = repositoryRoot) {
  const targetDirectory = path.join(root, "fuzz", "fuzz_targets");
  const sources = new Map(fs.readdirSync(targetDirectory, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".rs"))
    .map((entry) => [entry.name, fs.readFileSync(path.join(targetDirectory, entry.name), "utf8")]));
  const existingPaths = new Set();
  const crateManifests = new Map();
  const productionPaths = [...targets.values()].flatMap((requirement) =>
    requirement.modules.map(([, modulePath]) => path.resolve(targetDirectory, modulePath)));
  for (const name of productionCrates) {
    const directory = path.join(root, "crates", name);
    const manifest = path.join(directory, "Cargo.toml");
    if (fs.existsSync(manifest)) crateManifests.set(name, fs.readFileSync(manifest, "utf8"));
    productionPaths.push(path.join(directory, "src", "lib.rs"));
  }
  for (const file of productionPaths) {
    if (fs.existsSync(file) && fs.statSync(file).isFile()) existingPaths.add(file);
  }
  return {
    root, sources, existingPaths, crateManifests,
    cargoManifest: fs.readFileSync(path.join(root, "fuzz", "Cargo.toml"), "utf8"),
  };
}

export function validateParserFuzzCoverage(model) {
  const { root, cargoManifest, sources, existingPaths, crateManifests } = model;
  const targetDirectory = path.join(root, "fuzz", "fuzz_targets");
  const violations = [];
  const expectedFiles = [...targets.keys()].map((name) => `${name}.rs`).sort();
  const actualFiles = [...sources.keys()].sort();

  if (!/^\s*\[workspace\]\s*$/m.test(cargoManifest)) {
    violations.push("fuzz/Cargo.toml must declare its independent workspace and lockfile boundary");
  }
  const dependencySection = cargoManifest.split(/^\s*\[dependencies\]\s*$/m)[1]?.split(/^\s*\[/m)[0] ?? "";
  for (const name of productionCrates) {
    const declaration = new RegExp(
      `^\\s*${escaped(name)}\\s*=\\s*\\{\\s*path\\s*=\\s*"\\.\\./crates/${escaped(name)}"\\s*\\}\\s*$`, "m",
    );
    if (!declaration.test(dependencySection)) {
      violations.push(`fuzz/Cargo.toml must directly depend on the production crate ../crates/${name}`);
    }
    const manifest = crateManifests.get(name) ?? "";
    if (!new RegExp(`^\\s*name\\s*=\\s*"${escaped(name)}"\\s*$`, "m").test(manifest)
        || !existingPaths.has(path.join(root, "crates", name, "src", "lib.rs"))) {
      violations.push(`${name}: production crate manifest or library is missing`);
    }
  }

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
    if (!sources.has(`${target}.rs`)) continue;
    const source = sources.get(`${target}.rs`);
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

    // Former facades and copied crate source can compile while bypassing the
    // actual production crate graph. Only unextracted adapters may use #[path].
    for (const match of code.matchAll(/#\[\s*path\s*=\s*"([^"]+)"\s*\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;/g)) {
      if (!requirement.modules.some(([name, modulePath]) => name === match[2] && modulePath === match[1])) {
        violations.push(`${relativeFile}: unregistered source include ${match[1]} as ${match[2]}`);
      }
    }
    for (const [name, productionReference] of requirement.crates ?? []) {
      if (!productionReference.test(code)) {
        violations.push(`${relativeFile}: must directly reference production crate ${name}`);
      }
      const namespace = name.replaceAll("-", "_");
      if (new RegExp(`\\bmod\\s+${namespace}\\b|\\bas\\s+${namespace}\\b`).test(code)) {
        violations.push(`${relativeFile}: production crate namespace ${namespace} must not be shadowed`);
      }
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
      if (!resolvedModule.startsWith(sourceRoot) || !existingPaths.has(resolvedModule)) {
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

  return { violations, targetCount: targets.size };
}

if (process.argv[1] && path.resolve(process.argv[1]) === scriptPath) {
  const result = validateParserFuzzCoverage(loadParserFuzzModel());
  if (result.violations.length > 0) {
    throw new Error(
      `parser fuzz targets must execute production parser boundaries directly:\n${result.violations.join("\n")}`,
    );
  }

  console.log(
    `Parser fuzz production-coverage gate passed: ${result.targetCount} targets exercise declared production parsers`,
  );
}
