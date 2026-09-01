# libomemo.js 2.0.2 provenance and rebuild qualification

Northstar deploys the official browser ESM and Curve25519 WebAssembly files
attributed to `libomemo.js` 2.0.2. The upstream project is GPL-3.0 and names
tag `v2.0.2` and commit
`df3d34cab03306d34d6ed0bf8b3a3db152173bb4`.

This directory separates two claims which must not be conflated:

1. **Artifact provenance is traced and repository drift is detected.**
2. **The official 2.0.2 JavaScript/WASM is not qualified as a reproducible
   source build.**

The second claim remains false until the fail-closed requirements below are
met. A prebuilt WASM copied into a source archive is not a source rebuild.

## Evidence that is available

`libomemo.js-v2.0.2-source.tar.gz` contains 183 regular files. Its SHA-256 is
`952172631c2e16085420779b3ea039ce59a2ac0b1b20255ff16d1941d4226343`.
The archive's global PAX `comment` is the exact commit above, which binds the
exported tree to that commit identifier without executing archive content.
It does **not** prove that the tag signature was valid: the signed tag object,
detached signature, signer fingerprint and trust decision are not present.

The source tree records:

- `.nvmrc`: Node `v24.14.0`;
- npm lockfile format 3 with 344 registry packages, all carrying integrity
  values and no non-registry resolved package;
- Rollup `4.62.2`, esbuild `0.28.1`, TypeScript `6.0.3` and protobufjs
  `8.6.4` as exact resolved versions;
- the complete native C sources, `scripts/compile.js`, Rollup configuration,
  compile flags and generated build files.

The deployed hashes are:

| File | SHA-256 |
| --- | --- |
| `web/crypto/libomemo.js` | `29848fa0791bc07f6982e7e86a5261a3226518f581aba268ec8b030a11e30385` |
| `web/crypto/curve25519_compiled.wasm` | `3a32503ade92ed2bf522d49d51106a227dadb39c2a7b08a1023c216c7eec1286` |

The source archive's prebuilt `build/curve25519_compiled.wasm` is
byte-identical to the deployed WASM. The official npm distribution is
recorded as URL
`https://registry.npmjs.org/libomemo.js/-/libomemo.js-2.0.2.tgz`, registry
SHA-1 `6029b4a76dda80a7e7a9ebed89a5f2943aa7527f`. No trustworthy SHA-256
is asserted: the npm tarball bytes and registry attestation are not vendored,
so a stronger distribution digest cannot currently be re-verified from this
repository alone.

`SBOM.cdx.json` is CycloneDX 1.6 and binds the deployed hashes, source archive,
commit, npm distribution and `rebuild-qualification.json`.

## Evidence that is missing

The archive and upstream workflows do not identify the npm executable,
Emscripten, LLVM or Binaryen versions. They do not pin a compiler container or
system packages. The WASM has no custom sections at all, including no
`producers` section from which a compiler version could be recovered. The C
compile command uses shell globs, while the release platform, locale, timezone
and glob ordering are unrecorded. There is no pair of independent clean
builds, signed in-toto/SLSA provenance, signed tag object or offline npm
attestation.

Accordingly the exact Emscripten version must remain `null` in
`rebuild-qualification.json`. Guessing a plausible version, treating the
archive's prebuilt WASM as compiler output, or relabeling hash comparison as a
source rebuild is prohibited.

## Offline checks and fail-closed behavior

Run:

```sh
node scripts/audit-libomemo-source.mjs
node scripts/verify-libomemo-rebuild-qualification.mjs --self-test
node scripts/verify-crypto-artifacts.mjs
```

The audit parser verifies tar header checksums, rejects unsafe/duplicate paths,
reads the PAX commit, audits lockfile integrity and parses WASM sections without
executing upstream JavaScript. The qualification verifier binds all facts to
the SBOM and deployed bytes. Its self-test proves that a new version or guessed
compiler cannot reuse the 2.0.2 exception.

The stronger command deliberately fails for the current release:

```sh
node scripts/verify-libomemo-rebuild-qualification.mjs --require-reproducible
```

That failure is expected evidence, not a CI defect. CI permits only the exact
2.0.2 provenance-only exception. Any different component version must use
status `reproducible` and satisfy every evidence field; otherwise verification
fails closed.

## Contract for a future qualified upgrade

A future release must provide a builder OCI image referenced by immutable
`name@sha256:<digest>`, an offline-verifiable signature bundle/key, exact
Node/npm/Emscripten/LLVM/Binaryen versions, platform, locale, timezone and
`SOURCE_DATE_EPOCH`. The source archive, official npm tarball, tag signature,
signer trust record, registry attestation, SBOM and in-toto/SLSA provenance must
be committed with SHA-256 bindings.

The builder receives only the source archive and an empty output directory. It
must delete archive-supplied `build`, `dist` and `node_modules` before compiling
and must operate without a network. `scripts/rebuild-libomemo-hermetic.mjs`
uses the preloaded digest-pinned image with `--pull=never`, `--network=none`, a
read-only root, dropped capabilities and two fresh output directories. It
checks the image signature offline, verifies the toolchain report, performs
two independent builds and requires byte equality between both builds, the
manifest and the deployed JS/WASM.

No Dockerfile is supplied for 2.0.2 because no defensible compiler-image digest
or Emscripten version can be derived from the available evidence. Adding a
mutable `FROM` merely to make this checklist look complete is forbidden.

## Browser distribution trust boundary

Reproducible artifacts reduce accidental or build-system compromise. They do
not make a dynamically served web client independent from its distributor.
The same-origin server, TLS/CDN, release account and update path can replace
HTML, JavaScript, WASM or the verifier on a future load. High-risk deployments
need an independently installed/signed client and external transparency or
release verification; CSP, SRI and hash manifests alone cannot eliminate this
boundary when their verifier is delivered by the same server.
