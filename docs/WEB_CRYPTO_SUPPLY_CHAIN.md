# Browser cryptography supply-chain policy

This policy records the origin of bundled browser cryptography, requirements
for reproducible builds, and controls on artifact distribution.

## Current 2.0.2 decision

The vendored `libomemo.js` 2.0.2 source tree, official npm tarball, deployed
JavaScript/WASM hashes, commit-bearing PAX archive metadata and
CycloneDX SBOM are pinned and checked offline. The lockfile supplies integrity
for all 344 registry packages. The npm tarball's recorded SHA-1 and SHA-512
integrity match its retained bytes, and its ESM/WASM match the deployed files.
The retained npm ECDSA signature verifies the distribution SRI with the
registry's published key. The upstream annotated tag's PGP signature verifies
with the retained GitHub-listed maintainer key. These checks make the release
origin reviewable and detect repository drift.

Version 2.0.2 is classified `provenance-traced-not-reproducible`.
Neither the source archive nor its
workflows record npm, Emscripten, LLVM or Binaryen versions. The WASM has no
custom or `producers` section. Independent signer identity and
source-to-package build provenance are absent. The signed tag also differs
from the npm metadata's `gitHead` in the changelog and `chai` development
dependency/lockfile. These gaps prevent verification of the source-to-WASM
build; matching the published tarball is not a source rebuild.

The device-transfer KDF additionally vendors the exact official npm tarball and
deployed UMD artifact for `hash-wasm` 4.12.0, its MIT license, registry
integrity/SHA-1 metadata, historical registry signature, SHA-256 allowlist and
CycloneDX 1.6 SBOM under `third_party/hash-wasm`. CI verifies those bytes and
the ECDSA signature offline. The old registry key is now expired; npm reports
publication before expiry, but that date is not a signed timestamp.
Reproducible source builds remain unavailable because the upstream
compiler/bundler environment is not preserved.

## CI states

The policy has two valid states:

- Exactly version 2.0.2 may retain the explicit provenance-only exception and
  its fixed source/JS/WASM hashes. Compiler fields must stay null.
- A new version must be `reproducible`, contain every offline evidence record,
  use a digest-pinned and offline-signed builder, and pass two clean networkless
  builds against the deployed bytes.

Changing the version, artifact hashes, compiler claims, qualification manifest
or SBOM without satisfying the second state fails CI. The manual
`--require-reproducible` mode intentionally rejects 2.0.2 and is suitable for a
deployment policy that refuses this accepted legacy boundary.

## Rebuild isolation contract

The qualified builder image is preloaded by exact digest; the rebuild runner
will not pull by tag. Its signature bundle and public key are repository-bound
evidence. Containers run with no network, a read-only root, no capabilities,
`no-new-privileges`, bounded PIDs, fixed platform/locale/timezone/build epoch
and fresh output mounts. The only source input is the pinned archive. The
builder must remove generated `build`, `dist` and `node_modules` content before
running the pinned compiler and `npm ci` from an image-local content-addressed
cache.

The runner launches two containers, verifies their reported tool versions and
compares JavaScript and WASM byte-for-byte with each other, the qualification
manifest and deployed files. A mismatch is a release failure; no normalization
or silent replacement is allowed.

## Offline evidence package

A reproducible upgrade must retain:

- source archive and its commit/tag signature material;
- trusted signer fingerprint and the recorded trust decision;
- official npm tarball plus registry attestation;
- exact dependency lock and all package integrity values;
- builder image digest and offline-verifiable signature bundle;
- exact toolchain/platform/environment report and compile arguments;
- both clean-build result hashes;
- CycloneDX SBOM and signed in-toto/SLSA provenance.

Every referenced evidence file is path-safe and SHA-256 bound by the
qualification verifier. Signing and registry trust still depend on the
operator's offline trust roots; a repository author cannot self-assert an
upstream identity merely by editing the manifest.

## Permanent web-client boundary

Even a perfect reproducible build cannot stop the serving origin from sending
different code later. The web server, TLS/CDN, release credentials and update
pipeline remain in the OMEMO trust base. Independent installation/signing and
external transparency can reduce that risk; a verifier, CSP or SRI delivered
by the same potentially malicious origin cannot remove it.

See [the component evidence record](../third_party/libomemo.js/README.md) for
exact hashes and commands.
