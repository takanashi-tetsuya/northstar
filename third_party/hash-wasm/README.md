# hash-wasm 4.12.0 provenance

Northstar vendors only the Argon2 UMD browser artifact from `hash-wasm`
4.12.0. It is used to derive an AES-256-GCM key from an independent OMEMO
device-transfer passphrase. The passphrase, derived key and decrypted package
never leave the browser.

Upstream release metadata recorded from the npm registry:

- package: `hash-wasm@4.12.0`
- repository: <https://github.com/Daninet/hash-wasm>
- npm `gitHead`: `373b796205ab55fb4a657374dad6ea589bf75815`
- tarball: `https://registry.npmjs.org/hash-wasm/-/hash-wasm-4.12.0.tgz`
- npm SHA-1: `f9f1a9f9121e027a9acbf6db5d59452ace1ef9bb`
- npm integrity: `sha512-+/2B2rYLb48I/evdOIhP+K/DD2ca2fgBjp6O+GBEnCDk2e4rpeXIK8GvIyRPjTezgmWn9gmKwkQjjx6BtqDHVQ==`
- npm registry signature: `npm-registry-signature-4.12.0.json`
- registry-reported publication: 2024-11-19 19:01:58 UTC, before the signing
  key's 2025-01-29 expiry
- license: MIT, retained in `LICENSE`

Repository allow-list hashes:

| File | SHA-256 |
| --- | --- |
| `hash-wasm-4.12.0.tgz` | `1db32a125fb46177932ec8ac438d3cd8214ebdfaccb5d6611b657d88eb586f92` |
| `../../web/crypto/hash-wasm-argon2.umd.min.js` | `dcec617a2e1b700fa132d1583a186cb70611113395e869f2dd6cc82b415d3094` |
| `LICENSE` | `c14dea172f72f2714284a0ac2ab1b00b5352a01409d58255a46227ffc541debd` |

The retained npm tarball contains the TypeScript wrapper and C source shipped
by upstream, including `lib/argon2.ts` and `src/argon2.c`. The deployed UMD
file is copied byte-for-byte from `dist/argon2.umd.min.js` in that tarball and
contains the Argon2 WebAssembly bytes inline; no CDN or runtime network fetch
is used.

This record establishes exact npm provenance and repository drift detection.
Run `node scripts/check-hash-wasm-provenance.mjs --self-test` from the repository
root to verify the vendored tarball against the pinned historical npm registry
ECDSA key and confirm that the deployed Argon2 file matches the tarball. The
key expired on 2025-01-29. The signature verifies cryptographically, and npm's
packument reports publication while that key was valid. The reported date is
unsigned registry metadata, not a trusted signing timestamp; this record does
not assert current key validity. See npm's
[registry signature format](https://docs.npmjs.com/about-registry-signatures/).

It does **not** establish a source-reproducible build. The npm package includes
`lib/argon2.ts` and `src/argon2.c`, but `lib/argon2.ts` imports
`../wasm/argon2.wasm.json`, which the package does not contain. Its `build`
script invokes `./scripts/build.sh`, also absent from the package. There is no
dependency lockfile. The retained tarball therefore cannot serve as a complete
source-build input, and it has no signed build attestation linking its source
to the published minified JavaScript and embedded WebAssembly. These absences
can be checked offline with
`tar -tzf third_party/hash-wasm/hash-wasm-4.12.0.tgz` and the imports and
scripts in the packaged `lib/argon2.ts` and `package.json`.

`node scripts/check-hash-wasm-provenance.mjs --require-reproducible` deliberately
fails after verifying the npm signature and deployed bytes. A future upgrade
needs a pinned complete source tree, its lockfile, a digest-pinned networkless
toolchain, and two independent clean builds matching the shipped bytes before
Northstar can make the stronger claim.
