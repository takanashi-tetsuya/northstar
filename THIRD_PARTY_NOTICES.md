# Third-party notices

Northstar-owned code is licensed under [AGPL-3.0-only](LICENSE).
Bundled third-party components retain their respective licenses, listed below.

## libomemo.js 2.0.2 — GPL-3.0

The browser client uses the official libomemo.js 2.0.2 ESM artifact and its
Curve25519 WebAssembly module for X3DH and Double Ratchet. The upstream source
is [conversejs/libomemo.js](https://github.com/conversejs/libomemo.js), tag
`v2.0.2`, commit `df3d34cab03306d34d6ed0bf8b3a3db152173bb4`.

The [license](web/crypto/LICENSE-GPL-3.0.txt), source archive, artifact hashes
and provenance records are retained in the repository. See the
[component record](https://github.com/takanashi-tetsuya/northstar/blob/v0.2.1/third_party/libomemo.js/README.md) for corresponding source
and build limitations.

## hash-wasm 4.12.0 — MIT

OMEMO device-transfer packages use the Argon2id implementation from the official
`hash-wasm` 4.12.0 npm artifact, upstream commit
`373b796205ab55fb4a657374dad6ea589bf75815`. The
[component record](https://github.com/takanashi-tetsuya/northstar/blob/v0.2.1/third_party/hash-wasm/README.md) includes the npm tarball,
shipped source, license, integrity metadata, SBOM and deployed-artifact hashes.

Both cryptographic components have pinned provenance. Reproducible builds from
source remain unavailable because their upstream build environments are
incomplete. See the [browser cryptography supply-chain policy](https://github.com/takanashi-tetsuya/northstar/blob/v0.2.1/docs/WEB_CRYPTO_SUPPLY_CHAIN.md).

## Swagger UI 5.32.14 — Apache-2.0

The read-only API documentation uses the official `swagger-ui-dist` npm
artifact. The [component record](https://github.com/takanashi-tetsuya/northstar/blob/v0.2.1/third_party/swagger-ui/README.md) includes its
license, notice, npm tarball, package metadata and deployed-file hashes.
Northstar disables authorization and request submission in this UI.

All bundled browser resources are served locally.
