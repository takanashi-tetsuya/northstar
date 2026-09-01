# Third-party notices

Northstar's interface, XMPP-over-WebSocket client, state management and OMEMO
orchestration are implemented in this repository and do not use Converse.js.

The cryptographic core under `web/crypto` contains the official browser ESM
artifact from libomemo.js 2.0.2 and its Curve25519 WebAssembly module. They
implement X3DH and Double Ratchet and are licensed under GNU GPL 3.0. The
license is included as `web/crypto/LICENSE-GPL-3.0.txt`. The exact upstream
source is attributed upstream to tag `v2.0.2`, commit
`df3d34cab03306d34d6ed0bf8b3a3db152173bb4`, from
<https://github.com/conversejs/libomemo.js>. A complete source archive, artifact
hashes, official npm-package provenance and build limitations are retained in
`third_party/libomemo.js/README.md` and checked by CI.

The source archive's PAX metadata binds it to the recorded commit, but the
signed tag object, trusted signer record and official npm tarball bytes are not
vendored. The upstream WASM contains no compiler metadata, and the release did
not identify Emscripten/LLVM/Binaryen or the npm executable version. Northstar
therefore classifies 2.0.2 as provenance-traced but not source-reproducible.
The machine-readable qualification manifest and next-version CI gate are
documented in `docs/WEB_CRYPTO_SUPPLY_CHAIN.md`.

OMEMO device-transfer packages use the Argon2id implementation in the official
`hash-wasm` 4.12.0 npm artifact under the MIT license. Northstar retains the
exact npm tarball, its shipped source, license, npm integrity metadata,
CycloneDX SBOM and the byte-identical 29 KiB Argon2-only UMD artifact. Exact
hashes and the upstream `gitHead`
`373b796205ab55fb4a657374dad6ea589bf75815` are recorded in
`third_party/hash-wasm/README.md`. The artifact is provenance-traced but is not
claimed to be source-reproducible; no script or WebAssembly is loaded from a
CDN at runtime.

Northstar-owned code is licensed under AGPL-3.0-only. The cryptographic
component keeps its own GPL-3.0 license; Northstar's AGPL license does not
replace or restrict that component's license. Review both license texts and
the corresponding-source obligations before redistribution or network use.

The read-only API documentation UI vendors the official `swagger-ui-dist`
5.32.14 npm artifact under Apache-2.0. Its exact npm tarball, package metadata,
license, notice, deployed-file hashes and Northstar's no-authorization/no-submit
integration policy are recorded in `third_party/swagger-ui/README.md`. No
Swagger script, stylesheet, validator or other resource is loaded from a CDN.
