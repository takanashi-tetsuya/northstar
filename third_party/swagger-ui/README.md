# Swagger UI provenance and deployment policy

Northstar vendors `swagger-ui-dist` **5.32.14** from the official npm
registry. The upstream project is Apache-2.0 licensed. The npm release records
Git commit `6e8ce248db64190e4113676aba996943c56f2491`, registry SHA-1
`bb3a3e738bf17bc2ee2640a711fcc44be76fde4c`, and SRI value
`sha512-nOA2pSQhcmODMUQZpJHYKNuwniDUqcOWGNaSCOoZv12FdOSJ9JxV95HtyRGNMqEBj6h6lCNTy20TgZDYTSuUIg==`.
The exact npm tarball is retained as `swagger-ui-dist-5.32.14.tgz`; its SHA-256
is `609702d791d8d3cdcbc3a52632f6be2f9b743eadf6ba49ca9737dac2a6e0b2a3`.

Only the CSS, browser bundle, bundle notice and favicons under `dist/` are
served. `northstar-swagger-initializer.js` is Northstar-owned integration code,
not an upstream artifact. It fixes the OpenAPI URL to the same origin,
disables every submit method and both authorization controls, disables
credential persistence, and disables the external validator. The API docs are
therefore read-only even for an authenticated administrator. This is a
deliberate production policy: copy examples into a separately controlled API
client when a mutation must be tested.

Run `node scripts/verify-swagger-ui-artifacts.mjs` before release. Upgrades must
replace the tarball and every deployed upstream byte together, update the
versioned HTTP asset prefix, hashes, license notice and this file in one
review. Do not load any Swagger resource from a CDN.
