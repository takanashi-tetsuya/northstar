# M03-04 workload identity checkpoint

The runtime now has a provider-neutral workload identity boundary. It is an
incremental contract, not a claim that SPIRE is already running in every
deployment.

## Delivered

- `TrustDomain` and `SpiffeId` validate a bounded environment/region/service
  identity and render one canonical SPIFFE URI.
- `VerifiedWorkload` carries only verified identity metadata, certificate
  expiry and a non-secret serial; expired credentials fail closed.
- `MtlsPolicy` requires a matching trust domain and optional service
  allowlist. It rejects unknown services and cross-environment peers before
  handler dispatch.
- `deploy/spire/README.md` records the Workload API, rotation overlap and
  no-static-key rule. Provider-specific manifests remain deployment-owned.

## Evidence

```text
cargo test --locked -p foundation-service-runtime --all-targets  # 13 passed
cargo clippy --locked -p foundation-service-runtime --all-targets -- -D warnings
```

Live X.509-SVID acquisition, Tonic TLS channel installation and rotation
chaos tests still depend on the M04 runtime server and M23 platform work.

The next authorization increment will load the same identities from
`catalog/rpc-authorization.yaml`; this checkpoint intentionally keeps the
policy catalog separate from generated Protobuf and from protocol handlers.

The runtime now also exposes `AuthorizationRegistry`: unregistered RPCs are
denied, workload allowlists are checked before user scope/role checks, and an
authorized Tonic request receives only verified workload/principal extensions.
Tests cover confused-deputy, missing-principal and extension-injection paths.
