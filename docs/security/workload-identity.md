# Workload identity and mTLS boundary

Internal RPC trust is based on a short-lived workload identity, not on a
private network address. The runtime models a SPIFFE ID as:

```text
spiffe://<trust-domain>/service/<environment>/<region>/<service>
```

`TrustDomain`, `SpiffeId` and `VerifiedWorkload` in
`foundation-service-runtime` validate bounded ASCII path segments and a
certificate expiry. A peer outside the trust domain, an expired SVID, or an
unrecognised service is rejected before an RPC handler is called.

## Provider boundary

SPIRE (or another conforming workload identity provider) owns X.509-SVID
issuance, CA bundle distribution and rotation. `foundation-service-runtime`
owns only the acceptance policy. It does not parse private keys, generate
long-lived certificates, or treat Docker/Kubernetes network reachability as
authentication.

`MtlsPolicy` expresses the trust domain, whether client authentication is
required, and the allowlisted service identities for a listener. Generated
Tonic services must install this policy on both server and client channels;
the eventual transport adapter is responsible for obtaining the current SVID
and rebuilding a channel when the bundle rotates.

## Local and production profiles

- Development Compose may use a locally generated CA and a test trust domain.
  The identity and certificate metadata must still pass the same policy.
- Production must use SPIRE/SVID or an equivalent external CA/KMS integration.
  Static PEM keys or certificates committed to the repository are prohibited.
- Rotation is overlap-based: obtain the replacement bundle, accept old and
  new roots only for the bounded overlap, then retire the old root. A failed
  renewal changes readiness to false instead of silently accepting an expired
  peer.

The provider-neutral policy is implemented and unit-tested; the deployment
adapter and live certificate-rotation evidence remain part of the later
runtime/Kubernetes milestones.
