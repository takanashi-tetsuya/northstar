# SPIRE deployment boundary

This directory documents the production identity boundary without storing
keys or certificates. A deployment must provision a SPIRE server and one
agent per node, configure a trust domain per environment, and register each
Northstar service with selectors that map to its service/region/environment
SPIFFE path.

The application consumes short-lived X.509-SVIDs and the CA bundle through the
SPIRE Workload API. It does not read a static private key from a ConfigMap,
image layer or `.env`. Local Compose may substitute an audited test CA only;
that profile must never be promoted to production.

Before enabling an internal RPC route, verify:

1. the peer SVID trust domain equals the configured environment;
2. the service identity is allowlisted for that method;
3. the SVID and bundle are unexpired;
4. rotation keeps one bounded overlap and then retires the old root; and
5. readiness fails closed if Workload API renewal is unavailable.

Provider-specific server/agent manifests belong in the deployment repository
for the target cluster, not in this source tree.
