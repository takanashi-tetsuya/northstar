# Northstar threat model

This is the security design authority for changes to protocol, storage,
deployment and operations.  Every security change must reference one or more
threat IDs below and add evidence to the release record.

## Assets and trust boundaries

| Asset | Owner | Confidentiality | Integrity | Retention |
|---|---|---:|---:|---|
| credentials and SCRAM verifiers | Identity | high | high | account lifecycle |
| AuthGrant/SessionAssertion and resume tokens | Identity/Session | high | high | short-lived |
| message ciphertext/plaintext and MAM metadata | Ingress/MAM | high | high | policy/hold |
| roster, presence and room membership | Roster/Presence/MUC | medium | high | policy |
| IP/device/abuse state | Abuse policy | high | high | bounded window |
| administrator commands and audit records | Admin/Audit | high | high | legal hold |
| signing keys and provider secrets | KMS/Identity/Push | critical | critical | key policy |

The boundaries are C2S (TCP/WebSocket/BOSH to XMPP Edge), S2S (TLS/Dialback
to S2S Edge), Admin (loopback/private HTTP), service RPC (mTLS plus signed
assertions), each service's private PostgreSQL schema/role, event transport,
object storage, KMS and cross-region replication.  “Internal network” is not a
trust boundary: every service caller is authenticated and authorized.

## Attacker classes

- A malicious or automated XMPP client, including a slow reader and a NAT-shared
  botnet.
- A compromised Edge or application worker attempting lateral movement.
- A malicious or misconfigured federated domain.
- A dishonest or over-privileged operator or backup job.
- A supply-chain attacker changing generated contracts or web crypto artifacts.

## STRIDE control map

| ID | Threat | Required control | Evidence |
|---|---|---|---|
| T-STRIDE-01 | spoofed service/session identity | mTLS, audience-bound signed assertions, epoch CAS | M03-02 tests; M02 contract adapters |
| T-STRIDE-02 | tampered message/event | canonical input, idempotency, transactional outbox/inbox | ingress and event tests |
| T-STRIDE-03 | repudiation of admin action | append-only audit and correlation/causation IDs | audit/release evidence |
| T-STRIDE-04 | information disclosure | Secret types, redaction, least-privilege DB roles, E2EE policy | security and role-boundary suites |
| T-STRIDE-05 | resource exhaustion | bounded frames, queues, leases, rate/PoW policy and deadlines | parser/load/abuse suites |
| T-STRIDE-06 | privilege escalation | per-service schemas/roles, no cross-service SQL, verified principal only | catalog/architecture validators |

## Residual risk policy

At-least-once transport may repeat an event after a crash; visible effects must
be idempotent.  Web OMEMO still trusts the static-resource publishing chain
until an independently signed client is used.  These are explicit residual
risks, not reasons to weaken authentication or persistence.
