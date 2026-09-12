# Abuse cases and mitigations

| ID | Abuse case | Mitigation and failure decision | Test/evidence |
|---|---|---|---|
| AB-01 | registration burst or token farming | IP/account/device limits, invitation token policy, bounded PoW; fail closed | abuse policy properties |
| AB-02 | message spam/replay | admission identity and idempotency conflict; quadratic PoW escalation with cooldown | ingress and abuse tests |
| AB-03 | slow-reader queue exhaustion | ordered bounded output, durable recovery projection, disconnect on unrecoverable backpressure | delivery/SM integration |
| AB-04 | shared-NAT collateral damage | actor dimensions are separately sharded; IP pressure does not serialize all accounts | shared-NAT property test |
| AB-05 | forged service assertion | mTLS plus audience/key/epoch/signature verification; no “internal network” bypass | keyring tests |
| AB-06 | malicious federation peer | domain-bound TLS/Dialback, per-domain circuit breaker, bounded outbox and DLQ | federation suite |
| AB-07 | admin abuse or appeal flooding | separate admin listener, role checks, audit, stricter appeal rate/PoW and cooldown | admin/abuse evidence |
| AB-08 | contract/supply-chain tampering | Buf breaking/drift gates, signed descriptors/artifacts, generated-source review | contracts workflow |

Mitigation escalation is reversible and cools down stepwise.  A hard wait is
inserted before the maximum computational challenge so an attacker cannot
simply buy unlimited parallel CPU.  Maximum work is bounded for usability and
is never used as a substitute for account or network rate limits.
