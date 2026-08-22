# Architecture and security model

## Single-node layout

One Tokio process serves:

- XMPP client-to-server on TCP 5222 with mandatory STARTTLS;
- XMPP server-to-server on TCP 5269 with STARTTLS and SASL EXTERNAL;
- XMPP over WebSocket at `/xmpp-websocket`;
- versioned REST endpoints under `/api/v1`;
- the standalone user client and administration interface;
- readiness, liveness, Prometheus text metrics and rolling text or structured JSON logs.

PostgreSQL is the durable system of record for accounts, rosters, blocklists, archives, offline messages, PEP, vCards, rooms, upload slots, push registrations and audit events. Uploaded file bytes use an asynchronous storage interface whose current implementation writes atomically to local disk. Session, room-occupant and configurable Stream Management resumption state is intentionally in memory for the requested single-node deployment.

The design target is 1,000 simultaneous authenticated WebSocket sessions on one process. The included load fixture creates 1,000 real resources, checks the active-session metric and sends sample XMPP pings; it must be repeated on the production hardware before treating the target as a capacity guarantee. A multi-node design would require a distributed session/presence bus and shared object storage.

Bare-JID messages select the available resource with the highest non-negative RFC 6121 priority. Other resources that enabled Message Carbons receive the corresponding copy. Durable block entries are checked before delivery, archive or offline queueing.

## Federation

Outbound domains are resolved using `_xmpp-server._tcp` SRV records, then direct port 5269 fallback. Incoming and outgoing streams require STARTTLS. The peer proves possession of its certificate key during TLS, the chain is validated against public roots plus an optional operator root, the asserted DNS domain is validated, and only then is SASL EXTERNAL accepted. No stanza is accepted before domain authentication.

The resolver rejects private and special-use targets by default to reduce SSRF risk. Allow/deny domain patterns and explicit DNS overrides support controlled deployments and tests. Current delivery maintains a bounded outbound worker/connection per remote domain. Durable retry spooling, Server Dialback and federated MUC are not implemented.

## Message and file confidentiality

End-to-end confidentiality is a client property: if the server receives plaintext, the server can inspect it. Northstar’s browser client therefore implements OMEMO 2 with Stanza Content Encryption:

1. Each browser profile creates and retains private identity, signed-prekey, one-time-prekey and session material in IndexedDB.
2. Only public device lists and bundles are published through PEP.
3. A sender encrypts separately for the recipient’s devices and its own other devices before sending.
4. For group chat, the content key is wrapped for the devices of currently present participants. A member added later cannot decrypt messages sent before their device was included.
5. The server stores only the OMEMO envelope. It removes sibling body, subject, XHTML and other client-authored plaintext and may add a generic encrypted-message fallback.
6. Recipient devices retrieve ciphertext and decrypt locally.

With `REQUIRE_ENCRYPTED_ARCHIVE=true`, plaintext can be routed while both parties are online but is never written to MAM, offline storage or MUC history. Offline plaintext is rejected. This protects stored history; it does not hide live plaintext that a non-OMEMO client chooses to send.

Files are encrypted in the browser with a random AES-GCM key before upload. The HTTP service stores only ciphertext. The URL, key, IV, original name, content type and size are carried inside the OMEMO/SCE payload, so the server cannot reconstruct the file. Anyone with the opaque GET URL can fetch the ciphertext, consistent with XEP-0363; only devices receiving the encrypted metadata can decrypt it.

OMEMO still exposes delivery metadata such as JIDs, timestamps, online state, device IDs and approximate sizes. Users must verify fingerprints and plan key backup/recovery. Losing every private device key makes corresponding history unrecoverable.

## Trust boundaries

- Passwords use salted Argon2id hashes, with password work bounded by a semaphore.
- SASL PLAIN is advertised only after TCP TLS; production WebSocket access must use HTTPS/WSS.
- REST bearer tokens are random and only SHA-256 digests are stored.
- Administrator actions are audit logged.
- API responses never expose password hashes or OMEMO private keys.
- TLS private keys are mounted read-only in the container deployment.
- File PUT slots are expiring, one-use and exact-length/type checked.
- Push summaries contain a count only, not message bodies, ciphertext or sender JIDs.

## Recovery and operational boundaries

Stream Management resumption survives a transport break for `SM_RESUME_TIMEOUT_SECONDS` but not a server restart. MUC occupancy is removed when the transport drops and is not restored by session resumption. Durable encrypted messages remain recoverable through offline delivery and MAM. PostgreSQL and the upload directory must be backed up together; the server cannot recover users’ browser-held OMEMO private keys.

See `XEP_MATRIX.md` for protocol boundaries and `scripts/` for static, integration, federation and 1,000-session verification fixtures.
