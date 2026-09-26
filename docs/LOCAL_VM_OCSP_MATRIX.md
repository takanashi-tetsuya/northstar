# Local VM OCSP acceptance matrix

Run this drill only after the current VM soak has finished. It tests the
operator-supplied staple and the opt-in outbound S2S PKIX policy without using
a public network. The existing loopback tests in `scripts/test-ocsp-stapling.sh`
cover parser and handshake behavior; they are not VM interoperability evidence.

The lab's Prosody and ejabberd configurations do not provide OCSP staples.
Use a separate OpenSSL peer on the isolated `192.168.197.0/24` network for the
strict outbound matrix. It speaks Direct TLS, so STARTTLS interoperability
remains a separate test.

## Prepare the peer

After the soak, generate a fresh private fixture directory:

```sh
bash scripts/test-ocsp-stapling.sh --fixtures-only \
  target/qualification/ocsp-peer-fresh ocsp-peer.lab.test
```

This mode needs Python `cryptography` to sign an already-expired response; the
normal CI test path does not. The output directory is mode 0700 and its only
retained private key, `leaf.key`, is mode 0600. CA private keys are removed.
`manifest.json` records the OpenSSL and cryptography versions, certificate
fingerprints, and public response hashes. Check `SHA256SUMS` before copying the
public files and the peer leaf key to the isolated VM. Save the independent
fixture preflight result with the staging evidence:

```sh
python3 scripts/verify-ocsp-fixture.py target/qualification/ocsp-peer-fresh \
  > target/qualification/ocsp-fixture-preflight.json
```

The fixture generator runs this preflight itself; repeat it when staging to
record the exact inputs. It checks signatures, certificate IDs, response
statuses and update times without a network request. In particular,
`wrong-issuer.der` is a signed **good** status for the right leaf under the
unrelated issuer, so that case isolates issuer binding. The JSON proves only
what the fixture contains; record the Northstar handshake and peer logs
separately for each VM row. A fresh `good.der` expires after one day, so
regenerate the fixture if the drill is delayed.

Stage the files in a private directory, then install them as the user running
the peer:

```sh
install -d -m 700 "$HOME/ocsp-fixture"
install -m 600 STAGED/leaf.key "$HOME/ocsp-fixture/leaf.key"
install -m 600 STAGED/*.crt STAGED/*.der STAGED/SHA256SUMS "$HOME/ocsp-fixture/"
```

Replace `STAGED` with the private staging directory. The peer refuses a
symlinked or non-0700 fixture directory and a non-0600 private key. Never copy
a CA key.

The fixture CA differs from the lab CA. Add only its **public certificate** to
a temporary federation trust bundle on the Northstar candidate; otherwise
even `good.der` will fail ordinary PKIX. Add an A record and a
`_xmpps-server._tcp.ocsp-peer.lab.test` SRV record pointing to the peer's
isolated address and port. Use a disposable candidate configuration with these
explicit settings:

```text
FEDERATION_ALLOWLIST=ocsp-peer.lab.test
FEDERATION_DENYLIST=
FEDERATION_ALLOW_PRIVATE_IPS=true
FEDERATION_DNS_OVERRIDES=
FEDERATION_DANE_MODE=off
FEDERATION_EXTRA_ROOT_CERT_PATH=/path/to/private-lab-trust-bundle.pem
FEDERATION_OCSP_STAPLE_REQUIRED=true
```

The trust bundle contains the fixture's `root.crt` and any lab roots still
needed for this candidate. Do not use an address override or add a DANE-EE
TLSA record to this PKIX test:
DANE-EE uses a separate DNSSEC trust path in the verifier. Restore the prior
allowlist, private-address policy, trust bundle and DANE/OCSP settings after
the drill.

For each row below, start one peer instance, make one fresh S2S dial, then
record the handshake decision and close the instance. For example:

```sh
bash scripts/local-vm-lab-ocsp-peer.sh FIXTURE_DIR 192.168.197.X 5270 1.3 good
```

The peer serves one connection, includes the issuer certificate, and offers
`xmpp-server` ALPN. Run every case under both TLS 1.2 and TLS 1.3. Do not
reuse a live S2S connection or queued retry as evidence for a new row.

| Staple | Strict outbound result | What it isolates |
| --- | --- | --- |
| `good.der` | TLS accepted; XMPP stream begins | Fresh signed good status for this leaf |
| `revoked.der` | Reject | Explicit revoked status |
| `stale.der` | Reject | Signed good status with expired `nextUpdate` |
| `missing` | Reject | No staple returned |
| `wrong-leaf.der` | Reject | Status belongs to another leaf |
| `wrong-issuer.der` | Reject | Signed good status for this leaf under an unrelated issuer |

With strict OCSP disabled, the `missing` case should reach XMPP; that control
rules out a broken route or certificate chain. With strict OCSP enabled, a
matching SPKI pin must not bypass PKIX or staple rejection. If the six rows
pass, also reject the generated bad-signature, unknown-status, no-next-update,
and overlong-validity responses.

For Northstar as the **stapling server**, create a response for its actual lab
leaf using the lab CA after the soak. Point a disposable candidate instance's
`TLS_OCSP_RESPONSE_PATH` at it. Use independent `openssl s_client -status` on
both TLS versions against direct C2S and direct S2S; compare the returned DER
and exact leaf/issuer fingerprints. Bad or revoked reloads must leave the old
TLS snapshot active, while a missing configured response must fail closed.

Keep the exact candidate binary hash, peer version, DNS answer, certificate
fingerprints, response SHA-256, TLS version, Northstar decision and peer log in
private evidence. Restore DNS, trust bundle and service configuration. Remove
the private fixture directory when finished; retain only public fingerprints
and observations. Neither the OpenSSL peer nor the current peer setup proves
Prosody/ejabberd stapling or XMPP STARTTLS interoperability.
