# Test listener handoff

Integration fixtures must never treat an available port number as a reservation.
The child Northstar process owns the socket: fixtures configure loopback `:0`
addresses, pass a one-time nonce and an empty readiness-file destination, then
wait for the child to atomically publish its actual addresses.

Several active fixture listeners may request `:0` on the same loopback address.
Each request is a separate kernel allocation rather than an attempt to share a
fixed listener. Fixed bind addresses still fail configuration validation when
they overlap.

The readiness record contains a protocol version, the parent-issued nonce, the
child PID, and a stable map of listener purposes to resolved local addresses.
The parent rejects an absent, malformed, stale, nonce-mismatched, or
PID-mismatched record. This makes a fixture fail with a bounded diagnostic
instead of retrying an already released port forever.

`TEST_LISTENER_ACTIVATION=true` is accepted only when every active listener is
loopback and the XMPP domain is reserved for development (`localhost`,
`*.localhost`, or `*.test`). It is disabled by default and cannot expose a
production listener or accept an inherited socket.

## Privileged fixture endpoint

The XEP-0487 integration fixture is the sole Linux-only exception to
child-owned `:0` allocation. It must prove HTTPS default-port discovery on
`127.0.0.1:443`. `scripts/xep0487-socket-activation.py` therefore performs
only the privileged bind. It passes exactly that listener to a non-root Python
child with `pass_fds`, and keeps its own descriptor open until the child has:

1. verified it received an IPv4 TCP listener on the exact loopback address;
2. adopted it into the TLS HTTP server; and
3. atomically written a new, owner-only acknowledgement containing the
   parent-issued nonce, its PID, effective UID, and listener address.

The supervisor verifies every acknowledgement field and its filesystem
ownership before it releases the root-owned descriptor. It also terminates the
child process group on signal, startup failure, or acknowledgement timeout.
The server product does not implement descriptor activation, and Windows does
not claim equivalent inherited-handle support.

The shared verifier is:

```text
python3 scripts/wait-test-readiness.py <record> <nonce> <child-pid> [timeout-seconds]
```

It prints sorted `purpose=address` records after verification. Fixtures must
preserve their child log, the readiness record, and the verifier output when a
startup, takeover, or cleanup deadline expires.
