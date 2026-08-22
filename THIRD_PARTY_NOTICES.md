# Third-party notices

Northstar's interface, XMPP-over-WebSocket client, state management and OMEMO
orchestration are implemented in this repository and do not use Converse.js.

The cryptographic core under `web/crypto` contains `libomemo.js` and its
Curve25519 WebAssembly module. They implement X3DH and Double Ratchet and are
licensed under GNU GPL 3.0. The license is included as
`web/crypto/LICENSE-GPL-3.0.txt`; corresponding source is available from
<https://github.com/conversejs/libomemo.js>.

The cryptographic component keeps its own license. The MIT license for the
Rust server and Northstar interface does not replace or restrict that license.
