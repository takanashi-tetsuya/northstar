# Third-party notices

Northstar's interface, XMPP-over-WebSocket client, state management and OMEMO
orchestration are implemented in this repository and do not use Converse.js.

The cryptographic core under `web/crypto` contains `libomemo.js` and its
Curve25519 WebAssembly module. They implement X3DH and Double Ratchet and are
licensed under GNU GPL 3.0. The license is included as
`web/crypto/LICENSE-GPL-3.0.txt`; corresponding source is available from
<https://github.com/conversejs/libomemo.js>.

Northstar-owned code is licensed under AGPL-3.0-only. The cryptographic
component keeps its own GPL-3.0 license; Northstar's AGPL license does not
replace or restrict that component's license. Review both license texts and
the corresponding-source obligations before redistribution or network use.
