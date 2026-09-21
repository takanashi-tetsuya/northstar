"""Exercise WebAuthn over HTTP and use its returned credential over real XMPP."""

import base64
import hashlib
import hmac
from http.client import HTTPConnection
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.parse
import uuid


def run(wire):
    check = wire.check
    username = "passkey_wire"
    status, _ = wire.register_account(username, wire.PASSWORD)
    check(status == 201, "Passkey fixture account creation failed")
    origin = wire.PUBLIC_URL.rstrip("/")
    rp = urllib.parse.urlsplit(origin).hostname

    def http(path, payload, token=None, request_origin=origin):
        headers = {"Content-Type": "application/json", "Origin": request_origin}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        connection = HTTPConnection(wire.HTTP_HOST, wire.HTTP_PORT, timeout=10)
        connection.request("POST", path, json.dumps(payload), headers)
        response = connection.getresponse()
        result = json.loads(response.read())
        connection.close()
        return response.status, result

    def guarded(path, body, token=None):
        status, challenge = wire.api("POST", "/api/v1/anti-abuse/challenge", {
            "action": "login", "username": username,
            "intent": wire.pow_intent("POST", path, body),
        })
        check(status == 200, "Passkey login challenge could not be issued")
        requirement = challenge["requirement"]
        wait = max(requirement["hard_wait_seconds"], requirement["retry_after_seconds"])
        if wait:
            time.sleep(wait + 0.05)
        proof = {"challenge_id": challenge["challenge_id"],
                 "nonce": wire.solve_pow_prefix(challenge["prefix"], requirement["work_factor"])}
        return http(path, {**body, "pow": proof}, token)

    status, session = guarded("/api/v1/login", {"username": username, "password": wire.PASSWORD})
    check(status == 200, "Passkey fixture password login failed")
    bearer = session["token"]
    start_path = "/api/v1/me/passkeys/register/start"
    status, _ = http(start_path, {"password": wire.PASSWORD, "label": "Test key"}, bearer, "https://untrusted.invalid")
    check(status == 403, "Passkey enrollment accepted an unrelated HTTP Origin")
    status, ceremony = guarded(start_path, {"password": wire.PASSWORD, "label": "Test key"}, bearer)
    check(status == 200, "Passkey enrollment could not start")

    def b64(value):
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    def client_data(kind, challenge, claimed_origin=origin):
        return json.dumps({"type": kind, "challenge": challenge, "origin": claimed_origin,
                           "crossOrigin": False}, separators=(",", ":")).encode()

    def auth_data(flags, counter):
        return hashlib.sha256(rp.encode()).digest() + bytes([flags]) + counter.to_bytes(4, "big")

    with tempfile.TemporaryDirectory(prefix="northstar-passkey-") as directory:
        key_path = str(Path(directory) / "key.pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key_path], check=True, capture_output=True)
        public = subprocess.run(["openssl", "pkey", "-in", key_path, "-pubout", "-outform", "DER"], check=True, capture_output=True).stdout[-65:]
        check(len(public) == 65 and public[0] == 4, "invalid fixture EC public key")
        credential_id = hashlib.sha256(public).digest()
        cose = bytes.fromhex("a5010203262001215820") + public[1:33] + bytes.fromhex("225820") + public[33:]
        data = auth_data(0x45, 0) + bytes(16) + len(credential_id).to_bytes(2, "big") + credential_id + cose
        attestation = b"\xa3\x63fmt\x64none\x68authData\x58" + bytes([len(data)]) + data + b"\x67attStmt\xa0"
        registration = {"id": b64(credential_id), "rawId": b64(credential_id), "type": "public-key", "extensions": {},
                        "response": {"attestationObject": b64(attestation), "transports": ["internal"],
                                     "clientDataJSON": b64(client_data("webauthn.create", ceremony["options"]["publicKey"]["challenge"]))}}
        submitted = {"challenge_id": ceremony["challenge_id"], "credential": registration}
        status, registered = http("/api/v1/me/passkeys/register/finish", submitted, bearer)
        check(status == 200, "Passkey signature registration failed")
        status, _ = http("/api/v1/me/passkeys/register/finish", submitted, bearer)
        check(status == 401, "Passkey registration challenge was reusable")
        status, listing = wire.api("GET", "/api/v1/me/passkeys", token=bearer)
        check(status == 200 and len(listing["passkeys"]) == 1, "registered Passkey was absent")
        check("credential" not in listing["passkeys"][0], "Passkey metadata exposed verifier state")

        device = str(uuid.uuid4())
        status, ceremony = guarded("/api/v1/passkeys/login/start", {"username": username, "device_id": device})
        check(status == 200, "Passkey authentication could not start")
        client = client_data("webauthn.get", ceremony["options"]["publicKey"]["challenge"])
        data = auth_data(5, 1)
        signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key_path],
                                   input=data + hashlib.sha256(client).digest(), check=True, capture_output=True).stdout
        assertion = {"id": b64(credential_id), "rawId": b64(credential_id), "type": "public-key", "extensions": {},
                     "response": {"authenticatorData": b64(data), "clientDataJSON": b64(client), "signature": b64(signature), "userHandle": None}}
        submitted = {"challenge_id": ceremony["challenge_id"], "credential": assertion}
        status, logged_in = http("/api/v1/passkeys/login/finish", submitted)
        check(status == 200 and logged_in["device_id"] == device, "Passkey login failed")
        status, _ = http("/api/v1/passkeys/login/finish", submitted)
        check(status == 401, "Passkey assertion was replayable")
        check(wire.api("GET", "/api/v1/me", token=logged_in["token"])[0] == 200, "Passkey API session is unusable")

        secure = wire.open_starttls_stream(stream_from=f"{username}@{wire.DOMAIN}")
        fast = logged_in["fast"]["token"]
        initial = base64.b64encode(username.encode() + b"\0" + hmac.new(fast.encode(), b"Initiator", hashlib.sha256).digest()).decode()
        secure.sendall(("<authenticate xmlns='urn:xmpp:sasl:2' mechanism='HT-SHA-256-NONE'>"
                        f"<initial-response>{initial}</initial-response><user-agent id='{device}'><software>Northstar integration</software></user-agent>"
                        "<fast xmlns='urn:xmpp:fast:0' count='1'/><bind xmlns='urn:xmpp:bind:0'><tag>Passkey</tag></bind></authenticate>").encode())
        result = bytearray()
        while b"</success>" not in result:
            chunk = secure.recv(8192)
            check(bool(chunk), "Passkey FAST connection closed before authentication")
            result.extend(chunk)
            failure = re.search(rb"<failure[^>]*>(.*?)</failure>", result)
            check(failure is None, f"Passkey FAST authentication rejected: {failure.group(1).decode() if failure else ''}")
        check(b"<success" in result and b"<bound" in result, "Passkey FAST credential could not bind XMPP")
        additional = re.search(rb"<additional-data>([^<]+)</additional-data>", result)
        check(additional is not None and hmac.compare_digest(base64.b64decode(additional.group(1)),
              hmac.new(fast.encode(), b"Responder", hashlib.sha256).digest()), "Passkey FAST server proof failed")

        status, removed = guarded("/api/v1/me/passkeys/remove", {"id": registered["id"], "password": wire.PASSWORD}, bearer)
        check(status == 200 and removed["signed_out"], "Passkey removal did not revoke sessions")
        check(wire.api("GET", "/api/v1/me", token=logged_in["token"])[0] == 401, "removed key retained its API session")
        secure.settimeout(3)
        # Revocation may cancel the transport before a stream footer is sent.
        # Require EOF; an idle connection or an XML footer alone is insufficient.
        remaining = 65536
        while remaining > 0:
            chunk = secure.recv(min(8192, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
        check(remaining > 0, "revoked XMPP connection kept sending data")
        secure.close()
    print("Passkeys: enrollment, Origin, one-use challenges, login, FAST/Bind2 and revocation passed")
