#!/usr/bin/env python3
"""Two-domain federation interoperability test using the dependency-free WebSocket fixture."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
import pathlib
import re
import socket
import ssl
import subprocess
import time


ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("northstar_integration", ROOT / "integration-wsl.py")
fixture = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(fixture)

PASSWORD = "federation-password-123"
ALICE = "alice_fed"
BOB = "bob_fed"


def psql_schema(schema: str, sql: str) -> str:
    fixture.check(
        re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema) is not None,
        "federation fixture did not receive a safe random schema name",
    )
    psql_env = os.environ.copy()
    psql_env["PGPASSWORD"] = "xmpp-test-password"
    # Configure the schema at connection startup instead of prepending a SQL
    # `SET` statement. psql prints the `SET` command tag even with
    # --tuples-only/--no-align, which turns a scalar result such as `0` into
    # `SET\n0` and can make a privacy assertion report false persistence.
    # The schema is restricted above to an identifier-safe ASCII subset.
    existing_pgoptions = psql_env.get("PGOPTIONS", "").strip()
    schema_option = f"-c search_path={schema}"
    psql_env["PGOPTIONS"] = " ".join(
        option for option in (existing_pgoptions, schema_option) if option
    )
    return subprocess.run(
        [
            "psql",
            "--host",
            "127.0.0.1",
            "--username",
            "xmpp_test",
            "--dbname",
            "xmpp_test",
            "--tuples-only",
            "--no-align",
            "--set",
            "ON_ERROR_STOP=1",
            "--command",
            sql,
        ],
        check=True,
        capture_output=True,
        text=True,
        env=psql_env,
    ).stdout


def required_test_port(name: str) -> int:
    raw = os.environ.get(name, "")
    fixture.check(raw.isascii() and raw.isdecimal(), f"{name} must be a decimal TCP port")
    port = int(raw)
    fixture.check(1 <= port <= 65535, f"{name} must be from 1 through 65535")
    return port


def receive_tls_until(stream: socket.socket, marker: str) -> str:
    stream.settimeout(10)
    data = b""
    encoded = marker.encode()
    while encoded not in data:
        chunk = stream.recv(8192)
        fixture.check(bool(chunk), f"TLS stream ended before {marker!r}: {data!r}")
        data += chunk
        fixture.check(len(data) <= 1024 * 1024, "adversarial TLS response exceeded 1 MiB")
    return data.decode("utf-8")


def open_direct_c2s(
    *,
    server_hostname: str | None = "localhost",
    verify_server_hostname: bool = True,
    tls_version: ssl.TLSVersion | None = None,
) -> ssl.SSLSocket:
    cert_dir = pathlib.Path(os.environ["FEDERATION_TEST_CERT_DIR"])
    context = ssl.create_default_context(cafile=str(cert_dir / "federation-ca.crt"))
    context.check_hostname = verify_server_hostname
    if tls_version is not None:
        context.minimum_version = tls_version
        context.maximum_version = tls_version
    context.set_alpn_protocols(["xmpp-client"])
    raw = socket.create_connection(
        ("127.0.0.1", required_test_port("FEDERATION_TEST_CLIENT_DIRECT_TLS_PORT_A")),
        timeout=10,
    )
    stream = context.wrap_socket(raw, server_hostname=server_hostname)
    fixture.check(stream.selected_alpn_protocol() == "xmpp-client", "C2S Direct TLS ALPN failed")
    return stream


def begin_c2s(stream: socket.socket) -> str:
    stream.sendall(
        b"<stream:stream xmlns='jabber:client' "
        b"xmlns:stream='http://etherx.jabber.org/streams' "
        b"to='localhost' version='1.0'>"
    )
    return receive_tls_until(stream, "</stream:features>")


def open_starttls_c2s(tls_version: ssl.TLSVersion) -> ssl.SSLSocket:
    raw = socket.create_connection(
        ("127.0.0.1", required_test_port("FEDERATION_TEST_CLIENT_PORT_A")), timeout=10
    )
    try:
        features = begin_c2s(raw)
        fixture.check("<starttls" in features and "<required" in features, "C2S STARTTLS was not required")
        raw.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        proceed = receive_tls_until(raw, "/>")
        fixture.check("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>" in proceed, "C2S STARTTLS was rejected")
        cert_dir = pathlib.Path(os.environ["FEDERATION_TEST_CERT_DIR"])
        context = ssl.create_default_context(cafile=str(cert_dir / "federation-ca.crt"))
        context.minimum_version = tls_version
        context.maximum_version = tls_version
        return context.wrap_socket(raw, server_hostname="localhost")
    except BaseException:
        raw.close()
        raise


def verify_c2s_transport_boundaries() -> None:
    for expected_version, tls_version in (
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ):
        stream = open_direct_c2s(tls_version=tls_version)
        try:
            fixture.check(
                stream.version() == expected_version,
                f"C2S Direct TLS negotiated {stream.version()!r}, expected {expected_version}",
            )
            features = begin_c2s(stream)
            fixture.check(
                "<limits xmlns='urn:xmpp:stream-limits:0'>" in features
                and "<max-bytes>1048576</max-bytes>" in features
                and "<idle-seconds>15</idle-seconds>" in features,
                f"C2S Direct TLS omitted the enforced pre-authentication XEP-0478 limits: {features}",
            )
            fixture.check("<starttls" not in features, "C2S Direct TLS incorrectly offered STARTTLS")
        finally:
            stream.close()

    for expected_version, tls_version in (
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ):
        stream = open_starttls_c2s(tls_version)
        try:
            fixture.check(
                stream.version() == expected_version,
                f"C2S STARTTLS negotiated {stream.version()!r}, expected {expected_version}",
            )
            features = begin_c2s(stream)
            fixture.check(
                "<max-bytes>1048576</max-bytes>" in features
                and "<idle-seconds>15</idle-seconds>" in features,
                f"C2S STARTTLS omitted the enforced XEP-0478 limits: {features}",
            )
        finally:
            stream.close()

    # XEP-0368 requires SNI for Direct TLS. Northstar rejects it immediately
    # after the TLS handshake, before it accepts an XMPP stream opening.
    for server_hostname, label in ((None, "missing"), ("wrong.invalid", "wrong")):
        stream = open_direct_c2s(
            server_hostname=server_hostname,
            verify_server_hostname=False,
        )
        stream.settimeout(5)
        response = b""
        try:
            stream.sendall(
                b"<stream:stream xmlns='jabber:client' "
                b"xmlns:stream='http://etherx.jabber.org/streams' "
                b"to='localhost' version='1.0'>"
            )
            while len(response) <= 64 * 1024:
                chunk = stream.recv(8192)
                if not chunk:
                    break
                response += chunk
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            stream.close()
        fixture.check(
            not response,
            f"C2S Direct TLS accepted XMPP data after a {label} SNI: {response!r}",
        )

    # Prove that max-bytes is enforced after TLS and the initial stream open,
    # rather than being a discovery-only claim.
    stream = open_direct_c2s()
    try:
        features = begin_c2s(stream)
        fixture.check(
            "<max-bytes>1048576</max-bytes>" in features,
            "pre-authentication C2S stream did not advertise its 1 MiB limit",
        )
        oversized = (
            b"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>"
            + b"A" * (1024 * 1024)
            + b"</auth>"
        )
        stream.sendall(oversized)
        terminal = receive_tls_until(stream, "</stream:stream>")
        expected = (
            "<stream:error xmlns:stream='http://etherx.jabber.org/streams'>"
            "<policy-violation "
            "xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>"
            "</stream:stream>"
        )
        fixture.check(
            terminal == expected,
            f"oversized pre-authentication C2S XML did not receive the exact terminal policy-violation: {terminal!r}",
        )
    finally:
        stream.close()


def verify_c2s_authenticated_limits() -> None:
    stream = open_direct_c2s()
    try:
        features = begin_c2s(stream)
        fixture.check("<mechanism>PLAIN</mechanism>" in features, "C2S PLAIN was not advertised")
        credentials = base64.b64encode(f"\0{ALICE}\0{PASSWORD}".encode()).decode()
        stream.sendall(
            f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{credentials}</auth>".encode()
        )
        receive_tls_until(stream, "<success")
        authenticated_features = begin_c2s(stream)
        fixture.check(
            "<limits xmlns='urn:xmpp:stream-limits:0'>" in authenticated_features
            and "<max-bytes>1048576</max-bytes>" in authenticated_features
            and "<idle-seconds>300</idle-seconds>" in authenticated_features,
            f"authenticated C2S features omitted the enforced XEP-0478 limits: {authenticated_features}",
        )
    finally:
        stream.close()


def open_direct_s2s(
    client_certificate: str,
    client_key: str,
    *,
    server_hostname: str | None = "localhost",
    verify_server_hostname: bool = True,
    tls_version: ssl.TLSVersion | None = None,
) -> ssl.SSLSocket:
    cert_dir = pathlib.Path(os.environ["FEDERATION_TEST_CERT_DIR"])
    context = ssl.create_default_context(cafile=str(cert_dir / "federation-ca.crt"))
    context.check_hostname = verify_server_hostname
    context.load_cert_chain(client_certificate, client_key)
    if tls_version is not None:
        context.minimum_version = tls_version
        context.maximum_version = tls_version
    context.set_alpn_protocols(["xmpp-server"])
    raw = socket.create_connection(
        ("127.0.0.1", required_test_port("FEDERATION_TEST_S2S_DIRECT_TLS_PORT_A")),
        timeout=10,
    )
    stream = context.wrap_socket(raw, server_hostname=server_hostname)
    fixture.check(stream.selected_alpn_protocol() == "xmpp-server", "Direct TLS ALPN failed")
    return stream


def begin_s2s(stream: socket.socket, asserted_domain: str) -> str:
    stream.sendall(
        ("<stream:stream xmlns='jabber:server' "
         "xmlns:stream='http://etherx.jabber.org/streams' "
         "xmlns:db='jabber:server:dialback' "
         f"from='{asserted_domain}' to='localhost' version='1.0'>").encode()
    )
    return receive_tls_until(stream, "</stream:features>")


def open_starttls_s2s(
    client_certificate: str,
    client_key: str,
    tls_version: ssl.TLSVersion,
) -> ssl.SSLSocket:
    raw = socket.create_connection(
        ("127.0.0.1", required_test_port("FEDERATION_TEST_S2S_STARTTLS_PORT_A")),
        timeout=10,
    )
    try:
        features = begin_s2s(raw, "remote.localhost")
        fixture.check("<starttls" in features and "<required" in features, "S2S STARTTLS was not required")
        raw.sendall(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        proceed = receive_tls_until(raw, "/>")
        fixture.check("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>" in proceed, "S2S STARTTLS was rejected")
        cert_dir = pathlib.Path(os.environ["FEDERATION_TEST_CERT_DIR"])
        context = ssl.create_default_context(cafile=str(cert_dir / "federation-ca.crt"))
        context.load_cert_chain(client_certificate, client_key)
        context.minimum_version = tls_version
        context.maximum_version = tls_version
        return context.wrap_socket(raw, server_hostname="localhost")
    except BaseException:
        raw.close()
        raise


def assert_initial_s2s_error(
    certificate: str,
    key: str,
    payload: bytes,
    condition: str,
) -> None:
    stream = open_direct_s2s(certificate, key)
    try:
        stream.sendall(payload)
        terminal = receive_tls_until(stream, "</stream:stream>")
        fixture.check(
            terminal.startswith("<stream:stream ")
            and "version='1.0'" in terminal
            and f"<{condition} xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>" in terminal
            and terminal.endswith("</stream:stream>"),
            f"initial S2S error {condition} was not preceded by a complete server opening: {terminal!r}",
        )
    finally:
        stream.close()


def authenticate_external(stream: ssl.SSLSocket, asserted_domain: str) -> None:
    features = begin_s2s(stream, asserted_domain)
    fixture.check("<mechanism>EXTERNAL</mechanism>" in features, "EXTERNAL was not advertised")
    fixture.check(
        "<max-bytes>1048576</max-bytes>" in features
        and "<idle-seconds>15</idle-seconds>" in features,
        f"pre-authentication S2S features omitted the enforced XEP-0478 limits: {features}",
    )
    authorization = base64.b64encode(asserted_domain.encode()).decode()
    stream.sendall(
        f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>{authorization}</auth>".encode()
    )
    receive_tls_until(stream, "<success")
    authenticated_features = begin_s2s(stream, asserted_domain)
    fixture.check(
        "<max-bytes>1048576</max-bytes>" in authenticated_features
        and "<idle-seconds>300</idle-seconds>" in authenticated_features,
        "authenticated S2S features omitted the enforced XEP-0478 limits",
    )


def verify_s2s_transport_boundaries() -> None:
    cert_dir = pathlib.Path(os.environ["FEDERATION_TEST_CERT_DIR"])
    certificate = str(cert_dir / "federation-b.crt")
    key = str(cert_dir / "federation-b.key")

    for expected_version, tls_version in (
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ):
        stream = open_direct_s2s(certificate, key, tls_version=tls_version)
        try:
            fixture.check(
                stream.version() == expected_version,
                f"S2S Direct TLS negotiated {stream.version()!r}, expected {expected_version}",
            )
            features = begin_s2s(stream, "remote.localhost")
            fixture.check(
                "<limits xmlns='urn:xmpp:stream-limits:0'>" in features
                and "<max-bytes>1048576</max-bytes>" in features
                and "<idle-seconds>15</idle-seconds>" in features,
                f"S2S Direct TLS omitted the enforced XEP-0478 limits: {features}",
            )
        finally:
            stream.close()

    for expected_version, tls_version in (
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ):
        stream = open_starttls_s2s(certificate, key, tls_version)
        try:
            fixture.check(
                stream.version() == expected_version,
                f"S2S STARTTLS negotiated {stream.version()!r}, expected {expected_version}",
            )
            features = begin_s2s(stream, "remote.localhost")
            fixture.check(
                "<max-bytes>1048576</max-bytes>" in features
                and "<idle-seconds>15</idle-seconds>" in features,
                f"S2S STARTTLS omitted the enforced XEP-0478 limits: {features}",
            )
        finally:
            stream.close()

    valid_attributes = b"from='remote.localhost' to='localhost' version='1.0'>"
    for payload in (
        b"<other:stream xmlns='jabber:server' "
        b"xmlns:other='http://etherx.jabber.org/streams' " + valid_attributes,
        b"<other:stream xmlns='jabber:server' " + valid_attributes,
    ):
        assert_initial_s2s_error(certificate, key, payload, "bad-namespace-prefix")

    assert_initial_s2s_error(
        certificate,
        key,
        b"<stream:stream xmlns='jabber:client' "
        b"xmlns:stream='http://etherx.jabber.org/streams' " + valid_attributes,
        "invalid-namespace",
    )
    assert_initial_s2s_error(
        certificate,
        key,
        b"<stream:stream xmlns='jabber:server' "
        b"xmlns:stream='http://etherx.jabber.org/streams' "
        b"from='remote.localhost' to='localhost'>",
        "unsupported-version",
    )
    assert_initial_s2s_error(certificate, key, b"\xff", "unsupported-encoding")
    assert_initial_s2s_error(
        certificate,
        key,
        b"<?xml version='1.0' encoding='ISO-8859-1'?>"
        b"<stream:stream xmlns='jabber:server' "
        b"xmlns:stream='http://etherx.jabber.org/streams' " + valid_attributes,
        "unsupported-encoding",
    )

    declaration_stream = open_direct_s2s(certificate, key)
    try:
        begin_s2s(declaration_stream, "remote.localhost")
        declaration_stream.sendall(
            b"<?xml version='1.0'?><message xmlns='jabber:server' "
            b"from='remote.localhost' to='alice_fed@localhost'><body>forbidden</body></message>"
        )
        declaration_error = receive_tls_until(declaration_stream, "</stream:stream>")
        fixture.check(
            "<not-well-formed xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
            in declaration_error
            and declaration_error.endswith("</stream:stream>"),
            f"second XML declaration inside one S2S entity was accepted: {declaration_error!r}",
        )
    finally:
        declaration_stream.close()

    for server_hostname, label in ((None, "missing"), ("wrong.invalid", "wrong")):
        stream = open_direct_s2s(
            certificate,
            key,
            server_hostname=server_hostname,
            verify_server_hostname=False,
        )
        stream.settimeout(5)
        response = b""
        try:
            stream.sendall(
                b"<stream:stream xmlns='jabber:server' "
                b"xmlns:stream='http://etherx.jabber.org/streams' "
                b"from='remote.localhost' to='localhost' version='1.0'>"
            )
            while len(response) <= 64 * 1024:
                chunk = stream.recv(8192)
                if not chunk:
                    break
                response += chunk
                if b"</stream:stream>" in response:
                    break
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            stream.close()
        fixture.check(
            b"<stream:features" not in response and b"<host-unknown" in response,
            f"S2S Direct TLS did not reject a {label} SNI with host-unknown: {response!r}",
        )

    # XEP-0478's advertised max-bytes is an enforced byte boundary, not just a
    # discovery hint. Exercise it after TLS and stream establishment but before
    # either EXTERNAL or Dialback authenticates the peer. The exact terminal
    # response also proves that oversized first-level XML cannot fall through
    # into a generic SASL failure or leave the stream reusable.
    stream = open_direct_s2s(certificate, key)
    try:
        features = begin_s2s(stream, "remote.localhost")
        fixture.check(
            "<max-bytes>1048576</max-bytes>" in features,
            "pre-authentication S2S stream did not advertise its 1 MiB limit",
        )
        oversized = (
            b"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>"
            + b"A" * (1024 * 1024)
            + b"</auth>"
        )
        stream.sendall(oversized)
        terminal = receive_tls_until(stream, "</stream:stream>")
        expected = (
            "<stream:error><policy-violation "
            "xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>"
            "</stream:stream>"
        )
        fixture.check(
            terminal == expected,
            f"oversized pre-authentication S2S XML did not receive the exact terminal policy-violation: {terminal!r}",
        )
    finally:
        stream.close()


def verify_s2s_authentication_boundaries() -> None:
    if os.environ.get("FEDERATION_TEST_EXTERNAL", "true").lower() != "true":
        return
    cert_dir = pathlib.Path(os.environ["FEDERATION_TEST_CERT_DIR"])
    certificate = str(cert_dir / "federation-b.crt")
    key = str(cert_dir / "federation-b.key")

    stream = open_direct_s2s(certificate, key)
    try:
        authenticate_external(stream, "remote.localhost")
        stream.sendall(
            b"<message xmlns='jabber:server' from='mallory@evil.localhost' "
            b"to='alice_fed@localhost' type='chat'><body>spoof</body></message>"
        )
        response = receive_tls_until(stream, "</stream:stream>")
        fixture.check("<invalid-from" in response, "forged S2S from did not close with invalid-from")
    finally:
        stream.close()

    address_failures = (
        (
            "<message xmlns='jabber:server' from='bob_fed@remote.localhost' "
            "type='chat'><body>missing target</body></message>",
            "improper-addressing",
        ),
        (
            "<message xmlns='jabber:server' from='bob_fed@remote.localhost' "
            "to='alice_fed@other.localhost' type='chat'><body>wrong target</body></message>",
            "host-unknown",
        ),
    )
    for stanza, expected_condition in address_failures:
        stream = open_direct_s2s(certificate, key)
        try:
            authenticate_external(stream, "remote.localhost")
            stream.sendall(stanza.encode())
            response = receive_tls_until(stream, "</stream:stream>")
            fixture.check(
                f"<{expected_condition}" in response,
                f"S2S address violation did not close with {expected_condition}",
            )
        finally:
            stream.close()

    stream = open_direct_s2s(certificate, key)
    try:
        authenticate_external(stream, "remote.localhost")
        stream.sendall(
            b"<message xmlns='jabber:client' from='bob_fed@remote.localhost' "
            b"to='alice_fed@localhost' type='chat'><body>wrong core namespace</body></message>"
        )
        response = receive_tls_until(stream, "</stream:stream>")
        fixture.check(
            "<invalid-namespace xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>" in response,
            f"wrong S2S stanza core namespace did not close with invalid-namespace: {response!r}",
        )
    finally:
        stream.close()

    stream = open_direct_s2s(certificate, key)
    try:
        features = begin_s2s(stream, "remote.localhost")
        fixture.check("<mechanism>EXTERNAL</mechanism>" in features, "EXTERNAL was not advertised")
        stream.sendall(
            ("<db:result from='remote.localhost' to='localhost'>" + "0" * 64 + "</db:result>").encode()
        )
        response = receive_tls_until(stream, "</stream:stream>")
        fixture.check("<not-authorized" in response, "valid certificate was allowed to downgrade")
    finally:
        stream.close()

    stream = open_direct_s2s(certificate, key)
    try:
        stream.sendall(
            b"<stream:stream xmlns='jabber:server' "
            b"xmlns:stream='urn:example:wrong-stream-namespace' "
            b"from='remote.localhost' to='localhost' version='1.0'>"
        )
        response = receive_tls_until(stream, "</stream:stream>")
        fixture.check(
            "<invalid-namespace" in response,
            "invalid S2S stream namespace did not receive a fatal initial stream error",
        )
    finally:
        stream.close()

    stream = open_direct_s2s(
        str(cert_dir / "federation-evil.crt"), str(cert_dir / "federation-evil.key")
    )
    try:
        features = begin_s2s(stream, "remote.localhost")
        fixture.check(
            "<mechanism>EXTERNAL</mechanism>" not in features,
            "wrong-domain client certificate was offered SASL EXTERNAL",
        )
    finally:
        stream.close()


def verify_starttls_failure_boundary() -> None:
    stream = socket.create_connection(
        ("127.0.0.1", required_test_port("FEDERATION_TEST_S2S_STARTTLS_PORT_A")),
        timeout=10,
    )
    try:
        begin_s2s(stream, "remote.localhost")
        stream.sendall(
            b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><invalid/></starttls>"
        )
        response = receive_tls_until(stream, "</stream:stream>")
        fixture.check(
            "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'" in response
            and "<stream:error>" not in response,
            "malformed STARTTLS did not use the RFC 6120 TLS failure path",
        )
    finally:
        stream.close()


def endpoint(port: int, xmpp_port: int, domain: str) -> None:
    fixture.HTTP_HOST = "127.0.0.1"
    fixture.HTTP_PORT = port
    fixture.XMPP_PORT = xmpp_port
    fixture.DOMAIN = domain


def register(username: str) -> None:
    status, result = fixture.register_account(username, PASSWORD)
    fixture.check(status == 201, f"registration failed: {status} {result}")


def run() -> None:
    verify_starttls_failure_boundary()
    verify_c2s_transport_boundaries()
    verify_s2s_transport_boundaries()
    verify_s2s_authentication_boundaries()
    endpoint(
        required_test_port("FEDERATION_TEST_HTTP_PORT_A"),
        required_test_port("FEDERATION_TEST_CLIENT_PORT_A"),
        "localhost",
    )
    fixture.wait_ready()
    register(ALICE)
    verify_c2s_authenticated_limits()
    alice = fixture.XmppWebSocket(ALICE, PASSWORD, "alice-federation")

    endpoint(
        required_test_port("FEDERATION_TEST_HTTP_PORT_B"),
        required_test_port("FEDERATION_TEST_CLIENT_PORT_B"),
        "remote.localhost",
    )
    fixture.wait_ready()
    register(BOB)
    bob = fixture.XmppWebSocket(BOB, PASSWORD, "bob-federation")

    # RFC 6121 distinguishes connected, available, and interested resources.
    # Subscription approvals and roster pushes are delivered to interested
    # resources, so make both test clients request their roster and send
    # initial presence before asserting subscription notifications.
    for client, request_id in ((alice, "initial-roster-a"), (bob, "initial-roster-b")):
        client.send(
            f"<iq xmlns='jabber:client' type='get' id='{request_id}'>"
            "<query xmlns='jabber:iq:roster'/></iq>"
        )
        client.receive_until(request_id)
        client.send("<presence xmlns='jabber:client'/>")

    # RFC 6121 section 8.5.3.1 protects the existence of an exact resource.
    # Before the target has granted presence visibility, an IQ get/set --
    # including Jingle -- must fail without being delivered to that resource.
    alice.send(
        "<iq xmlns='jabber:client' type='set' id='pre-roster-jingle' "
        "to='bob_fed@remote.localhost/bob-federation'>"
        "<jingle xmlns='urn:xmpp:jingle:1' action='session-info' sid='pre-roster-call'>"
        "<ringing xmlns='urn:xmpp:jingle:apps:rtp:info:1'/></jingle></iq>"
    )
    pre_roster_error, _ = alice.receive_until("pre-roster-jingle", timeout=20)
    fixture.check(
        "type='error'" in pre_roster_error
        and "<service-unavailable " in pre_roster_error,
        f"pre-subscription exact-resource IQ leaked resource visibility: {pre_roster_error}",
    )

    # A remote actor must see the same XEP-0045 semantics as a local client:
    # authenticated real-JID disclosure, self-presence before bounded history,
    # current subject last, bidirectional groupchat, mediated decline, and
    # administrative kick/ban status delivery across S2S.
    federated_room = "federated-controls@conference.localhost"
    alice.send(
        f"<presence xmlns='jabber:client' to='{federated_room}/LocalAlice'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    local_owner, _ = alice.receive_until("code='110'", timeout=20)
    fixture.check(
        "code='201'" in local_owner and "affiliation='owner'" in local_owner,
        "local owner could not create the federated MUC fixture",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='fed-muc-instant' to='{federated_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='submit'/></query></iq>"
    )
    instant_room, _ = alice.receive_until("fed-muc-instant", timeout=20)
    fixture.check(
        "type='result'" in instant_room,
        "the initial owner could not accept the instant-room defaults",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='fed-muc-config-check' to='{federated_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'/></iq>"
    )
    room_config, _ = alice.receive_until("fed-muc-config-check", timeout=20)
    fixture.check(
        "muc#roomconfig_enablelogging" in room_config
        and (
            "muc#roomconfig_enablelogging' type='boolean'><value>1</value>"
            in room_config
            or "muc#roomconfig_enablelogging' type='boolean'><value>true</value>"
            in room_config
        ),
        f"instant federated MUC unexpectedly disabled history logging: {room_config}",
    )
    for index in (1, 2):
        message_id = f"fed-muc-history-{index}"
        alice.send(
            f"<message xmlns='jabber:client' to='{federated_room}' type='groupchat' id='{message_id}'>"
            + fixture.omemo2_envelope(
                111,
                [("alice_fed@localhost", [111]), ("bob_fed@remote.localhost", [777])],
                f"FED-MUC-CIPHERTEXT-{index}",
            )
            + "</message>"
        )
        accepted_message, _ = alice.receive_until(message_id)
        fixture.check(
            "type='error'" not in accepted_message
            and fixture.omemo_payload_b64(f"FED-MUC-CIPHERTEXT-{index}")
            in accepted_message,
            f"federated MUC history seed was not accepted as encrypted discussion: {accepted_message}",
        )
    alice.send(
        f"<message xmlns='jabber:client' to='{federated_room}' type='groupchat' id='fed-muc-subject'>"
        "<subject>Federated Subject</subject></message>"
    )
    accepted_subject, _ = alice.receive_until("fed-muc-subject")
    fixture.check(
        "type='error'" not in accepted_subject and "Federated Subject" in accepted_subject,
        f"federated MUC subject seed was rejected: {accepted_subject}",
    )

    schema_a = os.environ.get("FEDERATION_TEST_SCHEMA_A", "")
    fixture.check(
        re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema_a) is not None,
        "federation fixture did not receive a safe random schema name",
    )
    psql_env = os.environ.copy()
    psql_env["PGPASSWORD"] = "xmpp-test-password"
    persisted = subprocess.run(
        [
            "psql",
            "--host",
            "127.0.0.1",
            "--username",
            "xmpp_test",
            "--dbname",
            "xmpp_test",
            "--tuples-only",
            "--no-align",
            "--set",
            "ON_ERROR_STOP=1",
            "--command",
            f'SET search_path TO "{schema_a}"; '
            "SELECT r.logging_enabled::text, r.configuration_state, "
            "m.message_kind, m.encrypted::text, m.stanza "
            "FROM muc_rooms r JOIN muc_messages m ON m.room_id = r.id "
            "WHERE r.localpart = 'federated-controls' "
            "ORDER BY m.created_at, m.id;",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=psql_env,
    ).stdout
    persisted_rows = [line for line in persisted.splitlines() if "|" in line]
    discussion_rows = [line for line in persisted_rows if "|discussion|true|" in line]
    fixture.check(
        len(discussion_rows) == 2
        and all(line.startswith("true|active|") for line in discussion_rows)
        and fixture.omemo_payload_b64("FED-MUC-CIPHERTEXT-1") in persisted
        and fixture.omemo_payload_b64("FED-MUC-CIPHERTEXT-2") in persisted,
        f"federated MUC seed was not durably admitted before remote join: {persisted_rows}",
    )

    bob.send(
        f"<presence xmlns='jabber:client' to='{federated_room}/RemoteBob'>"
        "<x xmlns='http://jabber.org/protocol/muc'>"
        "<history maxchars='65536' maxstanzas='2' seconds='3600' since='2000-01-01T00:00:00Z'/>"
        "</x></presence>"
    )
    _, remote_join_frames = bob.receive_until("Federated Subject", timeout=20)
    remote_join = "".join(remote_join_frames)
    fixture.check(
        "code='110'" in remote_join
        and "affiliation='none'" in remote_join
        and "role='participant'" in remote_join
        and "bob_fed@remote.localhost/bob-federation" in remote_join
        and fixture.omemo_payload_b64("FED-MUC-CIPHERTEXT-1") in remote_join
        and fixture.omemo_payload_b64("FED-MUC-CIPHERTEXT-2") in remote_join
        and "urn:xmpp:delay" in remote_join
        and remote_join.index("code='110'")
        < remote_join.index(fixture.omemo_payload_b64("FED-MUC-CIPHERTEXT-1"))
        < remote_join.index("Federated Subject"),
        "remote MUC join did not preserve real JID and presence/history/subject ordering: "
        + remote_join,
    )
    remote_presence, _ = alice.receive_until(f"from='{federated_room}/RemoteBob'", timeout=20)
    fixture.check(
        "bob_fed@remote.localhost/bob-federation" in remote_presence,
        "federated non-anonymous MUC presence omitted the authenticated real JID",
    )
    bob.send(
        f"<presence xmlns='jabber:client' id='fed-muc-resync' to='{federated_room}/RemoteBob'>"
        "<x xmlns='http://jabber.org/protocol/muc'><history maxstanzas='0'/></x></presence>"
    )
    _, remote_resync_frames = bob.receive_until("Federated Subject", timeout=20)
    remote_resync = "".join(remote_resync_frames)
    fixture.check(
        f"from='{federated_room}/LocalAlice'" in remote_resync
        and "id='fed-muc-resync'" in remote_resync
        and "code='110'" in remote_resync
        and remote_resync.index(f"from='{federated_room}/LocalAlice'")
        < remote_resync.index("code='110'")
        < remote_resync.index("Federated Subject"),
        "federated repeated tagged join did not return roster, self-presence, then subject",
    )
    bob.send(
        f"<presence xmlns='jabber:client' id='fed-muc-rename' to='{federated_room}/RemoteBobRenamed'/>"
    )
    _, rename_frames = bob.receive_until(f"from='{federated_room}/RemoteBobRenamed'", timeout=20)
    rename = "".join(rename_frames)
    fixture.check(
        "code='303'" in rename and "nick='RemoteBobRenamed'" in rename,
        "federated nickname change omitted unavailable 303 and replacement presence",
    )
    bob.send(
        f"<presence xmlns='jabber:client' id='fed-muc-rename-back' to='{federated_room}/RemoteBob'/>"
    )
    _, rename_back_frames = bob.receive_until(f"from='{federated_room}/RemoteBob'", timeout=20)
    fixture.check(
        any("code='303'" in frame for frame in rename_back_frames),
        "federated nickname could not be restored after the rename test",
    )
    bob.send(
        f"<message xmlns='jabber:client' to='{federated_room}' type='groupchat' id='fed-muc-remote-message'>"
        + fixture.omemo2_envelope(
            777,
            [("alice_fed@localhost", [111]), ("bob_fed@remote.localhost", [777])],
            "FED-MUC-REMOTE-CIPHERTEXT",
        )
        + "</message>"
    )
    remote_groupchat, _ = alice.receive_until("fed-muc-remote-message", timeout=20)
    fixture.check(
        f"from='{federated_room}/RemoteBob'" in remote_groupchat
        and fixture.omemo_payload_b64("FED-MUC-REMOTE-CIPHERTEXT") in remote_groupchat,
        "remote occupant groupchat was not reflected across S2S",
    )
    bob.receive_until("fed-muc-remote-message", timeout=20)

    alice.send(
        f"<message xmlns='jabber:client' to='{federated_room}' type='normal' id='fed-muc-invite'>"
        "<x xmlns='http://jabber.org/protocol/muc#user'>"
        "<invite to='bob_fed@remote.localhost'><reason>Federated invitation</reason></invite>"
        "</x></message>"
    )
    remote_invitation, _ = bob.receive_until("Federated invitation", timeout=20)
    fixture.check(
        f"from='{federated_room}'" in remote_invitation
        and "alice_fed@localhost/alice-federation" in remote_invitation,
        "mediated MUC invitation was not delivered across S2S",
    )
    bob.send(
        f"<message xmlns='jabber:client' to='{federated_room}' type='normal' id='fed-muc-decline'>"
        "<x xmlns='http://jabber.org/protocol/muc#user'>"
        "<decline to='alice_fed@localhost'><reason>Federated decline</reason></decline>"
        "</x></message>"
    )
    remote_decline, _ = alice.receive_until("Federated decline", timeout=20)
    fixture.check(
        f"from='{federated_room}'" in remote_decline
        and "<decline from='bob_fed@remote.localhost'" in remote_decline,
        "mediated MUC decline was not delivered from a remote invitee",
    )

    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='fed-muc-kick' to='{federated_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#admin'>"
        "<item nick='RemoteBob' role='none'><reason>Federated kick</reason></item>"
        "</query></iq>"
    )
    alice.receive_until("fed-muc-kick")
    kicked, _ = bob.receive_until("code='307'", timeout=20)
    fixture.check(
        "Federated kick" in kicked and "type='unavailable'" in kicked,
        "remote occupant did not receive MUC kick status 307",
    )
    bob.send(
        f"<presence xmlns='jabber:client' to='{federated_room}/RemoteBobReturn'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    returned, _ = bob.receive_until("code='110'", timeout=20)
    fixture.check("role='participant'" in returned, "kicked remote occupant could not rejoin")
    alice.receive_until(f"from='{federated_room}/RemoteBobReturn'", timeout=20)
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='fed-muc-ban' to='{federated_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#admin'>"
        "<item jid='bob_fed@remote.localhost' affiliation='outcast'><reason>Federated ban</reason></item>"
        "</query></iq>"
    )
    alice.receive_until("fed-muc-ban")
    banned, _ = bob.receive_until("code='301'", timeout=20)
    fixture.check(
        "Federated ban" in banned and "type='unavailable'" in banned,
        "remote occupant did not receive MUC ban status 301",
    )
    bob.send(
        f"<presence xmlns='jabber:client' id='fed-muc-banned-rejoin' to='{federated_room}/DeniedBob'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    denied_join, _ = bob.receive_until("fed-muc-banned-rejoin", timeout=20)
    fixture.check(
        "type='error'" in denied_join and "forbidden" in denied_join,
        "outcast remote occupant could rejoin the MUC room",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='fed-muc-destroy' to='{federated_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<destroy><reason>Federated controls complete</reason></destroy>"
        "</query></iq>"
    )
    _, destroyed_frames = alice.receive_until("fed-muc-destroy")
    if not any("<destroy" in frame for frame in destroyed_frames):
        _, destroy_notice = alice.receive_until("<destroy")
        destroyed_frames.extend(destroy_notice)
    fixture.check(
        any("Federated controls complete" in frame for frame in destroyed_frames),
        "federated MUC room destruction did not notify the remaining owner",
    )

    # A remote first occupant owns the same durable locked-room lifecycle.
    # A concurrent local join must see item-not-found until that exact remote
    # full JID accepts the instant defaults, including across the S2S route.
    remote_created_room = "remote-created@conference.localhost"
    bob.send(
        f"<presence xmlns='jabber:client' id='remote-created-join' to='{remote_created_room}/RemoteOwner'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    remote_owner, _ = bob.receive_until("remote-created-join", timeout=20)
    fixture.check(
        "code='201'" in remote_owner and "affiliation='owner'" in remote_owner,
        "remote actor could not acquire the initial locked-room ownership",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='get' id='remote-locked-disco-outsider' to='{remote_created_room}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
    )
    remote_locked_disco, _ = alice.receive_until("remote-locked-disco-outsider", timeout=20)
    fixture.check(
        "type='error'" in remote_locked_disco and "item-not-found" in remote_locked_disco,
        "a remote-created locked room leaked through local outsider disco",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='remote-locked-disco-owner' to='{remote_created_room}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info'/></iq>"
    )
    remote_owner_disco, _ = bob.receive_until("remote-locked-disco-owner", timeout=20)
    fixture.check(
        "type='result'" in remote_owner_disco and "http://jabber.org/protocol/muc" in remote_owner_disco,
        "the exact remote creator could not inspect its locked room",
    )
    alice.send(
        f"<presence xmlns='jabber:client' id='locked-second-join' to='{remote_created_room}/TooEarly'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    locked_denial, _ = alice.receive_until("locked-second-join", timeout=20)
    fixture.check(
        "type='error'" in locked_denial and "item-not-found" in locked_denial,
        "a second actor entered a locked remote-created room",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='remote-owner-form' to='{remote_created_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'/></iq>"
    )
    remote_form, _ = bob.receive_until("remote-owner-form", timeout=20)
    fixture.check("muc#roomconfig" in remote_form, "remote owner could not fetch room config")
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='remote-owner-instant' to='{remote_created_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#roomconfig</value></field>"
        "<field var='muc#roomconfig_moderatedroom'><value>1</value></field>"
        "</x></query></iq>"
    )
    remote_instant, _ = bob.receive_until("remote-owner-instant", timeout=20)
    fixture.check("type='result'" in remote_instant, "remote owner could not unlock instant room")
    alice.send(
        f"<presence xmlns='jabber:client' id='unlocked-local-join' to='{remote_created_room}/LocalAfterUnlock'>"
        "<x xmlns='http://jabber.org/protocol/muc'/></presence>"
    )
    unlocked_join, _ = alice.receive_until("unlocked-local-join", timeout=20)
    fixture.check(
        "code='110'" in unlocked_join and "role='visitor'" in unlocked_join,
        "local actor could not join the remote-created room after atomic unlock",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='remote-room-occupant-disco' to='{remote_created_room}'>"
        "<query xmlns='http://jabber.org/protocol/disco#items'>"
        "<set xmlns='http://jabber.org/protocol/rsm'><max>10</max></set>"
        "</query></iq>"
    )
    remote_occupants, _ = bob.receive_until("remote-room-occupant-disco", timeout=20)
    fixture.check(
        f"jid='{remote_created_room}/RemoteOwner'" in remote_occupants
        and f"jid='{remote_created_room}/LocalAfterUnlock'" in remote_occupants,
        "federated room occupant discovery omitted a local or remote occupant",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='remote-room-register' to='{remote_created_room}'>"
        "<query xmlns='jabber:iq:register'><x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#register</value></field>"
        "<field var='muc#register_roomnick'><value>ReservedRemoteOwner</value></field>"
        "</x></query></iq>"
    )
    remote_registered, _ = bob.receive_until("remote-room-register", timeout=20)
    fixture.check("type='result'" in remote_registered, "remote room registration failed")
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='remote-room-register-get' to='{remote_created_room}'>"
        "<query xmlns='jabber:iq:register'/></iq>"
    )
    remote_registration, _ = bob.receive_until("remote-room-register-get", timeout=20)
    fixture.check(
        "<registered" in remote_registration and "ReservedRemoteOwner" in remote_registration,
        "remote reserved nickname was not durable",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='remote-reserved-nick-disco' to='{remote_created_room}'>"
        "<query xmlns='http://jabber.org/protocol/disco#info' node='x-roomuser-item'/></iq>"
    )
    reserved_nick_disco, _ = bob.receive_until("remote-reserved-nick-disco", timeout=20)
    fixture.check(
        "node='x-roomuser-item'" in reserved_nick_disco
        and "name='ReservedRemoteOwner'" in reserved_nick_disco,
        "remote reserved nickname was missing from room-user disco",
    )
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='remote-nick-cross-conflict' to='{remote_created_room}'>"
        "<query xmlns='jabber:iq:register'><x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#register</value></field>"
        "<field var='muc#register_roomnick'><value>ReservedRemoteOwner</value></field>"
        "</x></query></iq>"
    )
    cross_conflict, _ = alice.receive_until("remote-nick-cross-conflict", timeout=20)
    fixture.check(
        "type='error'" in cross_conflict and "conflict" in cross_conflict,
        "local registration reused a federated reserved nickname",
    )
    alice.send(
        f"<message xmlns='jabber:client' to='{remote_created_room}' type='normal' id='remote-room-voice-request'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field>"
        "<field var='muc#role'><value>participant</value></field>"
        "</x></message>"
    )
    remote_voice_request, _ = bob.receive_until("Voice request", timeout=20)
    fixture.check(
        f"<value>{ALICE}@localhost/{alice.resource}</value>" in remote_voice_request
        and "<value>LocalAfterUnlock</value>" in remote_voice_request,
        "remote moderator did not receive the exact cross-domain voice request identity",
    )
    bob.send(
        f"<message xmlns='jabber:client' to='{remote_created_room}' type='normal' id='remote-room-voice-approve'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/muc#request</value></field>"
        "<field var='muc#role'><value>participant</value></field>"
        f"<field var='muc#jid'><value>{ALICE}@localhost/{alice.resource}</value></field>"
        "<field var='muc#roomnick'><value>LocalAfterUnlock</value></field>"
        "<field var='muc#request_allow'><value>1</value></field>"
        "</x></message>"
    )
    voiced_local, _ = alice.receive_until(f"from='{remote_created_room}/LocalAfterUnlock'", timeout=20)
    fixture.check(
        "role='participant'" in voiced_local,
        "remote moderator approval did not grant the local visitor voice",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='remote-owner-destroy' to='{remote_created_room}'>"
        "<query xmlns='http://jabber.org/protocol/muc#owner'>"
        "<destroy><reason>Remote owner cleanup</reason></destroy></query></iq>"
    )
    remote_destroy, _ = bob.receive_until("remote-owner-destroy", timeout=20)
    fixture.check("type='result'" in remote_destroy, "remote owner could not destroy its room")

    alice.send(
        "<iq xmlns='jabber:client' type='get' id='federated-domain-ping' "
        "to='remote.localhost'><ping xmlns='urn:xmpp:ping'/></iq>"
    )
    domain_ping, _ = alice.receive_until("federated-domain-ping", timeout=20)
    fixture.check(
        "type='result'" in domain_ping and "from='remote.localhost'" in domain_ping,
        "domain-only federated IQ routing failed",
    )

    local_pubsub = "pubsub.localhost"
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='federated-pubsub-create' to='{local_pubsub}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='federation/managed'/>"
        "<configure><x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#node_config</value></field>"
        "<field var='pubsub#access_model'><value>authorize</value></field>"
        "</x></configure></pubsub></iq>"
    )
    alice.receive_until("federated-pubsub-create")
    bob.send(
        f"<iq xmlns='jabber:client' type='set' id='federated-pubsub-subscribe' to='{local_pubsub}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<subscribe node='federation/managed' jid='bob_fed@remote.localhost'/></pubsub></iq>"
    )
    remote_pending, _ = bob.receive_until("federated-pubsub-subscribe", timeout=20)
    fixture.check(
        "subscription='pending'" in remote_pending and "from='pubsub.localhost'" in remote_pending,
        "federated PubSub subscription did not enter pending state",
    )
    authorization, _ = alice.receive_until("pubsub#subscribe_authorization", timeout=20)
    fixture.check(
        "bob_fed@remote.localhost" in authorization,
        "local PubSub owner did not receive the remote authorization request",
    )
    alice.send(
        f"<message xmlns='jabber:client' to='{local_pubsub}'>"
        "<x xmlns='jabber:x:data' type='submit'>"
        "<field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#subscribe_authorization</value></field>"
        "<field var='pubsub#node'><value>federation/managed</value></field>"
        "<field var='pubsub#subscriber_jid'><value>bob_fed@remote.localhost</value></field>"
        "<field var='pubsub#allow'><value>true</value></field>"
        "</x></message>"
    )
    approved, _ = bob.receive_until("subscription='subscribed'", timeout=20)
    fixture.check("federation/managed" in approved, "remote PubSub approval notification failed")
    alice.send(
        f"<iq xmlns='jabber:client' type='set' id='federated-pubsub-publish' to='{local_pubsub}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='federation/managed'>"
        "<item id='remote-visible'><value xmlns='urn:northstar:federation'>REMOTE-PUBSUB-EVENT</value></item>"
        "</publish></pubsub></iq>"
    )
    alice.receive_until("federated-pubsub-publish")
    remote_event, _ = bob.receive_until("REMOTE-PUBSUB-EVENT", timeout=20)
    fixture.check(
        "from='pubsub.localhost'" in remote_event and "type='headline'" in remote_event,
        "federated generic PubSub event was not delivered",
    )
    bob.send(
        f"<iq xmlns='jabber:client' type='get' id='federated-pubsub-items' to='{local_pubsub}'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='federation/managed'/></pubsub></iq>"
    )
    remote_items, _ = bob.receive_until("federated-pubsub-items", timeout=20)
    fixture.check("REMOTE-PUBSUB-EVENT" in remote_items, "federated generic PubSub retrieval failed")

    bob.send(
        "<iq xmlns='jabber:client' type='set' id='remote-pep-publish'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:omemo:2:devices'>"
        "<item id='current'><devices xmlns='urn:xmpp:omemo:2'><device id='777'/></devices></item>"
        "</publish></pubsub></iq>"
    )
    bob.receive_until("remote-pep-publish")
    bob.send(
        "<iq xmlns='jabber:client' type='set' id='remote-vcard-set'>"
        "<vCard xmlns='vcard-temp'><FN>Federated Bob</FN></vCard></iq>"
    )
    bob.receive_until("remote-vcard-set")
    remote_avatar = fixture.png_1x1_rgba(49, 130, 206)
    remote_avatar_hash = hashlib.sha1(remote_avatar).hexdigest()
    remote_avatar_data = base64.b64encode(remote_avatar).decode()
    bob.send(
        "<iq xmlns='jabber:client' type='set' id='remote-avatar-data'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:avatar:data'>"
        f"<item id='{remote_avatar_hash}'><data xmlns='urn:xmpp:avatar:data'>{remote_avatar_data}</data></item>"
        "</publish></pubsub></iq>"
    )
    bob.receive_until("remote-avatar-data")
    bob.send(
        "<iq xmlns='jabber:client' type='set' id='remote-avatar-metadata'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:avatar:metadata'>"
        f"<item id='{remote_avatar_hash}'><metadata xmlns='urn:xmpp:avatar:metadata'>"
        f"<info bytes='{len(remote_avatar)}' id='{remote_avatar_hash}' type='image/png' width='1' height='1'/>"
        "</metadata></item></publish></pubsub></iq>"
    )
    bob.receive_until("remote-avatar-metadata")
    bob.send(
        "<iq xmlns='jabber:client' type='set' id='remote-vcard4'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:vcard4'>"
        "<item id='current'><vcard xmlns='urn:ietf:params:xml:ns:vcard-4.0'>"
        "<fn><text>Federated Bob vCard4</text></fn></vcard></item>"
        "</publish></pubsub></iq>"
    )
    bob.receive_until("remote-vcard4")

    alice.send(
        "<iq xmlns='jabber:client' type='get' id='federated-pep' "
        "to='bob_fed@remote.localhost'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<items node='urn:xmpp:omemo:2:devices'/></pubsub></iq>"
    )
    federated_pep, _ = alice.receive_until("federated-pep", timeout=20)
    fixture.check("device id='777'" in federated_pep, "federated PEP query failed")
    alice.send(
        "<iq xmlns='jabber:client' type='get' id='federated-vcard' "
        "to='bob_fed@remote.localhost'><vCard xmlns='vcard-temp'/></iq>"
    )
    federated_vcard, _ = alice.receive_until("federated-vcard", timeout=20)
    fixture.check(
        "Federated Bob" in federated_vcard
        and remote_avatar_data in federated_vcard,
        "federated vCard/avatar conversion query failed",
    )
    for request_id, node, expected in [
        ("federated-avatar-data", "urn:xmpp:avatar:data", remote_avatar_data),
        ("federated-avatar-metadata", "urn:xmpp:avatar:metadata", remote_avatar_hash),
        ("federated-vcard4", "urn:xmpp:vcard4", "Federated Bob vCard4"),
    ]:
        alice.send(
            f"<iq xmlns='jabber:client' type='get' id='{request_id}' to='bob_fed@remote.localhost'>"
            f"<pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='{node}'/></pubsub></iq>"
        )
        response, _ = alice.receive_until(request_id, timeout=20)
        fixture.check(expected in response, f"federated {node} retrieval failed")
    bob.send("<presence xmlns='jabber:client' to='alice_fed@localhost'/>")
    federated_avatar_presence, _ = alice.receive_until(remote_avatar_hash, timeout=20)
    fixture.check(
        "vcard-temp:x:update" in federated_avatar_presence,
        "federated directed presence omitted the authoritative avatar hash",
    )

    alice.send(
        "<presence xmlns='jabber:client' to='bob_fed@remote.localhost'/>"
    )
    remote_presence, _ = bob.receive_until("alice_fed@localhost", timeout=20)
    fixture.check("type='error'" not in remote_presence, "federated presence failed")
    alice.send(
        "<presence xmlns='jabber:client' to='bob_fed@remote.localhost' type='subscribe'/>"
    )
    subscription, _ = bob.receive_until("type='subscribe'", timeout=20)
    fixture.check("alice_fed@localhost" in subscription, "federated subscription request failed")
    bob.send(
        "<presence xmlns='jabber:client' to='alice_fed@localhost' type='subscribed'/>"
    )
    alice.receive_until("type='subscribed'", timeout=20)
    alice.send(
        "<iq xmlns='jabber:client' type='get' id='federated-roster-a'>"
        "<query xmlns='jabber:iq:roster'/></iq>"
    )
    roster_a, _ = alice.receive_until("federated-roster-a")
    fixture.check(
        "bob_fed@remote.localhost" in roster_a and "subscription='to'" in roster_a,
        "federated subscriber roster state was not persisted",
    )
    bob.send(
        "<iq xmlns='jabber:client' type='get' id='federated-roster-b'>"
        "<query xmlns='jabber:iq:roster'/></iq>"
    )
    roster_b, _ = bob.receive_until("federated-roster-b")
    fixture.check(
        "alice_fed@localhost" in roster_b and "subscription='from'" in roster_b,
        "federated approver roster state was not persisted",
    )

    # Jingle remains endpoint-to-endpoint signalling across federation. Both
    # servers validate the visible XEP-0166/0167/0176/0320 shape and domain
    # authorization, but neither server becomes the session or media endpoint.
    fingerprint = ":".join(["AA"] * 32)
    alice.send(
        "<iq xmlns='jabber:client' type='set' id='federated-jingle-init' "
        "to='bob_fed@remote.localhost/bob-federation'>"
        "<jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' sid='fed-call-1'>"
        "<content creator='initiator' name='audio'>"
        "<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'>"
        "<payload-type id='111' name='opus' clockrate='48000' channels='2'/><rtcp-mux/></description>"
        "<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1' pwd='opaque-pwd' ufrag='opaque-ufrag'>"
        f"<fingerprint xmlns='urn:xmpp:jingle:apps:dtls:0' hash='sha-256' setup='actpass'>{fingerprint}</fingerprint>"
        "<candidate component='1' foundation='1' generation='0' id='candidate-1' ip='10.0.0.7' port='50000' priority='1' protocol='udp' type='host'/>"
        "</transport></content></jingle></iq>"
    )
    federated_call, _ = bob.receive_until("federated-jingle-init", timeout=20)
    fixture.check(
        "urn:xmpp:jingle:apps:rtp:1" in federated_call
        and "urn:xmpp:jingle:transports:ice-udp:1" in federated_call
        and "urn:xmpp:jingle:apps:dtls:0" in federated_call
        and "from='alice_fed@localhost/alice-federation'" in federated_call
        and "to='bob_fed@remote.localhost/bob-federation'" in federated_call,
        f"federated exact-resource Jingle offer was altered: {federated_call}",
    )
    bob.send(
        "<iq xmlns='jabber:client' type='error' id='federated-jingle-init' "
        "to='alice_fed@localhost/alice-federation'>"
        "<jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' sid='fed-call-1'/>"
        "<error type='cancel'><item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
        "<unknown-session xmlns='urn:xmpp:jingle:errors:1'/></error></iq>"
    )
    federated_call_error, _ = alice.receive_until("federated-jingle-init", timeout=20)
    fixture.check(
        "type='error'" in federated_call_error
        and "unknown-session" in federated_call_error
        and "urn:xmpp:jingle:errors:1" in federated_call_error
        and "from='bob_fed@remote.localhost/bob-federation'" in federated_call_error,
        f"federated endpoint-owned Jingle error was not routed intact: {federated_call_error}",
    )
    alice.send(
        "<iq xmlns='jabber:client' type='set' id='federated-jingle-invalid-ice' "
        "to='bob_fed@remote.localhost/bob-federation'>"
        "<jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' sid='fed-call-invalid'>"
        "<content creator='initiator' name='audio'>"
        "<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/>"
        "<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'>"
        "<candidate component='1' foundation='1' generation='0' id='candidate-1' ip='10.0.0.7' port='50000' priority='1' protocol='udp' type='host'/>"
        "</transport></content></jingle></iq>"
    )
    invalid_federated_call, _ = alice.receive_until(
        "federated-jingle-invalid-ice", timeout=20
    )
    fixture.check(
        "type='error'" in invalid_federated_call and "bad-request" in invalid_federated_call,
        f"malformed federated ICE reached the remote endpoint: {invalid_federated_call}",
    )

    # Bypass the remote C2S validator once and inject the same malformed
    # stanza on an independently authenticated S2S stream. This proves the
    # recipient-domain boundary validates hostile federated XML as well. The
    # forced-Dialback variant exercises the ordinary two-server route above;
    # direct injection is available only in the EXTERNAL fixture.
    if os.environ.get("FEDERATION_TEST_EXTERNAL", "true").lower() == "true":
        cert_dir = pathlib.Path(os.environ["FEDERATION_TEST_CERT_DIR"])
        injected = open_direct_s2s(
            str(cert_dir / "federation-b.crt"), str(cert_dir / "federation-b.key")
        )
        try:
            authenticate_external(injected, "remote.localhost")
            injected.sendall(
                b"<iq xmlns='jabber:server' type='set' id='inbound-jingle-invalid-ice' "
                b"from='bob_fed@remote.localhost/bob-federation' "
                b"to='alice_fed@localhost/alice-federation'>"
                b"<jingle xmlns='urn:xmpp:jingle:1' action='session-initiate' sid='inbound-invalid'>"
                b"<content creator='initiator' name='audio'>"
                b"<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/>"
                b"<transport xmlns='urn:xmpp:jingle:transports:ice-udp:1'>"
                b"<candidate component='1' foundation='1' generation='0' id='candidate-1' "
                b"ip='10.0.0.7' port='50000' priority='1' protocol='udp' type='host'/>"
                b"</transport></content></jingle></iq>"
            )
            inbound_rejection = receive_tls_until(
                injected, "inbound-jingle-invalid-ice"
            )
            fixture.check(
                "type='error'" in inbound_rejection and "bad-request" in inbound_rejection,
                f"recipient domain accepted malformed inbound Jingle: {inbound_rejection}",
            )
        finally:
            injected.close()

    alice.send(
        "<message xmlns='jabber:client' to='bob_fed@remote.localhost' type='chat' id='federated-jmi'>"
        "<propose xmlns='urn:xmpp:jingle-message:0' id='fed-jmi-1'>"
        "<description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/></propose>"
        "<store xmlns='urn:xmpp:hints'/></message>"
    )
    federated_jmi, _ = bob.receive_until("federated-jmi", timeout=20)
    fixture.check(
        "urn:xmpp:jingle-message:0" in federated_jmi
        and "fed-jmi-1" in federated_jmi
        and "from='alice_fed@localhost/alice-federation'" in federated_jmi,
        f"federated XEP-0353 proposal was not routed: {federated_jmi}",
    )

    # Automatic XEP-0163 notification selection requires a verified
    # XEP-0115 `node+notify` capability. This lightweight fixture does not
    # emulate a disco-capable desktop client, so use the standard explicit
    # XEP-0060 subscription path; explicit subscriptions intentionally do
    # not depend on entity caps.
    alice.send(
        "<iq xmlns='jabber:client' type='set' id='remote-pep-subscribe' "
        "to='bob_fed@remote.localhost'><pubsub xmlns='http://jabber.org/protocol/pubsub'>"
        "<subscribe node='urn:xmpp:omemo:2:devices' jid='alice_fed@localhost'/></pubsub></iq>"
    )
    pep_subscription, _ = alice.receive_until("remote-pep-subscribe", timeout=20)
    fixture.check(
        "subscription='subscribed'" in pep_subscription,
        "federated explicit PEP subscription failed",
    )

    bob.send(
        "<iq xmlns='jabber:client' type='set' id='remote-pep-notify'>"
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:omemo:2:devices'>"
        "<item id='current'><devices xmlns='urn:xmpp:omemo:2'><device id='777'/><device id='778'/></devices></item>"
        "</publish></pubsub></iq>"
    )
    bob.receive_until("remote-pep-notify")
    pep_event, _ = alice.receive_until("device id='778'", timeout=20)
    fixture.check(
        "type='headline'" in pep_event
        and "from='bob_fed@remote.localhost'" in pep_event
        and "to='alice_fed@localhost'" in pep_event,
        "federated PEP notification was not addressed or delivered correctly",
    )

    endpoint(
        required_test_port("FEDERATION_TEST_HTTP_PORT_A"),
        required_test_port("FEDERATION_TEST_CLIENT_PORT_A"),
        "localhost",
    )
    alice_carbon = fixture.XmppWebSocket(ALICE, PASSWORD, "alice-federation-carbon")
    alice_carbon.send(
        "<iq xmlns='jabber:client' type='set' id='fed-carbon-enable-a'>"
        "<enable xmlns='urn:xmpp:carbons:2'/></iq>"
    )
    enabled_a, _ = alice_carbon.receive_until("fed-carbon-enable-a")
    fixture.check(
        "type='result'" in enabled_a
        and "from='alice_fed@localhost'" in enabled_a
        and "to='alice_fed@localhost/alice-federation-carbon'" in enabled_a,
        f"local federated Carbon resource was not enabled: {enabled_a}",
    )
    endpoint(
        required_test_port("FEDERATION_TEST_HTTP_PORT_B"),
        required_test_port("FEDERATION_TEST_CLIENT_PORT_B"),
        "remote.localhost",
    )
    bob_carbon = fixture.XmppWebSocket(BOB, PASSWORD, "bob-federation-carbon")
    bob_carbon.send(
        "<iq xmlns='jabber:client' type='set' id='fed-carbon-enable-b'>"
        "<enable xmlns='urn:xmpp:carbons:2'/></iq>"
    )
    enabled_b, _ = bob_carbon.receive_until("fed-carbon-enable-b")
    fixture.check(
        "type='result'" in enabled_b
        and "from='bob_fed@remote.localhost'" in enabled_b
        and "to='bob_fed@remote.localhost/bob-federation-carbon'" in enabled_b,
        f"remote federated Carbon resource was not enabled: {enabled_b}",
    )

    alice.send(
        "<message xmlns='jabber:client' to='bob_fed@remote.localhost' type='chat' id='fed-a-b'>"
        + fixture.omemo2_envelope(
            111,
            [("alice_fed@localhost", [111]), ("bob_fed@remote.localhost", [777])],
            "FEDERATED-CIPHERTEXT-A",
        )
        +
        "<origin-id xmlns='urn:xmpp:sid:0' id='federated-origin-a'/>"
        "<stanza-id xmlns='urn:xmpp:sid:0' id='spoof-a' by='alice_fed@localhost'/>"
        "<stanza-id xmlns='urn:xmpp:sid:0' id='spoof-b' by='bob_fed@remote.localhost'/>"
        "<request xmlns='urn:xmpp:receipts'/>"
        "</message>"
    )
    inbound, _ = bob.receive_until("fed-a-b", timeout=20)
    fixture.check(
        fixture.omemo_payload_b64("FEDERATED-CIPHERTEXT-A") in inbound
        and "alice_fed@localhost" in inbound
        and "federated-origin-a" in inbound
        and "spoof-a" not in inbound
        and "spoof-b" not in inbound
        # The durable sender outbox and the receiving server each add one
        # authoritative XEP-0359 stanza-id. Client-forged IDs for either
        # authority were removed above and must never survive federation.
        and inbound.count("<stanza-id") == 2
        and "by='alice_fed@localhost'" in inbound
        and "by='bob_fed@remote.localhost'" in inbound,
        f"A-to-B federated message failed: {inbound}",
    )
    sent_carbon, _ = alice_carbon.receive_until("fed-a-b", timeout=20)
    received_carbon, _ = bob_carbon.receive_until("fed-a-b", timeout=20)
    fixture.check(
        "<sent xmlns='urn:xmpp:carbons:2'>" in sent_carbon
        and fixture.omemo_payload_b64("FEDERATED-CIPHERTEXT-A") in sent_carbon,
        f"federated sender resource did not receive the ciphertext Carbon: {sent_carbon}",
    )
    fixture.check(
        "<received xmlns='urn:xmpp:carbons:2'>" in received_carbon
        and fixture.omemo_payload_b64("FEDERATED-CIPHERTEXT-A") in received_carbon,
        f"federated recipient resource did not receive the ciphertext Carbon: {received_carbon}",
    )

    # An explicit XEP-0334 no-store message must never enter the durable S2S
    # outbox. Install a database rejection probe after the authenticated A->B
    # stream exists: the message can arrive only through that live stream.
    schema_a = os.environ.get("FEDERATION_TEST_SCHEMA_A", "")
    schema_b = os.environ.get("FEDERATION_TEST_SCHEMA_B", "")
    marker = "fed-no-store-persistence-probe"
    no_store_guard = f"""
        CREATE OR REPLACE FUNCTION reject_federated_no_store_outbox()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF position('{marker}' in NEW.stanza) > 0 THEN
                RAISE EXCEPTION 'no-store stanza entered durable S2S outbox';
            END IF;
            RETURN NEW;
        END;
        $$;
        DROP TRIGGER IF EXISTS reject_federated_no_store_outbox ON s2s_outbox;
        CREATE TRIGGER reject_federated_no_store_outbox
        BEFORE INSERT ON s2s_outbox
        FOR EACH ROW EXECUTE FUNCTION reject_federated_no_store_outbox();
    """
    psql_schema(schema_a, no_store_guard)
    try:
        alice.send(
            f"<message xmlns='jabber:client' to='bob_fed@remote.localhost' "
            f"type='chat' id='{marker}'>"
            + fixture.omemo2_envelope(
                111,
                [("alice_fed@localhost", [111]), ("bob_fed@remote.localhost", [777])],
                "FEDERATED-NO-STORE-CIPHERTEXT",
            )
            + "<origin-id xmlns='urn:xmpp:sid:0' id='federated-no-store-origin'/>"
            "<no-store xmlns='urn:xmpp:hints'/></message>"
        )
        no_store_inbound, _ = bob.receive_until(marker, timeout=20)
        fixture.check(
            fixture.omemo_payload_b64("FEDERATED-NO-STORE-CIPHERTEXT")
            in no_store_inbound
            and "<no-store xmlns='urn:xmpp:hints'" in no_store_inbound,
            f"federated no-store message did not use the live S2S route: {no_store_inbound}",
        )
        no_store_sent_carbon, _ = alice_carbon.receive_until(marker, timeout=20)
        no_store_received_carbon, _ = bob_carbon.receive_until(marker, timeout=20)
        fixture.check(
            "<sent xmlns='urn:xmpp:carbons:2'>" in no_store_sent_carbon
            and "<received xmlns='urn:xmpp:carbons:2'>" in no_store_received_carbon,
            "federated no-store message did not preserve online Carbons",
        )

        for schema in (schema_a, schema_b):
            persisted_no_store = psql_schema(
                schema,
                f"""
                SELECT
                    (SELECT COUNT(*) FROM s2s_outbox WHERE stanza LIKE '%{marker}%') +
                    (SELECT COUNT(*) FROM message_archive WHERE stanza LIKE '%{marker}%') +
                    (SELECT COUNT(*) FROM offline_messages WHERE stanza LIKE '%{marker}%') +
                    (SELECT COUNT(*) FROM information_schema.columns
                        WHERE table_schema=current_schema()
                          AND table_name='personal_message_admissions'
                          AND column_name='payload_value');
                """,
            ).strip()
            fixture.check(
                persisted_no_store == "0",
                f"federated no-store content persisted in schema {schema}: {persisted_no_store}",
            )
    finally:
        psql_schema(
            schema_a,
            "DROP TRIGGER IF EXISTS reject_federated_no_store_outbox ON s2s_outbox; "
            "DROP FUNCTION IF EXISTS reject_federated_no_store_outbox();",
        )

    # REQUIRE_ENCRYPTED_ARCHIVE is enabled for both fixture servers. A
    # plaintext message therefore has no personal MAM projection, but its
    # origin-id still has to be admitted atomically with the durable S2S
    # outbox row. This is the wire-level regression for migration 0081.
    plaintext_origin = (
        "<message xmlns='jabber:client' to='bob_fed@remote.localhost' "
        "type='chat' id='fed-plaintext-origin'>"
        "<body>FEDERATED-PLAINTEXT-ORIGIN</body>"
        "<origin-id xmlns='urn:xmpp:sid:0' id='federated-plaintext-origin'/>"
        "</message>"
    )
    alice.send(plaintext_origin)
    plaintext_inbound, _ = bob.receive_until("FEDERATED-PLAINTEXT-ORIGIN", timeout=20)
    fixture.check(
        "from='alice_fed@localhost/alice-federation'" in plaintext_inbound
        and "federated-plaintext-origin" in plaintext_inbound,
        f"plaintext origin-id message did not cross federation: {plaintext_inbound}",
    )
    plaintext_sent_carbon, _ = alice_carbon.receive_until(
        "FEDERATED-PLAINTEXT-ORIGIN", timeout=20
    )
    plaintext_received_carbon, _ = bob_carbon.receive_until(
        "FEDERATED-PLAINTEXT-ORIGIN", timeout=20
    )
    fixture.check(
        "<sent xmlns='urn:xmpp:carbons:2'>" in plaintext_sent_carbon
        and "<received xmlns='urn:xmpp:carbons:2'>" in plaintext_received_carbon,
        "plaintext origin-id message did not produce federated Carbons",
    )

    alice.send(plaintext_origin)
    try:
        duplicate_plaintext = bob.receive(1)
        fixture.check(
            "FEDERATED-PLAINTEXT-ORIGIN" not in duplicate_plaintext,
            f"exact plaintext origin-id replay crossed federation: {duplicate_plaintext}",
        )
    except (TimeoutError, socket.timeout):
        pass

    alice.send(
        "<message xmlns='jabber:client' to='bob_fed@remote.localhost' "
        "type='chat' id='fed-plaintext-conflict'>"
        "<body>CHANGED-FEDERATED-PLAINTEXT</body>"
        "<origin-id xmlns='urn:xmpp:sid:0' id='federated-plaintext-origin'/>"
        "</message>"
    )
    plaintext_conflict, _ = alice.receive_until("fed-plaintext-conflict", timeout=20)
    fixture.check(
        "type='error'" in plaintext_conflict and "<conflict" in plaintext_conflict,
        f"changed plaintext payload reused an origin-id: {plaintext_conflict}",
    )

    bob.send(
        "<message xmlns='jabber:client' to='alice_fed@localhost' type='chat' id='fed-receipt'>"
        "<received xmlns='urn:xmpp:receipts' id='fed-a-b'/></message>"
    )
    receipt, _ = alice.receive_until("fed-receipt", timeout=20)
    receipt_sent_carbon, _ = bob_carbon.receive_until("fed-receipt", timeout=20)
    receipt_received_carbon, _ = alice_carbon.receive_until("fed-receipt", timeout=20)
    fixture.check(
        "<received xmlns='urn:xmpp:receipts' id='fed-a-b'" in receipt
        and "<sent xmlns='urn:xmpp:carbons:2'>" in receipt_sent_carbon
        and "<received xmlns='urn:xmpp:carbons:2'>" in receipt_received_carbon,
        "XEP-0184 receipt or its required rules:0 Carbons did not cross federation",
    )

    alice.send(
        "<message xmlns='jabber:client' to='bob_fed@remote.localhost/bob-federation' type='chat' id='fed-private'>"
        + fixture.omemo2_envelope(
            111,
            [("alice_fed@localhost", [111]), ("bob_fed@remote.localhost", [777])],
            "PRIVATE-CIPHERTEXT",
        )
        +
        "<private xmlns='urn:xmpp:carbons:2'/></message>"
    )
    bob.receive_until("fed-private", timeout=20)
    for carbon_client, direction in (
        (alice_carbon, "sender"),
        (bob_carbon, "recipient"),
    ):
        try:
            private_copy = carbon_client.receive(1)
            fixture.check(
                "fed-private" not in private_copy,
                f"private federated message leaked a {direction} Carbon: {private_copy}",
            )
        except (TimeoutError, socket.timeout):
            pass

    alice_carbon.send(
        "<iq xmlns='jabber:client' type='set' id='fed-carbon-privacy-list'>"
        "<query xmlns='jabber:iq:privacy'><list name='fed-carbon-deny'>"
        "<item type='jid' value='bob_fed@remote.localhost' action='deny' order='1'><message/></item>"
        "</list></query></iq>"
    )
    privacy_list, _ = alice_carbon.receive_until("fed-carbon-privacy-list")
    fixture.check("type='result'" in privacy_list, "Carbon privacy-list definition failed")
    alice_carbon.send(
        "<iq xmlns='jabber:client' type='set' id='fed-carbon-privacy-active'>"
        "<query xmlns='jabber:iq:privacy'><active name='fed-carbon-deny'/></query></iq>"
    )
    privacy_active, _ = alice_carbon.receive_until("fed-carbon-privacy-active")
    fixture.check("type='result'" in privacy_active, "Carbon privacy-list activation failed")
    bob.send(
        "<message xmlns='jabber:client' to='alice_fed@localhost' type='chat' id='fed-b-a'>"
        + fixture.omemo2_envelope(
            777,
            [("alice_fed@localhost", [111]), ("bob_fed@remote.localhost", [777])],
            "FEDERATED-CIPHERTEXT-B",
        )
        + "</message>"
    )
    reply, _ = alice.receive_until("fed-b-a", timeout=20)
    fixture.check(
        fixture.omemo_payload_b64("FEDERATED-CIPHERTEXT-B") in reply
        and "bob_fed@remote.localhost" in reply,
        "B-to-A federated message failed",
    )
    bob_carbon.receive_until("fed-b-a", timeout=20)
    try:
        denied_carbon = alice_carbon.receive(1)
        fixture.check(
            "fed-b-a" not in denied_carbon,
            f"received Carbon bypassed the resource active privacy list: {denied_carbon}",
        )
    except (TimeoutError, socket.timeout):
        pass
    alice_carbon.close()
    bob_carbon.close()

    bob.send(
        "<iq xmlns='jabber:client' type='set' id='fed-block-alice'>"
        "<block xmlns='urn:xmpp:blocking'><item jid='alice_fed@localhost'/></block></iq>"
    )
    blocked, _ = bob.receive_until("fed-block-alice")
    fixture.check("type='result'" in blocked, "federated contact could not be blocked")
    unavailable = ""
    unavailable_frames = []
    unavailable_deadline = time.monotonic() + 20
    while time.monotonic() < unavailable_deadline:
        try:
            frame = alice.receive(max(0.1, unavailable_deadline - time.monotonic()))
        except (TimeoutError, socket.timeout):
            break
        unavailable_frames.append(frame)
        if (
            "<presence" in frame
            and "type='unavailable'" in frame
            and "from='bob_fed@remote.localhost" in frame
        ):
            unavailable = frame
            break
    fixture.check(
        bool(unavailable),
        f"cross-domain block did not send unavailable presence: {unavailable_frames}",
    )
    alice.send(
        "<iq xmlns='jabber:client' type='get' id='fed-blocked-inbound-iq' "
        "to='bob_fed@remote.localhost/bob-federation'><ping xmlns='urn:xmpp:ping'/></iq>"
    )
    hidden, _ = alice.receive_until("fed-blocked-inbound-iq", timeout=20)
    fixture.check("service-unavailable" in hidden, "cross-domain inbound IQ bypassed block")
    bob.send(
        "<iq xmlns='jabber:client' type='get' id='fed-blocked-outbound-iq' "
        "to='alice_fed@localhost'><ping xmlns='urn:xmpp:ping'/></iq>"
    )
    denied, _ = bob.receive_until("fed-blocked-outbound-iq")
    fixture.check(
        "not-acceptable" in denied and "urn:xmpp:blocking:errors" in denied,
        "cross-domain outbound IQ bypassed block",
    )
    bob.send(
        "<iq xmlns='jabber:client' type='set' id='fed-unblock-alice'>"
        "<unblock xmlns='urn:xmpp:blocking'><item jid='alice_fed@localhost'/></unblock></iq>"
    )
    bob.receive_until("fed-unblock-alice")
    available = ""
    available_frames = []
    available_deadline = time.monotonic() + 20
    while time.monotonic() < available_deadline:
        try:
            frame = alice.receive(max(0.1, available_deadline - time.monotonic()))
        except (TimeoutError, socket.timeout):
            break
        available_frames.append(frame)
        if (
            "<presence" in frame
            and "from='bob_fed@remote.localhost" in frame
            and "type='unavailable'" not in frame
        ):
            available = frame
            break
    fixture.check(
        bool(available),
        f"cross-domain unblock did not restore presence: {available_frames}",
    )

    bob.send(
        "<iq xmlns='jabber:client' type='set' id='fed-push-enable'>"
        "<enable xmlns='urn:xmpp:push:0' jid='alice_fed@localhost' node='fed-push-node'/></iq>"
    )
    push_enabled, _ = bob.receive_until("fed-push-enable")
    fixture.check(
        "type='result'" in push_enabled,
        f"remote account could not enable a federated XEP-0357 service: {push_enabled}",
    )

    bob.close()
    time.sleep(0.3)
    alice.send(
        "<message xmlns='jabber:client' to='bob_fed@remote.localhost' type='chat' id='fed-offline'>"
        + fixture.omemo2_envelope(
            111,
            [("alice_fed@localhost", [111]), ("bob_fed@remote.localhost", [777])],
            "FEDERATED-OFFLINE-CIPHERTEXT",
        )
        + "</message>"
    )
    federated_push, _ = alice.receive_until("fed-push-node", timeout=20)
    fixture.check(
        "urn:xmpp:push:summary" in federated_push
        and "<value>1</value>" in federated_push
        and fixture.omemo_payload_b64("FEDERATED-OFFLINE-CIPHERTEXT") not in federated_push
        and "FEDERATED-PLAINTEXT-LEAK" not in federated_push
        and "alice_fed@localhost" not in federated_push.split("<notification", 1)[-1],
        f"federated Push was missing or leaked message metadata: {federated_push}",
    )
    federated_push_id = re.search(r"id='(push-[^']+)'", federated_push)
    fixture.check(federated_push_id is not None, "federated Push correlation id was missing")
    alice.send(
        f"<iq xmlns='jabber:client' type='result' id='{federated_push_id.group(1)}' "
        "to='remote.localhost'/>"
    )
    endpoint(
        required_test_port("FEDERATION_TEST_HTTP_PORT_B"),
        required_test_port("FEDERATION_TEST_CLIENT_PORT_B"),
        "remote.localhost",
    )
    bob = fixture.XmppWebSocket(BOB, PASSWORD, "bob-federation-reconnected")
    offline, _ = bob.receive_until("fed-offline", timeout=20)
    fixture.check(
        fixture.omemo_payload_b64("FEDERATED-OFFLINE-CIPHERTEXT") in offline
        and "FEDERATED-PLAINTEXT-LEAK" not in offline,
        "federated encrypted offline storage leaked plaintext or lost ciphertext",
    )

    bob.close()
    alice.close()
    authentication = (
        "SASL EXTERNAL"
        if os.environ.get("S2S_SASL_EXTERNAL_ENABLED", "true").lower() == "true"
        else "TLS-protected callback-verified XEP-0220 Dialback"
    )
    print(
        "federation: randomized listeners and schemas, C2S/S2S TLS 1.2/1.3, ALPN, "
        "Direct TLS SNI and stream/framing/size boundaries, DNS override, STARTTLS, "
        f"certificate validation, {authentication}, generic PubSub approval/events/retrieval, PEP/vCard IQ, "
        "cross-domain PEP notifications, blocking, stable stanza IDs, presence "
        "subscriptions, bidirectional and offline messaging passed"
    )


if __name__ == "__main__":
    run()
