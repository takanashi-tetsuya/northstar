#!/usr/bin/env python3
"""Single-node 1,000-session design-envelope probe.

This is deliberately a validation workload, not an SLA or a production
capacity guarantee. Thresholds are conservative defaults and can be tightened
for the deployment host through XMPP_LOAD_* environment variables.
"""

from __future__ import annotations

import base64
import concurrent.futures
import importlib.util
import json
import os
import pathlib
import random
import re
import socket
import ssl
import statistics
import threading
import time


ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("northstar_integration", ROOT / "integration-wsl.py")
fixture = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(fixture)

USERNAME = os.environ["XMPP_LOAD_USERNAME"]
SENDER = os.environ["XMPP_LOAD_SENDER_USERNAME"]
PASSWORD = os.environ["XMPP_LOAD_PASSWORD"]
SERVER_PID = int(os.environ["XMPP_LOAD_SERVER_PID"])
CA_CERT = os.environ["XMPP_LOAD_CA_CERT"]
SESSION_COUNT = int(os.environ.get("XMPP_LOAD_SESSIONS", "1000"))
WORKERS = int(os.environ.get("XMPP_LOAD_WORKERS", "64"))
TLS_SAMPLES = int(os.environ.get("XMPP_LOAD_TLS_SAMPLES", "32"))
RESUME_COUNT = int(os.environ.get("XMPP_LOAD_RESUME_COUNT", "100"))
OVERLOAD_ATTEMPTS = int(os.environ.get("XMPP_LOAD_OVERLOAD_ATTEMPTS", "32"))
MAX_CONNECTIONS = int(os.environ.get("XMPP_LOAD_MAX_CONNECTIONS", "1005"))


def limit(name: str, default: float) -> float:
    return float(os.environ.get(name, str(default)))


LIMITS = {
    "tls_transport_p50": limit("XMPP_LOAD_MAX_TLS_TRANSPORT_P50_SECONDS", 2),
    "tls_transport_p95": limit("XMPP_LOAD_MAX_TLS_TRANSPORT_P95_SECONDS", 5),
    "tls_transport_p99": limit("XMPP_LOAD_MAX_TLS_TRANSPORT_P99_SECONDS", 10),
    "tls_auth_p50": limit("XMPP_LOAD_MAX_TLS_AUTH_P50_SECONDS", 10),
    "tls_auth_p95": limit("XMPP_LOAD_MAX_TLS_AUTH_P95_SECONDS", 20),
    "tls_auth_p99": limit("XMPP_LOAD_MAX_TLS_AUTH_P99_SECONDS", 30),
    "ws_p50": limit("XMPP_LOAD_MAX_WS_P50_SECONDS", 15),
    "ws_p95": limit("XMPP_LOAD_MAX_WS_P95_SECONDS", 45),
    "ws_p99": limit("XMPP_LOAD_MAX_WS_P99_SECONDS", 60),
    "ramp": limit("XMPP_LOAD_MAX_RAMP_SECONDS", 120),
    "message_p50": limit("XMPP_LOAD_MAX_MESSAGE_P50_SECONDS", 5),
    "message_p95": limit("XMPP_LOAD_MAX_MESSAGE_P95_SECONDS", 15),
    "message_p99": limit("XMPP_LOAD_MAX_MESSAGE_P99_SECONDS", 30),
    "message_rate": limit("XMPP_LOAD_MIN_MESSAGES_PER_SECOND", 20),
    "rss_mib": limit("XMPP_LOAD_MAX_RSS_MIB", 2048),
    "fds": limit("XMPP_LOAD_MAX_FDS", 2500),
    "retained_rss_mib": limit("XMPP_LOAD_MAX_RETAINED_RSS_MIB", 512),
    "overload_rejection": limit("XMPP_LOAD_MAX_OVERLOAD_REJECTION_SECONDS", 15),
}


def percentile(values: list[float], percentile_value: float) -> float:
    fixture.check(bool(values), "cannot calculate a percentile from no samples")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * percentile_value + 0.999999)))
    return ordered[index]


def summary(values: list[float]) -> dict[str, float]:
    return {
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": max(values),
        "mean": statistics.fmean(values),
    }


def assert_summary(label: str, measured: dict[str, float], prefix: str) -> None:
    for percentile_name in ("p50", "p95", "p99"):
        threshold = LIMITS[f"{prefix}_{percentile_name}"]
        fixture.check(
            measured[percentile_name] <= threshold,
            f"{label} {percentile_name} {measured[percentile_name]:.3f}s exceeded "
            f"the {threshold:.3f}s design threshold",
        )


def metrics() -> dict[str, float]:
    status, body = fixture.metrics_api()
    fixture.check(status == 200, f"metrics endpoint failed during load: {status}")
    values: dict[str, float] = {}
    for name, value in re.findall(r"^([a-zA-Z_:][a-zA-Z0-9_:]*) ([0-9.eE+-]+)$", body, re.MULTILINE):
        values[name] = float(value)
    return values


def wait_metric(name: str, expected: int, timeout: float = 30) -> dict[str, float]:
    deadline = time.monotonic() + timeout
    last: dict[str, float] = {}
    while time.monotonic() < deadline:
        last = metrics()
        if int(last.get(name, -1)) == expected:
            return last
        time.sleep(0.1)
    raise AssertionError(f"{name} did not reach {expected}: {last.get(name)}")


class ProcessSampler:
    def __init__(self, pid: int):
        self.pid = pid
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="northstar-process-sampler", daemon=True)
        self.samples: list[tuple[float, int, int, float]] = []
        self._previous: tuple[float, int] | None = None
        self.clock_ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])

    def read(self) -> tuple[float, int, int, float]:
        now = time.monotonic()
        status = pathlib.Path(f"/proc/{self.pid}/status").read_text(encoding="utf-8")
        rss_match = re.search(r"^VmRSS:\s+(\d+)\s+kB$", status, re.MULTILINE)
        fixture.check(rss_match is not None, "server VmRSS was unavailable")
        rss_kib = int(rss_match.group(1))
        fds = len(list(pathlib.Path(f"/proc/{self.pid}/fd").iterdir()))
        fields = pathlib.Path(f"/proc/{self.pid}/stat").read_text(encoding="utf-8").split()
        ticks = int(fields[13]) + int(fields[14])
        cpu_percent = 0.0
        if self._previous is not None:
            previous_time, previous_ticks = self._previous
            elapsed = now - previous_time
            if elapsed > 0:
                cpu_percent = ((ticks - previous_ticks) / self.clock_ticks) / elapsed * 100
        self._previous = (now, ticks)
        sample = (now, rss_kib, fds, cpu_percent)
        self.samples.append(sample)
        return sample

    def _run(self) -> None:
        while not self.stop_event.wait(0.2):
            try:
                self.read()
            except (FileNotFoundError, ProcessLookupError):
                return

    def start(self) -> tuple[float, int, int, float]:
        baseline = self.read()
        self.thread.start()
        return baseline

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=5)
        fixture.check(not self.thread.is_alive(), "server process sampler did not stop")
        self.read()


class MetricSampler:
    def __init__(self):
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="northstar-metric-sampler", daemon=True)
        self.samples: list[dict[str, float]] = []
        self.errors: list[str] = []

    def read(self) -> None:
        self.samples.append(metrics())

    def _run(self) -> None:
        while not self.stop_event.wait(1):
            try:
                self.read()
            except (AssertionError, ConnectionError, EOFError, OSError, TimeoutError) as error:
                self.errors.append(repr(error))

    def start(self) -> None:
        self.read()
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=15)
        fixture.check(not self.thread.is_alive(), "metrics sampler did not stop")
        self.read()
        fixture.check(not self.errors, f"metrics sampling failed during load: {self.errors}")


def direct_tls_login(sample: int) -> float:
    context = ssl.create_default_context(cafile=CA_CERT)
    context.set_alpn_protocols(["xmpp-client"])
    raw = socket.create_connection((fixture.HTTP_HOST, fixture.XMPPS_PORT), timeout=20)
    tls_started = time.monotonic()
    secure = context.wrap_socket(raw, server_hostname=fixture.DOMAIN)
    tls_elapsed = time.monotonic() - tls_started
    try:
        fixture.check(secure.selected_alpn_protocol() == "xmpp-client", "direct TLS ALPN failed")
        stream = (
            f"<stream:stream to='{fixture.DOMAIN}' version='1.0' xmlns='jabber:client' "
            "xmlns:stream='http://etherx.jabber.org/streams'>"
        ).encode()
        secure.sendall(stream)
        features = fixture.read_until(secure, b"</stream:features>", timeout=20)
        fixture.check(b"<mechanism>PLAIN</mechanism>" in features, "direct TLS SASL PLAIN missing")
        encoded = base64.b64encode(f"\0{USERNAME}\0{PASSWORD}".encode()).decode()
        secure.sendall(
            f"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{encoded}</auth>".encode()
        )
        fixture.check(b"<success" in fixture.read_until(secure, b"/>", timeout=20),
                      "direct TLS authentication failed")
        secure.sendall(stream)
        fixture.read_until(secure, b"</stream:features>", timeout=20)
        bind_id = f"load-tls-{sample}"
        secure.sendall(
            f"<iq type='set' id='{bind_id}'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
            f"<resource>{bind_id}</resource></bind></iq>".encode()
        )
        bound = fixture.read_until(secure, b"</iq>", timeout=20)
        fixture.check(bind_id.encode() in bound and b"type='result'" in bound,
                      "direct TLS resource binding failed")
    finally:
        secure.close()
    return tls_elapsed


def timed_tls(sample: int) -> tuple[float, float]:
    started = time.monotonic()
    transport_elapsed = direct_tls_login(sample)
    return transport_elapsed, time.monotonic() - started


def timed_websocket(index: int, resource_prefix: str = "load") -> tuple[int, object, float]:
    started = time.monotonic()
    session = fixture.XmppWebSocket(
        USERNAME, PASSWORD, f"{resource_prefix}-{index}", initial_presence=False
    )
    return index, session, time.monotonic() - started


def fanout(sender, sessions: list[object]) -> tuple[dict[str, float], float]:
    nonce = random.SystemRandom().randrange(1 << 63)
    sent: dict[str, float] = {}
    started = time.monotonic()
    for index in range(len(sessions)):
        marker = f"load-message-{nonce}-{index}"
        sent[marker] = time.monotonic()
        sender.send(
            f"<message xmlns='jabber:client' type='chat' "
            f"to='{USERNAME}@{fixture.DOMAIN}/load-{index}' id='{marker}'>"
            f"<body>{marker}</body><no-store xmlns='urn:xmpp:hints'/></message>"
        )

    def receive(index: int) -> float:
        marker = f"load-message-{nonce}-{index}"
        frame, _ = sessions[index].receive_until(marker, timeout=60)
        fixture.check(marker in frame, f"message for load-{index} was not delivered")
        return time.monotonic() - sent[marker]

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        latencies = list(executor.map(receive, range(len(sessions))))
    elapsed = time.monotonic() - started
    return summary(latencies), len(sessions) / elapsed


def resume_random_sessions(sessions: list[object]) -> None:
    chosen = random.SystemRandom().sample(range(len(sessions)), RESUME_COUNT)
    resume_ids: dict[int, str] = {}
    for index in chosen:
        sessions[index].send("<enable xmlns='urn:xmpp:sm:3' resume='true'/>")
        enabled, _ = sessions[index].receive_until("<enabled ", timeout=20)
        match = re.search(r"\bid='([^']+)'", enabled)
        fixture.check(match is not None and "resume='true'" in enabled,
                      f"load-{index} did not enable resumable SM")
        resume_ids[index] = match.group(1)
    wait_metric("xmpp_resumable_sessions", RESUME_COUNT)
    for index in chosen:
        sessions[index].abort()

    def resume(index: int) -> tuple[int, object]:
        replacement = fixture.XmppWebSocket(
            USERNAME,
            PASSWORD,
            f"ignored-resume-{index}",
            resume=(resume_ids[index], 0),
            initial_presence=False,
        )
        ping_id = f"load-resume-ping-{index}"
        replacement.send(
            f"<iq xmlns='jabber:client' type='get' id='{ping_id}'>"
            "<ping xmlns='urn:xmpp:ping'/></iq>"
        )
        reply, _ = replacement.receive_until(ping_id, timeout=20)
        fixture.check("type='result'" in reply,
                      f"load-{index} was not usable after SM resume")
        return index, replacement

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(WORKERS, RESUME_COUNT)) as executor:
        for index, replacement in executor.map(resume, chosen):
            sessions[index] = replacement


def overload_and_recover() -> dict[str, float]:
    accepted: list[object] = []
    rejected_latencies: list[float] = []

    def attempt(index: int) -> tuple[object | None, float, bool]:
        started = time.monotonic()
        try:
            session = fixture.XmppWebSocket(
                USERNAME, PASSWORD, f"overload-{index}", initial_presence=False
            )
            return session, time.monotonic() - started, False
        except AssertionError as error:
            explicit_503 = "HTTP/1.1 503" in str(error)
            fixture.check(explicit_503, f"overload attempt failed for an unexpected reason: {error}")
            return None, time.monotonic() - started, True

    with concurrent.futures.ThreadPoolExecutor(max_workers=OVERLOAD_ATTEMPTS) as executor:
        results = list(executor.map(attempt, range(OVERLOAD_ATTEMPTS)))
    for session, elapsed, explicitly_rejected in results:
        if explicitly_rejected:
            rejected_latencies.append(elapsed)
        else:
            fixture.check(session is not None, "overload admission returned no session")
            accepted.append(session)
    fixture.check(rejected_latencies, "connection overload produced no bounded rejection")
    fixture.check(
        percentile(rejected_latencies, 0.95) <= LIMITS["overload_rejection"],
        "overload rejection was not prompt",
    )
    peak = metrics()
    fixture.check(int(peak["xmpp_active_sessions"]) <= MAX_CONNECTIONS,
                  f"active sessions exceeded configured capacity: {peak['xmpp_active_sessions']}")
    for session in accepted:
        session.close()
    wait_metric("xmpp_active_sessions", SESSION_COUNT + 1)
    recovery = fixture.XmppWebSocket(USERNAME, PASSWORD, "overload-recovery", initial_presence=False)
    fixture.check(int(wait_metric("xmpp_active_sessions", SESSION_COUNT + 2)["xmpp_active_sessions"])
                  == SESSION_COUNT + 2, "server did not admit a connection after overload drained")
    recovery.close()
    wait_metric("xmpp_active_sessions", SESSION_COUNT + 1)
    return {
        "accepted": float(len(accepted)),
        "rejected": float(len(rejected_latencies)),
        "rejection_p95": percentile(rejected_latencies, 0.95),
    }


def run() -> None:
    fixture.check(SESSION_COUNT == 1000, "this design-envelope probe requires exactly 1000 sessions")
    fixture.check(1 <= RESUME_COUNT <= SESSION_COUNT, "invalid SM resume sample size")
    fixture.check(WORKERS >= 1, "load worker count must be positive")
    fixture.check(TLS_SAMPLES >= 20, "at least 20 direct TLS samples are required")
    fixture.check(OVERLOAD_ATTEMPTS > MAX_CONNECTIONS - (SESSION_COUNT + 1),
                  "overload attempts must exceed the remaining connection capacity")
    for prefix in ("tls_transport", "tls_auth", "ws", "message"):
        fixture.check(
            0 < LIMITS[f"{prefix}_p50"] <= LIMITS[f"{prefix}_p95"]
            <= LIMITS[f"{prefix}_p99"],
            f"invalid monotonic {prefix} percentile thresholds",
        )
    fixture.check(all(value > 0 for value in LIMITS.values()),
                  "all load envelope thresholds must be positive")
    fixture.wait_ready()
    for username in (USERNAME, SENDER):
        status, result = fixture.register_account(username, PASSWORD)
        fixture.check(status == 201, f"load registration failed for {username}: {status} {result}")

    # Do not let the asynchronous database collector's first tick appear as a
    # load-induced outage in the sampled health minimum.
    baseline_metrics = wait_metric("xmpp_database_collector_up", 1)
    fixture.check(int(baseline_metrics.get("xmpp_database_up", 0)) == 1,
                  "database was unavailable before load")
    sampler = ProcessSampler(SERVER_PID)
    baseline = sampler.start()
    metric_sampler = MetricSampler()
    metric_sampler.start()
    sessions: list[object | None] = [None] * SESSION_COUNT
    sender = None
    completed = False
    results: dict[str, object] = {}
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, TLS_SAMPLES)) as executor:
            tls_timings = list(executor.map(timed_tls, range(TLS_SAMPLES)))
        tls_transport_summary = summary([timing[0] for timing in tls_timings])
        tls_auth_summary = summary([timing[1] for timing in tls_timings])
        assert_summary("direct TLS transport handshake", tls_transport_summary, "tls_transport")
        assert_summary("direct TLS authentication", tls_auth_summary, "tls_auth")
        results["direct_tls_transport_seconds"] = tls_transport_summary
        results["direct_tls_authentication_seconds"] = tls_auth_summary
        # Do not let asynchronous disconnect processing from the TLS sample
        # consume admission slots or contaminate the 1,000-session ramp.
        wait_metric("xmpp_active_sessions", 0)

        ramp_started = time.monotonic()
        websocket_latencies: list[float] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
            futures = [executor.submit(timed_websocket, index) for index in range(SESSION_COUNT)]
            for future in concurrent.futures.as_completed(futures):
                index, session, elapsed = future.result()
                sessions[index] = session
                websocket_latencies.append(elapsed)
        ramp_elapsed = time.monotonic() - ramp_started
        fixture.check(ramp_elapsed <= LIMITS["ramp"],
                      f"1000-session ramp {ramp_elapsed:.3f}s exceeded {LIMITS['ramp']:.3f}s")
        websocket_summary = summary(websocket_latencies)
        assert_summary("WebSocket authentication", websocket_summary, "ws")
        wait_metric("xmpp_active_sessions", SESSION_COUNT)
        results["websocket_seconds"] = websocket_summary
        results["ramp_seconds"] = ramp_elapsed

        sender = fixture.XmppWebSocket(SENDER, PASSWORD, "load-sender", initial_presence=False)
        wait_metric("xmpp_active_sessions", SESSION_COUNT + 1)
        complete_sessions = [session for session in sessions if session is not None]
        fixture.check(len(complete_sessions) == SESSION_COUNT, "a load session slot was empty")
        message_summary, message_rate = fanout(sender, complete_sessions)
        assert_summary("full-JID message round trip", message_summary, "message")
        fixture.check(message_rate >= LIMITS["message_rate"],
                      f"message throughput {message_rate:.2f}/s was below {LIMITS['message_rate']:.2f}/s")
        results["message_seconds"] = message_summary
        results["messages_per_second"] = message_rate

        resume_random_sessions(complete_sessions)
        sessions = complete_sessions
        wait_metric("xmpp_active_sessions", SESSION_COUNT + 1)
        results["sm_resumed_sessions"] = RESUME_COUNT
        results["overload"] = overload_and_recover()

        peak_metrics = metrics()
        fixture.check(int(peak_metrics["xmpp_active_sessions"]) == SESSION_COUNT + 1,
                      "load population was not stable after overload recovery")
        fixture.check(int(peak_metrics.get("xmpp_database_up", 0)) == 1,
                      "database became unavailable during load")
        fixture.check(int(peak_metrics.get("xmpp_database_collector_up", 0)) == 1,
                      "database metrics collector failed during load")
        fixture.check(
            peak_metrics["xmpp_database_pool_connections"]
            <= peak_metrics["xmpp_database_pool_max_connections"],
            "database pool exceeded its configured maximum",
        )
        results["database_pool"] = {
            "connections": peak_metrics["xmpp_database_pool_connections"],
            "idle": peak_metrics["xmpp_database_pool_idle_connections"],
            "maximum": peak_metrics["xmpp_database_pool_max_connections"],
        }
        completed = True
    finally:
        if sender is not None:
            sender.close()
        for session in sessions:
            if session is not None:
                session.close()
        if completed:
            wait_metric("xmpp_active_sessions", 0, timeout=60)
            wait_metric("xmpp_resumable_sessions", 0, timeout=60)
            time.sleep(3)
        metric_sampler.stop()
        sampler.stop()

    baseline_rss = baseline[1]
    peak_rss = max(sample[1] for sample in sampler.samples)
    peak_fds = max(sample[2] for sample in sampler.samples)
    peak_cpu = max(sample[3] for sample in sampler.samples)
    final_rss = sampler.samples[-1][1]
    final_fds = sampler.samples[-1][2]
    final_metrics = metrics()
    baseline_pool_connections = int(baseline_metrics["xmpp_database_pool_connections"])
    final_pool_connections = int(final_metrics["xmpp_database_pool_connections"])
    retained_pool_fds = max(0, final_pool_connections - baseline_pool_connections)
    fixture.check(peak_rss / 1024 <= LIMITS["rss_mib"],
                  f"peak RSS {peak_rss / 1024:.1f} MiB exceeded {LIMITS['rss_mib']:.1f} MiB")
    fixture.check(peak_fds <= LIMITS["fds"],
                  f"peak FD count {peak_fds} exceeded {LIMITS['fds']:.0f}")
    fixture.check(
        final_fds <= baseline[2] + 16 + retained_pool_fds,
        "FDs did not return near baseline after accounting for healthy retained "
        f"database-pool sockets: baseline={baseline[2]} final={final_fds} "
        f"pool_growth={retained_pool_fds}",
    )
    retained_mib = max(0, final_rss - baseline_rss) / 1024
    fixture.check(retained_mib <= LIMITS["retained_rss_mib"],
                  f"post-close retained RSS {retained_mib:.1f} MiB exceeded the leak guard")
    pool_connections = [sample["xmpp_database_pool_connections"]
                        for sample in metric_sampler.samples]
    pool_idle = [sample["xmpp_database_pool_idle_connections"]
                 for sample in metric_sampler.samples]
    database_up = [sample.get("xmpp_database_up", 0) for sample in metric_sampler.samples]
    collector_up = [sample.get("xmpp_database_collector_up", 0)
                    for sample in metric_sampler.samples]
    active_sessions = [sample["xmpp_active_sessions"] for sample in metric_sampler.samples]
    fixture.check(min(database_up) == 1, "database health dropped during sampled load")
    fixture.check(min(collector_up) == 1, "database metrics collector dropped during sampled load")
    fixture.check(max(pool_connections) <= 32, "database pool exceeded the 32-connection envelope")
    fixture.check(max(active_sessions) <= MAX_CONNECTIONS,
                  "sampled active sessions exceeded the connection envelope")
    fixture.check(max(active_sessions) >= SESSION_COUNT + 1,
                  "metrics sampler never observed the full load population")
    results["sampled_database_pool"] = {
        "samples": len(metric_sampler.samples),
        "peak_connections": max(pool_connections),
        "minimum_idle_connections": min(pool_idle),
        "configured_maximum": 32,
    }
    results["sampled_active_sessions_peak"] = max(active_sessions)
    results["process"] = {
        "baseline_rss_mib": baseline_rss / 1024,
        "peak_rss_mib": peak_rss / 1024,
        "final_rss_mib": final_rss / 1024,
        "peak_fds": peak_fds,
        "final_fds": final_fds,
        "retained_database_pool_fds_allowed": retained_pool_fds,
        "peak_cpu_percent_one_core_equals_100": peak_cpu,
        "mean_sampled_cpu_percent_one_core_equals_100": statistics.fmean(
            sample[3] for sample in sampler.samples
        ),
    }
    results["thresholds"] = LIMITS
    results["samples"] = {
        "direct_tls": TLS_SAMPLES,
        "websocket_sessions": SESSION_COUNT,
        "message_roundtrips": SESSION_COUNT,
        "sm_resumes": RESUME_COUNT,
        "overload_attempts": OVERLOAD_ATTEMPTS,
    }
    results["scope"] = (
        "single-node design validation only; results are not a production capacity or SLA guarantee"
    )
    print(json.dumps(results, indent=2, sort_keys=True))
    print("load production envelope: TLS/WS, 1000 sessions, fanout, SM resume, overload recovery, resources and cleanup passed")


if __name__ == "__main__":
    run()
