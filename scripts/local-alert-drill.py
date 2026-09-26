#!/usr/bin/env python3
"""Loopback metric and webhook fixture for an isolated alert-delivery drill.

This fixture does not replace an actual on-call receiver. Run it only on an
isolated lab host with a temporary Prometheus rule and Alertmanager route.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import urllib.request
import uuid


ALERT = "NorthstarAlertDeliveryDrill"
MAX_BODY = 65536
HEX = re.compile(r"[0-9a-f]{16,64}")
ACTOR = re.compile(r"[A-Za-z0-9_.@-]{1,80}")
CONFIG_FILES = ("prometheus.yml", "drill-rules.yml", "alertmanager.yml")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def seconds(start: str | None, end: str | None) -> float | None:
    if start is None or end is None:
        return None
    first = datetime.fromisoformat(start.replace("Z", "+00:00"))
    last = datetime.fromisoformat(end.replace("Z", "+00:00"))
    return round((last - first).total_seconds(), 3)


def private_dir(path: Path) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("drill state must be a real directory")
    stat = path.stat()
    if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise ValueError("drill state must be owner-only")
    return path.resolve()


def paths(directory: Path) -> tuple[Path, Path]:
    directory = private_dir(directory)
    return directory / "state.json", directory / "events.jsonl"


def read_state(directory: Path) -> dict:
    state_file, _ = paths(directory)
    if state_file.is_symlink() or not state_file.is_file():
        raise ValueError("drill state file is missing or unsafe")
    state = json.loads(state_file.read_text(encoding="ascii"))
    if (not isinstance(state, dict)
            or not isinstance(state.get("drill_id"), str)
            or str(uuid.UUID(state["drill_id"])) != state["drill_id"]
            or not isinstance(state.get("active"), bool)):
        raise ValueError("drill state file is malformed")
    return state


def save_state(directory: Path, state: dict) -> None:
    state_file, _ = paths(directory)
    descriptor, temporary = tempfile.mkstemp(prefix=".state-", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as output:
            json.dump(state, output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, state_file)
        parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def events_file(directory: Path, write: bool):
    _, event_path = paths(directory)
    if event_path.is_symlink() or not event_path.is_file():
        raise ValueError("drill event file is missing or unsafe")
    file = event_path.open("r+", encoding="ascii")
    fcntl.flock(file, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
    return file


def read_events(directory: Path) -> list[dict]:
    with events_file(directory, False) as file:
        return [json.loads(line) for line in file if line.strip()]


def append(directory: Path, event: dict) -> None:
    with events_file(directory, True) as file:
        file.seek(0, os.SEEK_END)
        file.write(json.dumps({"utc": now(), **event}, sort_keys=True) + "\n")
        file.flush()
        os.fsync(file.fileno())


def initialize(directory: Path) -> str:
    directory.mkdir(mode=0o700)
    drill_id = str(uuid.uuid4())
    event_path = directory / "events.jsonl"
    descriptor = os.open(event_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)
    save_state(directory, {"drill_id": drill_id, "active": False})
    append(directory, {"event": "initialized", "drill_id": drill_id})
    return drill_id


def write_configs(directory: Path, fixture_port: int, prometheus_port: int,
                  alertmanager_port: int) -> dict[str, str]:
    directory = private_dir(directory)
    read_state(directory)
    ports = (fixture_port, prometheus_port, alertmanager_port)
    if any(not 1 <= port <= 65535 for port in ports) or len(set(ports)) != 3:
        raise ValueError("fixture, Prometheus and Alertmanager need distinct valid ports")
    configs = {
        "prometheus.yml": (
            "global:\n"
            "  scrape_interval: 5s\n"
            "  evaluation_interval: 5s\n"
            "rule_files:\n"
            f"  - {json.dumps(str(directory / 'drill-rules.yml'))}\n"
            "alerting:\n"
            "  alertmanagers:\n"
            "    - static_configs:\n"
            f"        - targets: ['127.0.0.1:{alertmanager_port}']\n"
            "scrape_configs:\n"
            "  - job_name: northstar-alert-drill\n"
            "    static_configs:\n"
            f"      - targets: ['127.0.0.1:{fixture_port}']\n"
        ),
        "drill-rules.yml": (
            "groups:\n"
            "  - name: northstar-alert-drill\n"
            "    rules:\n"
            f"      - alert: {ALERT}\n"
            "        expr: northstar_alert_drill_active == 1\n"
            "        for: 10s\n"
            "        labels:\n"
            "          severity: critical\n"
            "        annotations:\n"
            "          summary: Isolated Northstar alert delivery drill\n"
        ),
        "alertmanager.yml": (
            "route:\n"
            "  receiver: northstar-loopback-drill\n"
            "  group_by: ['alertname', 'severity', 'drill_id']\n"
            "  group_wait: 1s\n"
            "  group_interval: 5s\n"
            "  repeat_interval: 1m\n"
            "receivers:\n"
            "  - name: northstar-loopback-drill\n"
            "    webhook_configs:\n"
            f"      - url: http://127.0.0.1:{fixture_port}/alertmanager\n"
            "        send_resolved: true\n"
        ),
    }
    if any((directory / name).exists() or (directory / name).is_symlink()
           for name in CONFIG_FILES):
        raise ValueError("temporary configuration already exists; use a fresh drill directory")
    created = []
    try:
        for name, content in configs.items():
            path = directory / name
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(descriptor, "w", encoding="ascii") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return config_hashes(directory)


def config_hashes(directory: Path) -> dict[str, str]:
    directory = private_dir(directory)
    hashes = {}
    for name in CONFIG_FILES:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            continue
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def set_condition(directory: Path, active: bool) -> None:
    state = read_state(directory)
    if state["active"] == active:
        raise ValueError("condition is already in the requested state")
    state["active"] = active
    save_state(directory, state)
    append(directory, {"event": "condition_on" if active else "condition_off",
                       "drill_id": state["drill_id"]})


def acknowledge(directory: Path, actor: str) -> None:
    if ACTOR.fullmatch(actor) is None:
        raise ValueError("actor must be a short operator identifier")
    events = read_events(directory)
    if not any(item.get("event") == "firing_received" for item in events):
        raise ValueError("cannot acknowledge before the firing notification")
    if any(item.get("event") == "acknowledged" for item in events):
        raise ValueError("drill has already been acknowledged")
    append(directory, {"event": "acknowledged", "drill_id": read_state(directory)["drill_id"],
                       "actor": actor})


def parse_notification(directory: Path, body: bytes) -> list[dict]:
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise ValueError("webhook body is not an object")
    if payload.get("status") not in {"firing", "resolved"}:
        raise ValueError("webhook status is invalid")
    alerts = payload.get("alerts")
    if not isinstance(alerts, list) or not 1 <= len(alerts) <= 8:
        raise ValueError("webhook must contain one to eight drill alerts")
    drill_id = read_state(directory)["drill_id"]
    received = []
    for alert in alerts:
        if not isinstance(alert, dict):
            raise ValueError("webhook alert is not an object")
        labels = alert.get("labels")
        if not isinstance(labels, dict) or labels.get("alertname") != ALERT \
                or labels.get("drill_id") != drill_id \
                or labels.get("severity") not in {"warning", "critical"} \
                or alert.get("status") != payload["status"] \
                or HEX.fullmatch(alert.get("fingerprint", "")) is None:
            raise ValueError("webhook contains an unrelated or malformed alert")
        received.append({"event": f"{payload['status']}_received", "drill_id": drill_id,
                         "severity": labels["severity"], "fingerprint": alert["fingerprint"],
                         "alert_starts_at": alert.get("startsAt"),
                         "alert_ends_at": alert.get("endsAt")})
    return received


def handler(directory: Path):
    class DrillHandler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def do_GET(self):  # noqa: N802
            if self.path != "/metrics":
                self.send_error(404)
                return
            state = read_state(directory)
            body = ("# TYPE northstar_alert_drill_active gauge\n"
                    f'northstar_alert_drill_active{{drill_id="{state["drill_id"]}"}} '
                    f'{int(state["active"])}\n').encode("ascii")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):  # noqa: N802
            if self.path != "/alertmanager":
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
                if not 0 <= length <= MAX_BODY:
                    raise ValueError("webhook is too large or has no length")
                records = parse_notification(directory, self.rfile.read(length))
                for record in records:
                    append(directory, record)
            except (ValueError, KeyError, TypeError, UnicodeError, OSError):
                self.send_error(400, "invalid drill webhook")
                return
            self.send_response(204)
            self.end_headers()

        def log_message(self, format, *args):
            # Do not print webhook bodies or client-provided labels.
            pass

    return DrillHandler


def report(directory: Path) -> dict:
    events = read_events(directory)
    first = {}
    for item in events:
        first.setdefault(item["event"], item)
    state = read_state(directory)
    timestamps = {name: first.get(name, {}).get("utc") for name in
                  ("condition_on", "firing_received", "acknowledged",
                   "condition_off", "resolved_received")}
    fixture_sequence_complete = (all(timestamps.values()) and not state["active"]
                and list(timestamps.values()) == sorted(timestamps.values())
                and first["firing_received"].get("fingerprint")
                == first["resolved_received"].get("fingerprint")
                and first["firing_received"].get("severity")
                == first["resolved_received"].get("severity"))
    return {
        "drill_id": state["drill_id"],
        "temporary_config_sha256": config_hashes(directory),
        "timestamps_utc": timestamps,
        "condition_to_notification_seconds": seconds(timestamps["condition_on"],
                                                      timestamps["firing_received"]),
        "notification_to_ack_seconds": seconds(timestamps["firing_received"],
                                                timestamps["acknowledged"]),
        "condition_clear_to_resolved_seconds": seconds(timestamps["condition_off"],
                                                       timestamps["resolved_received"]),
        "ack_actor": first.get("acknowledged", {}).get("actor"),
        "fixture_sequence_complete": fixture_sequence_complete,
        "rto_seconds": None,
        "rpo_seconds": None,
        "rto_rpo_reason": "Synthetic alert only; measure service and data recovery separately.",
    }


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="northstar-alert-drill-") as temporary:
        directory = Path(temporary) / "state"
        drill_id = initialize(directory)
        hashes = write_configs(directory, 18993, 19090, 19093)
        assert set(hashes) == set(CONFIG_FILES)
        assert json.dumps(str(directory / "drill-rules.yml")) in (
            directory / "prometheus.yml").read_text(encoding="ascii")
        assert all((directory / name).stat().st_mode & 0o077 == 0
                   for name in CONFIG_FILES)
        try:
            write_configs(directory, 18993, 19090, 19093)
            raise AssertionError("configuration unexpectedly overwritten")
        except ValueError:
            pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler(directory))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}"
        try:
            set_condition(directory, True)
            assert f'{{drill_id="{drill_id}"}} 1' in urllib.request.urlopen(
                url + "/metrics", timeout=5).read().decode("ascii")
            alert = {"labels": {"alertname": ALERT, "drill_id": drill_id,
                                "severity": "critical"},
                     "fingerprint": "0123456789abcdef", "startsAt": now()}
            for status in ("firing", "resolved"):
                if status == "resolved":
                    acknowledge(directory, "self-test")
                    set_condition(directory, False)
                alert["status"] = status
                request = urllib.request.Request(url + "/alertmanager",
                    data=json.dumps({"status": status, "alerts": [alert]}).encode("ascii"),
                    headers={"Content-Type": "application/json"}, method="POST")
                assert urllib.request.urlopen(request, timeout=5).status == 204
            assert report(directory)["fixture_sequence_complete"]
            assert report(directory)["temporary_config_sha256"] == hashes
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
    print("loopback alert receiver self-test passed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "config", "on", "off", "ack", "report", "serve"):
        command = commands.add_parser(name)
        command.add_argument("state_dir", type=Path)
        if name == "ack":
            command.add_argument("--actor", required=True)
        if name == "serve":
            command.add_argument("--port", type=int, default=18993)
        if name == "config":
            command.add_argument("--fixture-port", type=int, default=18993)
            command.add_argument("--prometheus-port", type=int, default=19090)
            command.add_argument("--alertmanager-port", type=int, default=19093)
    commands.add_parser("self-test")
    args = parser.parse_args()
    if args.command == "self-test":
        self_test()
    elif args.command == "init":
        print(initialize(args.state_dir))
    elif args.command == "config":
        hashes = write_configs(args.state_dir, args.fixture_port,
                               args.prometheus_port, args.alertmanager_port)
        print(json.dumps({"sha256": hashes,
                          "listen": {"fixture": f"127.0.0.1:{args.fixture_port}",
                                     "prometheus": f"127.0.0.1:{args.prometheus_port}",
                                     "alertmanager": f"127.0.0.1:{args.alertmanager_port}"}},
                         indent=2, sort_keys=True))
    elif args.command == "on":
        set_condition(args.state_dir, True)
    elif args.command == "off":
        set_condition(args.state_dir, False)
    elif args.command == "ack":
        acknowledge(args.state_dir, args.actor)
    elif args.command == "report":
        print(json.dumps(report(args.state_dir), indent=2, sort_keys=True))
    else:
        if not 1 <= args.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        directory = private_dir(args.state_dir)
        read_state(directory)
        read_events(directory)
        with ThreadingHTTPServer(("127.0.0.1", args.port), handler(directory)) as server:
            print(f"loopback drill receiver ready at 127.0.0.1:{args.port}", flush=True)
            server.serve_forever()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        parser_error = f"alert drill refused: {error}"
        raise SystemExit(parser_error) from error
