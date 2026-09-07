#!/usr/bin/env python3
"""Two-domain MIX-PAM and durable S2S handoff runtime probe."""

from __future__ import annotations

import base64
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import hmac
import importlib.util
import json
import os
import pathlib
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Iterator, Mapping, Sequence


ROOT = pathlib.Path(__file__).resolve().parent
PASSWORD = "mix-federation-password-123"
ALICE = "mix_fed_alice"
BOB = "mix_fed_bob"
CHANNEL = "fedruntime@mix.remote.localhost"
CORE = "urn:xmpp:mix:core:1"
PAM = "urn:xmpp:mix:pam:2"

# The fixture has historically given a REST login or a WebSocket construction
# ten seconds.  A fixture-only admission lane prevents a 50-pair run from
# creating a host-wide Argon2 burst, but it is deliberately separate from an
# authentication attempt: no credentials have been submitted while a worker
# waits for a lane.  Once admitted, every REST/XMPP authentication keeps one
# strict, non-extendable ten-second I/O deadline.
CLIENT_AUTH_IO_TIMEOUT_SECONDS = 10.0
LOGIN_SLOT_POLL_SECONDS = 0.025
LOGIN_SLOT_MAX_COUNT = 128
LOGIN_SLOT_DIRECTORY_ENV = "NORTHSTAR_MIX_FEDERATION_LOGIN_SLOT_DIR"
LOGIN_SLOT_COUNT_ENV = "NORTHSTAR_MIX_FEDERATION_LOGIN_SLOT_COUNT"
LOGIN_SLOT_FILE_PREFIX = "northstar-mix-login-slot-"
LOGIN_SLOT_FILE_SUFFIX = ".lock"

# The large listener matrix launches its workers independently, but its first
# credential exchange must not race the tail of another worker's server
# bootstrap.  The parent owns this directory and issues one HMAC key per pair.
# A child can publish only its own readiness and can proceed only after the
# parent has verified every pair and issued that pair's release record.  This
# is fixture orchestration, not a product admission limit: all server and MIX
# business work remains concurrent after the one setup release.
PHASE_CONTROL_DIRECTORY_ENV = "NORTHSTAR_MIX_FEDERATION_PHASE_CONTROL_DIR"
PHASE_RUN_NONCE_ENV = "NORTHSTAR_MIX_FEDERATION_PHASE_RUN_NONCE"
PHASE_ROUND_ENV = "NORTHSTAR_MIX_FEDERATION_PHASE_ROUND"
PHASE_PAIR_ENV = "NORTHSTAR_MIX_FEDERATION_PHASE_PAIR"
PHASE_RECORD_VERSION = 1
PHASE_NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
PHASE_DECIMAL_RE = re.compile(r"^[1-9][0-9]{0,5}$")
PHASE_CONTROL_MODE = 0o700
PHASE_FILE_MODE = 0o600
PHASE_POLL_SECONDS = 0.025
# `link(2)` followed by `unlink(2)` looks like an atomic no-replace publish at
# first glance, but there is a real observation window in which the published
# record has two links.  The strict reader correctly rejects that state, which
# made a high-concurrency barrier occasionally fail closed.  This fixture is
# explicitly Linux/WSL-only, so use the kernel's atomic no-replace rename
# instead of weakening the reader's link-count invariant.
RENAME_NOREPLACE = 1
LISTENER_ARGUMENT_RE = re.compile(
    r"^(?P<purpose>[a-z0-9-]{1,64})=(?P<pid>[1-9][0-9]{0,9}):(?P<port>[1-9][0-9]{0,4})$"
)


def _rename_phase_record_noreplace(
    directory_descriptor: int,
    temporary: str,
    name: str,
) -> bool:
    """Publish a fully-written record atomically without a hard-link window.

    ``False`` means a peer already published this exact record name.  A
    missing Linux ``renameat2`` is a fail-closed fixture prerequisite rather
    than an excuse to return to the racy link/unlink fallback.
    """

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (AttributeError, OSError) as error:
        raise RuntimeError(
            "MIX federation phase barrier requires Linux renameat2"
        ) from error
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if renameat2(
        directory_descriptor,
        os.fsencode(temporary),
        directory_descriptor,
        os.fsencode(name),
        RENAME_NOREPLACE,
    ) == 0:
        return True
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        return False
    raise OSError(error_number, "renameat2 phase record publish failed")


@dataclass(frozen=True)
class PhaseBarrierConfiguration:
    directory: str
    run_nonce: str
    round: int
    pair: int


@dataclass(frozen=True)
class ListenerIdentity:
    purpose: str
    pid: int
    port: int
    socket_inode: int


def _phase_integer(value: str, label: str) -> int:
    if PHASE_DECIMAL_RE.fullmatch(value) is None:
        raise RuntimeError(f"{label} must be a positive canonical decimal integer")
    return int(value)


def _phase_key_name(pair: int) -> str:
    return f"pair-{pair:03d}.key"


def _phase_record_name(kind: str, round_number: int, pair: int) -> str:
    if kind not in {"ready", "release", "listeners"}:
        raise RuntimeError("invalid MIX federation phase record kind")
    return f"{kind}-r{round_number:03d}-p{pair:03d}.json"


def _open_phase_directory(directory: str) -> tuple[int, os.stat_result]:
    if not os.path.isabs(directory):
        raise RuntimeError("MIX federation phase directory must be absolute")
    normalized = os.path.normpath(directory)
    if os.path.realpath(normalized) != normalized:
        raise RuntimeError("MIX federation phase directory must not traverse symbolic links")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        raise RuntimeError("MIX federation phase barrier requires O_NOFOLLOW and O_DIRECTORY")
    try:
        descriptor = os.open(
            normalized,
            os.O_RDONLY | os.O_CLOEXEC | nofollow | directory_flag,
        )
    except OSError as error:
        raise RuntimeError("MIX federation phase directory could not be opened safely") from error
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISDIR(details.st_mode):
            raise RuntimeError("MIX federation phase path is not a directory")
        if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != PHASE_CONTROL_MODE:
            raise RuntimeError("MIX federation phase directory must be owned by this user with mode 0700")
        return descriptor, details
    except BaseException:
        os.close(descriptor)
        raise


def _read_phase_file(directory_descriptor: int, name: str, label: str) -> bytes:
    if "/" in name or name.startswith("."):
        raise RuntimeError(f"invalid MIX federation {label} file name")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeError("MIX federation phase barrier requires O_NOFOLLOW")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | nofollow,
            dir_fd=directory_descriptor,
        )
    except FileNotFoundError:
        raise
    except OSError as error:
        raise RuntimeError(f"MIX federation {label} file could not be opened safely") from error
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) != PHASE_FILE_MODE
            or details.st_nlink != 1
            or details.st_size > 65_536
        ):
            raise RuntimeError(f"MIX federation {label} file has unsafe metadata")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 8192)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_phase_key(configuration: PhaseBarrierConfiguration) -> bytes:
    descriptor, _details = _open_phase_directory(configuration.directory)
    try:
        raw = _read_phase_file(descriptor, _phase_key_name(configuration.pair), "phase key")
    finally:
        os.close(descriptor)
    try:
        encoded = raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise RuntimeError("MIX federation phase key is not ASCII") from error
    if re.fullmatch(r"[0-9a-f]{64}", encoded) is None:
        raise RuntimeError("MIX federation phase key is not a 256-bit hexadecimal key")
    return bytes.fromhex(encoded)


def _canonical_record(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _signed_record(key: bytes, payload: Mapping[str, object]) -> dict[str, object]:
    result = dict(payload)
    result["signature"] = hmac.new(key, _canonical_record(payload), hashlib.sha256).hexdigest()
    return result


def _write_phase_record(
    directory: str,
    name: str,
    record: Mapping[str, object],
    *,
    replace: bool,
) -> bool:
    """Write a mode-0600 JSON record atomically below the parent-owned root.

    ``False`` means an exclusive record already exists.  A replacement is
    used only for the listener ledger: a restarted B process receives new
    sockets, so the current record must replace the prior generation.
    """

    if "/" in name or name.startswith("."):
        raise RuntimeError("invalid MIX federation phase record name")
    directory_descriptor, _details = _open_phase_directory(directory)
    temporary = f".{name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    try:
        try:
            existing = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            not stat.S_ISREG(existing.st_mode)
            or existing.st_uid != os.geteuid()
            or stat.S_IMODE(existing.st_mode) != PHASE_FILE_MODE
            or existing.st_nlink != 1
        ):
            raise RuntimeError("MIX federation phase record target has unsafe metadata")
        if existing is not None and not replace:
            return False
        encoded = _canonical_record(record) + b"\n"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            PHASE_FILE_MODE,
            dir_fd=directory_descriptor,
        )
        try:
            offset = 0
            while offset < len(encoded):
                offset += os.write(descriptor, encoded[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if replace:
            os.replace(
                temporary,
                name,
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
            )
            temporary = ""
            return True
        if not _rename_phase_record_noreplace(directory_descriptor, temporary, name):
            return False
        temporary = ""
        return True
    finally:
        if temporary:
            try:
                os.unlink(temporary, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
        os.close(directory_descriptor)


def _read_phase_record(directory: str, name: str) -> dict[str, object]:
    descriptor, _details = _open_phase_directory(directory)
    try:
        raw = _read_phase_file(descriptor, name, "phase record")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("MIX federation phase record is not valid JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError("MIX federation phase record is not an object")
    return value


def _verify_phase_record(
    configuration: PhaseBarrierConfiguration,
    kind: str,
    expected: Mapping[str, object],
) -> dict[str, object]:
    record = _read_phase_record(
        configuration.directory,
        _phase_record_name(kind, configuration.round, configuration.pair),
    )
    if set(record) != set(expected) | {"signature"}:
        raise RuntimeError("MIX federation phase record has an unexpected shape")
    signature = record.pop("signature", None)
    if not isinstance(signature, str) or re.fullmatch(r"[0-9a-f]{64}", signature) is None:
        raise RuntimeError("MIX federation phase record signature is invalid")
    if record != dict(expected):
        raise RuntimeError("MIX federation phase record does not match its expected identity")
    key = _read_phase_key(configuration)
    calculated = hmac.new(key, _canonical_record(record), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, calculated):
        raise RuntimeError("MIX federation phase record signature did not verify")
    return record


def phase_barrier_configuration_from_environment(
    environment: Mapping[str, str] | None = None,
) -> PhaseBarrierConfiguration | None:
    values = os.environ if environment is None else environment
    raw = {
        PHASE_CONTROL_DIRECTORY_ENV: values.get(PHASE_CONTROL_DIRECTORY_ENV),
        PHASE_RUN_NONCE_ENV: values.get(PHASE_RUN_NONCE_ENV),
        PHASE_ROUND_ENV: values.get(PHASE_ROUND_ENV),
        PHASE_PAIR_ENV: values.get(PHASE_PAIR_ENV),
    }
    if all(value is None for value in raw.values()):
        return None
    if any(value is None or value == "" for value in raw.values()):
        raise RuntimeError("MIX federation phase barrier variables must be set together")
    directory = str(raw[PHASE_CONTROL_DIRECTORY_ENV])
    run_nonce = str(raw[PHASE_RUN_NONCE_ENV])
    if PHASE_NONCE_RE.fullmatch(run_nonce) is None:
        raise RuntimeError("MIX federation phase run nonce is invalid")
    return PhaseBarrierConfiguration(
        directory=directory,
        run_nonce=run_nonce,
        round=_phase_integer(str(raw[PHASE_ROUND_ENV]), PHASE_ROUND_ENV),
        pair=_phase_integer(str(raw[PHASE_PAIR_ENV]), PHASE_PAIR_ENV),
    )


def _phase_payload(configuration: PhaseBarrierConfiguration, kind: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "version": PHASE_RECORD_VERSION,
        "kind": kind,
        "fixture": "mix-federation",
        "run_nonce": configuration.run_nonce,
        "round": configuration.round,
        "pair": configuration.pair,
    }
    if kind == "ready":
        payload["servers"] = ["a", "b"]
    return payload


def publish_phase_ready(configuration: PhaseBarrierConfiguration) -> None:
    payload = _phase_payload(configuration, "ready")
    key = _read_phase_key(configuration)
    if not _write_phase_record(
        configuration.directory,
        _phase_record_name("ready", configuration.round, configuration.pair),
        _signed_record(key, payload),
        replace=False,
    ):
        _verify_phase_record(configuration, "ready", payload)


def await_phase_release(configuration: PhaseBarrierConfiguration) -> None:
    expected = _phase_payload(configuration, "release")
    while True:
        try:
            _read_phase_record(
                configuration.directory,
                _phase_record_name("release", configuration.round, configuration.pair),
            )
        except FileNotFoundError:
            # The stress parent owns the deadline and monitors the exact
            # worker groups.  Giving this child a second, independent timer
            # would turn phase scheduling into a false network timeout.
            time.sleep(PHASE_POLL_SECONDS)
            continue
        # A published record with a missing key or bad signature is a control
        # plane failure, not an incomplete barrier.  Propagate it immediately
        # so the worker cannot spin until the outer stress deadline.
        _verify_phase_record(configuration, "release", expected)
        return


def _parent_phase_configuration(
    directory: str,
    run_nonce: str,
    round_number: int,
    pair: int,
) -> PhaseBarrierConfiguration:
    if PHASE_NONCE_RE.fullmatch(run_nonce) is None:
        raise RuntimeError("MIX federation parent phase run nonce is invalid")
    if round_number <= 0 or pair <= 0:
        raise RuntimeError("MIX federation parent phase identity is invalid")
    return PhaseBarrierConfiguration(directory, run_nonce, round_number, pair)


def parent_phase_ready(
    directory: str,
    run_nonce: str,
    round_number: int,
    pairs: int,
) -> bool:
    if pairs <= 0:
        raise RuntimeError("MIX federation parent phase pair count is invalid")
    for pair in range(1, pairs + 1):
        configuration = _parent_phase_configuration(directory, run_nonce, round_number, pair)
        try:
            _read_phase_record(
                configuration.directory,
                _phase_record_name("ready", configuration.round, configuration.pair),
            )
        except FileNotFoundError:
            return False
        # A record is present, so any subsequent failure (including a missing
        # pair key) is malformed control state and must not be downgraded to a
        # harmless "not ready" poll result.
        _verify_phase_record(configuration, "ready", _phase_payload(configuration, "ready"))
    return True


def parent_release_phase(
    directory: str,
    run_nonce: str,
    round_number: int,
    pairs: int,
) -> None:
    if not parent_phase_ready(directory, run_nonce, round_number, pairs):
        raise RuntimeError("MIX federation parent cannot release an incomplete readiness barrier")
    for pair in range(1, pairs + 1):
        configuration = _parent_phase_configuration(directory, run_nonce, round_number, pair)
        payload = _phase_payload(configuration, "release")
        key = _read_phase_key(configuration)
        if not _write_phase_record(
            configuration.directory,
            _phase_record_name("release", configuration.round, configuration.pair),
            _signed_record(key, payload),
            replace=False,
        ):
            _verify_phase_record(configuration, "release", payload)


def _listening_socket_inodes(port: int) -> set[int]:
    inodes: set[int] = set()
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = pathlib.Path(path).read_text(encoding="ascii").splitlines()[1:]
        except OSError as error:
            raise RuntimeError("could not read Linux TCP listener table") from error
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "0A" or ":" not in fields[1]:
                continue
            raw_port = fields[1].rsplit(":", 1)[1]
            try:
                if int(raw_port, 16) == port:
                    inodes.add(int(fields[9]))
            except ValueError:
                raise RuntimeError("Linux TCP listener table contained an invalid entry")
    return inodes


def _process_socket_inodes(pid: int) -> set[int]:
    root = pathlib.Path(f"/proc/{pid}/fd")
    try:
        entries = list(root.iterdir())
    except OSError as error:
        raise RuntimeError("MIX federation listener owner is no longer inspectable") from error
    inodes: set[int] = set()
    for entry in entries:
        try:
            target = os.readlink(entry)
        except OSError:
            continue
        match = re.fullmatch(r"socket:\[(\d+)\]", target)
        if match is not None:
            inodes.add(int(match.group(1)))
    return inodes


def listener_identity(purpose: str, pid: int, port: int) -> ListenerIdentity:
    if not purpose or not re.fullmatch(r"[a-z0-9-]{1,64}", purpose):
        raise RuntimeError("MIX federation listener purpose is invalid")
    if pid <= 0 or not 1 <= port <= 65535:
        raise RuntimeError("MIX federation listener identity is invalid")
    owned = _process_socket_inodes(pid)
    matching = owned & _listening_socket_inodes(port)
    if len(matching) != 1:
        raise RuntimeError("MIX federation listener could not be uniquely attributed to its owner")
    return ListenerIdentity(purpose, pid, port, next(iter(matching)))


def _parse_listener_argument(value: str) -> tuple[str, int, int]:
    match = LISTENER_ARGUMENT_RE.fullmatch(value)
    if match is None:
        raise RuntimeError("MIX federation listener ledger argument is invalid")
    pid = int(match.group("pid"))
    port = int(match.group("port"))
    if port > 65535:
        raise RuntimeError("MIX federation listener ledger port is invalid")
    return match.group("purpose"), pid, port


def record_listener_ledger(
    configuration: PhaseBarrierConfiguration,
    raw_entries: Sequence[str],
) -> None:
    entries: list[ListenerIdentity] = []
    seen_purposes: set[str] = set()
    seen_ports: set[int] = set()
    for raw in raw_entries:
        purpose, pid, port = _parse_listener_argument(raw)
        if purpose in seen_purposes or port in seen_ports:
            raise RuntimeError("MIX federation listener ledger has duplicate identities")
        seen_purposes.add(purpose)
        seen_ports.add(port)
        entries.append(listener_identity(purpose, pid, port))
    if not entries:
        raise RuntimeError("MIX federation listener ledger cannot be empty")
    entries.sort(key=lambda entry: (entry.purpose, entry.port, entry.pid))
    payload: dict[str, object] = {
        **_phase_payload(configuration, "listeners"),
        "listeners": [
            {
                "purpose": entry.purpose,
                "pid": entry.pid,
                "port": entry.port,
                "socket_inode": entry.socket_inode,
            }
            for entry in entries
        ],
    }
    key = _read_phase_key(configuration)
    _write_phase_record(
        configuration.directory,
        _phase_record_name("listeners", configuration.round, configuration.pair),
        _signed_record(key, payload),
        replace=True,
    )


def _verified_listener_ledger(configuration: PhaseBarrierConfiguration) -> list[ListenerIdentity]:
    base = _phase_payload(configuration, "listeners")
    record = _read_phase_record(
        configuration.directory,
        _phase_record_name("listeners", configuration.round, configuration.pair),
    )
    required = set(base) | {"listeners", "signature"}
    if set(record) != required:
        raise RuntimeError("MIX federation listener ledger has an unexpected shape")
    signature = record.pop("signature", None)
    if not isinstance(signature, str) or re.fullmatch(r"[0-9a-f]{64}", signature) is None:
        raise RuntimeError("MIX federation listener ledger signature is invalid")
    listeners = record.get("listeners")
    if not isinstance(listeners, list) or not listeners:
        raise RuntimeError("MIX federation listener ledger is empty")
    if {key: value for key, value in record.items() if key != "listeners"} != base:
        raise RuntimeError("MIX federation listener ledger does not match its expected identity")
    key = _read_phase_key(configuration)
    calculated = hmac.new(key, _canonical_record(record), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, calculated):
        raise RuntimeError("MIX federation listener ledger signature did not verify")
    entries: list[ListenerIdentity] = []
    purposes: set[str] = set()
    ports: set[int] = set()
    for value in listeners:
        if not isinstance(value, dict) or set(value) != {"purpose", "pid", "port", "socket_inode"}:
            raise RuntimeError("MIX federation listener ledger entry is invalid")
        purpose = value["purpose"]
        pid = value["pid"]
        port = value["port"]
        inode = value["socket_inode"]
        if (
            not isinstance(purpose, str)
            or re.fullmatch(r"[a-z0-9-]{1,64}", purpose) is None
            or not isinstance(pid, int)
            or not isinstance(port, int)
            or not isinstance(inode, int)
            or pid <= 0
            or not 1 <= port <= 65535
            or inode <= 0
            or purpose in purposes
            or port in ports
        ):
            raise RuntimeError("MIX federation listener ledger entry is invalid")
        purposes.add(purpose)
        ports.add(port)
        entries.append(ListenerIdentity(purpose, pid, port, inode))
    return entries


def verify_listener_ledger_after_quiescence(
    directory: str,
    run_nonce: str,
    round_number: int,
    pairs: int,
) -> tuple[int, int]:
    """Validate exact socket identities after the parent has reaped workers.

    A numerical ephemeral port may legitimately be reused by another live
    worker before that worker exits.  Only an original socket inode still in
    the Linux LISTEN table is a leak.  This function intentionally relies on
    its caller to establish process-group quiescence first.
    """

    total = 0
    reused = 0
    leaks: list[str] = []
    for pair in range(1, pairs + 1):
        configuration = _parent_phase_configuration(directory, run_nonce, round_number, pair)
        for entry in _verified_listener_ledger(configuration):
            total += 1
            current = _listening_socket_inodes(entry.port)
            if entry.socket_inode in current:
                leaks.append(f"pair={pair} purpose={entry.purpose} port={entry.port}")
            elif current:
                reused += 1
    if leaks:
        raise RuntimeError(
            "MIX federation owned listener remained after worker quiescence: "
            + ", ".join(leaks)
        )
    return total, reused


@dataclass(frozen=True)
class LoginSlotFile:
    """An identity-attested, empty lock file owned by this test user."""

    name: str
    device: int
    inode: int


@dataclass(frozen=True)
class LoginSlotConfiguration:
    """Immutable description of a parent-created authentication slot set."""

    directory: str
    directory_device: int
    directory_inode: int
    slots: tuple[LoginSlotFile, ...]


@dataclass(frozen=True)
class AuthenticationAttempt:
    """A one-shot, monotonic deadline shared by slot acquisition and login."""

    deadline: float

    def remaining_timeout(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("MIX federation authentication deadline elapsed")
        return remaining


def _slot_names(count: int) -> tuple[str, ...]:
    return tuple(
        f"{LOGIN_SLOT_FILE_PREFIX}{index:03d}{LOGIN_SLOT_FILE_SUFFIX}"
        for index in range(count)
    )


def _require_flock():
    """Load POSIX flock only when the opt-in WSL test gate is requested."""

    try:
        import fcntl
    except ImportError as error:  # pragma: no cover - the fixture runs on Linux.
        raise RuntimeError("MIX federation login slots require POSIX flock support") from error
    return fcntl


def _open_nofollow_directory(directory: str) -> tuple[int, os.stat_result]:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        raise RuntimeError("MIX federation login slots require O_NOFOLLOW and O_DIRECTORY")
    flags = os.O_RDONLY | os.O_CLOEXEC | nofollow | directory_flag
    try:
        descriptor = os.open(directory, flags)
    except OSError as error:
        raise RuntimeError("MIX federation login slot directory could not be opened safely") from error
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISDIR(details.st_mode):
            raise RuntimeError("MIX federation login slot path is not a directory")
        return descriptor, details
    except BaseException:
        os.close(descriptor)
        raise


def _validate_slot_directory_mode(details: os.stat_result) -> None:
    if details.st_uid != os.geteuid():
        raise RuntimeError("MIX federation login slot directory is not owned by this user")
    if stat.S_IMODE(details.st_mode) != 0o700:
        raise RuntimeError("MIX federation login slot directory must have mode 0700")


def _validate_slot_file_mode(details: os.stat_result, name: str) -> None:
    if not stat.S_ISREG(details.st_mode):
        raise RuntimeError(f"MIX federation login slot is not a regular file: {name}")
    if details.st_uid != os.geteuid():
        raise RuntimeError(f"MIX federation login slot is not owned by this user: {name}")
    if stat.S_IMODE(details.st_mode) != 0o600:
        raise RuntimeError(f"MIX federation login slot must have mode 0600: {name}")
    if details.st_nlink != 1 or details.st_size != 0:
        raise RuntimeError(f"MIX federation login slot is not an empty single-link file: {name}")


def _validate_slot_files(
    directory_descriptor: int,
    expected_names: tuple[str, ...],
    expected_slots: tuple[LoginSlotFile, ...] | None = None,
) -> list[int]:
    """Open and identity-check each fixed file relative to a safe directory FD."""

    try:
        entries = set(os.listdir(directory_descriptor))
    except OSError as error:
        raise RuntimeError("could not list MIX federation login slot directory") from error
    if entries != set(expected_names):
        raise RuntimeError("MIX federation login slot directory has an unexpected file set")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeError("MIX federation login slots require O_NOFOLLOW")
    descriptors: list[int] = []
    try:
        for index, name in enumerate(expected_names):
            try:
                descriptor = os.open(
                    name,
                    os.O_RDWR | os.O_CLOEXEC | nofollow,
                    dir_fd=directory_descriptor,
                )
            except OSError as error:
                raise RuntimeError(f"MIX federation login slot could not be opened safely: {name}") from error
            try:
                details = os.fstat(descriptor)
                _validate_slot_file_mode(details, name)
                if expected_slots is not None:
                    expected = expected_slots[index]
                    if (details.st_dev, details.st_ino) != (expected.device, expected.inode):
                        raise RuntimeError(f"MIX federation login slot identity changed: {name}")
            except BaseException:
                os.close(descriptor)
                raise
            descriptors.append(descriptor)
        return descriptors
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        raise


def login_slot_configuration_from_environment(
    environment: Mapping[str, str] | None = None,
) -> LoginSlotConfiguration | None:
    """Validate an opt-in, parent-created fixed slot set without creating it.

    A fixture child never creates, repairs, or follows a path for this gate.
    The parent owns the set before concurrent workers start; every child then
    checks the same directory/file identities again before taking a lock.
    """

    values = os.environ if environment is None else environment
    raw_directory = values.get(LOGIN_SLOT_DIRECTORY_ENV)
    raw_count = values.get(LOGIN_SLOT_COUNT_ENV)
    if raw_directory is None and raw_count is None:
        return None
    if raw_directory is None or raw_count is None:
        raise RuntimeError(
            f"{LOGIN_SLOT_DIRECTORY_ENV} and {LOGIN_SLOT_COUNT_ENV} must be set together"
        )
    if not raw_directory:
        raise RuntimeError(f"{LOGIN_SLOT_DIRECTORY_ENV} must name an absolute directory")
    if re.fullmatch(r"[1-9][0-9]{0,2}", raw_count) is None:
        raise RuntimeError(f"{LOGIN_SLOT_COUNT_ENV} must be a positive decimal integer")
    count = int(raw_count)
    if count > LOGIN_SLOT_MAX_COUNT:
        raise RuntimeError(
            f"{LOGIN_SLOT_COUNT_ENV} must not exceed {LOGIN_SLOT_MAX_COUNT} for this fixture"
        )
    if not os.path.isabs(raw_directory):
        raise RuntimeError(f"{LOGIN_SLOT_DIRECTORY_ENV} must be absolute")
    directory = os.path.normpath(raw_directory)
    if os.path.realpath(directory) != directory:
        raise RuntimeError(f"{LOGIN_SLOT_DIRECTORY_ENV} must not traverse symbolic links")

    descriptor, details = _open_nofollow_directory(directory)
    try:
        _validate_slot_directory_mode(details)
        names = _slot_names(count)
        descriptors = _validate_slot_files(descriptor, names)
        try:
            slots = tuple(
                LoginSlotFile(name, os.fstat(slot).st_dev, os.fstat(slot).st_ino)
                for name, slot in zip(names, descriptors, strict=True)
            )
        finally:
            for slot in descriptors:
                os.close(slot)
        return LoginSlotConfiguration(directory, details.st_dev, details.st_ino, slots)
    finally:
        os.close(descriptor)


def _open_configured_login_slots(configuration: LoginSlotConfiguration) -> list[int]:
    directory_descriptor, details = _open_nofollow_directory(configuration.directory)
    try:
        if (details.st_dev, details.st_ino) != (
            configuration.directory_device,
            configuration.directory_inode,
        ):
            raise RuntimeError("MIX federation login slot directory identity changed")
        _validate_slot_directory_mode(details)
        return _validate_slot_files(
            directory_descriptor,
            tuple(slot.name for slot in configuration.slots),
            configuration.slots,
        )
    finally:
        os.close(directory_descriptor)


@contextmanager
def claim_login_slot(
    configuration: LoginSlotConfiguration,
    *,
    deadline: float | None = None,
    timeout_seconds: float | None = CLIENT_AUTH_IO_TIMEOUT_SECONDS,
) -> Iterator[None]:
    """Claim one fixed cross-process fixture admission lane.

    A finite deadline is used by the isolated filesystem self-test.  Runtime
    phases use ``timeout_seconds=None``: parent supervision still bounds the
    worker, while the *subsequent* credential operation receives a fresh,
    strict I/O deadline.  Treating pre-attempt fixture scheduling as network
    I/O made large valid matrices reject work before an authentication began.
    """

    if deadline is None and timeout_seconds is not None and (
        timeout_seconds <= 0 or timeout_seconds > CLIENT_AUTH_IO_TIMEOUT_SECONDS
    ):
        raise ValueError("MIX federation login slot timeout must fit the client I/O deadline")
    fcntl = _require_flock()
    if deadline is None and timeout_seconds is not None:
        deadline = time.monotonic() + timeout_seconds
    locked_descriptor: int | None = None
    attempt = 0
    while locked_descriptor is None:
        descriptors = _open_configured_login_slots(configuration)
        try:
            # Rotate the first candidate between processes/retries.  This is
            # only a fairness hint; correctness comes from each kernel lock.
            first = (os.getpid() + attempt) % len(descriptors)
            for offset in range(len(descriptors)):
                candidate = descriptors[(first + offset) % len(descriptors)]
                try:
                    fcntl.flock(candidate, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                except OSError as error:
                    if error.errno not in (errno.EACCES, errno.EAGAIN):
                        raise RuntimeError("MIX federation login slot lock failed") from error
                    continue
                locked_descriptor = candidate
                break
            if locked_descriptor is not None:
                for descriptor in descriptors:
                    if descriptor != locked_descriptor:
                        os.close(descriptor)
                descriptors = []
            else:
                for descriptor in descriptors:
                    os.close(descriptor)
                descriptors = []
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
        if locked_descriptor is not None:
            break
        if deadline is None:
            remaining = LOGIN_SLOT_POLL_SECONDS
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for a MIX federation authentication slot")
        attempt += 1
        time.sleep(min(LOGIN_SLOT_POLL_SECONDS, remaining))
    try:
        yield
    finally:
        # flock locks are released by the kernel if a worker crashes.  An
        # explicit unlock makes the normal hand-off immediate as well.
        try:
            fcntl.flock(locked_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(locked_descriptor)


LOGIN_SLOT_CONFIGURATION: LoginSlotConfiguration | None = None


@contextmanager
def fixture_phase_auth_admission() -> Iterator[None]:
    """Serialize only the fixture's setup/authentication phase when requested."""

    if LOGIN_SLOT_CONFIGURATION is None:
        yield
        return
    with claim_login_slot(LOGIN_SLOT_CONFIGURATION, timeout_seconds=None):
        yield


@contextmanager
def authentication_attempt() -> Iterator[AuthenticationAttempt]:
    """Give a real credential exchange one strict, absolute I/O budget."""

    yield AuthenticationAttempt(time.monotonic() + CLIENT_AUTH_IO_TIMEOUT_SECONDS)


def environment_flag(name: str) -> bool:
    value = os.environ.get(name, "false")
    if value not in ("true", "false"):
        raise RuntimeError(f"{name} must be exactly true or false")
    return value == "true"


# Runtime configuration is intentionally deferred until after --self-test.
# That lets the gate's isolated filesystem checks run without requiring live
# relay ports or importing the much larger integration fixture.
def required_fixture_http_port(name: str) -> str:
    """Read a fixture relay port without silently falling back to a default.

    The two relay ports are published by the shell owner after both children
    have completed their readiness handoff.  Treat an absent, blank, or
    malformed value as a fixture wiring failure: using integration-wsl.py's
    generic default would send a domain to the wrong relay and hide a broken
    listener handoff.
    """

    value = os.environ.get(name)
    if value is None or re.fullmatch(r"[1-9][0-9]{0,4}", value) is None:
        raise RuntimeError(f"{name} must be an integer relay port from 1 through 65535")
    if int(value) > 65535:
        raise RuntimeError(f"{name} must be an integer relay port from 1 through 65535")
    return value


def load_fixture(name: str, domain: str, http_port: str):
    saved = {key: os.environ.get(key) for key in ("XMPP_TEST_DOMAIN", "XMPP_TEST_HTTP_PORT")}
    try:
        os.environ["XMPP_TEST_DOMAIN"] = domain
        os.environ["XMPP_TEST_HTTP_PORT"] = http_port
        spec = importlib.util.spec_from_file_location(name, ROOT / "integration-wsl.py")
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module
    finally:
        # Keep an explicit caller override intact even if the imported fixture
        # raises while its module-level configuration is being evaluated.
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


A = None
B = None


def initialize_runtime() -> None:
    """Load fixture-specific state only for an actual runtime phase."""

    global LOGIN_SLOT_CONFIGURATION, A, B
    LOGIN_SLOT_CONFIGURATION = login_slot_configuration_from_environment()
    A = load_fixture(
        "northstar_mix_fed_a", "localhost", required_fixture_http_port("MIX_FED_HTTP_A")
    )
    B = load_fixture(
        "northstar_mix_fed_b", "remote.localhost", required_fixture_http_port("MIX_FED_HTTP_B")
    )


class Inbox:
    def __init__(self, client: object):
        self.client = client
        self.pending: list[str] = []

    def wait(self, marker: str, timeout: float = 30) -> str:
        deadline = time.monotonic() + timeout
        while True:
            for index, frame in enumerate(self.pending):
                if marker in frame:
                    return self.pending.pop(index)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"federated MIX inbox timed out for {marker!r}: {self.pending!r}")
            self.pending.append(self.client.receive(remaining))

    def send(self, stanza: str) -> None:
        self.client.send(stanza)

    def close(self) -> None:
        self.client.close()


def check(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def register(fixture, username: str) -> None:
    # Registration derives the same password verifier as login.  The phase
    # caller controls cross-worker admission; this actual exchange owns only
    # its strict network/credential deadline.
    with authentication_attempt() as attempt:
        status, result = fixture.register_account(
            username, PASSWORD, deadline=attempt.deadline
        )
    check(status == 201, f"registration failed for {username}: {status} {result}")


def login(fixture, username: str) -> str:
    # The bearer and every later operation run normally and never expose the
    # fixture's authentication admission state here.
    with authentication_attempt() as attempt:
        status, result = fixture.api(
            "POST",
            "/api/v1/login",
            {"username": username, "password": PASSWORD},
            deadline=attempt.deadline,
        )
    check(status == 200, f"login failed for {username}: {status} {result}")
    return result["token"]


def connect(fixture, username: str, resource: str) -> Inbox:
    # Construction includes connect, upgrade, SASL, bind and initial presence.
    # Discovery and later stanzas are outside this exchange's I/O deadline.
    with authentication_attempt() as attempt:
        websocket = fixture.XmppWebSocket(
            username, PASSWORD, resource, deadline=attempt.deadline
        )
    client = Inbox(websocket)
    node = f"https://northstar.invalid/mix-fed-{username}-{resource}"
    name = "Northstar MIX Federation Runtime"
    verification = f"client/pc//{name}<urn:xmpp:mix:core:1<urn:xmpp:mix:pam:2<"
    version = base64.b64encode(hashlib.sha1(verification.encode()).digest()).decode()
    client.send(
        "<presence xmlns='jabber:client'>"
        f"<c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='{node}' ver='{version}'/>"
        "</presence>"
    )
    query = client.wait(f"node='{node}#")
    query_id = re.search(r"id='([^']+)'", query)
    check(query_id is not None, f"caps query lacked id: {query}")
    client.send(
        f"<iq xmlns='jabber:client' type='result' id='{query_id.group(1)}'>"
        f"<query xmlns='http://jabber.org/protocol/disco#info' node='{node}#{version}'>"
        f"<identity category='client' type='pc' name='{name}'/>"
        "<feature var='urn:xmpp:mix:core:1'/><feature var='urn:xmpp:mix:pam:2'/></query></iq>"
    )
    barrier = f"barrier-{resource}"
    client.send(f"<iq xmlns='jabber:client' type='get' id='{barrier}'><ping xmlns='urn:xmpp:ping'/></iq>")
    check("type='result'" in client.wait(f"id='{barrier}'"), "caps barrier failed")
    return client


def iq(client: Inbox, stanza_id: str, to: str, payload: str) -> str:
    client.send(f"<iq xmlns='jabber:client' type='set' id='{stanza_id}' to='{to}'>{payload}</iq>")
    return client.wait(f"id='{stanza_id}'")


def setup() -> None:
    A.wait_ready()
    B.wait_ready()
    # All child servers are already live when this lane is acquired.  Limit
    # only the CPU-heavy credential bootstrap; MIX discovery and delivery
    # below resume at full cross-worker concurrency.
    with fixture_phase_auth_admission():
        register(A, ALICE)
        register(B, BOB)
        bob_token = login(B, BOB)
        alice = connect(A, ALICE, "setup-a")
        bob = connect(B, BOB, "setup-b")
    created = iq(bob, "fed-create", "mix.remote.localhost", f"<create xmlns='{CORE}' channel='fedruntime'/>")
    check("type='result'" in created, f"remote channel create failed: {created}")
    nodes = "".join(
        f"<subscribe node='{node}'/>"
        for node in (
            "urn:xmpp:mix:nodes:messages",
            "urn:xmpp:mix:nodes:presence",
            "urn:xmpp:mix:nodes:participants",
        )
    )
    bob_join = iq(
        bob,
        "fed-join-bob",
        "mix_fed_bob@remote.localhost",
        f"<client-join xmlns='{PAM}' channel='{CHANNEL}'><join xmlns='{CORE}'>{nodes}<nick>Bob</nick></join></client-join>",
    )
    check("type='result'" in bob_join, f"local PAM join failed: {bob_join}")
    alice_join = iq(
        alice,
        "fed-join-alice",
        "mix_fed_alice@localhost",
        f"<client-join xmlns='{PAM}' channel='{CHANNEL}'><join xmlns='{CORE}'>{nodes}<nick>Alice</nick></join></client-join>",
    )
    check("type='result'" in alice_join and "#fedruntime@mix.remote.localhost" in alice_join, f"federated PAM join failed: {alice_join}")
    bob.client.send_with_pow(
        f"<message xmlns='jabber:client' type='groupchat' id='fed-live' to='{CHANNEL}'><body>federated MIX live</body></message>",
        bob_token,
    )
    live = alice.wait("federated MIX live")
    check("type='groupchat'" in live, f"reverse federated MIX delivery failed: {live}")
    alice.close()
    bob.close()
    print("MIX federation setup: create/local-PAM/remote-PAM/reverse-delivery PASS")


def enqueue() -> None:
    with fixture_phase_auth_admission():
        token = login(A, ALICE)
        alice = connect(A, ALICE, "enqueue-a")
    alice.client.send_with_pow(
        f"<message xmlns='jabber:client' type='groupchat' id='fed-durable' to='{CHANNEL}'><body>durable MIX handoff</body></message>",
        token,
    )
    time.sleep(1)
    alice.close()
    print("MIX federation durable message submitted while remote server is down")


def finish() -> None:
    A.wait_ready()
    B.wait_ready()
    with fixture_phase_auth_admission():
        alice_token = login(A, ALICE)
        bob_token = login(B, BOB)
        bob = connect(B, BOB, "finish-b")
        alice = connect(A, ALICE, "finish-a")
    replayed_live = bob.wait("durable MIX handoff")
    check(
        "<result xmlns='urn:xmpp:mam:2'" not in replayed_live,
        f"durable outbox replay unexpectedly arrived as a MAM wrapper: {replayed_live}",
    )
    mam = iq(
        bob,
        "fed-durable-mam",
        CHANNEL,
        "<query xmlns='urn:xmpp:mam:2' queryid='fed-durable-query'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mam:2</value></field></x><set xmlns='http://jabber.org/protocol/rsm'><max>20</max></set></query>",
    )
    check("<fin " in mam, f"durable MIX MAM query failed: {mam}")
    durable = bob.wait("durable MIX handoff")
    check(
        "<result xmlns='urn:xmpp:mam:2'" in durable,
        f"durable MIX handoff was not committed to channel MAM: {durable}",
    )
    alice.client.send_with_pow(
        f"<message xmlns='jabber:client' type='groupchat' id='fed-after' to='{CHANNEL}'><body>MIX federation after restart</body></message>",
        alice_token,
    )
    after = bob.wait("MIX federation after restart")
    check("type='groupchat'" in after, f"post-restart federated delivery failed: {after}")
    bob.client.send_with_pow(
        f"<message xmlns='jabber:client' type='groupchat' id='fed-reverse' to='{CHANNEL}'><body>MIX reverse after restart</body></message>",
        bob_token,
    )
    reverse = alice.wait("MIX reverse after restart")
    check("type='groupchat'" in reverse, f"post-restart reverse delivery failed: {reverse}")
    left = iq(
        alice,
        "fed-leave",
        "mix_fed_alice@localhost",
        f"<client-leave xmlns='{PAM}' channel='{CHANNEL}'><leave xmlns='{CORE}'/></client-leave>",
    )
    check("type='result'" in left, f"federated PAM leave failed: {left}")
    alice.close()
    bob.close()
    print("MIX federation finish: durable-drain/bidirectional-delivery/PAM-leave PASS")


def _write_login_slots(directory: pathlib.Path, count: int) -> None:
    """Make an exact owner-only slot set for the local gate self-test."""

    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    for name in _slot_names(count):
        descriptor = os.open(directory / name, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)


def _expect_login_slot_configuration_error(values: Mapping[str, str]) -> None:
    try:
        login_slot_configuration_from_environment(values)
    except RuntimeError:
        return
    raise AssertionError("unsafe MIX federation login slot configuration was accepted")


def _authentication_wrapper_self_test() -> None:
    """Ensure every credential exchange creates its own strict deadline."""

    entered: list[str] = []

    @contextmanager
    def observed_attempt() -> Iterator[AuthenticationAttempt]:
        entered.append("attempt")
        yield AuthenticationAttempt(time.monotonic() + CLIENT_AUTH_IO_TIMEOUT_SECONDS)

    class FakeWebSocket:
        def __init__(
            self,
            username: str,
            _password: str,
            resource: str,
            timeout: float = CLIENT_AUTH_IO_TIMEOUT_SECONDS,
            deadline: float | None = None,
        ):
            check(0 < timeout <= CLIENT_AUTH_IO_TIMEOUT_SECONDS, "XMPP constructor received an invalid timeout")
            check(
                deadline is not None and time.monotonic() < deadline,
                "XMPP constructor did not receive the shared absolute deadline",
            )
            node = f"https://northstar.invalid/mix-fed-{username}-{resource}"
            self.frames = [
                f"<iq id='caps-self-test' node='{node}#self-test'/>",
                f"<iq type='result' id='barrier-{resource}'/>",
            ]

        def send(self, _stanza: str) -> None:
            return None

        def receive(self, _timeout: float) -> str:
            return self.frames.pop(0)

        def close(self) -> None:
            return None

    class FakeFixture:
        XmppWebSocket = FakeWebSocket

        @staticmethod
        def api(
            method: str,
            path: str,
            body: object,
            timeout: float = CLIENT_AUTH_IO_TIMEOUT_SECONDS,
            deadline: float | None = None,
        ) -> tuple[int, object]:
            check(
                method == "POST" and path == "/api/v1/login" and isinstance(body, dict),
                "login wrapper issued an unexpected request",
            )
            check(0 < timeout <= CLIENT_AUTH_IO_TIMEOUT_SECONDS, "REST login received an invalid timeout")
            check(
                deadline is not None and time.monotonic() < deadline,
                "REST login did not receive the shared absolute deadline",
            )
            return 200, {"token": "opaque-self-test-token"}

        @staticmethod
        def register_account(
            username: str,
            password: str,
            timeout: float = CLIENT_AUTH_IO_TIMEOUT_SECONDS,
            deadline: float | None = None,
        ) -> tuple[int, object]:
            check(username == "selftest" and password == PASSWORD, "registration wrapper used invalid credentials")
            check(0 < timeout <= CLIENT_AUTH_IO_TIMEOUT_SECONDS, "registration received an invalid timeout")
            check(
                deadline is not None and time.monotonic() < deadline,
                "registration did not receive the shared absolute deadline",
            )
            return 201, {"username": username}

    original_attempt = authentication_attempt
    try:
        globals()["authentication_attempt"] = observed_attempt
        check(register(FakeFixture, "selftest") is None, "registration wrapper unexpectedly returned a login token")
        check(login(FakeFixture, "selftest") == "opaque-self-test-token", "login wrapper failed")
        connect(FakeFixture, "selftest", "resource")
    finally:
        globals()["authentication_attempt"] = original_attempt
    check(
        entered == ["attempt", "attempt", "attempt"],
        "registration, REST, and XMPP authentication did not each create one strict deadline",
    )
    deadline_fixture = load_fixture("northstar_mix_deadline_self_test", "localhost", "18080")
    deadline_fixture.deadline_io_self_test()


def login_slot_self_test() -> None:
    """Exercise opt-in validation, contention, release, and symlink rejection."""

    _require_flock()
    check(login_slot_configuration_from_environment({}) is None, "unset login slots were not a no-op")
    _authentication_wrapper_self_test()
    with tempfile.TemporaryDirectory(prefix="northstar-mix-login-slots-") as raw_root:
        root = pathlib.Path(raw_root)
        directory = root / "slots"
        _write_login_slots(directory, 2)
        values = {
            LOGIN_SLOT_DIRECTORY_ENV: str(directory),
            LOGIN_SLOT_COUNT_ENV: "2",
        }
        configuration = login_slot_configuration_from_environment(values)
        check(configuration is not None and len(configuration.slots) == 2, "valid login slots were rejected")
        with claim_login_slot(configuration, timeout_seconds=0.2):
            pass
        _expect_login_slot_configuration_error(
            {LOGIN_SLOT_DIRECTORY_ENV: "relative-slots", LOGIN_SLOT_COUNT_ENV: "1"}
        )
        _expect_login_slot_configuration_error({LOGIN_SLOT_COUNT_ENV: "1"})
        _expect_login_slot_configuration_error({LOGIN_SLOT_DIRECTORY_ENV: str(directory)})
        _expect_login_slot_configuration_error(
            {LOGIN_SLOT_DIRECTORY_ENV: str(directory), LOGIN_SLOT_COUNT_ENV: "0"}
        )

        unexpected = directory / "unexpected"
        unexpected.touch(mode=0o600)
        os.chmod(unexpected, 0o600)
        _expect_login_slot_configuration_error(values)
        unexpected.unlink()

        slot_zero = directory / _slot_names(2)[0]
        slot_target = root / "slot-target"
        slot_target.touch(mode=0o600)
        os.chmod(slot_target, 0o600)
        slot_zero.unlink()
        slot_zero.symlink_to(slot_target)
        _expect_login_slot_configuration_error(values)
        slot_zero.unlink()
        descriptor = os.open(slot_zero, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(descriptor)
        os.chmod(slot_zero, 0o600)

        linked_directory = root / "linked-slots"
        linked_directory.symlink_to(directory, target_is_directory=True)
        _expect_login_slot_configuration_error(
            {LOGIN_SLOT_DIRECTORY_ENV: str(linked_directory), LOGIN_SLOT_COUNT_ENV: "2"}
        )

        single_directory = root / "single-slot"
        _write_login_slots(single_directory, 1)
        single = login_slot_configuration_from_environment(
            {LOGIN_SLOT_DIRECTORY_ENV: str(single_directory), LOGIN_SLOT_COUNT_ENV: "1"}
        )
        check(single is not None, "single login slot configuration was rejected")
        slot_path = single_directory / _slot_names(1)[0]
        holder = subprocess.Popen(
            [
                sys.executable,
                "-c",
                (
                    "import fcntl, os, sys; "
                    "fd = os.open(sys.argv[1], os.O_RDWR); "
                    "fcntl.flock(fd, fcntl.LOCK_EX); "
                    "print('locked', flush=True); "
                    "sys.stdin.readline()"
                ),
                str(slot_path),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            check(holder.stdout is not None and holder.stdout.readline().strip() == "locked", "slot holder did not lock")
            try:
                with claim_login_slot(single, timeout_seconds=0.15):
                    raise AssertionError("a held slot was acquired")
            except TimeoutError:
                pass
        finally:
            if holder.stdin is not None:
                holder.stdin.write("\n")
                holder.stdin.flush()
            try:
                holder.wait(timeout=3)
            except subprocess.TimeoutExpired:
                holder.kill()
                holder.wait(timeout=3)
                raise AssertionError("slot holder did not exit")
        check(holder.returncode == 0, "slot holder exited unexpectedly")
        # Runtime phase admission waits before it creates a credential I/O
        # deadline; this proves a released lane is reacquired through that
        # unbounded-but-parent-supervised path.
        with claim_login_slot(single, timeout_seconds=None):
            pass
    print("MIX federation login slot gate self-test PASS")


def _write_phase_key(directory: pathlib.Path, pair: int) -> None:
    """Create one parent-owned test key with the exact production metadata."""

    path = directory / _phase_key_name(pair)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PHASE_FILE_MODE)
    try:
        os.write(descriptor, f"{secrets.token_hex(32)}\n".encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, PHASE_FILE_MODE)


def _write_phase_keys(directory: pathlib.Path, pairs: int) -> None:
    directory.mkdir(mode=PHASE_CONTROL_MODE)
    os.chmod(directory, PHASE_CONTROL_MODE)
    for pair in range(1, pairs + 1):
        _write_phase_key(directory, pair)


def _expect_phase_error(operation: object, message: str) -> None:
    try:
        assert callable(operation)
        operation()
    except RuntimeError:
        return
    raise AssertionError(message)


def phase_barrier_self_test() -> None:
    """Cover a signed all-pair release and exact listener lifetime checks.

    This is deliberately self-contained: it uses only temporary local sockets
    and an inherited descriptor, rather than a Northstar process or database.
    The two listener cases prove that a harmless numerical port reuse does not
    fail cleanup while an inherited original socket does.
    """

    with tempfile.TemporaryDirectory(prefix="northstar-mix-phase-") as raw_root:
        root = pathlib.Path(raw_root)
        control = root / "phase"
        _write_phase_keys(control, 2)
        nonce = secrets.token_hex(32)
        first = PhaseBarrierConfiguration(str(control), nonce, 1, 1)
        second = PhaseBarrierConfiguration(str(control), nonce, 1, 2)

        publish_phase_ready(first)
        check(
            (control / _phase_record_name("ready", 1, 1)).stat().st_nlink == 1,
            "MIX readiness publication left a transient hard-link window",
        )
        check(
            not parent_phase_ready(str(control), nonce, 1, 2),
            "parent released MIX setup before every pair was ready",
        )
        publish_phase_ready(second)
        check(
            parent_phase_ready(str(control), nonce, 1, 2),
            "parent did not accept every signed MIX readiness record",
        )
        parent_release_phase(str(control), nonce, 1, 2)
        await_phase_release(first)
        await_phase_release(second)

        _expect_phase_error(
            lambda: parent_phase_ready(str(control), secrets.token_hex(32), 1, 2),
            "a stale MIX readiness record was accepted under another run nonce",
        )

        # An incorrectly signed readiness record must never turn an incomplete
        # barrier into a successful release.
        tampered = control / _phase_record_name("ready", 1, 2)
        original = json.loads(tampered.read_text(encoding="utf-8"))
        original["pair"] = 1
        tampered.write_text(json.dumps(original), encoding="utf-8")
        os.chmod(tampered, PHASE_FILE_MODE)
        _expect_phase_error(
            lambda: parent_phase_ready(str(control), nonce, 1, 2),
            "tampered MIX readiness was accepted",
        )

        # Restore a valid pair-two record before exercising the per-pair
        # listener ledger.  The replacement models the parent repairing an
        # interrupted control record before it has released any workers.
        valid_second = _phase_payload(second, "ready")
        _write_phase_record(
            str(control),
            _phase_record_name("ready", 1, 2),
            _signed_record(_read_phase_key(second), valid_second),
            replace=True,
        )

        # Pair one owns the test socket; pair two gets an independent clean
        # listener so each ledger is independently meaningful.
        first_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        first_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        first_socket.bind(("127.0.0.1", 0))
        first_socket.listen(1)
        first_port = int(first_socket.getsockname()[1])
        record_listener_ledger(first, [f"reuse={os.getpid()}:{first_port}"])
        first_socket.close()

        reused_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        reused_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        reused_socket.bind(("127.0.0.1", first_port))
        reused_socket.listen(1)
        second_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        second_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        second_socket.bind(("127.0.0.1", 0))
        second_socket.listen(1)
        second_port = int(second_socket.getsockname()[1])
        record_listener_ledger(second, [f"second={os.getpid()}:{second_port}"])
        second_socket.close()
        reused_socket.close()
        total, reused = verify_listener_ledger_after_quiescence(str(control), nonce, 1, 2)
        check(total == 2 and reused == 0, "clean MIX listener ledgers did not verify")

        # Reuse the numerical port while preserving a *different* socket inode:
        # the verifier must regard it as a nonleak.  Pair two's ledger is
        # replaced because a restarted fixture side has new descriptors.
        first_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        first_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        first_socket.bind(("127.0.0.1", 0))
        first_socket.listen(1)
        first_port = int(first_socket.getsockname()[1])
        record_listener_ledger(first, [f"reuse={os.getpid()}:{first_port}"])
        first_socket.close()
        reused_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        reused_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        reused_socket.bind(("127.0.0.1", first_port))
        reused_socket.listen(1)
        second_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        second_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        second_socket.bind(("127.0.0.1", 0))
        second_socket.listen(1)
        record_listener_ledger(second, [f"second={os.getpid()}:{int(second_socket.getsockname()[1])}"])
        second_socket.close()
        total, reused = verify_listener_ledger_after_quiescence(str(control), nonce, 1, 2)
        check(total == 2 and reused == 1, "numerical port reuse was mistaken for a MIX listener leak")
        reused_socket.close()

        # Finally prove that the verifier detects a real leaked listener when
        # the original descriptor was inherited by a descendant.  The parent
        # closes its copy, so this cannot pass merely because the self-test
        # process still owns the socket.
        leaked_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        leaked_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        leaked_socket.bind(("127.0.0.1", 0))
        leaked_socket.listen(1)
        leaked_port = int(leaked_socket.getsockname()[1])
        record_listener_ledger(first, [f"inherited={os.getpid()}:{leaked_port}"])
        holder = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import signal,time; signal.signal(signal.SIGTERM, lambda *_: None); time.sleep(60)",
            ],
            pass_fds=(leaked_socket.fileno(),),
        )
        try:
            leaked_socket.close()
            _expect_phase_error(
                lambda: verify_listener_ledger_after_quiescence(str(control), nonce, 1, 2),
                "inherited MIX listener leak was not detected",
            )
        finally:
            holder.kill()
            holder.wait(timeout=3)
            try:
                leaked_socket.close()
            except OSError:
                pass
    print("MIX federation phase barrier and listener ledger self-test PASS")


def _phase_cli_parent_status(argv: list[str]) -> int:
    if len(argv) != 4:
        raise RuntimeError("phase parent status requires DIRECTORY NONCE ROUND PAIRS")
    directory, nonce, raw_round, raw_pairs = argv
    round_number = _phase_integer(raw_round, "ROUND")
    pairs = _phase_integer(raw_pairs, "PAIRS")
    try:
        ready = parent_phase_ready(directory, nonce, round_number, pairs)
    except RuntimeError as error:
        print(f"MIX federation phase status rejected: {error}", file=sys.stderr)
        return 2
    return 0 if ready else 1


def _phase_cli_parent_release(argv: list[str]) -> None:
    if len(argv) != 4:
        raise RuntimeError("phase parent release requires DIRECTORY NONCE ROUND PAIRS")
    directory, nonce, raw_round, raw_pairs = argv
    parent_release_phase(
        directory,
        nonce,
        _phase_integer(raw_round, "ROUND"),
        _phase_integer(raw_pairs, "PAIRS"),
    )


def _phase_cli_listener_verify(argv: list[str]) -> None:
    if len(argv) != 4:
        raise RuntimeError("listener ledger verification requires DIRECTORY NONCE ROUND PAIRS")
    directory, nonce, raw_round, raw_pairs = argv
    total, reused = verify_listener_ledger_after_quiescence(
        directory,
        nonce,
        _phase_integer(raw_round, "ROUND"),
        _phase_integer(raw_pairs, "PAIRS"),
    )
    print(f"MIX federation listener ledger verified listeners={total} reused_ports={reused}")


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        login_slot_self_test()
        return 0
    if argv == ["--phase-self-test"]:
        phase_barrier_self_test()
        return 0
    if argv == ["--phase-publish-ready"]:
        configuration = phase_barrier_configuration_from_environment()
        if configuration is None:
            raise RuntimeError("MIX federation phase readiness requires parent barrier variables")
        publish_phase_ready(configuration)
        return 0
    if argv == ["--phase-await-release"]:
        configuration = phase_barrier_configuration_from_environment()
        if configuration is None:
            raise RuntimeError("MIX federation phase release wait requires parent barrier variables")
        await_phase_release(configuration)
        return 0
    if argv and argv[0] == "--phase-parent-status":
        return _phase_cli_parent_status(argv[1:])
    if argv and argv[0] == "--phase-parent-release":
        _phase_cli_parent_release(argv[1:])
        return 0
    if argv and argv[0] == "--listener-ledger-verify":
        _phase_cli_listener_verify(argv[1:])
        return 0
    if argv and argv[0] == "--listener-ledger-record":
        configuration = phase_barrier_configuration_from_environment()
        if configuration is None:
            raise RuntimeError("MIX federation listener ledger requires parent barrier variables")
        record_listener_ledger(configuration, argv[1:])
        return 0
    phases = {"setup": setup, "enqueue": enqueue, "finish": finish}
    if len(argv) != 1 or argv[0] not in phases:
        raise RuntimeError(
            "usage: mix-federation-runtime-wsl.py "
            "[--self-test|--phase-self-test|--phase-publish-ready|--phase-await-release|"
            "--phase-parent-status DIRECTORY NONCE ROUND PAIRS|"
            "--phase-parent-release DIRECTORY NONCE ROUND PAIRS|"
            "--listener-ledger-record PURPOSE=PID:PORT...|"
            "--listener-ledger-verify DIRECTORY NONCE ROUND PAIRS|setup|enqueue|finish]"
        )
    initialize_runtime()
    phases[argv[0]]()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
