#!/usr/bin/env python3
"""Read-only Redis/Sentinel failover preflight on one isolated lab guest.

Run as root through local-vm-lab-redis-failover-preflight.py after the soak.
This script never installs services, changes roles, or writes Redis keys.
"""

import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys


DATA_GUESTS = {"infra", "ejabberd"}
SENTINEL_GUESTS = {"infra", "ejabberd", "dns-ca"}
DATA_DIR = {
    "infra": Path("/etc/northstar-lab-redis"),
    "ejabberd": Path("/etc/northstar-lab-redis-replica"),
}
DATA_SERVICE = {
    "infra": "northstar-lab-redis.service",
    "ejabberd": "northstar-lab-redis-replica.service",
}
SENTINEL_DIR = Path("/etc/northstar-lab-sentinel")
SENTINEL_SERVICE = "northstar-lab-sentinel.service"
ALLOWED_DATA_COMMANDS = {
    "ping", "role", "time", "get", "set", "setex", "expire", "ttl",
    "exists", "del", "sadd", "srem", "smembers", "scard", "zadd",
    "zrem", "zrangebyscore", "zremrangebyscore", "scan", "publish",
    "subscribe", "unsubscribe", "psubscribe", "punsubscribe", "eval",
    "evalsha", "script|load", "hget", "hset", "hdel", "hexists",
    "hlen", "hvals", "hgetall", "hkeys", "hincrby",
}
SENTINEL_DATA_COMMANDS = {
    "multi", "slaveof", "ping", "exec", "subscribe", "config|rewrite",
    "role", "publish", "info", "client|setname", "client|kill",
    "script|kill",
}
REPLICATION_COMMANDS = {"psync", "replconf", "ping"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def private_file(path: Path) -> None:
    require(path.is_file() and not path.is_symlink(), f"missing private file: {path}")
    metadata = path.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    redis = pwd.getpwnam("redis")
    require(mode & 0o027 == 0, f"private file is group-writable or world-accessible: {path}")
    require(metadata.st_uid in {0, redis.pw_uid} and
            (mode & 0o070 == 0 or metadata.st_gid == redis.pw_gid),
            f"private file has an unexpected owner or group: {path}")


def sentinel_state_directory() -> None:
    require(SENTINEL_DIR.is_dir() and not SENTINEL_DIR.is_symlink(),
            "Sentinel state directory is missing")
    metadata = SENTINEL_DIR.stat()
    redis = pwd.getpwnam("redis")
    require(metadata.st_uid == redis.pw_uid and
            stat.S_IMODE(metadata.st_mode) == 0o700,
            "Sentinel state directory must be redis-owned and mode 0700")
    private_file(SENTINEL_DIR / "sentinel.conf")
    config_metadata = (SENTINEL_DIR / "sentinel.conf").stat()
    require(config_metadata.st_uid == redis.pw_uid and
            bool(config_metadata.st_mode & stat.S_IWUSR),
            "Sentinel cannot persist election state")


def run(args: list[str], *, password: str | None = None) -> str:
    env = os.environ.copy()
    if password is not None:
        env["REDISCLI_AUTH"] = password
    result = subprocess.run(args, capture_output=True, text=True, env=env,
                            timeout=10, check=False)
    require(result.returncode == 0, f"command failed: {args[0]}")
    output = result.stdout.strip()
    require(output and not re.search(r"^(?:\(error\) |ERR |NOAUTH |NOPERM )", output),
            f"Redis error: {args[0]}")
    return output


def directives(path: Path) -> dict[str, list[list[str]]]:
    private_file(path)
    entries: dict[str, list[list[str]]] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        entries.setdefault(parts[0].lower(), []).append(parts[1:])
    return entries


def one(config: dict[str, list[list[str]]], name: str, expected: list[str]) -> None:
    require(config.get(name) == [expected], f"unsafe or missing {name}")


def acl_line(path: Path, name: str) -> set[str]:
    config = directives(path)
    lines = config.get("user", [])
    matches = [line for line in lines if line and line[0] == name]
    require(len(matches) == 1, f"missing or duplicate ACL user: {name}")
    return set(matches[0][1:])


def scoped_acl(tokens: set[str], name: str, commands: set[str],
               allowed_extra: set[str]) -> None:
    require("on" in tokens and
            len([t for t in tokens if t.startswith(">") and len(t) > 1]) == 1,
            f"{name} ACL lacks a unique password")
    require({t[1:] for t in tokens if t.startswith("+")} == commands,
            f"{name} ACL command scope changed")
    require(all(t in allowed_extra or t == "on" or t.startswith(">") or
                (t.startswith("+") and t[1:] in commands) for t in tokens),
            f"{name} ACL contains an unexpected privilege")
    require(all(not t.startswith(">") or len(t) > 1 for t in tokens),
            f"{name} ACL contains an empty password")


def check_acl(path: Path, *, data: bool) -> None:
    names = {line[0] for line in directives(path).get("user", []) if line}
    expected_names = ({"default", "northstar", "sentinel-control", "replication"}
                      if data else {"default", "sentinel-peer", "sentinel-observer"})
    require(names == expected_names, "unexpected Redis ACL identity")
    require(acl_line(path, "default") == {"off"}, "default Redis ACL is enabled")
    if data:
        northstar = acl_line(path, "northstar")
        scoped_acl(northstar, "northstar", ALLOWED_DATA_COMMANDS,
                   {"~northstar:ns-a.lab.test:*", "&northstar:ns-a.lab.test:*",
                    "reset", "resetchannels"})
        require("~northstar:ns-a.lab.test:*" in northstar and
                "&northstar:ns-a.lab.test:*" in northstar,
                "Northstar ACL namespace or channel scope changed")
        control = acl_line(path, "sentinel-control")
        scoped_acl(control, "sentinel-control", SENTINEL_DATA_COMMANDS,
                   {"&__sentinel__:hello", "reset", "resetchannels"})
        require("&__sentinel__:hello" in control,
                "Sentinel control ACL key/channel scope changed")
        replica = acl_line(path, "replication")
        scoped_acl(replica, "replication", REPLICATION_COMMANDS,
                   {"reset", "resetchannels"})
    else:
        for name in ("sentinel-peer", "sentinel-observer"):
            tokens = acl_line(path, name)
            require("on" in tokens and any(t.startswith(">") and len(t) > 1 for t in tokens),
                    f"{name} ACL lacks password")
        peer = acl_line(path, "sentinel-peer")
        scoped_acl(peer, "sentinel-peer", {"@all"},
                   {"allchannels", "reset", "resetchannels"})
        require("+@all" in peer and "allchannels" in peer,
                "Sentinel peer cannot coordinate with voters")
        observer = acl_line(path, "sentinel-observer")
        observer_commands = {"ping", "role", "sentinel|get-master-addr-by-name",
                             "sentinel|ckquorum", "sentinel|replicas"}
        scoped_acl(observer, "sentinel-observer", observer_commands,
                   {"reset", "resetchannels"})


def check_tls(config: dict[str, list[list[str]]], guest: str, *, sentinel: bool) -> None:
    require(not {"include", "requirepass", "user", "rename-command"}.intersection(config),
            "config contains an unreviewed override or authentication path")
    one(config, "port", ["0"])
    one(config, "tls-port", ["26379" if sentinel else "6379"])
    one(config, "tls-auth-clients", ["yes"])
    one(config, "protected-mode", ["yes"])
    one(config, "tls-replication", ["yes"])
    for item in ("tls-cert-file", "tls-key-file", "tls-ca-cert-file"):
        require(len(config.get(item, [])) == 1 and len(config[item][0]) == 1,
                f"missing {item}")
        path = Path(config[item][0][0])
        require(path.is_file() and not path.is_symlink(), f"missing TLS file: {item}")
    cert = config["tls-cert-file"][0][0]
    ca = config["tls-ca-cert-file"][0][0]
    run(["openssl", "verify", "-x509_strict", "-verify_hostname",
         f"{guest}.lab.test", "-CAfile", ca, cert])
    key = config["tls-key-file"][0][0]
    private_file(Path(key))
    cert_pub = run(["openssl", "x509", "-in", cert, "-pubkey", "-noout"])
    key_pub = run(["openssl", "pkey", "-in", key, "-pubout"])
    require(cert_pub == key_pub, "TLS certificate and key do not match")


def redis_cli(guest: str, config: dict[str, list[list[str]]], user: str,
              password_path: Path, port: int, *command: str) -> str:
    private_file(password_path)
    password = password_path.read_text().strip()
    require(bool(password) and "\n" not in password, "empty or malformed credential")
    return run(redis_args(guest, config, user, port, *command), password=password)


def redis_args(guest: str, config: dict[str, list[list[str]]], user: str,
               port: int, *command: str) -> list[str]:
    return ["redis-cli", "--raw", "--tls", "--cacert",
            config["tls-ca-cert-file"][0][0], "--cert",
            config["tls-cert-file"][0][0], "--key",
            config["tls-key-file"][0][0], "--sni", f"{guest}.lab.test",
            "--user", user, "-h", f"{guest}.lab.test", "-p", str(port),
            *command]


def denied(guest: str, config: dict[str, list[list[str]]], password_path: Path,
           *command: str) -> None:
    private_file(password_path)
    env = os.environ.copy()
    env["REDISCLI_AUTH"] = password_path.read_text().strip()
    require(bool(env["REDISCLI_AUTH"]), "empty Redis credential")
    result = subprocess.run(redis_args(guest, config, "northstar", 6379, *command),
                            capture_output=True, text=True, env=env, timeout=10,
                            check=False)
    require(re.match(r"^(?:\(error\) )?NOPERM\b", result.stdout.strip()) is not None,
            "Northstar runtime ACL granted a forbidden read-only probe")


def active(unit: str, config_path: Path) -> None:
    require(run(["systemctl", "is-active", unit]) == "active", f"inactive {unit}")
    command = run(["systemctl", "show", "--value", "--property=ExecStart", unit])
    require(str(config_path) in command, f"{unit} uses an unexpected config")


def flat_reply_fields(reply: str) -> dict[str, str]:
    lines = reply.splitlines()
    require(len(lines) > 0 and len(lines) % 2 == 0,
            "malformed Sentinel reply")
    fields: dict[str, str] = {}
    for index in range(0, len(lines), 2):
        key, value = lines[index:index + 2]
        require(key not in fields, "unexpected duplicate Sentinel field")
        fields[key] = value
    return fields


def inspect_data(guest: str) -> dict[str, object]:
    directory = DATA_DIR[guest]
    config = directives(directory / "redis.conf")
    check_tls(config, guest, sentinel=False)
    one(config, "aclfile", [str(directory / "users.acl")])
    check_acl(directory / "users.acl", data=True)
    if guest == "ejabberd":
        one(config, "replicaof", ["infra.lab.test", "6379"])
    one(config, "masteruser", ["replication"])
    one(config, "replica-announce-ip", [f"{guest}.lab.test"])
    one(config, "replica-announce-port", ["6379"])
    require(len(config.get("masterauth", [])) == 1 and
            len(config["masterauth"][0]) == 1 and
            f">{config['masterauth'][0][0]}" in acl_line(directory / "users.acl", "replication"),
            "replication credential differs from ACL")
    one(config, "replica-read-only", ["yes"])
    active(DATA_SERVICE[guest], directory / "redis.conf")
    role = redis_cli(guest, config, "northstar", directory / "password",
                     6379, "ROLE").splitlines()[0]
    denied(guest, config, directory / "password", "SCARD", "outside:cluster")
    denied(guest, config, directory / "password", "CONFIG", "GET", "protected-mode")
    denied(guest, config, directory / "password", "ACL", "LIST")
    info = redis_cli(guest, config, "sentinel-control",
                     directory / "sentinel-control-password", 6379,
                     "INFO", "replication")
    fields = dict(line.split(":", 1) for line in info.splitlines()
                  if ":" in line and not line.startswith("#"))
    expected = "master" if guest == "infra" else "slave"
    require(role == expected and fields.get("role") == expected,
            f"{guest} has unexpected Redis role")
    if guest == "ejabberd":
        require(fields.get("master_link_status") == "up", "replica link is down")
    else:
        # The old primary must be able to authenticate to the promoted node
        # before it is ever allowed to rejoin as a replica.
        replication_ping = run(
            ["redis-cli", "--raw", "--tls", "--cacert",
             config["tls-ca-cert-file"][0][0], "--cert",
             config["tls-cert-file"][0][0], "--key",
             config["tls-key-file"][0][0], "--sni", "ejabberd.lab.test",
             "--user", "replication", "-h", "ejabberd.lab.test",
             "-p", "6379", "PING"],
            password=config["masterauth"][0][0])
        require(replication_ping == "PONG", "old primary cannot authenticate to replica")
    return {"guest": guest, "role": role, "replication": {
        key: fields.get(key) for key in ("role", "master_host", "master_link_status",
                                     "master_repl_offset", "slave_repl_offset")}}


def inspect_sentinel(guest: str) -> dict[str, object]:
    sentinel_state_directory()
    config = directives(SENTINEL_DIR / "sentinel.conf")
    check_tls(config, guest, sentinel=True)
    one(config, "aclfile", [str(SENTINEL_DIR / "users.acl")])
    check_acl(SENTINEL_DIR / "users.acl", data=False)
    require(config.get("sentinel", []) and
            any(line == ["monitor", "northstar", "infra.lab.test", "6379", "2"]
                for line in config["sentinel"]), "Sentinel monitor/quorum changed")
    require(["resolve-hostnames", "yes"] in config["sentinel"] and
            ["announce-hostnames", "yes"] in config["sentinel"],
            "Sentinel TLS hostname handling is disabled")
    require(["announce-ip", f"{guest}.lab.test"] in config["sentinel"] and
            ["announce-port", "26379"] in config["sentinel"],
            "Sentinel voter hostname or port is not announced")
    require(any(line[:2] == ["auth-user", "northstar"] and
                line[2:] == ["sentinel-control"] for line in config["sentinel"]),
            "Sentinel data ACL identity missing")
    data_auth = [line[2] for line in config["sentinel"]
                 if len(line) == 3 and line[:2] == ["auth-pass", "northstar"]]
    private_file(SENTINEL_DIR / "data-password")
    require(len(data_auth) == 1 and data_auth[0] ==
            (SENTINEL_DIR / "data-password").read_text().strip(),
            "Sentinel data credential missing or mismatched")
    if guest in DATA_GUESTS:
        data_directory = DATA_DIR[guest]
        private_file(data_directory / "sentinel-control-password")
        require(data_auth[0] ==
                (data_directory / "sentinel-control-password").read_text().strip() and
                f">{data_auth[0]}" in acl_line(data_directory / "users.acl", "sentinel-control"),
                "Sentinel data credential differs from local Redis ACL")
    require(any(line[:1] == ["sentinel-user"] and line[1:] == ["sentinel-peer"]
                for line in config["sentinel"]), "Sentinel peer ACL identity missing")
    peer_auth = [line[1] for line in config["sentinel"]
                 if len(line) == 2 and line[0] == "sentinel-pass"]
    private_file(SENTINEL_DIR / "peer-password")
    require(len(peer_auth) == 1 and peer_auth[0] ==
            (SENTINEL_DIR / "peer-password").read_text().strip() and
            f">{peer_auth[0]}" in acl_line(SENTINEL_DIR / "users.acl", "sentinel-peer"),
            "Sentinel peer credential missing or mismatched")
    private_file(SENTINEL_DIR / "observer-password")
    observer_password = (SENTINEL_DIR / "observer-password").read_text().strip()
    require(observer_password and
            f">{observer_password}" in acl_line(SENTINEL_DIR / "users.acl", "sentinel-observer"),
            "Sentinel observer credential differs from ACL")
    active(SENTINEL_SERVICE, SENTINEL_DIR / "sentinel.conf")
    role = redis_cli(guest, config, "sentinel-observer",
                     SENTINEL_DIR / "observer-password", 26379,
                     "ROLE").splitlines()[0]
    require(role == "sentinel", f"{guest} is not a Sentinel")
    address = redis_cli(guest, config, "sentinel-observer",
                        SENTINEL_DIR / "observer-password", 26379,
                        "SENTINEL", "get-master-addr-by-name", "northstar").splitlines()
    require(len(address) == 2 and address[1] == "6379" and
            address[0] in {"infra.lab.test", "ejabberd.lab.test"},
            "Sentinel returned an unexpected primary")
    quorum = redis_cli(guest, config, "sentinel-observer",
                       SENTINEL_DIR / "observer-password", 26379,
                       "SENTINEL", "CKQUORUM", "northstar")
    require(quorum.startswith("OK "), "Sentinel quorum unavailable")
    replica = flat_reply_fields(redis_cli(
        guest, config, "sentinel-observer",
        SENTINEL_DIR / "observer-password", 26379,
        "SENTINEL", "REPLICAS", "northstar"))
    flags = set(replica.get("flags", "").split(","))
    require(replica.get("ip") == "ejabberd.lab.test" and
            replica.get("port") == "6379" and "slave" in flags and
            not flags.intersection({"s_down", "o_down", "disconnected", "master"}),
            "Sentinel does not see a healthy expected replica")
    return {"guest": guest, "role": role, "master": address[0],
            "quorum": quorum}


def main() -> None:
    require(os.geteuid() == 0, "guest preflight requires root")
    require(len(sys.argv) == 2 and sys.argv[1] in SENTINEL_GUESTS,
            "usage: local-vm-lab-redis-failover-guest.py infra|ejabberd|dns-ca")
    guest = sys.argv[1]
    require("v=8.0.2" in run(["redis-server", "--version"]),
            "guest Redis version differs from the frozen lab build")
    result = {"guest": guest, "data": inspect_data(guest) if guest in DATA_GUESTS else None,
              "sentinel": inspect_sentinel(guest)}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"Redis failover preflight failed: {error}", file=sys.stderr)
        sys.exit(1)
