#!/usr/bin/env python3
"""Offline checks for the read-only Redis failover preflight."""

import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


guest = load("failover_guest", "local-vm-lab-redis-failover-guest.py")
host = load("failover_host", "local-vm-lab-redis-failover-preflight.py")


def snapshots():
    return {
        "infra": {"guest": "infra", "data": {"role": "master",
                  "replication": {"role": "master"}},
                  "sentinel": {"guest": "infra", "role": "sentinel",
                               "master": "infra.lab.test", "quorum": "OK 3 voters"}},
        "ejabberd": {"guest": "ejabberd", "data": {"role": "slave",
                     "replication": {"role": "slave", "master_link_status": "up",
                                     "master_host": "infra.lab.test"}},
                     "sentinel": {"guest": "ejabberd", "role": "sentinel",
                                  "master": "infra.lab.test", "quorum": "OK 3 voters"}},
        "dns-ca": {"guest": "dns-ca", "data": None,
                   "sentinel": {"guest": "dns-ca", "role": "sentinel",
                                "master": "infra.lab.test", "quorum": "OK 3 voters"}},
    }


def acl_file(directory: Path, northstar_extra: str = "") -> Path:
    lines = [
        "user default off",
        "user northstar on >test-password ~northstar:ns-a.lab.test:* "
        "&northstar:ns-a.lab.test:* " + northstar_extra + " " +
        " ".join("+" + item for item in sorted(guest.ALLOWED_DATA_COMMANDS)),
        "user sentinel-control on >test-password &__sentinel__:hello " +
        " ".join("+" + item for item in sorted(guest.SENTINEL_DATA_COMMANDS)),
        "user replication on >test-password " +
        " ".join("+" + item for item in sorted(guest.REPLICATION_COMMANDS)),
    ]
    path = directory / "users.acl"
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o600)
    return path


def sentinel_acl_file(directory: Path, peer_extra: str = "") -> Path:
    path = directory / "users.acl"
    path.write_text("user default off\n"
                    f"user sentinel-peer on >test-password allchannels +@all {peer_extra}\n"
                    "user sentinel-observer on >observer-password +ping +role "
                    "+sentinel|get-master-addr-by-name +sentinel|ckquorum "
                    "+sentinel|replicas\n")
    path.chmod(0o600)
    return path


class RedisFailoverPreflightTests(unittest.TestCase):
    def test_sentinel_replica_reply(self):
        self.assertEqual(guest.flat_reply_fields(
            "ip\nejabberd.lab.test\nport\n6379\nflags\nslave"),
            {"ip": "ejabberd.lab.test", "port": "6379", "flags": "slave"})
        with self.assertRaises(ValueError):
            guest.flat_reply_fields("ip\nejabberd.lab.test\nport")

    def test_initial_topology(self):
        self.assertEqual(host.verify(snapshots())["phase"], "pre-fault-only")

    def test_sentinel_disagreement_fails(self):
        evidence = snapshots()
        evidence["dns-ca"]["sentinel"]["master"] = "ejabberd.lab.test"
        with self.assertRaises(ValueError):
            host.verify(evidence)

    def test_replica_link_failure_fails(self):
        evidence = snapshots()
        evidence["ejabberd"]["data"]["replication"]["master_link_status"] = "down"
        with self.assertRaises(ValueError):
            host.verify(evidence)

    def test_exact_data_acl_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(guest.pwd, "getpwnam", return_value=SimpleNamespace(
                    pw_uid=os.getuid(), pw_gid=os.getgid())):
                guest.check_acl(acl_file(Path(directory)), data=True)

    def test_broad_namespace_and_sentinel_channel_fail(self):
        for extra in ("~*", "&__sentinel__:hello", "+@all", "+config"):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as directory:
                with mock.patch.object(guest.pwd, "getpwnam", return_value=SimpleNamespace(
                        pw_uid=os.getuid(), pw_gid=os.getgid())):
                    with self.assertRaises(ValueError):
                        guest.check_acl(acl_file(Path(directory), extra), data=True)

    def test_world_readable_acl_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = acl_file(Path(directory))
            path.chmod(0o644)
            with mock.patch.object(guest.pwd, "getpwnam", return_value=SimpleNamespace(
                    pw_uid=os.getuid(), pw_gid=os.getgid())):
                with self.assertRaises(ValueError):
                    guest.check_acl(path, data=True)

    def test_sentinel_peer_must_not_allow_passwordless_access(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(guest.pwd, "getpwnam", return_value=SimpleNamespace(
                    pw_uid=os.getuid(), pw_gid=os.getgid())):
                guest.check_acl(sentinel_acl_file(Path(directory)), data=False)
                with self.assertRaises(ValueError):
                    guest.check_acl(sentinel_acl_file(Path(directory), "nopass"), data=False)


if __name__ == "__main__":
    unittest.main()
