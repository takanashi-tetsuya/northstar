#!/usr/bin/env python3
"""Offline checks for the exact three-authority SIGKILL takeover deadline."""

import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("cluster_fixture", Path(__file__).with_name("cluster-wsl.py"))
cluster = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cluster)
TARGET = "alice_cluster@cluster.localhost/ttl-takeover"


def authority():
    return {
        "database": "xmpp_test", "schema": "takeover_fixture", "host": "127.0.0.1",
        "port": 54321, "namespace": cluster.DOMAIN, "full_jid": TARGET, "node": "node-a",
        "instance": "00000000-0000-0000-0000-000000000001", "epoch": 7,
        "connection": "00000000-0000-0000-0000-000000000002",
        "live_remaining": 119.8, "process_remaining": 89.5,
        "database_observed_at": 1000.0,
        "live_expires_at": 1119.8, "process_expires_at": 1089.5,
    }


class TakeoverExpiryTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(cluster.os.environ, {"PGPORT": "54321"})
        self.schema = patch.object(cluster, "SCHEMA", "takeover_fixture")
        self.environment.start()
        self.schema.start()
        self.addCleanup(self.environment.stop)
        self.addCleanup(self.schema.stop)

    def test_exact_snapshot_is_accepted(self):
        snapshot = authority()
        with patch.object(cluster, "database_scalar", return_value=json.dumps(snapshot)) as database:
            self.assertEqual(cluster.read_takeover_authority(TARGET), snapshot)
        query = database.call_args.args[0]
        for constraint in (
            "lease.connection_id=route.connection_uuid",
            "instance.instance_uuid=route.owner_instance_uuid",
            "instance.instance_epoch=route.owner_instance_epoch",
            "route.claim_proof_kind='lease'",
        ):
            self.assertIn(constraint, query)
        self.assertEqual(database.call_args.kwargs["timeout"], 3)

    def test_wrong_identity_and_endpoint_are_rejected(self):
        for field, value in (
            ("database", "other"), ("schema", "public"), ("host", "remote.example"),
            ("port", 54322), ("namespace", "other.example"), ("full_jid", TARGET + "-other"),
            ("node", "node-b"), ("instance", "00000000-0000-0000-0000-000000000000"),
            ("connection", "not-a-uuid"), ("epoch", 0), ("epoch", True),
        ):
            with self.subTest(field=field, value=value):
                snapshot = authority()
                snapshot[field] = value
                with self.assertRaises((AssertionError, ValueError)):
                    cluster.validate_takeover_authority(snapshot, TARGET)

    def test_missing_explicit_database_port_is_rejected(self):
        with patch.dict(cluster.os.environ, {"PGPORT": ""}):
            with self.assertRaisesRegex(AssertionError, "endpoint"):
                cluster.validate_takeover_authority(authority(), TARGET)

    def test_unreasonable_or_old_lease_does_not_change_the_contract(self):
        for field, value in (
            ("live_remaining", 120.1), ("live_remaining", 105),
            ("live_remaining", float("nan")), ("live_remaining", True),
            ("process_remaining", 90.1), ("process_remaining", 0),
            ("process_remaining", float("inf")),
        ):
            with self.subTest(field=field, value=value):
                snapshot = authority()
                snapshot[field] = value
                with self.assertRaises(AssertionError):
                    cluster.validate_takeover_authority(snapshot, TARGET)

    def test_database_deadlines_are_fixed_consistent_and_finite(self):
        for field, value in (
            ("database_observed_at", 999), ("live_expires_at", 1001),
            ("process_expires_at", 1080), ("live_expires_at", float("inf")),
            ("process_expires_at", "1089.5"), ("database_observed_at", True),
        ):
            with self.subTest(field=field, value=value):
                snapshot = authority()
                snapshot[field] = value
                with self.assertRaises(AssertionError):
                    cluster.validate_takeover_authority(snapshot, TARGET)

    def test_budget_uses_live_lease_not_just_ninety_second_redis_ttl(self):
        deadline = cluster.takeover_expiry_deadline(authority(), 89, 1000, 1000.1)
        self.assertAlmostEqual(deadline, 1134.9)
        self.assertGreater(deadline, 1105)
        self.assertLessEqual(deadline, 1135)

    def test_observation_delay_cannot_extend_absolute_hard_ceiling(self):
        self.assertEqual(cluster.takeover_expiry_deadline(authority(), 90, 1000, 1014), 1135)
        for observed in (999, 1015.1, float("inf")):
            with self.subTest(observed=observed):
                with self.assertRaises(AssertionError):
                    cluster.takeover_expiry_deadline(authority(), 90, 1000, observed)
        for ttl in (-2, 0, 1, 91, True):
            with self.subTest(ttl=ttl):
                with self.assertRaises(AssertionError):
                    cluster.takeover_expiry_deadline(authority(), ttl, 1000, 1000)

    def test_both_exact_postgresql_authorities_must_be_expired(self):
        for live in (False, True):
            for process in (False, True):
                with self.subTest(live=live, process=process):
                    observation = {"original_deadlines_elapsed": True, "identity_matches": True, "live_active": live, "process_active": process}
                    with patch.object(cluster, "database_scalar", return_value=json.dumps(observation)) as database:
                        self.assertEqual(cluster.takeover_authorities_expired(authority(), 0.8), not live and not process)
                    query = database.call_args.args[0]
                    self.assertIn("connection_id='00000000-0000-0000-0000-000000000002'::UUID", query)
                    self.assertIn("instance_epoch=7", query)
                    self.assertEqual(database.call_args.kwargs["timeout"], 0.8)
                    self.assertNotRegex(query.upper(), r"\b(UPDATE|DELETE|INSERT)\b")

    def test_missing_original_rows_cannot_pass_before_their_captured_deadlines(self):
        observation = {"original_deadlines_elapsed": False, "identity_matches": True,
                       "live_active": False, "process_active": False}
        with patch.object(cluster, "database_scalar", return_value=json.dumps(observation)) as database:
            self.assertFalse(cluster.takeover_authorities_expired(authority(), 1))
        query = database.call_args.args[0]
        self.assertEqual(query.count("clock_timestamp()"), 1)
        self.assertIn("observed.now_at>=to_timestamp(1119.8)", query)
        self.assertIn("observed.now_at>=to_timestamp(1089.5)", query)

    def test_authority_replacement_or_malformed_observation_is_not_expiry(self):
        baseline = {"original_deadlines_elapsed": True, "identity_matches": True, "live_active": False, "process_active": False}
        for observation in (
            {**baseline, "identity_matches": False},
            {**baseline, "live_active": 0},
            {"identity_matches": True}, [],
        ):
            with self.subTest(observation=observation):
                with patch.object(cluster, "database_scalar", return_value=json.dumps(observation)):
                    with self.assertRaises(AssertionError):
                        cluster.takeover_authorities_expired(authority(), 1)

    def test_poll_never_accepts_redis_expiry_without_postgresql_expiry(self):
        now = [0.0]
        with patch.object(cluster.time, "monotonic", side_effect=lambda: now[0]), \
                patch.object(cluster.time, "sleep", side_effect=lambda delay: now.__setitem__(0, now[0] + delay)), \
                patch.object(cluster, "redis_cli", return_value="0") as redis, \
                patch.object(cluster, "takeover_authorities_expired", side_effect=[False, True]) as database:
            self.assertTrue(cluster.wait_for_takeover_expiry(authority(), "fixture:alive", 1))
        self.assertEqual(database.call_count, 2)
        self.assertEqual(redis.call_count, 2)
        self.assertGreater(now[0], 0)

    def test_redis_still_alive_cannot_pass_on_postgresql_expiry(self):
        now = [0.0]
        with patch.object(cluster.time, "monotonic", side_effect=lambda: now[0]), \
                patch.object(cluster.time, "sleep", side_effect=lambda delay: now.__setitem__(0, now[0] + delay)), \
                patch.object(cluster, "redis_cli", return_value="1"), \
                patch.object(cluster, "takeover_authorities_expired", return_value=True):
            self.assertFalse(cluster.wait_for_takeover_expiry(authority(), "fixture:alive", 0.2))

    def test_late_expiry_result_cannot_pass_or_trigger_a_final_recheck(self):
        now = [0.0]

        def late_database(*_args):
            now[0] = 1.1
            return True

        with patch.object(cluster.time, "monotonic", side_effect=lambda: now[0]), \
                patch.object(cluster, "redis_cli", return_value="0") as redis, \
                patch.object(cluster, "takeover_authorities_expired", side_effect=late_database) as database:
            self.assertFalse(cluster.wait_for_takeover_expiry(authority(), "fixture:alive", 1))
        self.assertEqual(database.call_count, 1)
        self.assertEqual(redis.call_count, 1)

    def test_expired_budget_does_not_read_any_authority(self):
        with patch.object(cluster.time, "monotonic", return_value=1), \
                patch.object(cluster, "redis_cli") as redis, \
                patch.object(cluster, "takeover_authorities_expired") as database:
            self.assertFalse(cluster.wait_for_takeover_expiry(authority(), "fixture:alive", 1))
        redis.assert_not_called()
        database.assert_not_called()


if __name__ == "__main__":
    unittest.main()
