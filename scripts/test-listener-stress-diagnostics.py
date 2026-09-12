#!/usr/bin/env python3
"""Exercise the stress driver's real bounded diagnostic functions without servers."""

from __future__ import annotations

import os
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
DRIVER = PROJECT / "scripts/listener-readiness-stress-wsl.sh"
SOURCE = DRIVER.read_text(encoding="utf-8")


def function(name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\) \{{\n.*?^\}}$", SOURCE, re.M | re.S)
    if not match:
        raise AssertionError(f"missing production function: {name}")
    return match.group(0)


FUNCTIONS = "\n".join(function(name) for name in (
    "record_parent_diagnostic", "capture_failure_log_priority",
    "append_runtime_log_tails", "retain_parent_diagnostic_artifact",
))


class DiagnosticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="northstar-diagnostic-test.")
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.runtime = self.base / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.output = self.base / "artifacts"
        self.output.mkdir(mode=0o700)

    def log(self, name: str, text: str) -> Path:
        path = self.runtime / name
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
        return path

    def invoke(self, body: str) -> tuple[str, str]:
        script = "\n".join((
            "set -euo pipefail", "umask 077",
            f"project_dir={shlex.quote(str(PROJECT))}",
            f"runtime_dir={shlex.quote(str(self.runtime))}",
            f"diagnostic_root_resolved={shlex.quote(str(self.output))}",
            'parent_diagnostic_raw="$runtime_dir/parent-diagnostics.raw.log"',
            ': >"$parent_diagnostic_raw"',
            "parent_diagnostic_max_bytes=524288",
            "parent_diagnostic_artifact=''",
            "fixture=federation", "mode=regular", "round=3",
            "parent_failure_phase=federation-transport-release-r3",
            "declare -a workers=() round_logs=() failed_worker_logs=()",
            "declare -a failure_log_priority=() cleanup_debt=()",
            "failure_log_round=''", "failure_log_priority_captured=false",
            FUNCTIONS, body,
        ))
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, timeout=15,
            env={**os.environ, "LC_ALL": "C", "GITHUB_STEP_SUMMARY": ""},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Broken pipe", result.stderr)
        artifacts = list(self.output.glob("*.redacted.log"))
        self.assertEqual(len(artifacts), 1, result.stderr)
        self.assertEqual(artifacts[0].stat().st_mode & 0o777, 0o600)
        return artifacts[0].read_text(encoding="utf-8"), result.stdout

    def test_exited_worker_precedes_current_round_and_snapshot_survives_cleanup(self):
        for pair in range(1, 51):
            self.log(f"federation.round-1.pair-{pair}.log", "HISTORICAL_ROUND\n")
            self.log(f"federation.round-3.pair-{pair}.log", f"CURRENT_PAIR_{pair}\n")
        text, _ = self.invoke(r"""
for ((pair=1;pair<=50;pair++)); do
  round_logs+=("$runtime_dir/federation.round-3.pair-$pair.log")
  workers+=("$$")
done
# A real child exits while all other diagnostic worker identities remain live.
(exit 0) & ended=$!
wait "$ended"
workers[48]="$ended"
capture_failure_log_priority
[[ "¤{failure_log_priority[0]}" == "¤{round_logs[48]}" ]]
[[ "¤{#failure_log_priority[@]}" == 1 ]]
# Parent cleanup now terminates peers; the already captured ranking cannot change.
for ((index=0;index<50;index++)); do workers[$index]="$ended"; done
capture_failure_log_priority
[[ "¤{#failure_log_priority[@]}" == 1 ]]
append_runtime_log_tails
retain_parent_diagnostic_artifact 2
""".replace("¤", "$"))
        self.assertIn("failure_round=3\n", text)
        self.assertIn("priority_worker_log=federation.round-3.pair-49.log\n", text)
        self.assertIn("CURRENT_PAIR_49\n", text)
        self.assertNotIn("HISTORICAL_ROUND", text)
        self.assertEqual(text.count("--- runtime_log="), 12)

    def test_explicit_failure_outranks_other_finished_workers_without_duplicate_tails(self):
        self.log("federation.round-3.pair-1.log", "SUCCESSFUL_SIBLING\n")
        self.log("federation.round-3.pair-2.log", "EXPLICIT_FAILURE\n")
        text, _ = self.invoke(r"""
round_logs=("$runtime_dir/federation.round-3.pair-1.log" "$runtime_dir/federation.round-3.pair-2.log")
(exit 0) & ended=$!
wait "$ended"
workers=("$ended" "$ended")
failed_worker_logs=("¤{round_logs[1]}")
append_runtime_log_tails
retain_parent_diagnostic_artifact 1
""".replace("¤", "$"))
        self.assertIn("priority_worker_log=federation.round-3.pair-2.log\n", text)
        self.assertEqual(text.count("--- runtime_log="), 2)
        self.assertEqual(text.count("EXPLICIT_FAILURE"), 1)
        self.assertGreater(text.index("EXPLICIT_FAILURE"), text.index("SUCCESSFUL_SIBLING"))

    def test_maximum_mix_detail_suffix_preserves_failed_worker_with_original_caps(self):
        for pair in range(1, 51):
            self.log(f"mix-federation.round-3.pair-{pair}.log", "W" * 32767 + "\n")
        self.log(
            "mix-federation.round-3.pair-49.log",
            "F" * 32000 + "\nFIRST_FAILURE_MARKER\nAuthorization: Bearer PRIVATE_TOKEN_SENTINEL\n"
            "-----BEGIN RSA PRIVATE KEY-----\nPRIVATE_PEM_SENTINEL\n"
            "-----END RSA PRIVATE KEY-----\n",
        )
        # The existing producer caps each of three snapshots at four private DBs.
        for pair in range(1, 5):
            for kind, limit in (("detail", 49152), ("dead-letter-detail", 32768),
                                ("s2s-head-detail", 16384)):
                self.log(f"mix-federation-authority-{kind}-{pair}.raw.log",
                         ("D" * (limit - 1)) + "\n")
        text, _ = self.invoke(r"""
fixture=mix-federation
for ((pair=1;pair<=50;pair++)); do
  round_logs+=("$runtime_dir/mix-federation.round-3.pair-$pair.log")
done
failed_worker_logs=("¤{round_logs[48]}")
append_runtime_log_tails
[[ $(wc -c <"$parent_diagnostic_raw") -gt 524288 ]]
retain_parent_diagnostic_artifact 2
""".replace("¤", "$"))
        self.assertIn("--- runtime_log=mix-federation.round-3.pair-49.log bounded_tail ---", text)
        self.assertIn("FIRST_FAILURE_MARKER", text)
        self.assertNotIn("PRIVATE_TOKEN_SENTINEL", text)
        self.assertNotIn("PRIVATE_PEM_SENTINEL", text)
        self.assertEqual(text.count("mix_federation_recipient_claim_detail="), 4)
        self.assertEqual(text.count("mix_federation_dead_letter_detail="), 4)
        self.assertEqual(text.count("mix_federation_s2s_fifo_head_detail="), 4)
        # The original cap bounds the transcript suffix; fixed metadata is additional.
        self.assertLessEqual(len(text.encode("utf-8")), 524288 + 1024)

    def test_selection_rejects_symlink_nested_and_external_candidates(self):
        outside = self.base / "outside.log"
        outside.write_text("OUTSIDE_SECRET\n", encoding="utf-8")
        (self.runtime / "link.log").symlink_to(outside)
        nested = self.runtime / "nested"
        nested.mkdir()
        (nested / "child.log").write_text("NESTED_SECRET\n", encoding="utf-8")
        self.log("valid.log", "VALID_DIAGNOSTIC\n")
        self.log("mix-federation-authority-summary.raw.log", "EXCLUDED_AUTHORITY_SUMMARY\n")
        text, _ = self.invoke(r"""
failed_worker_logs=("$runtime_dir/link.log" "$runtime_dir/nested/child.log" "$runtime_dir/../outside.log")
append_runtime_log_tails
retain_parent_diagnostic_artifact 2
""")
        self.assertIn("VALID_DIAGNOSTIC", text)
        for marker in ("OUTSIDE_SECRET", "NESTED_SECRET", "EXCLUDED_AUTHORITY_SUMMARY"):
            self.assertNotIn(marker, text)
        self.assertEqual(text.count("--- runtime_log="), 1)

    def test_preflight_failure_without_round_or_workers_retains_safe_metadata(self):
        text, _ = self.invoke(r"""
unset round
parent_failure_phase=database-preflight
append_runtime_log_tails
retain_parent_diagnostic_artifact 2
""")
        self.assertIn("first_failure_phase=database-preflight", text)
        self.assertIn("failure_round=unknown", text)
        self.assertNotIn("priority_worker_log=", text)

    def test_redactor_failure_does_not_fall_back_to_raw_logs(self):
        self.log("failure.log", "Authorization: Bearer FALLBACK_SECRET\n")
        text, _ = self.invoke(r"""
append_runtime_log_tails
python3() { return 1; }
retain_parent_diagnostic_artifact 2
""")
        self.assertIn("diagnostic_redactor_failed=true", text)
        self.assertIn("first_failure_phase=", text)
        self.assertNotIn("FALLBACK_SECRET", text)

    def test_production_wiring_freezes_before_cancellation_and_preserves_limits(self):
        cleanup = function("cleanup")
        self.assertLess(cleanup.index("capture_failure_log_priority"),
                        cleanup.index("signal_worker_groups TERM"))
        selection = function("append_runtime_log_tails")
        self.assertNotRegex(selection, r"\b(?:find|sort)\b.*\|")
        self.assertIn(">= 12", selection)
        self.assertIn("tail -c 32768", selection)
        self.assertIn("readonly parent_diagnostic_max_bytes=524288", SOURCE)
        self.assertIn("detail_database_limit=4", function("append_mix_federation_database_snapshots"))
        self.assertIn('failed_worker_logs+=("$log")', SOURCE)
        self.assertIn('failed_worker_logs+=("¤{round_logs[$((pair - 1))]}")'.replace("¤", "$"), SOURCE)

    def test_stage_timings_cover_success_and_interrupted_stage_without_database_names(self):
        script = '\n'.join((
            'set -euo pipefail', f'parent_diagnostic_raw={shlex.quote(str(self.runtime / "timing.log"))}',
            'parent_diagnostic_max_bytes=524288', 'parent_stage=""', 'round=3', 'fixture=federation',
            function('record_parent_diagnostic'), function('parent_stage_begin'), function('parent_stage_end'),
            'parent_stage_begin provision', 'sleep .02', 'parent_stage_end 0',
            'trap \'parent_stage_end "$?"\' EXIT', 'parent_stage_begin workload', 'false',
        ))
        result = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        values = [json.loads(line.split('=', 1)[1]) for line in result.stdout.splitlines()]
        self.assertEqual([(v['phase'], v['status']) for v in values], [('provision', 0), ('workload', 1)])
        self.assertGreaterEqual(values[0]['elapsed_ms'], 20)
        self.assertTrue(all(v['elapsed_ms'] >= 0 and v['round'] == 3 for v in values))
        self.assertTrue(all(set(v) == {'phase', 'status', 'round', 'fixture', 'elapsed_ms'} for v in values))


if __name__ == "__main__":
    unittest.main()
