#!/usr/bin/env python3
"""Small profile/evidence regressions; no compiler, database or server runs."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("profile_guard", ROOT / "scripts/check-runtime-test-profile.py")
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class RuntimeProfileTests(unittest.TestCase):
    def test_checked_in_profile(self):
        with (ROOT / "Cargo.toml").open("rb") as handle:
            GUARD.validate_manifest(tomllib.load(handle))

    def test_profile_wiring_rejects_child_or_parent_debug_fallback(self):
        names = ["listener-readiness-stress-wsl.sh", "federation-wsl.sh", "mix-federation-runtime-wsl.sh"]
        sources = {name: (ROOT / "scripts" / name).read_text(encoding="utf-8") for name in names}
        GUARD.validate_fixture_sources(sources)
        for name in names:
            with self.subTest(name=name):
                changed = dict(sources)
                changed[name] = changed[name].replace("$fixture_cargo_profile_directory", "debug")
                with self.assertRaises(ValueError):
                    GUARD.validate_fixture_sources(changed)
        for invariant in ['"NORTHSTAR_RUNTIME_TEST_PROFILE=$fixture_cargo_profile"',
                          '--message-format=json-render-diagnostics', '--check-environment',
                          'scripts/ci-runtime-artifact.py" restore',
                          '--bundle "$NORTHSTAR_RUNTIME_ARTIFACT_DIR" --binary "$candidate" || return 1']:
            changed = dict(sources)
            changed[names[0]] = changed[names[0]].replace(invariant, "")
            with self.assertRaises(ValueError):
                GUARD.validate_fixture_sources(changed)

    def test_profile_rejects_each_weakened_setting(self):
        replacements = {"inherits": "release", "opt-level": 0, "debug-assertions": False,
                        "overflow-checks": False, "panic": "abort"}
        for key, value in replacements.items():
            with self.subTest(key=key):
                settings = dict(GUARD.EXPECTED_PROFILE, **{key: value})
                with self.assertRaises(ValueError):
                    GUARD.validate_manifest({"profile": {"runtime-test": settings}})

    def test_profile_rejects_hidden_package_override_and_missing_fields(self):
        for changes in [{"package": {"*": {"debug-assertions": False}}}, {"opt-level": True}]:
            with self.assertRaises(ValueError):
                GUARD.validate_manifest({"profile": {"runtime-test": dict(GUARD.EXPECTED_PROFILE, **changes)}})
        settings = dict(GUARD.EXPECTED_PROFILE)
        del settings["overflow-checks"]
        with self.assertRaises(ValueError):
            GUARD.validate_manifest({"profile": {"runtime-test": settings}})

    def test_capacity_rejects_ambient_compiler_overrides(self):
        for name in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
                     "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
                     "CARGO_PROFILE_RUNTIME_TEST_OPT_LEVEL", "CARGO_PROFILE_DEV_PANIC"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                GUARD.validate_environment({name: "override"})
        GUARD.validate_environment({"RUSTFLAGS": "", "CARGO_BUILD_JOBS": "2", "CARGO_TARGET_DIR": "target-test"})

    def records(self, directory):
        binary = directory / "runtime-test/rust-xmpp-server"
        source = directory / "src/main.rs"
        artifact = {"reason": "compiler-artifact", "executable": str(binary), "fresh": True,
                    "target": {"name": "rust-xmpp-server", "kind": ["bin"], "src_path": str(source)},
                    "profile": {"opt_level": "2", "debug_assertions": True,
                                "overflow_checks": True, "test": False}}
        return [artifact, {"reason": "build-finished", "success": True}], binary, source

    def test_fresh_fingerprinted_artifact_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            records, binary, source = self.records(Path(directory))
            GUARD.validate_build_records(records, binary, source)

    def test_build_rejects_weakened_effective_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            for key, value in {"opt_level": "0", "debug_assertions": False,
                               "overflow_checks": False, "test": True}.items():
                with self.subTest(key=key):
                    records, binary, source = self.records(Path(directory))
                    records[0]["profile"][key] = value
                    with self.assertRaises(ValueError):
                        GUARD.validate_build_records(records, binary, source)

    def test_build_rejects_stale_path_other_source_failure_and_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            original, binary, source = self.records(Path(directory))
            mutations = [lambda r: r[0].update(executable=str(binary.parent.parent / "debug/rust-xmpp-server")),
                         lambda r: r[0]["target"].update(src_path=str(source.parent / "other.rs")),
                         lambda r: r[1].update(success=False), lambda r: r[1].update(success=1), lambda r: r.pop(),
                         lambda r: r.append(copy.deepcopy(r[0])), lambda r: r.pop(0)]
            for mutate in mutations:
                records = copy.deepcopy(original)
                mutate(records)
                with self.assertRaises(ValueError):
                    GUARD.validate_build_records(records, binary, source)

    def test_bounded_mixed_build_log(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "build.log"
            records, binary, source = self.records(Path(directory))
            path.write_text("Compiling runtime\n" + "\n".join(map(json.dumps, records)), encoding="utf-8")
            GUARD.validate_build_records(GUARD.read_build_records(path), binary, source)
            path.write_bytes(b"{" + b"x" * GUARD.MAX_BUILD_LINE_BYTES)
            with self.assertRaises(ValueError):
                GUARD.read_build_records(path)
            path.write_bytes(b"{not valid JSON}\n")
            with self.assertRaises(ValueError):
                GUARD.read_build_records(path)

    def test_shared_shell_selection_preserves_dev_and_rejects_other_profiles(self):
        helper = ROOT / "scripts/lib/runtime-test-profile.sh"
        script = 'source "$1"; fixture_select_runtime_profile "$2" || exit $?; printf "%s|%s" "$fixture_cargo_profile" "$fixture_cargo_profile_directory"'
        for name, expected in [("dev", "dev|debug"), ("runtime-test", "runtime-test|runtime-test")]:
            result = subprocess.run(["bash", "-c", script, "profile-test", str(helper), name],
                                    capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout, expected)
        for name in ["release", "../debug", "runtime-test/../debug"]:
            result = subprocess.run(["bash", "-c", script, "profile-test", str(helper), name],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
