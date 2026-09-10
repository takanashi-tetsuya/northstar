#!/usr/bin/env python3
"""Validate the reviewed capacity profile and Cargo's current build artifact."""

import argparse
import json
import os
from pathlib import Path
import sys
import tomllib


EXPECTED_PROFILE = {
    "inherits": "dev",
    "opt-level": 2,
    "debug-assertions": True,
    "overflow-checks": True,
    "panic": "unwind",
}
MAX_BUILD_LOG_BYTES = 16 * 1024 * 1024
MAX_BUILD_LINE_BYTES = 2 * 1024 * 1024


def validate_manifest(document):
    profile = document.get("profile", {}).get("runtime-test")
    if not isinstance(profile, dict) or set(profile) != set(EXPECTED_PROFILE):
        raise ValueError("capacity runtime-test profile differs from the reviewed settings")
    for key, expected in EXPECTED_PROFILE.items():
        if type(profile[key]) is not type(expected) or profile[key] != expected:
            raise ValueError(f"capacity runtime-test profile has invalid {key}")


def validate_environment(environment):
    # A fixed capacity lane must not silently inherit a different compiler
    # contract. Normal dev fixtures are not subject to this preflight check.
    for name, value in environment.items():
        if value and (name.endswith("RUSTFLAGS") or name.startswith("CARGO_PROFILE_")):
            raise ValueError(f"capacity profile refuses external compiler override {name}")


def validate_fixture_sources(sources):
    expected = {
        "listener-readiness-stress-wsl.sh": [
            "fixture_select_runtime_profile runtime-test",
            '"NORTHSTAR_RUNTIME_TEST_PROFILE=$fixture_cargo_profile"',
            '--profile "$fixture_cargo_profile" --message-format=json-render-diagnostics',
            '--manifest "$project_dir/Cargo.toml" --check-environment || return 1',
            'candidate="$configured_target_dir/$fixture_cargo_profile_directory/rust-xmpp-server"',
            '"$resolved_target_dir/$fixture_cargo_profile_directory/rust-xmpp-server"',
            '--build-log "$runtime_dir/parent-preflight-build.raw.log"',
            '--binary "$resolved_binary" --source "$project_dir/src/main.rs" || return 1',
        ],
        "federation-wsl.sh": [
            'fixture_select_runtime_profile "${NORTHSTAR_RUNTIME_TEST_PROFILE:-dev}"',
            '--profile "$fixture_cargo_profile"',
            'binary="$target_dir/$fixture_cargo_profile_directory/rust-xmpp-server"',
        ],
        "mix-federation-runtime-wsl.sh": [
            'fixture_select_runtime_profile "${NORTHSTAR_RUNTIME_TEST_PROFILE:-dev}"',
            '--profile "$fixture_cargo_profile"',
            'binary="${CARGO_TARGET_DIR:-$project_dir/target}/$fixture_cargo_profile_directory/rust-xmpp-server"',
        ],
    }
    for name, invariants in expected.items():
        source = sources[name]
        if any(invariant not in source for invariant in invariants):
            raise ValueError(f"capacity profile build/child selection contract changed in {name}")


def validate_build_records(records, binary, source):
    artifacts = []
    finished = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Cargo build record is not an object")
        if record.get("reason") == "build-finished":
            finished.append(record.get("success"))
        if record.get("reason") == "compiler-artifact":
            target = record.get("target", {})
            if not isinstance(target, dict):
                raise ValueError("Cargo artifact target is not an object")
            if target.get("name") == "rust-xmpp-server" and target.get("kind") == ["bin"]:
                artifacts.append(record)
    if len(finished) != 1 or finished[0] is not True or len(artifacts) != 1:
        raise ValueError("capacity build must contain one successful current server artifact")
    artifact = artifacts[0]
    profile = artifact.get("profile", {})
    if not isinstance(profile, dict):
        raise ValueError("Cargo artifact profile is not an object")
    expected = {
        "opt_level": "2",
        "debug_assertions": True,
        "overflow_checks": True,
        "test": False,
    }
    for key, value in expected.items():
        if type(profile.get(key)) is not type(value) or profile[key] != value:
            raise ValueError(f"capacity server artifact has invalid {key}")
    executable = artifact.get("executable")
    src_path = artifact.get("target", {}).get("src_path")
    if not isinstance(executable, str) or Path(executable).resolve() != Path(binary).resolve():
        raise ValueError("capacity server artifact does not match the selected binary")
    if not isinstance(src_path, str) or Path(src_path).resolve() != Path(source).resolve():
        raise ValueError("capacity server artifact does not belong to this workspace source")


def read_build_records(path):
    records = []
    total = 0
    with Path(path).open("rb") as handle:
        while line := handle.readline(MAX_BUILD_LINE_BYTES + 1):
            total += len(line)
            if len(line) > MAX_BUILD_LINE_BYTES or total > MAX_BUILD_LOG_BYTES:
                raise ValueError("capacity build evidence exceeds its bounded size")
            # The existing phase recorder combines Cargo JSON stdout with
            # human-readable compiler diagnostics on stderr.
            if line.lstrip().startswith(b"{"):
                records.append(json.loads(line))
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--check-environment", action="store_true")
    parser.add_argument("--build-log", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--source", type=Path)
    args = parser.parse_args()
    if not (args.manifest or args.build_log):
        parser.error("a manifest or current build log is required")
    if bool(args.build_log) != bool(args.binary and args.source):
        parser.error("build evidence requires --build-log, --binary and --source together")
    try:
        if args.manifest:
            with args.manifest.open("rb") as handle:
                validate_manifest(tomllib.load(handle))
            scripts = args.manifest.resolve().parent / "scripts"
            validate_fixture_sources({name: (scripts / name).read_text(encoding="utf-8") for name in [
                "listener-readiness-stress-wsl.sh", "federation-wsl.sh", "mix-federation-runtime-wsl.sh",
            ]})
        if args.check_environment:
            validate_environment(os.environ)
        if args.build_log:
            validate_build_records(read_build_records(args.build_log), args.binary, args.source)
    except (OSError, ValueError, TypeError) as error:
        print(f"runtime-test profile rejected: {error}", file=sys.stderr)
        return 1
    print("runtime-test profile: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
