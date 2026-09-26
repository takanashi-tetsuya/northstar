#!/usr/bin/env python3
"""Record read-only client prerequisites for the isolated VM lab."""

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess


PACKAGES = (
    "gajim", "python3-nbxmpp", "dino", "firefox", "firefox-esr",
    "chromium", "chromium-browser", "android-sdk-platform-tools",
)
COMMANDS = (
    "gajim", "dino", "firefox", "chromium", "chromium-browser",
    "google-chrome", "node", "adb", "emulator", "qemu-system-x86_64", "virsh",
)
ARTIFACT_LABELS = {
    "northstar-binary", "lab-ca", "client-image", "android-apk",
    "browser-binary", "playwright-package",
}


def run(args: list[str]) -> str | None:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=5, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return result.stdout


def package_versions() -> dict[str, str | None]:
    output = run([
        "dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n",
        *PACKAGES,
    ])
    versions: dict[str, str | None] = dict.fromkeys(PACKAGES)
    if output is not None:
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) == 3 and parts[0] in versions and parts[2].startswith("ii"):
                versions[parts[0]] = parts[1]
    return versions


def file_record(path_text: str) -> dict[str, str | int]:
    path = Path(path_text)
    if not path.is_file():
        raise ValueError(f"artifact is not a regular file: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"path": str(path.resolve()), "bytes": size, "sha256": digest.hexdigest()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--role", choices=("host-preflight", "isolated-client-vm"),
        default="host-preflight", help="where this inventory was collected",
    )
    parser.add_argument(
        "--artifact", action="append", default=[], metavar="LABEL=FILE",
        help="hash a non-secret binary, lab CA, image, APK or Playwright package",
    )
    args = parser.parse_args()

    artifacts = {}
    for item in args.artifact:
        label, separator, path = item.partition("=")
        if separator != "=" or label not in ARTIFACT_LABELS or not path:
            parser.error(f"--artifact must be LABEL=FILE; labels: {', '.join(sorted(ARTIFACT_LABELS))}")
        if label in artifacts:
            parser.error(f"duplicate artifact label: {label}")
        try:
            artifacts[label] = file_record(path)
        except (OSError, ValueError) as error:
            parser.error(str(error))

    repo = Path(__file__).resolve().parent.parent
    commit = run(["git", "-C", str(repo), "rev-parse", "HEAD"])
    commit = commit.strip() if commit and re.fullmatch(r"[0-9a-f]{40}", commit.strip()) else None
    report = {
        "schema": "northstar-isolated-client-inventory-v1",
        "captured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "role": args.role,
        "qualification": "inventory_only_no_client_or_network_test",
        "source_commit": commit,
        "packages": package_versions(),
        "commands": {name: shutil.which(name) is not None for name in COMMANDS},
        "artifacts": artifacts,
        "manual_requirements": [
            "verify the client VM has only the isolated lab interface and no default route",
            "capture negotiated XMPP features and client/server logs for each test",
            "verify the actual browser and Playwright versions; a Firefox launcher package is insufficient",
            "record Monal hardware availability separately",
        ],
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
