#!/usr/bin/env python3
"""Stage one TLSA RRset in a copy of the isolated lab's unsigned zone."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile


SOA_SERIAL = re.compile(
    r"(?im)^(@\s+IN\s+SOA\s+dns-ca\.lab\.test\.\s+hostmaster\.lab\.test\.\s+\(\s*)"
    r"(\d{1,10})(\s+)"
)
TLSA_OWNER = re.compile(r"^_[1-9][0-9]{0,4}\._tcp\.[a-z0-9-]+\.lab\.test\.$")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def regular_bytes(path: Path, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError(f"expected a regular file of at most {maximum} bytes: {path}")
    return path.read_bytes()


def tlsa_record(line: str, owner: str) -> str:
    fields = line.split()
    if (
        len(fields) != 8
        or fields[0].lower() != owner
        or not fields[1].isdigit()
        or not 1 <= int(fields[1]) <= 3600
        or fields[2:4] != ["IN", "TLSA"]
        or fields[4] not in ("0", "1", "2", "3")
        or fields[5:7] != ["1", "1"]
        or re.fullmatch(r"[0-9a-fA-F]{64}", fields[7]) is None
    ):
        raise ValueError("expected a TLSA usage 0..3, selector 1, SHA-256 RR for the chosen owner")
    return " ".join(fields[:7] + [fields[7].lower()])


def stage_zone(base: str, owner: str, records: list[str]) -> tuple[str, int, int]:
    if TLSA_OWNER.fullmatch(owner) is None or int(owner.split(".", 1)[0][1:]) > 65535:
        raise ValueError("TLSA owner must be an isolated lab peer's TCP port")
    matches = list(SOA_SERIAL.finditer(base))
    if len(matches) != 1:
        raise ValueError("expected exactly one lab zone SOA serial")
    old_serial = int(matches[0].group(2))
    if not 1 <= old_serial < 4_294_967_295:
        raise ValueError("SOA serial cannot be incremented safely")
    if len(records) > 4 or len(set(records)) != len(records):
        raise ValueError("expected at most four distinct TLSA records")
    normalized = [tlsa_record(line, owner) for line in records]
    if len(set(normalized)) != len(normalized):
        raise ValueError("duplicate TLSA record")

    updated = SOA_SERIAL.sub(
        lambda match: match.group(1) + str(old_serial + 1) + match.group(3),
        base,
        count=1,
    )
    lines = []
    for line in updated.splitlines():
        if line.lstrip().startswith(";"):
            lines.append(line)
            continue
        fields = line.split()
        if fields and fields[0].upper() in ("$INCLUDE", "$GENERATE"):
            raise ValueError("zone includes generated or external records; TLSA replacement is ambiguous")
        if "TLSA" in [field.upper() for field in fields[:4]]:
            if not fields or TLSA_OWNER.fullmatch(fields[0].lower()) is None:
                raise ValueError("existing TLSA owner must be an absolute lab peer name")
            if fields[0].lower() == owner:
                continue
        lines.append(line)
    lines.extend(normalized)
    return "\n".join(lines) + "\n", old_serial, old_serial + 1


def self_test() -> None:
    owner = "_5269._tcp.prosody.lab.test."
    zone = "$TTL 300\n@ IN SOA dns-ca.lab.test. hostmaster.lab.test. ( 2026092602 3600 900 604800 300 )\n"
    good = f"{owner} 300 IN TLSA 1 1 1 {'a' * 64}"
    bad = f"{owner} 300 IN TLSA 1 1 1 {'b' * 64}"
    staged, old, new = stage_zone(zone, owner, [good])
    assert (old, new) == (2026092602, 2026092603)
    assert staged.count(" IN TLSA ") == 1
    replaced, _, _ = stage_zone(staged, owner, [bad])
    assert good not in replaced and bad in replaced
    overlap, _, _ = stage_zone(zone, owner, [good, bad])
    assert overlap.count(" IN TLSA ") == 2
    empty, _, _ = stage_zone(replaced, owner, [])
    assert " IN TLSA " not in empty
    for ambiguous in (
        good.replace(owner, "_5269._tcp.prosody"),
        "$INCLUDE other.zone",
    ):
        try:
            stage_zone(zone + ambiguous + "\n", owner, [bad])
        except ValueError:
            pass
        else:
            raise AssertionError("ambiguous existing zone records were accepted")
    for bad_records in ([good, good], [good.replace(owner, "evil.test.")]):
        try:
            stage_zone(zone, owner, bad_records)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid TLSA records were accepted")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "zone"
        path.write_text(zone)
        assert regular_bytes(path, 65536).decode() == zone
        link = path.with_name("link")
        link.symlink_to(path)
        try:
            regular_bytes(link, 65536)
        except ValueError:
            pass
        else:
            raise AssertionError("symlinked zone snapshot was accepted")
    print("local DANE zone staging self-test: ok")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--base-zone", type=Path)
    parser.add_argument("--expected-base-sha256")
    parser.add_argument("--owner")
    parser.add_argument("--records", type=Path, help="zero or more replacement TLSA records")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if any(getattr(args, name) is None for name in ("base_zone", "expected_base_sha256", "owner", "output")):
        parser.error("--base-zone, --expected-base-sha256, --owner and --output are required")
    base_bytes = regular_bytes(args.base_zone, 65536)
    if sha256(base_bytes) != args.expected_base_sha256.lower():
        raise ValueError("base zone SHA-256 does not match the pinned snapshot")
    base = base_bytes.decode("ascii")
    records = regular_bytes(args.records, 4096).decode("ascii").splitlines() if args.records else []
    records = [line.strip() for line in records if line.strip()]
    staged, old, new = stage_zone(base, args.owner.lower(), records)
    payload = staged.encode("ascii")
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
    print(json.dumps({
        "scope": "host-only zone staging; no guest or DNS service was changed",
        "base_sha256": sha256(base_bytes), "staged_sha256": sha256(payload),
        "old_soa_serial": old, "new_soa_serial": new,
        "tlsa_owner": args.owner.lower(), "tlsa_record_count": len(records),
        "output": str(args.output),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, UnicodeError) as error:
        print(f"local DANE zone staging failed: {error}", file=sys.stderr)
        sys.exit(2)
