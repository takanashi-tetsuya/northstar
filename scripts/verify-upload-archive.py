#!/usr/bin/env python3
"""Reject upload archives that could escape or mutate the restore directory."""

from __future__ import annotations

import pathlib
import re
import sys
import tarfile


MAX_ARCHIVE_MEMBERS = 1_000_000
UPLOAD_OBJECT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def fail(message: str) -> None:
    raise SystemExit(f"unsafe upload archive: {message}")


def canonical_name(name: str) -> str:
    if not name or "\x00" in name or "\\" in name:
        fail(f"invalid member name {name!r}")
    path = pathlib.PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        fail(f"member escapes restore root: {name!r}")
    parts = tuple(part for part in path.parts if part not in ("", "."))
    if not parts:
        return "."
    return "/".join(parts)


def verify(path: pathlib.Path) -> None:
    seen: set[str] = set()
    with tarfile.open(path, mode="r:gz") as archive:
        for count, member in enumerate(archive, start=1):
            if count > MAX_ARCHIVE_MEMBERS:
                fail(f"contains more than {MAX_ARCHIVE_MEMBERS} entries")
            name = canonical_name(member.name)
            if name in seen and name != ".":
                fail(f"contains duplicate member {member.name!r}")
            seen.add(name)
            if member.issym() or member.islnk():
                fail(f"links are not permitted: {member.name!r}")
            if not (member.isfile() or member.isdir()):
                fail(f"special file is not permitted: {member.name!r}")
            if member.isdir() and name != ".":
                fail(f"nested directories are not permitted: {member.name!r}")
            if member.isfile() and not UPLOAD_OBJECT.fullmatch(name):
                fail(f"file is outside the UUID upload namespace: {member.name!r}")
            if member.size < 0:
                fail(f"negative member size: {member.name!r}")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {pathlib.Path(sys.argv[0]).name} UPLOAD_ARCHIVE")
    archive = pathlib.Path(sys.argv[1])
    if not archive.is_file():
        fail(f"archive does not exist: {archive}")
    try:
        verify(archive)
    except (OSError, tarfile.TarError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
