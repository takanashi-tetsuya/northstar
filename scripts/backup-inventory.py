#!/usr/bin/env python3
"""Validate the exact-version S3 object set bound to a database dump."""

import argparse
import hashlib
import os
import pathlib
import re
import sys
import tarfile
import uuid

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
HEX = re.compile(r"[0-9a-f]{64}")
HEADER = "northstar-upload-inventory-v1"


def inventory(path: pathlib.Path) -> list[tuple[str, str, str, int, str]]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("inventory must be a regular non-symlink file")
    if path.stat().st_size > 512 * 1024 * 1024:
        raise ValueError("inventory exceeds the bounded input size")
    lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    if not lines or lines[0] != HEADER:
        raise ValueError("inventory header is invalid")
    rows = []
    previous = ""
    for number, line in enumerate(lines[1:], 2):
        fields = line.split("\t")
        if len(fields) != 5:
            raise ValueError(f"inventory row {number} has wrong field count")
        object_id, key, version, size, digest = fields
        if not UUID.fullmatch(object_id) or object_id <= previous:
            raise ValueError(f"inventory row {number} is unsorted, repeated, or has invalid UUID")
        if not UUID.fullmatch(key.removeprefix(f"objects/{object_id}/")) or key != f"objects/{object_id}/{key.rsplit('/', 1)[-1]}":
            raise ValueError(f"inventory row {number} has an invalid key")
        if not version or len(version) > 1024 or any(ord(ch) < 32 or ord(ch) == 127 for ch in version):
            raise ValueError(f"inventory row {number} has an invalid version")
        if not size.isdigit() or int(size) > 2**63 - 1 or not HEX.fullmatch(digest):
            raise ValueError(f"inventory row {number} has an invalid size or digest")
        rows.append((object_id, key, version, int(size), digest))
        previous = object_id
    return rows


def restored_inventory(source: pathlib.Path, results: pathlib.Path, output: pathlib.Path) -> None:
    old = inventory(source)
    if results.is_symlink() or not results.is_file() or output.exists():
        raise ValueError("restore result or target inventory path is unsafe")
    if results.stat().st_size > 512 * 1024 * 1024:
        raise ValueError("restore result exceeds the bounded input size")
    lines = results.read_text(encoding="utf-8", errors="strict").splitlines()
    if not lines or lines[0] != "northstar-s3-restore-results-v1" or len(lines) - 1 != len(old):
        raise ValueError("restore result header or row count is invalid")
    target_lines = [HEADER]
    for number, (raw, source_row) in enumerate(zip(lines[1:], old), 1):
        fields = raw.split("\t")
        if len(fields) != 5 or fields[0] != source_row[0] or fields[3] != str(source_row[3]) or fields[4] != source_row[4]:
            raise ValueError(f"restore result differs from signed inventory at row {number}")
        if fields[1] == source_row[1] or not fields[2]:
            raise ValueError(f"restore reused the source locator at row {number}")
        target_lines.append(raw)
    output.write_text("\n".join(target_lines) + "\n", encoding="utf-8")
    output.chmod(0o600)
    inventory(output)


def copy_field(value: str) -> str:
    if any(ch in value for ch in ("\t", "\n", "\r", "\x00")):
        raise ValueError("inventory field cannot be encoded as COPY text")
    return value.replace("\\", "\\\\")


def write_attempts(source: pathlib.Path, output: pathlib.Path) -> None:
    rows = inventory(source)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(output, flags, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write("northstar-s3-restore-attempts-v1\n")
        for object_id, key, _, _, _ in rows:
            attempt = uuid.uuid4()
            while str(attempt) == key.rsplit("/", 1)[-1]:
                attempt = uuid.uuid4()
            handle.write(f"{object_id}\t{attempt}\n")
        handle.flush()
        os.fsync(handle.fileno())


def write_remap_sql(
    source: pathlib.Path,
    target: pathlib.Path,
    output: pathlib.Path,
    source_namespace: str,
    source_generation: int,
    target_namespace: str,
) -> None:
    old = inventory(source)
    new = inventory(target)
    if len(old) != len(new) or output.exists():
        raise ValueError("source and target inventories differ in count or output exists")
    if not HEX.fullmatch(source_namespace) or not HEX.fullmatch(target_namespace) or source_generation < 1:
        raise ValueError("storage authority is invalid")
    if source_generation >= 2**63 - 1:
        raise ValueError("storage generation cannot advance")
    for original, replacement in zip(old, new):
        if original[0] != replacement[0] or original[3:] != replacement[3:] or original[1] == replacement[1]:
            raise ValueError("target inventory does not exactly replace the source")
    with output.open("x", encoding="utf-8") as sql:
        sql.write("SET LOCAL search_path TO public,pg_catalog;\n")
        sql.write("CREATE TEMP TABLE northstar_s3_restore_map (id uuid PRIMARY KEY, old_key text NOT NULL, old_version text NOT NULL, new_key text NOT NULL, new_version text NOT NULL, object_size bigint NOT NULL, object_sha256 text NOT NULL) ON COMMIT DROP;\n")
        sql.write("COPY northstar_s3_restore_map(id,old_key,old_version,new_key,new_version,object_size,object_sha256) FROM STDIN;\n")
        for original, replacement in zip(old, new):
            fields = (original[0], original[1], original[2], replacement[1], replacement[2], str(original[3]), original[4])
            sql.write("\t".join(copy_field(value) for value in fields) + "\n")
        sql.write("\\.\n")
        sql.write(f"""DO $northstar_s3_restore$
DECLARE changed bigint;
BEGIN
  IF (SELECT count(*) FROM public.upload_storage_authority)<>1
     OR NOT EXISTS (SELECT 1 FROM public.upload_storage_authority
                     WHERE singleton AND storage_backend='s3'
                       AND namespace_sha256=decode('{source_namespace}','hex')
                       AND generation={source_generation}) THEN
    RAISE EXCEPTION 'restored S3 authority differs from signed backup';
  END IF;
  IF (SELECT count(*) FROM public.upload_slots)<>{len(old)}
     OR (SELECT count(*) FROM northstar_s3_restore_map)<>{len(old)}
     OR EXISTS (SELECT 1 FROM public.upload_storage_jobs)
     OR EXISTS (SELECT 1 FROM public.upload_cleanup_queue)
     OR EXISTS (SELECT 1 FROM public.upload_storage_migration_runs WHERE state='copying')
     OR EXISTS (
       SELECT 1 FROM public.upload_slots s
       LEFT JOIN northstar_s3_restore_map m ON m.id=s.id
       WHERE m.id IS NULL OR s.storage_backend<>'s3'
          OR s.storage_state<>'committed' OR NOT s.uploaded OR s.uploading
          OR s.storage_object_key<>m.old_key
          OR s.storage_object_version<>m.old_version
          OR s.storage_size<>m.object_size
          OR s.storage_sha256<>decode(m.object_sha256,'hex')
          OR s.storage_fence>=9223372036854775807
          OR m.new_key<>('objects/' || s.id::text || '/' || split_part(m.new_key,'/',3)::uuid::text)
     ) THEN
    RAISE EXCEPTION 'restored S3 locators do not match the signed exact-version inventory';
  END IF;
  UPDATE public.upload_slots s
     SET storage_attempt=split_part(m.new_key,'/',3)::uuid,
         storage_object_key=m.new_key,
         storage_object_version=m.new_version,
         storage_sha256=decode(m.object_sha256,'hex'),
         content_sha256=decode(m.object_sha256,'hex'),
         storage_size=m.object_size,
         storage_fence=s.storage_fence+1,
         storage_updated_at=clock_timestamp(),
         storage_scrub_next_at=clock_timestamp()
    FROM northstar_s3_restore_map m WHERE s.id=m.id;
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed<>{len(old)} THEN
    RAISE EXCEPTION 'S3 restore updated an incomplete locator set';
  END IF;
  EXECUTE 'ALTER TABLE public.upload_storage_authority DISABLE TRIGGER upload_storage_authority_immutable';
  UPDATE public.upload_storage_authority
     SET namespace_sha256=decode('{target_namespace}','hex'),
         generation={source_generation + 1},updated_at=clock_timestamp()
   WHERE singleton AND storage_backend='s3'
     AND namespace_sha256=decode('{source_namespace}','hex')
     AND generation={source_generation};
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed<>1 THEN RAISE EXCEPTION 'S3 restore authority cutover did not update exactly one row'; END IF;
  EXECUTE 'ALTER TABLE public.upload_storage_authority ENABLE TRIGGER upload_storage_authority_immutable';
END
$northstar_s3_restore$;
""")
        sql.flush()
    output.chmod(0o600)


def archive_matches(path: pathlib.Path, rows: list[tuple[str, str, str, int, str]]) -> None:
    expected = {row[0]: row for row in rows}
    seen = set()
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = member.name.removeprefix("./")
            if name not in expected or not member.isfile() or name in seen:
                raise ValueError(f"upload archive contains an unexpected member: {member.name}")
            if member.size != expected[name][3]:
                raise ValueError(f"upload archive size mismatch: {name}")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"upload archive member is unreadable: {name}")
            hasher = hashlib.sha256()
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                hasher.update(chunk)
            if hasher.hexdigest() != expected[name][4]:
                raise ValueError(f"upload archive digest mismatch: {name}")
            seen.add(name)
    if seen != set(expected):
        raise ValueError("upload archive omits inventory objects")


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("rows", type=pathlib.Path)
    build.add_argument("output", type=pathlib.Path)
    verify = commands.add_parser("verify")
    verify.add_argument("inventory", type=pathlib.Path)
    verify.add_argument("archive", type=pathlib.Path)
    verify.add_argument("count", type=int)
    verify.add_argument("size", type=int)
    pack = commands.add_parser("pack")
    pack.add_argument("inventory", type=pathlib.Path)
    pack.add_argument("objects", type=pathlib.Path)
    pack.add_argument("archive", type=pathlib.Path)
    results = commands.add_parser("results")
    results.add_argument("source", type=pathlib.Path)
    results.add_argument("results", type=pathlib.Path)
    results.add_argument("target", type=pathlib.Path)
    remap = commands.add_parser("remap-sql")
    remap.add_argument("source", type=pathlib.Path)
    remap.add_argument("target", type=pathlib.Path)
    remap.add_argument("output", type=pathlib.Path)
    remap.add_argument("source_namespace")
    remap.add_argument("source_generation", type=int)
    remap.add_argument("target_namespace")
    attempts = commands.add_parser("attempts")
    attempts.add_argument("source", type=pathlib.Path)
    attempts.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()
    if args.command == "build":
        if args.rows.is_symlink() or not args.rows.is_file() or args.output.exists():
            raise ValueError("inventory source or destination is unsafe")
        if args.rows.stat().st_size > 512 * 1024 * 1024:
            raise ValueError("inventory source exceeds the bounded input size")
        args.output.write_text(HEADER + "\n" + args.rows.read_text(encoding="utf-8"), encoding="utf-8")
        args.output.chmod(0o600)
        rows = inventory(args.output)
        print(len(rows), sum(row[3] for row in rows))
    elif args.command == "verify":
        rows = inventory(args.inventory)
        if len(rows) != args.count or sum(row[3] for row in rows) != args.size:
            raise ValueError("inventory count or byte total differs from manifest")
        archive_matches(args.archive, rows)
    elif args.command == "pack":
        rows = inventory(args.inventory)
        if args.objects.is_symlink() or not args.objects.is_dir() or args.archive.exists():
            raise ValueError("object directory or archive destination is unsafe")
        with tarfile.open(args.archive, "w:gz", format=tarfile.GNU_FORMAT) as archive:
            for object_id, _, _, size, digest in rows:
                path = args.objects / object_id
                if path.is_symlink() or not path.is_file() or path.stat().st_size != size:
                    raise ValueError(f"exported object is missing or has wrong size: {object_id}")
                hasher = hashlib.sha256()
                with path.open("rb") as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        hasher.update(chunk)
                if hasher.hexdigest() != digest:
                    raise ValueError(f"exported object has wrong digest: {object_id}")
                archive.add(path, arcname=object_id, recursive=False)
        args.archive.chmod(0o600)
        archive_matches(args.archive, rows)
    elif args.command == "results":
        restored_inventory(args.source, args.results, args.target)
    elif args.command == "attempts":
        write_attempts(args.source, args.output)
    else:
        write_remap_sql(args.source, args.target, args.output, args.source_namespace,
                        args.source_generation, args.target_namespace)


if __name__ == "__main__":
    try:
        main()
    except (OSError, UnicodeError, ValueError, tarfile.TarError) as error:
        print(f"S3 backup inventory rejected: {error}", file=sys.stderr)
        sys.exit(1)
