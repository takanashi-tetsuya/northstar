#!/usr/bin/env python3
"""Offline checks for the exact-version S3 backup inventory."""

import importlib.util
import hashlib
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent


def module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


inventory = module("backup_inventory", ROOT / "backup-inventory.py")
security = module("backup_security", ROOT / "backup-security.py")
OBJECT_ID = "00000000-0000-4000-8000-000000000001"
ATTEMPT = "00000000-0000-4000-8000-000000000002"


class S3InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.objects = self.root / "objects"
        self.objects.mkdir()
        self.object = self.objects / OBJECT_ID
        self.object.write_bytes(b"exact-version-object")
        self.digest = hashlib.sha256(self.object.read_bytes()).hexdigest()
        self.manifest = self.root / "upload-inventory.tsv"
        self.manifest.write_text(
            f"{inventory.HEADER}\n{OBJECT_ID}\tobjects/{OBJECT_ID}/{ATTEMPT}\tversion-1\t20\t{self.digest}\n",
            encoding="utf-8",
        )
        self.archive = self.root / "uploads.tar.gz"

    def test_exact_version_archive_roundtrip(self):
        rows = inventory.inventory(self.manifest)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][2], "version-1")
        with tarfile.open(self.archive, "w:gz") as archive:
            archive.add(self.object, arcname=OBJECT_ID)
        inventory.archive_matches(self.archive, rows)

    def test_missing_and_changed_objects_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "omits inventory"):
            with tarfile.open(self.archive, "w:gz"):
                pass
            inventory.archive_matches(self.archive, inventory.inventory(self.manifest))
        self.object.write_bytes(b"x" * 20)
        with tarfile.open(self.archive, "w:gz") as archive:
            archive.add(self.object, arcname=OBJECT_ID)
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            inventory.archive_matches(self.archive, inventory.inventory(self.manifest))

    def test_noncanonical_or_duplicate_inventory_fails(self):
        original = self.manifest.read_text(encoding="utf-8")
        self.manifest.write_text(original + original.splitlines()[1] + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unsorted, repeated"):
            inventory.inventory(self.manifest)
        self.manifest.write_text(original.replace("version-1", ""), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalid version"):
            inventory.inventory(self.manifest)

    def test_v3_manifest_requires_authenticated_inventory(self):
        values = {
            "format": "northstar-backup-v3",
            "manifest_version": "3",
            "backup_generation": "00000000-0000-4000-8000-000000000003",
            "backup_sequence": "1",
            "created_at": "2026-01-01T00:00:00Z",
            "northstar_version": "0.2.0",
            "postgresql_version": "17",
            "successful_migrations": "148",
            "encryption": "age",
            "signature": "openssl-ed25519",
            "signing_key_id": "sha256:" + "a" * 64,
            "database_archive": "database.dump.age",
            "database_archive_sha256": "a" * 64,
            "database_plain_sha256": "a" * 64,
            "database_contents": "database.contents.age",
            "database_contents_archive_sha256": "a" * 64,
            "database_contents_plain_sha256": "a" * 64,
            "upload_archive": "uploads.tar.gz.age",
            "upload_archive_sha256": "a" * 64,
            "upload_plain_sha256": "a" * 64,
            "upload_consistency": "immutable-exact-version-objects",
            "storage_backend": "s3",
            "storage_namespace_sha256": "b" * 64,
            "storage_generation": "2",
            "upload_inventory": "upload-inventory.tsv.age",
            "upload_inventory_archive_sha256": "c" * 64,
            "upload_inventory_plain_sha256": "d" * 64,
            "upload_object_count": "1",
            "upload_object_bytes": "20",
        }
        manifest = self.root / "manifest.txt"
        manifest.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
        self.assertEqual(security.validate_manifest(manifest)["storage_backend"], "s3")
        del values["upload_inventory_plain_sha256"]
        manifest.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
        with self.assertRaisesRegex(security.SecurityError, "missing fields"):
            security.validate_manifest(manifest)

    def test_restore_results_require_fresh_exact_locator(self):
        new_attempt = "00000000-0000-4000-8000-000000000004"
        results = self.root / "results.tsv"
        target = self.root / "target.tsv"
        sql = self.root / "remap.sql"
        results.write_text(
            f"northstar-s3-restore-results-v1\n{OBJECT_ID}\tobjects/{OBJECT_ID}/{new_attempt}"
            f"\tversion-2\t20\t{self.digest}\n", encoding="utf-8"
        )
        inventory.restored_inventory(self.manifest, results, target)
        inventory.write_remap_sql(self.manifest, target, sql, "a" * 64, 4, "b" * 64)
        self.assertIn("generation=5", sql.read_text(encoding="utf-8"))
        same_key = results.read_text(encoding="utf-8").replace(new_attempt, ATTEMPT)
        results.write_text(same_key, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "reused the source locator"):
            inventory.restored_inventory(self.manifest, results, self.root / "bad.tsv")


if __name__ == "__main__":
    unittest.main()
