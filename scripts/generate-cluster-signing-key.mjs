#!/usr/bin/env node

import { createHash, generateKeyPairSync } from "node:crypto";
import { closeSync, mkdirSync, openSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}

if (process.argv.length !== 4) {
  fail(
    "usage: node scripts/generate-cluster-signing-key.mjs PRIVATE.pkcs8.b64 PUBLIC.raw.b64",
  );
}

const privatePath = resolve(process.argv[2]);
const publicPath = resolve(process.argv[3]);
if (privatePath === publicPath) fail("private and public output paths must differ");
mkdirSync(dirname(privatePath), { recursive: true, mode: 0o700 });
mkdirSync(dirname(publicPath), { recursive: true, mode: 0o700 });

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" });
const spki = publicKey.export({ format: "der", type: "spki" });
const ed25519SpkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
if (
  spki.length !== ed25519SpkiPrefix.length + 32 ||
  !spki.subarray(0, ed25519SpkiPrefix.length).equals(ed25519SpkiPrefix)
) {
  fail("runtime emitted an unexpected Ed25519 SubjectPublicKeyInfo encoding");
}
const rawPublic = spki.subarray(ed25519SpkiPrefix.length);

function exclusiveWrite(path, value) {
  let fd;
  try {
    fd = openSync(path, "wx", 0o600);
    writeFileSync(fd, `${value}\n`, { encoding: "utf8" });
  } catch (error) {
    fail(`refusing to overwrite or create ${path}: ${error.message}`);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

exclusiveWrite(privatePath, pkcs8.toString("base64url"));
exclusiveWrite(publicPath, rawPublic.toString("base64url"));

const digest = createHash("sha256").update(rawPublic).digest();
process.stdout.write(
  `created owner-only Ed25519 files\nkey_id=${digest.subarray(0, 12).toString("base64url")}\npublic_sha256=${digest.toString("base64url")}\n`,
);
