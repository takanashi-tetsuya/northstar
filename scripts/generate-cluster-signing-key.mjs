#!/usr/bin/env node

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import { closeSync, mkdirSync, openSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const privateV1Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
const publicPrefix = Buffer.from("302a300506032b6570032100", "hex");

// Node exports PrivateKeyInfo v1, without its public component. Northstar's
// strict ring parser deliberately requires RFC 5958 / RFC 8410 v2 so it can
// verify that the public component matches the seed. Encode only the fixed
// Ed25519 shape; reject future provider/OID changes instead of slicing blindly.
export function encodeEd25519Pkcs8V2(privateV1, publicSpki) {
  if (!Buffer.isBuffer(privateV1) || privateV1.length !== privateV1Prefix.length + 32 ||
      !privateV1.subarray(0, privateV1Prefix.length).equals(privateV1Prefix)) {
    throw new Error("runtime emitted an unexpected Ed25519 PrivateKeyInfo encoding");
  }
  if (!Buffer.isBuffer(publicSpki) || publicSpki.length !== publicPrefix.length + 32 ||
      !publicSpki.subarray(0, publicPrefix.length).equals(publicPrefix)) {
    throw new Error("runtime emitted an unexpected Ed25519 SubjectPublicKeyInfo encoding");
  }
  const derivedPublic = createPublicKey(createPrivateKey({ key: privateV1, format: "der", type: "pkcs8" }))
    .export({ format: "der", type: "spki" });
  if (!derivedPublic.equals(publicSpki)) {
    throw new Error("Ed25519 public and private components do not match");
  }
  return Buffer.concat([
    Buffer.from("3051020101300506032b657004220420", "hex"),
    privateV1.subarray(privateV1Prefix.length),
    Buffer.from("812100", "hex"),
    publicSpki.subarray(publicPrefix.length),
  ]);
}

function exclusiveWrite(path, value) {
  let fd;
  try {
    fd = openSync(path, "wx", 0o600);
    writeFileSync(fd, Buffer.isBuffer(value) ? value : `${value}\n`, { encoding: "utf8" });
  } catch (error) {
    throw new Error(`refusing to overwrite or create ${path}: ${error.message}`);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function main() {
  if (![4, 5].includes(process.argv.length)) {
    throw new Error("usage: node scripts/generate-cluster-signing-key.mjs PRIVATE.pkcs8.b64 PUBLIC.raw.b64 [OPENSSL_PRIVATE_V1.der]");
  }
  const privatePath = resolve(process.argv[2]);
  const publicPath = resolve(process.argv[3]);
  const opensslPrivatePath = process.argv[4] && resolve(process.argv[4]);
  const paths = [privatePath, publicPath, opensslPrivatePath].filter(Boolean);
  if (new Set(paths).size !== paths.length) throw new Error("private and public output paths must differ");
  mkdirSync(dirname(privatePath), { recursive: true, mode: 0o700 });
  mkdirSync(dirname(publicPath), { recursive: true, mode: 0o700 });
  if (opensslPrivatePath) mkdirSync(dirname(opensslPrivatePath), { recursive: true, mode: 0o700 });
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateV1 = privateKey.export({ format: "der", type: "pkcs8" });
  let pkcs8;
  try {
    const spki = publicKey.export({ format: "der", type: "spki" });
    pkcs8 = encodeEd25519Pkcs8V2(privateV1, spki);
    const rawPublic = spki.subarray(publicPrefix.length);
    exclusiveWrite(privatePath, pkcs8.toString("base64url"));
    exclusiveWrite(publicPath, rawPublic.toString("base64url"));
    // OpenSSL 3.0's fixture signer reads v1 only. This explicit optional copy
    // has the same seed/identity; it is never used as runtime configuration.
    if (opensslPrivatePath) exclusiveWrite(opensslPrivatePath, privateV1);
    const digest = createHash("sha256").update(rawPublic).digest();
    process.stdout.write(
      `created owner-only Ed25519 files\nkey_id=${digest.subarray(0, 12).toString("base64url")}\npublic_sha256=${digest.toString("base64url")}\n`,
    );
  } finally {
    privateV1.fill(0);
    pkcs8?.fill(0);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 2;
  }
}
