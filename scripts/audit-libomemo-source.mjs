import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const archivePath = resolve(
  root,
  'third_party/libomemo.js/libomemo.js-v2.0.2-source.tar.gz',
);
const archiveRoot = 'libomemo.js-v2.0.2/';

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function field(header, start, length) {
  const end = header.subarray(start, start + length).indexOf(0);
  return header
    .subarray(start, start + (end < 0 ? length : end))
    .toString('utf8')
    .trim();
}

function tarNumber(header, start, length) {
  const raw = field(header, start, length).replace(/\0/g, '').trim();
  if (!/^[0-7]+$/.test(raw)) throw new Error(`invalid tar octal field ${raw}`);
  return Number.parseInt(raw, 8);
}

function parsePax(data) {
  const values = {};
  let offset = 0;
  while (offset < data.length) {
    const separator = data.indexOf(0x20, offset);
    if (separator < 0) throw new Error('malformed PAX record length');
    const lengthText = data.subarray(offset, separator).toString('ascii');
    if (!/^[1-9][0-9]*$/.test(lengthText)) throw new Error('invalid PAX record length');
    const length = Number.parseInt(lengthText, 10);
    const end = offset + length;
    if (end > data.length || data[end - 1] !== 0x0a) throw new Error('truncated PAX record');
    const record = data.subarray(separator + 1, end - 1).toString('utf8');
    const equals = record.indexOf('=');
    if (equals <= 0) throw new Error('malformed PAX key/value');
    const key = record.slice(0, equals);
    if (Object.hasOwn(values, key)) throw new Error(`duplicate PAX key: ${key}`);
    values[key] = record.slice(equals + 1);
    offset = end;
  }
  return values;
}

function parseTar(gzip) {
  if (gzip.length > 32 * 1024 * 1024) throw new Error('source archive exceeds 32 MiB');
  const tar = gunzipSync(gzip, { maxOutputLength: 128 * 1024 * 1024 });
  const entries = new Map();
  const globalPax = {};
  let nextPax = {};
  let offset = 0;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const storedChecksum = tarNumber(header, 148, 8);
    let actualChecksum = 0;
    for (let index = 0; index < header.length; index += 1) {
      actualChecksum += index >= 148 && index < 156 ? 0x20 : header[index];
    }
    if (storedChecksum !== actualChecksum) throw new Error('source tar header checksum mismatch');
    const name = field(header, 0, 100);
    const prefix = field(header, 345, 155);
    const type = header[156] === 0 ? '0' : String.fromCharCode(header[156]);
    const size = tarNumber(header, 124, 12);
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (dataEnd > tar.length) throw new Error(`truncated source archive entry: ${name}`);
    if (type === 'g' || type === 'x') {
      const metadata = parsePax(tar.subarray(dataStart, dataEnd));
      if (type === 'g') Object.assign(globalPax, metadata);
      else nextPax = metadata;
      offset = dataStart + Math.ceil(size / 512) * 512;
      continue;
    }
    const headerPath = prefix ? `${prefix}/${name}` : name;
    const path = nextPax.path ?? headerPath;
    nextPax = {};
    if (
      path.startsWith('/') ||
      path.includes('\\') ||
      path.split('/').some((part) => part === '..') ||
      !path.startsWith(archiveRoot)
    ) {
      throw new Error(`unsafe source archive path: ${path}`);
    }
    if (!['0', '5'].includes(type)) throw new Error(`unsupported tar entry type ${type}: ${path}`);
    if (entries.has(path)) throw new Error(`duplicate source archive entry: ${path}`);
    if (type === '0') entries.set(path, Buffer.from(tar.subarray(dataStart, dataEnd)));
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  return { entries, globalPax };
}

function required(entries, path) {
  const bytes = entries.get(`${archiveRoot}${path}`);
  if (!bytes) throw new Error(`source archive is missing ${path}`);
  return bytes;
}

function text(entries, path) {
  return required(entries, path).toString('utf8');
}

function readUleb(bytes, cursor) {
  let value = 0;
  let shift = 0;
  for (let count = 0; count < 5; count += 1) {
    if (cursor.offset >= bytes.length) throw new Error('truncated WASM LEB128');
    const byte = bytes[cursor.offset++];
    value |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return value >>> 0;
    shift += 7;
  }
  throw new Error('oversized WASM LEB128');
}

function readWasmString(bytes, cursor, limit) {
  const length = readUleb(bytes, cursor);
  if (cursor.offset + length > limit) throw new Error('truncated WASM string');
  const value = bytes.subarray(cursor.offset, cursor.offset + length).toString('utf8');
  cursor.offset += length;
  return value;
}

function parseProducers(payload, cursor, limit) {
  const fields = {};
  const fieldCount = readUleb(payload, cursor);
  for (let index = 0; index < fieldCount; index += 1) {
    const fieldName = readWasmString(payload, cursor, limit);
    const valueCount = readUleb(payload, cursor);
    const values = [];
    for (let valueIndex = 0; valueIndex < valueCount; valueIndex += 1) {
      values.push({
        name: readWasmString(payload, cursor, limit),
        version: readWasmString(payload, cursor, limit),
      });
    }
    fields[fieldName] = values;
  }
  return fields;
}

function wasmEvidence(bytes) {
  if (bytes.subarray(0, 8).toString('hex') !== '0061736d01000000') {
    throw new Error('curve25519 artifact is not a WASM v1 module');
  }
  const sections = [];
  const customSections = [];
  let producers = null;
  const cursor = { offset: 8 };
  while (cursor.offset < bytes.length) {
    const id = bytes[cursor.offset++];
    const size = readUleb(bytes, cursor);
    const end = cursor.offset + size;
    if (end > bytes.length) throw new Error('truncated WASM section');
    sections.push({ id, size });
    if (id === 0) {
      const name = readWasmString(bytes, cursor, end);
      customSections.push(name);
      if (name === 'producers') producers = parseProducers(bytes, cursor, end);
    }
    cursor.offset = end;
  }
  return { customSections, producers, sections };
}

export async function collectLibomemoEvidence() {
  const archive = await readFile(archivePath);
  const { entries, globalPax } = parseTar(archive);
  const packageJson = JSON.parse(text(entries, 'package.json'));
  const lockfile = JSON.parse(text(entries, 'package-lock.json'));
  const compileScript = text(entries, 'scripts/compile.js');
  const rollupConfig = text(entries, 'rollup.config.js');
  const testWorkflow = text(entries, '.github/workflows/karma-tests.yml');
  const codeqlWorkflow = text(entries, '.github/workflows/codeql-analysis.yml');
  const makefile = text(entries, 'Makefile');
  const wasm = required(entries, 'build/curve25519_compiled.wasm');
  const lockRoot = lockfile.packages?.[''];
  const packageVersion = (name) => lockfile.packages?.[`node_modules/${name}`]?.version ?? null;
  const lockedPackages = Object.entries(lockfile.packages ?? {}).filter(([path]) => path !== '');
  const registryPackages = lockedPackages.filter(([, value]) =>
    value.resolved?.startsWith('https://registry.npmjs.org/'),
  );
  const registryPackagesMissingIntegrity = registryPackages
    .filter(([, value]) => typeof value.integrity !== 'string' || value.integrity.length === 0)
    .map(([path]) => path);
  const nonRegistryResolvedPackages = lockedPackages
    .filter(([, value]) => value.resolved && !value.resolved.startsWith('https://registry.npmjs.org/'))
    .map(([path, value]) => ({ path, resolved: value.resolved }));
  const toolchainCorpus = [
    compileScript,
    rollupConfig,
    testWorkflow,
    codeqlWorkflow,
    makefile,
    JSON.stringify(packageJson),
  ].join('\n');
  const compilerVersionPins = {
    emscripten: toolchainCorpus.match(/(?:emscripten|emsdk)[^\n]{0,80}\b\d+\.\d+(?:\.\d+)?/gi) ?? [],
    llvm: toolchainCorpus.match(/llvm[^\n]{0,80}\b\d+\.\d+(?:\.\d+)?/gi) ?? [],
    binaryen: toolchainCorpus.match(/(?:binaryen|wasm-opt)[^\n]{0,80}\b\d+\.\d+(?:\.\d+)?/gi) ?? [],
    digestPinnedBuilder: toolchainCorpus.match(/\bsha256:[0-9a-f]{64}\b/gi) ?? [],
  };
  return {
    sourceArchive: {
      path: 'third_party/libomemo.js/libomemo.js-v2.0.2-source.tar.gz',
      sha256: sha256(archive),
      regularFileCount: entries.size,
      root: archiveRoot,
      globalPax,
    },
    package: {
      name: packageJson.name,
      version: packageJson.version,
      packageManager: packageJson.packageManager ?? null,
      node: text(entries, '.nvmrc').trim(),
      lockfileVersion: lockfile.lockfileVersion,
      lockRootVersion: lockRoot?.version ?? null,
      rollup: packageVersion('rollup'),
      esbuild: packageVersion('esbuild'),
      typescript: packageVersion('typescript'),
      protobufjs: packageVersion('protobufjs'),
      lockedPackageCount: lockedPackages.length,
      registryPackageCount: registryPackages.length,
      registryPackagesMissingIntegrity,
      nonRegistryResolvedPackages,
    },
    buildInputs: {
      packageJsonSha256: sha256(required(entries, 'package.json')),
      packageLockSha256: sha256(required(entries, 'package-lock.json')),
      compileScriptSha256: sha256(required(entries, 'scripts/compile.js')),
      rollupConfigSha256: sha256(required(entries, 'rollup.config.js')),
      makefileSha256: sha256(required(entries, 'Makefile')),
      workflowSha256: {
        tests: sha256(required(entries, '.github/workflows/karma-tests.yml')),
        codeql: sha256(required(entries, '.github/workflows/codeql-analysis.yml')),
      },
    },
    compilerVersionPins,
    wasm: {
      archiveEntry: `${archiveRoot}build/curve25519_compiled.wasm`,
      sha256: sha256(wasm),
      ...wasmEvidence(wasm),
    },
    buildArtifactIsPresentInSourceArchive: entries.has(
      `${archiveRoot}build/curve25519_compiled.wasm`,
    ),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(await collectLibomemoEvidence(), null, 2));
}
