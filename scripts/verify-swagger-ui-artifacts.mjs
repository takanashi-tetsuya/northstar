import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const expected = new Map([
  ['third_party/swagger-ui/swagger-ui-dist-5.32.14.tgz', '609702d791d8d3cdcbc3a52632f6be2f9b743eadf6ba49ca9737dac2a6e0b2a3'],
  ['third_party/swagger-ui/LICENSE', 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30'],
  ['third_party/swagger-ui/package.json', '822d8e6352829e632ba71f12ce38c27da61a6b64f5b8debce42df8547fe280ee'],
  ['third_party/swagger-ui/dist/swagger-ui.css', 'd7f39f764aa18c7b47dd05b9af5613e373e4ac0f3557c2693d52d0abc2464d76'],
  ['third_party/swagger-ui/dist/swagger-ui-bundle.js', '16d93d5cc19e54c98fb0b81157dbb3bd90780aa36b914e128a643b31e54a93f4'],
  ['third_party/swagger-ui/dist/favicon-16x16.png', 'af24ad604dd7b3bcda8f975ab973075f4a2f70a4087944a12f8ef8b63a3e07c2'],
  ['third_party/swagger-ui/dist/favicon-32x32.png', '3ed612f41e050ca5e7000cad6f1cbe7e7da39f65fca99c02e99e6591056e5837'],
]);

for (const [relativePath, expectedHash] of expected) {
  const absolutePath = path.join(root, relativePath);
  const actualHash = crypto.createHash('sha256').update(fs.readFileSync(absolutePath)).digest('hex');
  if (actualHash !== expectedHash) {
    throw new Error(`${relativePath} does not match its pinned Swagger UI 5.32.14 hash`);
  }
}

const packageDocument = JSON.parse(
  fs.readFileSync(path.join(root, 'third_party/swagger-ui/package.json'), 'utf8'),
);
if (packageDocument.name !== 'swagger-ui-dist' || packageDocument.version !== '5.32.14') {
  throw new Error('Swagger UI package metadata is not pinned to swagger-ui-dist 5.32.14');
}

const initializer = fs.readFileSync(
  path.join(root, 'third_party/swagger-ui/dist/northstar-swagger-initializer.js'),
  'utf8',
);
for (const invariant of [
  "url: '/api/openapi.yaml'",
  'supportedSubmitMethods: []',
  'tryItOutEnabled: false',
  'persistAuthorization: false',
  'validatorUrl: null',
  'AuthorizeBtn: () => null',
  'AuthorizeOperationBtn: () => null',
]) {
  if (!initializer.includes(invariant)) {
    throw new Error(`Swagger UI initializer lost security invariant: ${invariant}`);
  }
}
if (/https?:\/\//i.test(initializer)) {
  throw new Error('Swagger UI initializer must not contact a third-party origin');
}

console.log(`Swagger UI ${packageDocument.version} artifacts and read-only policy verified`);
