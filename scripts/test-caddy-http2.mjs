import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import http2 from 'node:http2';

const [port, certificate] = process.argv.slice(2);
assert.match(port ?? '', /^[0-9]+$/);
assert(Number(port) > 0 && Number(port) < 65536);
const client = http2.connect(`https://127.0.0.1:${port}`, {
  ca: readFileSync(certificate),
  servername: 'localhost',
});
const deadline = setTimeout(() => {
  client.destroy(new Error('HTTP/2 body rejection did not finish within five seconds'));
}, 5000);
const collect = (stream) => new Promise((resolve, reject) => {
  let headers;
  let body = '';
  stream.setEncoding('utf8');
  stream.on('response', (value) => { headers = value; });
  stream.on('data', (value) => { body += value; });
  stream.on('error', reject);
  // The peer must close/reset the rejected stream, not only send headers.
  stream.on('close', () => resolve({ headers, body }));
});
client.on('error', (error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
try {
  const incomplete = client.request({ ':method': 'POST', ':authority': '127.0.0.1', ':path': '/api/reject/429', 'content-length': '128' });
  const rejected = collect(incomplete);
  incomplete.write('{');
  const first = await rejected;
  assert.equal(first.headers[':status'], 429);
  assert.equal(first.headers.connection, undefined);
  assert.match(first.body, /fixture_429/);

  const normal = client.request({ ':method': 'POST', ':authority': '127.0.0.1', ':path': '/api/normal', 'content-length': '2' });
  const completed = collect(normal);
  normal.end('{}');
  const second = await completed;
  assert.equal(second.headers[':status'], 200);
  assert.equal(second.body, '{}');
  console.log('Caddy HTTP/2: unfinished stream rejected and closed; same connection remains usable');
} finally {
  clearTimeout(deadline);
  client.destroy();
}
