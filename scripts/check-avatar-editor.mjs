import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root = new URL('../', import.meta.url);
const editorSource = await readFile(new URL('web/avatar-editor.js', root), 'utf8');
const editorUrl = `data:text/javascript;base64,${Buffer.from(editorSource).toString('base64')}`;
const {
  MAX_AVATAR_INPUT_BYTES,
  MAX_AVATAR_OUTPUT_BYTES,
  formatAvatarBytes,
} = await import(editorUrl);

assert.equal(MAX_AVATAR_INPUT_BYTES, 50 * 1024 * 1024);
assert.ok(MAX_AVATAR_OUTPUT_BYTES < 256 * 1024);
assert.equal(formatAvatarBytes(50 * 1024 * 1024), '50.0 MiB');
assert.equal(formatAvatarBytes(255 * 1024), '255 KiB');
assert.match(editorSource, /decodeWithImageBitmap/);
assert.match(editorSource, /decodeWithWebCodecs/);
assert.match(editorSource, /decodeWithImageElement/);
assert.match(editorSource, /canvasToBlob\(output, 'image\/png'\)/);
assert.doesNotMatch(editorSource, /canvasToBlob\(output, 'image\/jpeg'/);
assert.match(editorSource, /\[512, 448, 384, 320, 256, 224, 192, 160, 128, 96, 64, 48, 32\]/);
assert.match(editorSource, /blob\.size <= MAX_AVATAR_OUTPUT_BYTES/);

const html = await readFile(new URL('web/client.html', root), 'utf8');
const client = await readFile(new URL('web/client.js', root), 'utf8');
const css = await readFile(new URL('web/client.css', root), 'utf8');
assert.match(html, /id="avatar-editor-dialog"/);
assert.match(html, /id="avatar-crop-canvas"/);
assert.match(html, /accept="image\/\*,\.avif,[^"]*\.heic,[^"]*\.tiff,[^"]*\.webp"/);
assert.match(client, /file\.size > MAX_AVATAR_INPUT_BYTES/);
assert.match(client, /avatarCropper\.moveBy/);
assert.match(client, /avatarCropper\.rotate\(-90\)/);
assert.match(client, /await avatarCropper\.exportAvatar\(\)/);
assert.match(client, /blob\.type \|\| 'image\/png'/);
assert.match(client, /bytes='\$\{blob\.size\}' height='\$\{dimension\}'/);
assert.match(client, /!candidate\.hasAttribute\('url'\).*image\/png/);
assert.match(client, /textContent\?\.replace\(\/\\s\/g, ''\)/);
assert.doesNotMatch(client, /await state\.xmpp\.setVCard\(/);
assert.match(client, /subscribePep\(jid, NS\.AVATAR_METADATA\)/);
assert.match(css, /\.avatar-crop-guide/);

console.log('avatar editor static checks passed');
