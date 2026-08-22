import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const root = new URL('../', import.meta.url);
const source = await readFile(new URL('web/i18n.js', root), 'utf8');
const moduleUrl = new URL(`web/i18n.js?static-check=${Date.now()}`, root);
const { LANGUAGES, RECOMMENDED_LANGUAGES, searchLanguages, translate } = await import(moduleUrl);

assert.equal(LANGUAGES.length, 84, `expected 84 retained languages, received ${LANGUAGES.length}`);
assert.equal(new Set(LANGUAGES.map(({ code }) => code)).size, LANGUAGES.length);
assert.deepEqual(
  RECOMMENDED_LANGUAGES.map(({ code }) => code),
  ['en', 'fr', 'de', 'ja', 'ko', 'zh-CN', 'es', 'zh-TW'],
);
assert.equal(LANGUAGES.find(({ code }) => code === 'zh-TW')?.label, '中華民國語 / Traditional Chinese');
assert.ok(LANGUAGES.every(({ label }) => label.includes(' / ')));
for (const code of ['la', 'eo']) {
  assert.ok(LANGUAGES.some((language) => language.code === code), `missing ${code}`);
}
for (const code of ['grc', 'ang', 'got', 'sa', 'lzh', 'sux']) {
  assert.ok(!LANGUAGES.some((language) => language.code === code), `low-resource locale ${code} was not removed`);
}
for (let index = 1; index < LANGUAGES.length; index += 1) {
  assert.ok(
    LANGUAGES[index - 1].english.localeCompare(LANGUAGES[index].english, 'en', { sensitivity: 'base' }) <= 0,
    `${LANGUAGES[index - 1].english} is not before ${LANGUAGES[index].english}`,
  );
}
assert.ok(searchLanguages('latin').some(({ code }) => code === 'la'));
assert.ok(searchLanguages('拉丁').some(({ code }) => code === 'la'));
assert.ok(searchLanguages('esperanto').some(({ code }) => code === 'eo'));
assert.ok(searchLanguages('世界语').some(({ code }) => code === 'eo'));
assert.ok(searchLanguages('traditional').some(({ code }) => code === 'zh-TW'));
assert.equal(searchLanguages('no-language-can-match-this-value').length, 0);

const samples = [
  ['登录', 'en', 'Sign in'],
  ['登录', 'zh-CN', '登录'],
  ['登录', 'zh-TW', '登入'],
  ['登录', 'ko', '로그인'],
  ['登录', 'ja', 'ログイン'],
  ['登录', 'es', 'Iniciar sesión'],
  ['登录', 'fr', 'Se connecter'],
  ['登录', 'de', 'Anmelden'],
  ['登录', 'ru', 'Войти'],
  ['登录', 'eo', 'Ensaluti'],
  ['机器翻译，可能存在错误', 'en', 'Machine translation; errors may be present'],
  ['机器翻译，可能存在错误', 'zh-TW', '機器翻譯，可能存在錯誤'],
  ['机器翻译，可能存在错误', 'ru', 'Машинный перевод; возможны ошибки'],
  ['连接到 xmpp.example.test', 'eo', 'Konektita al xmpp.example.test'],
  ['3 人在线', 'de', '3 online'],
  ['群聊 · 7 人在线', 'ja', 'グループ · 7人オンライン'],
  ['alice@example.test 正在输入…', 'ko', 'alice@example.test 님이 입력 중…'],
  ['文件下载失败 (503)', 'fr', 'Échec du téléchargement du fichier (503)'],
  ['设备 42', 'es', 'Dispositivo 42'],
  ['OMEMO 完整性校验失败', 'en', 'OMEMO integrity verification failed'],
  ['OMEMO 完整性校验失败', 'fr', 'OMEMO integrity verification failed'],
];

for (const [input, language, expected] of samples) {
  assert.equal(translate(input, language), expected, `${language}: ${input}`);
}

for (const page of ['web/index.html', 'web/client.html']) {
  const html = await readFile(new URL(page, root), 'utf8');
  assert.match(html, /<html lang="en">/);
  assert.match(html, /\/i18n\.css/);
  assert.match(html, /data-language-host/);
}

const client = await readFile(new URL('web/client.js', root), 'utf8');
const css = await readFile(new URL('web/i18n.css', root), 'utf8');
assert.match(client, /initializeI18n\(\)/);
assert.match(client, /translate\(`群聊/);
assert.match(source, /input\.addEventListener\('input', renderResults\)/);
assert.match(source, /clear\.textContent = '×'/);
assert.match(source, /search\.textContent = '🔍'/);
assert.match(source, /localStorage\.getItem\(STORAGE_KEY\) \|\| 'en'/);
assert.match(source, /机器翻译，可能存在错误/);
assert.match(source, /HUMAN_TRANSLATED_CODES\.has\(locale\)/);
assert.match(source, /data-machine-translation-notice/);
assert.match(css, /\.machine-translation-notice\.hidden\s*{\s*display:\s*none;/);

console.log(`i18n static checks passed for ${LANGUAGES.length} languages`);
