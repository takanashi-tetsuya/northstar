import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

import { LANGUAGES } from '../web/i18n.js';
import { MACHINE_TEMPLATES, MACHINE_TRANSLATIONS } from '../web/locales.generated.js';

const HUMAN_CODES = new Set(['en', 'zh-CN', 'zh-TW', 'ko', 'ja', 'es', 'fr', 'de']);
const machineCodes = LANGUAGES.map(({ code }) => code).filter((code) => !HUMAN_CODES.has(code)).sort();
const translationCodes = Object.keys(MACHINE_TRANSLATIONS).sort();
const templateCodes = Object.keys(MACHINE_TEMPLATES).sort();
const i18nSource = fs.readFileSync(new URL('../web/i18n.js', import.meta.url), 'utf8');
const rowsStart = i18nSource.indexOf('const ROWS = ');
const rowsEnd = i18nSource.indexOf('\n];', rowsStart);
assert.ok(rowsStart >= 0 && rowsEnd > rowsStart, 'could not parse the canonical ROWS catalog');
const rows = Array.from(
  vm.runInNewContext(i18nSource.slice(i18nSource.indexOf('[', rowsStart), rowsEnd + 2)),
  (row) => Array.from(row),
);
const expectedSources = rows.map((row) => row[0]).sort();
assert.equal(new Set(expectedSources).size, expectedSources.length, 'ROWS contains duplicate source keys');
for (const [index, row] of rows.entries()) {
  assert.equal(row.length, 8, `ROWS[${index}] must contain Simplified Chinese plus seven recommended-language translations`);
  for (const value of row) assert.ok(typeof value === 'string' && value.trim(), `ROWS[${index}] contains an empty translation`);
  assert.match(row[0], /[\u3400-\u9fff]/u, `ROWS[${index}] must use a Simplified-Chinese UI source key`);
  assert.notEqual(row[0], row[1], `ROWS[${index}] leaked its English translation into the source key`);
}
const expectedTemplateIds = [
  'administrator', 'bundle_incomplete', 'complete_address', 'config_failed', 'connected_to',
  'contact_request', 'decrypt_failed', 'device', 'device_label', 'download_failed',
  'encrypted_devices', 'file_failed', 'file_key_devices_failed', 'file_limit', 'group_online_count',
  'group_topic', 'history_failed', 'message_devices_failed', 'message_failed', 'online_count',
  'receiving_devices', 'remove_contact', 'request_failed', 'typing', 'upload_failed',
  'transfer_cancel_failed', 'transfer_export_failed', 'transfer_export_uncertain', 'transfer_import_failed',
  'destroy_room', 'device_erase_failed', 'disconnect_resource', 'invitation_once', 'join_failed',
  'offline_removed', 'plaintext_reason', 'pow_solved', 'pow_tier', 'pow_wait', 'pow_working',
  'pow_working_rate', 'reconcile_operation', 'reconcile_target', 'remove_remote_device',
  'replace_session', 'report_submitted', 'security_distrusted', 'security_tofu',
].sort();
const templateSource = fs.readFileSync(new URL('./generate-locales.mjs', import.meta.url), 'utf8');
const templateSourceStart = templateSource.indexOf('const TEMPLATE_SOURCE = Object.freeze({');
const templateSourceEnd = templateSource.indexOf('\n});', templateSourceStart);
const templateDefinitions = vm.runInNewContext(`(${templateSource.slice(templateSource.indexOf('{', templateSourceStart), templateSourceEnd + 2)})`);
assert.deepEqual(Object.keys(templateDefinitions).sort(), expectedTemplateIds, 'generator templates and runtime template inventory differ');

assert.equal(machineCodes.length, 76);
assert.deepEqual(translationCodes, machineCodes, 'machine translation packs must exactly match the retained catalog');
assert.deepEqual(templateCodes, machineCodes, 'machine template packs must exactly match the retained catalog');
const referenceSources = expectedSources;
assert.ok(referenceSources.length >= 309, `expected the expanded interface catalog, received ${referenceSources.length} strings`);

for (const code of machineCodes) {
  const pack = MACHINE_TRANSLATIONS[code];
  const templates = MACHINE_TEMPLATES[code];
  assert.equal(Object.keys(pack).length, referenceSources.length, `${code}: incomplete static string pack`);
  assert.deepEqual(Object.keys(pack).sort(), referenceSources, `${code}: string keys differ from the reference pack`);
  assert.deepEqual(Object.keys(templates).sort(), expectedTemplateIds, `${code}: incomplete template pack`);
  assert.ok(pack['机器翻译，可能存在错误']?.trim(), `${code}: missing machine-translation notice`);
  for (const [source, value] of Object.entries(pack)) {
    assert.equal(typeof value, 'string', `${code}: ${source} is not a string`);
    assert.ok(value.trim(), `${code}: ${source} is empty`);
    assert.ok(value.length < 1200, `${code}: ${source} is implausibly long`);
    assert.ok(!value.includes('\uFFFD'), `${code}: ${source} contains an invalid Unicode replacement character`);
    assert.ok(!/\[NS\d{3}\]|\[end of text\]/i.test(value), `${code}: ${source} leaked a model marker`);
    assert.ok(!/<2[a-z-]+>/i.test(value), `${code}: ${source} leaked a model language tag`);
    assert.ok(!/(.)\1{15,}/u.test(value), `${code}: ${source} contains an implausible repeated run`);
    assert.ok(!/(\S+)(?:\s+\1){7,}/iu.test(value), `${code}: ${source} contains an implausible repeated token`);
  }
  for (const [id, value] of Object.entries(templates)) {
    const source = templateDefinitions[id];
    for (let position = 1; position <= 4; position += 1) {
      const expected = source.split(`__NSVALUE${position}__`).length - 1;
      assert.equal(value.split(`$${position}`).length - 1, expected, `${code}: template ${id} has an invalid $${position} count`);
    }
    assert.ok(!value.includes('__NSVALUE'), `${code}: template ${id} leaked a generator placeholder`);
    assert.ok(value.length < 1000, `${code}: template ${id} is implausibly long`);
    assert.ok(!/(\S+)(?:\s+\1){7,}/iu.test(value), `${code}: template ${id} contains an implausible repeated token`);
  }
}

console.log(`locale pack checks passed for ${machineCodes.length} machine-translated languages`);
