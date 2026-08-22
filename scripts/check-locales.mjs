import assert from 'node:assert/strict';

import { LANGUAGES } from '../web/i18n.js';
import { MACHINE_TEMPLATES, MACHINE_TRANSLATIONS } from '../web/locales.generated.js';

const HUMAN_CODES = new Set(['en', 'zh-CN', 'zh-TW', 'ko', 'ja', 'es', 'fr', 'de']);
const machineCodes = LANGUAGES.map(({ code }) => code).filter((code) => !HUMAN_CODES.has(code)).sort();
const translationCodes = Object.keys(MACHINE_TRANSLATIONS).sort();
const templateCodes = Object.keys(MACHINE_TEMPLATES).sort();
const expectedTemplateIds = [
  'administrator', 'bundle_incomplete', 'complete_address', 'config_failed', 'connected_to',
  'contact_request', 'decrypt_failed', 'device', 'device_label', 'download_failed',
  'encrypted_devices', 'file_failed', 'file_key_devices_failed', 'file_limit', 'group_online_count',
  'group_topic', 'history_failed', 'message_devices_failed', 'message_failed', 'online_count',
  'receiving_devices', 'remove_contact', 'request_failed', 'typing', 'upload_failed',
].sort();

assert.equal(machineCodes.length, 76);
assert.deepEqual(translationCodes, machineCodes, 'machine translation packs must exactly match the retained catalog');
assert.deepEqual(templateCodes, machineCodes, 'machine template packs must exactly match the retained catalog');
const referenceSources = Object.keys(MACHINE_TRANSLATIONS[machineCodes[0]]).sort();
assert.ok(referenceSources.length >= 309, `expected the expanded interface pack, received ${referenceSources.length} strings`);

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
    assert.equal(value.split('$1').length - 1, 1, `${code}: template ${id} must contain $1 exactly once`);
    assert.equal(value.split('$2').length - 1, id === 'device_label' ? 1 : 0, `${code}: template ${id} has an invalid $2 count`);
    assert.ok(!value.includes('__NSVALUE'), `${code}: template ${id} leaked a generator placeholder`);
    assert.ok(value.length < 1000, `${code}: template ${id} is implausibly long`);
    assert.ok(!/(\S+)(?:\s+\1){7,}/iu.test(value), `${code}: template ${id} contains an implausible repeated token`);
  }
}

console.log(`locale pack checks passed for ${machineCodes.length} machine-translated languages`);
