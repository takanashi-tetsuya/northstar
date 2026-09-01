import { spawn } from 'node:child_process';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import vm from 'node:vm';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const i18nPath = path.join(projectRoot, 'web', 'i18n.js');
const outputPath = path.join(projectRoot, 'web', 'locales.generated.js');
const toolRoot = path.join(projectRoot, '.translation-tools');
const executable = path.join(toolRoot, 'llama', 'llama-completion.exe');
const model = path.join(toolRoot, 'madlad400-3b-mt-q4_k_m.gguf');
const progressPath = path.join(toolRoot, 'locales-progress.json');
const promptRoot = path.join(toolRoot, 'prompts');
const HUMAN_LANGUAGES = new Set(['en', 'zh-CN', 'zh-TW', 'ko', 'ja', 'es', 'fr', 'de']);
const TARGET_CODE = { fil: 'tl' };
const BATCH_SIZE = 16;
const SMALL_BATCH_LANGUAGES = new Set(['bg', 'el']);
const CONCURRENCY = 2;

const TEMPLATE_SOURCE = Object.freeze({
  connected_to: 'Connected to __NSVALUE1__',
  administrator: 'Administrator: __NSVALUE1__',
  online_count: '__NSVALUE1__ online',
  group_online_count: 'Group · __NSVALUE1__ online',
  contact_request: '__NSVALUE1__ wants to add you as a contact',
  typing: '__NSVALUE1__ is typing…',
  encrypted_devices: '__NSVALUE1__ encrypted devices',
  receiving_devices: '__NSVALUE1__ receiving devices found; the server can store ciphertext only.',
  device: 'Device __NSVALUE1__',
  request_failed: 'Request failed (__NSVALUE1__)',
  config_failed: 'Could not read the server configuration: __NSVALUE1__',
  complete_address: 'Enter a complete XMPP address on __NSVALUE1__',
  remove_contact: 'Remove __NSVALUE1__ from contacts?',
  history_failed: 'Could not read history: __NSVALUE1__',
  decrypt_failed: '[Could not decrypt: __NSVALUE1__]',
  group_topic: 'Group topic: __NSVALUE1__',
  message_devices_failed: '__NSVALUE1__ other devices did not receive the message',
  message_failed: 'Message not sent: __NSVALUE1__',
  file_limit: 'The file cannot exceed __NSVALUE1__',
  upload_failed: 'Encrypted file upload failed (__NSVALUE1__)',
  file_key_devices_failed: '__NSVALUE1__ devices did not receive the file key',
  file_failed: 'File not sent: __NSVALUE1__',
  download_failed: 'File download failed (__NSVALUE1__)',
  device_label: '__NSVALUE1__ · Device __NSVALUE2__',
  bundle_incomplete: 'The OMEMO public-key bundle for device __NSVALUE1__ is incomplete',
  join_failed: 'Could not join __NSVALUE1__: __NSVALUE2__',
  replace_session: 'Replace the OMEMO session for __NSVALUE1__ · Device __NSVALUE2__?',
  remove_remote_device: 'Remove __NSVALUE1__ · Device __NSVALUE2__ from the account? That browser will no longer receive new encrypted messages.',
  device_erase_failed: 'The device was not erased: __NSVALUE1__',
  invitation_once: 'Shown once only; copy it now: __NSVALUE1__',
  disconnect_resource: 'Disconnect __NSVALUE1__? The client may reconnect automatically.',
  destroy_room: 'Permanently destroy __NSVALUE1__? All occupants will be disconnected.',
  reconcile_operation: 'Manually mark this indeterminate operation as __NSVALUE1__? Verify external evidence first.',
  reconcile_target: 'Manually mark this indeterminate target as __NSVALUE1__? Verify external evidence first.',
  security_tofu: 'Encrypting to __NSVALUE1__ devices; __NSVALUE2__ were accepted using TOFU and were not independently verified.',
  security_distrusted: 'Encrypting to __NSVALUE1__ devices; __NSVALUE2__ explicitly distrusted devices were excluded.',
  report_submitted: 'Submitted __NSVALUE1__ · __NSVALUE2__ evidence items',
  offline_removed: 'Removed __NSVALUE1__ queued messages.',
  pow_wait: 'Sending is too frequent. Wait __NSVALUE1__ seconds before computing again to prevent work from piling up.',
  pow_solved: 'Proof of work completed in __NSVALUE1__ seconds.',
  pow_tier: 'Abuse-prevention tier __NSVALUE1__ · Work __NSVALUE2__ / maximum __NSVALUE3__ · Cooldown drops one tier every __NSVALUE4__ seconds',
  pow_working_rate: 'Computing proof of work… __NSVALUE1__ hashes · __NSVALUE2__/second',
  pow_working: 'Computing proof of work… __NSVALUE1__ hashes',
  plaintext_reason: 'The peer requested plaintext (__NSVALUE1__). Northstar blocked the downgrade.',
  transfer_export_failed: 'Transfer export failed: __NSVALUE1__',
  transfer_export_uncertain: 'The transfer export outcome is uncertain and the source device remains frozen: __NSVALUE1__',
  transfer_cancel_failed: 'Transfer cancellation failed: __NSVALUE1__',
  transfer_import_failed: 'Transfer import failed: __NSVALUE1__',
});
const TEMPLATE_OVERRIDES = Object.freeze({
  bg: {
    contact_request: '__NSVALUE1__ иска да ви добави като контакт',
    message_devices_failed: '__NSVALUE1__ други устройства не получиха съобщението',
  },
  el: {
    contact_request: '__NSVALUE1__ θέλει να σας προσθέσει ως επαφή',
    receiving_devices: 'Βρέθηκαν __NSVALUE1__ συσκευές λήψης· ο διακομιστής μπορεί να αποθηκεύσει μόνο κρυπτογραφημένο κείμενο.',
    file_key_devices_failed: '__NSVALUE1__ συσκευές δεν έλαβαν το κλειδί αρχείου',
  },
  ga: {
    replace_session: 'Ionadaigh an seisiún OMEMO do __NSVALUE1__ · Gléas __NSVALUE2__?',
  },
  ka: {
    history_failed: 'ისტორიის წაკითხვა ვერ მოხერხდა: __NSVALUE1__',
  },
  ku: {
    security_tofu: 'Ji bo __NSVALUE1__ cîhazan tê şîfrekirin; __NSVALUE2__ bi TOFU hatin pejirandin û bi serbixwe nehatin piştrastkirin.',
    security_distrusted: 'Ji bo __NSVALUE1__ cîhazan tê şîfrekirin; __NSVALUE2__ cîhazên ku bi eşkere nehatine pêbawerkirin hatin derxistin.',
    pow_wait: 'Şandin pir zêde ye. Ji bo ku kar li hev nekomin, berî hesabkirina dî __NSVALUE1__ çirkeyan bisekine.',
    pow_solved: 'Delîla karê di __NSVALUE1__ çirkeyan de qediya.',
  },
  la: {
    pow_working_rate: 'Probatio operis computatur… __NSVALUE1__ digestiones · __NSVALUE2__ per secundum',
  },
  ps: {
    pow_tier: 'د ناوړه ګټې مخنیوي کچه __NSVALUE1__ · کار __NSVALUE2__ / اعظمي __NSVALUE3__ · د سړېدو کچه په هر __NSVALUE4__ ثانیو کې یو پړاو راټیټېږي',
  },
  ur: { connected_to: '__NSVALUE1__ سے منسلک' },
  yo: {
    group_topic: 'Àkòrí ẹgbẹ́: __NSVALUE1__',
    disconnect_resource: 'Ge asopọ __NSVALUE1__? Oníbàárà lè tún sopọ̀ laifọwọyi.',
  },
});
const TRANSLATION_OVERRIDES = Object.freeze({
  el: {
    '首次使用即信任（TOFU）': 'Εμπιστοσύνη κατά την πρώτη χρήση (TOFU)',
  },
  ha: {
    '图片像素尺寸过大，无法安全处理': 'Girman piksel na hoton ya yi yawa don a sarrafa shi cikin aminci',
  },
  yo: {
    '从我的账户移除此设备': 'Yọ ẹ̀rọ yìí kúrò nínú àkọọlẹ̀ mi',
    '从账户移除此浏览器设备并永久删除其本地 OMEMO 密钥？加密历史记录无法恢复这些棘轮密钥。': 'Yọ ẹ̀rọ aṣàwákiri yìí kúrò nínú àkọọlẹ̀ kí o sì pa àwọn bọ́tìnì OMEMO agbègbè rẹ̀ rẹ́ títí láé? Ìtàn ìfiránṣẹ́ tí a parọ́ kò lè mú àwọn bọ́tìnì ratchet wọ̀nyí padà.',
    '正在加载操作证据…': 'Ń ṣàkójọ ẹ̀rí iṣẹ́…',
    '请输入不含秘密的证据说明，解释结果如何得到验证：': 'Tẹ àlàyé ẹ̀rí tí kò ní àṣírí, kí o sì ṣàlàyé bí a ṣe jẹ́rìí sí àbájáde náà:',
    '删除所有排队的离线消息？此操作无法撤销。': 'Pa gbogbo àwọn ìfiránṣẹ́ aìlórí ayélujára tí ó wà ní ìdúró? A kò lè dá ìṣe yìí padà.',
    '独立页面提供注册、联系人、在线状态、历史消息、送达状态以及 OMEMO 设备指纹管理。默认优先使用端到端加密。': 'Ojú-ìwé ọ̀tọ̀ yìí n pèsè ìforúkọsílẹ̀, àwọn olùbásọ̀rọ̀, ipò lórí ayélujára, ìtàn ìfiránṣẹ́, ipò jíṣẹ́ àti ìṣàkóso ìka ọwọ́ ẹrọ OMEMO. A máa ń yan ìfipamọ́ láti ìbẹ̀rẹ̀ dé òpin ní àkọ́kọ́.',
    '查看举报处理结果，并在已处理的举报上提交一次申诉。申诉采用更严格的账号限流和工作量证明。': 'Wo àbájáde ìṣètò ẹ̀sùn, kí o sì fi ẹ̀bẹ̀ kan sílẹ̀ fún ẹ̀sùn tí a ti yanjú. Àwọn ẹ̀bẹ̀ ní ìdíwọ̀n oṣùwọ̀n àkọọlẹ̀ àti ẹ̀rí iṣẹ́ tó muna ju.',
    '请选择 1–20 条聊天记录作为证据。所选消息的明文会在你明确提交后发送给管理人员，即使原消息使用了 OMEMO；未选中的消息不会提交。': 'Yan ìgbasilẹ ìjíròrò 1–20 gẹ́gẹ́ bí ẹ̀rí. Nígbà tí o bá fi ránṣẹ́ ní kedere, ọ̀rọ̀ gbangba nínú àwọn ìfiránṣẹ́ tí o yàn ni a ó fi ranṣẹ́ sí àwọn alábòójútó, bí ó tilẹ̀ jẹ́ pé OMEMO ni a lò; àwọn tí o kò yàn kì yóò lọ.',
    '举报需要工作量证明。频繁举报会按台阶提高工作量和等待时间；限制有上限，停止频繁操作后会逐级冷却并恢复。最大工作量设计目标约为中端手机 8 秒。': 'Ìjábọ̀ nílò ẹ̀rí iṣẹ́. Ìjábọ̀ loorekoore máa ń pọ̀ sí iṣẹ́ àti àkókò ìdúró ní ìpele; ààlà tó ga jù lọ wà, ó sì máa dín kù lẹ́yìn ìsinmi. Iṣẹ́ tó pọ̀ jù lọ ni a ṣe àfojúsùn rẹ̀ sí bí ìṣẹ́jú-aaya mẹ́jọ lórí fóònù àárín.',
    '每份举报只能申诉一次。申诉的账号限流和工作量证明比普通举报更严格，且同样会逐级冷却。': 'A lè bẹ̀bẹ̀ lẹ́ẹ̀kan péré fún ìjábọ̀ kọọkan. Ìdíwọ̀n oṣùwọ̀n àkọọlẹ̀ àti ẹ̀rí iṣẹ́ fún ẹ̀bẹ̀ muna ju ti ìjábọ̀ lọ, wọ́n sì máa dín kù ní ìpele.',
    '说明为什么对处理结果不满意（至少 20 个字符）': 'Ṣàlàyé ìdí tí o kò fi tẹ́lọ́rùn pẹ̀lú àbájáde (ó kéré tán àmì 20)',
    '账户': 'Àkọọlẹ̀',
    '账号认证失败': 'Ìfàṣẹ̀sí àkọọlẹ̀ kùnà',
    '服务器已关闭开放注册': 'Olùpín ti pa ìforúkọsílẹ̀ gbangba',
  },
});

function arrayExpression(source, declaration) {
  const start = source.indexOf(declaration);
  if (start < 0) throw new Error(`Could not find ${declaration}`);
  const expressionStart = source.indexOf('[', start);
  const expressionEnd = source.indexOf('\n];', expressionStart);
  if (expressionEnd < 0) throw new Error(`Could not parse ${declaration}`);
  return source.slice(expressionStart, expressionEnd + 2);
}

function listExpression(source, declaration) {
  const start = source.indexOf(declaration);
  if (start < 0) throw new Error(`Could not find ${declaration}`);
  const tickStart = source.indexOf('`', start);
  const tickEnd = source.indexOf('`', tickStart + 1);
  return source.slice(tickStart + 1, tickEnd).trim().split(/\s+/);
}

async function loadProgress() {
  try {
    return JSON.parse(await readFile(progressPath, 'utf8'));
  } catch {
    return { translations: {}, templates: {} };
  }
}

let progressWrite = Promise.resolve();

async function saveProgress(progress) {
  const snapshot = `${JSON.stringify(progress)}\n`;
  progressWrite = progressWrite.then(() => writeFile(progressPath, snapshot, 'utf8'));
  await progressWrite;
}

function completionOnce(promptPath, target, maxTokens) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, [
      '-m', model,
      '-ngl', '999',
      '-c', '512',
      '-n', String(maxTokens),
      '--temp', '0',
      '--no-display-prompt',
      '--no-perf',
      '--no-warmup',
      '-fit', 'off',
      '-f', promptPath,
    ], { cwd: projectRoot, windowsHide: true });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code !== 0) reject(new Error(`${target}: translator exited ${code}: ${stderr.slice(-800)}`));
      else resolve(stdout.replace(/\s*\[end of text\][\s\S]*$/, '').trim());
    });
  });
}

async function completion(promptPath, target, maxTokens) {
  let lastError;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      return await completionOnce(promptPath, target, maxTokens);
    } catch (error) {
      lastError = error;
      if (attempt < 3) await delay(750 * attempt);
    }
  }
  throw lastError;
}

function parseBatch(output, batch) {
  const result = new Map();
  const pattern = /\[NS(\d{3})\]\s*([\s\S]*?)(?=\[NS\d{3}\]|$)/g;
  for (const match of output.matchAll(pattern)) {
    const index = Number(match[1]);
    const value = match[2].trim().replace(/^[-–—]\s*/, '');
    if (batch[index] && value) result.set(batch[index].key, value);
  }
  // Some MADLAD target languages preserve every opening bracket but translate
  // away the ASCII marker body (for example, "[NS000] Text" becomes
  // "[Translation"). Accept that output only when the anonymous segment count
  // exactly matches the input count, so positional alignment remains strict.
  if (result.size !== batch.length && output.includes('[')) {
    const positional = output.trim().split(/\s*\[/)
      .map((value) => value.trim().replace(/^NS\d{3}\]\s*/, ''))
      .filter(Boolean);
    if (positional.length === batch.length) {
      result.clear();
      for (let index = 0; index < batch.length; index += 1) result.set(batch[index].key, positional[index]);
      return result;
    }
  }
  if (batch.length === 1 && !result.size && output.trim()) {
    result.set(batch[0].key, output.replace(/^\[NS\d{3}\]\s*/, '').trim());
  } else if (!result.has(batch[0]?.key)) {
    const firstMarker = output.search(/\[NS\d{3}\]/);
    const leading = (firstMarker < 0 ? output : output.slice(0, firstMarker)).trim();
    if (leading) result.set(batch[0].key, leading);
  }
  return result;
}

async function translateBatch(language, batch, sequence) {
  const target = TARGET_CODE[language] || language;
  const promptPath = path.join(promptRoot, `${language}-${sequence}.txt`);
  const prompt = `<2${target}> ${batch.map((entry, index) => `[NS${String(index).padStart(3, '0')}] ${entry.english}`).join(' ')}`;
  await writeFile(promptPath, prompt, 'utf8');
  try {
    const estimatedTokens = batch.reduce((total, entry) => total + Math.ceil(entry.english.length * 1.8), 0);
    const output = await completion(promptPath, language, Math.min(700, Math.max(96, estimatedTokens + (batch.length * 14))));
    const translated = parseBatch(output, batch);
    if (translated.size === batch.length) return translated;
    if (batch.length === 1) throw new Error(`${language}: model did not preserve the item marker for ${batch[0].key}`);
    const midpoint = Math.ceil(batch.length / 2);
    const left = await translateBatch(language, batch.slice(0, midpoint), `${sequence}a`);
    const right = await translateBatch(language, batch.slice(midpoint), `${sequence}b`);
    return new Map([...left, ...right]);
  } finally {
    await rm(promptPath, { force: true });
  }
}

async function translateLanguage(language, entries, progress) {
  const batchSize = SMALL_BATCH_LANGUAGES.has(language) ? 1 : BATCH_SIZE;
  const translateEntries = async (items, sequencePrefix) => {
    const translated = new Map();
    for (let offset = 0; offset < items.length; offset += batchSize) {
      const batch = items.slice(offset, offset + batchSize);
      const sequence = `${sequencePrefix}-${String(offset / batchSize).padStart(3, '0')}`;
      const results = await translateBatch(language, batch, sequence);
      for (const [key, value] of results) translated.set(key, value);
    }
    return translated;
  };

  const pack = { ...(progress.translations[language] || {}) };
  const missingEntries = entries.filter(({ key }) => !pack[key]?.trim());
  if (missingEntries.length) {
    const fixed = await translateEntries(missingEntries, 'text');
    for (const { key } of missingEntries) pack[key] = fixed.get(key);
    progress.translations[language] = pack;
    await saveProgress(progress);
    process.stdout.write(`updated ${language} (+${missingEntries.length}, ${Object.keys(pack).length} strings)\n`);
  }

  if (progress.templates[language]
    && Object.keys(TEMPLATE_SOURCE).every((key) => progress.templates[language][key]?.trim())
    && !progress.degradedTemplates[language]?.length) return;

  const templateEntries = Object.entries(TEMPLATE_SOURCE)
    .map(([key, english]) => ({ key: `__template__${key}`, english }));
  const translated = await translateEntries(templateEntries, 'template');
  const templates = {};
  for (const key of Object.keys(TEMPLATE_SOURCE)) {
    const entry = { key: `__template__${key}`, english: TEMPLATE_SOURCE[key] };
    let value = TEMPLATE_OVERRIDES[language]?.[key] || translated.get(entry.key);
    const placeholders = [...entry.english.matchAll(/__NSVALUE(\d+)__/g)]
      .map((match) => match[0]);
    const sentinels = ['987654321', '123456789', '246813579', '975318642'];
    const placeholderSignature = (text) => [...String(text || '').matchAll(/__NSVALUE\d+__/g)]
      .map((match) => match[0])
      .sort()
      .join('|');
    const expectedPlaceholderSignature = placeholderSignature(entry.english);
    const placeholdersPreserved = () => placeholderSignature(value) === expectedPlaceholderSignature;
    if (!placeholdersPreserved()) {
      const sentinelEntry = {
        ...entry,
        english: placeholders.reduce((text, placeholder, index) =>
          text.replaceAll(placeholder, sentinels[index]), entry.english),
      };
      for (let attempt = 1; attempt <= 3; attempt += 1) {
        const retry = await translateBatch(language, [sentinelEntry], `retry-${key}-${attempt}`);
        const candidate = retry.get(entry.key);
        if (placeholders.every((_, index) => candidate?.split(sentinels[index]).length - 1 === 1)
          && sentinels.filter((sentinel) => candidate?.includes(sentinel)).length === placeholders.length) {
          value = placeholders.reduce((text, placeholder, index) =>
            text.replaceAll(sentinels[index], placeholder), candidate);
          break;
        }
      }
    }
    if (!placeholdersPreserved()) {
      // Fail closed to the stable English source rather than emitting a
      // translation with reordered or missing runtime values.
      value = TEMPLATE_SOURCE[key];
      progress.degradedTemplates[language] ||= [];
      if (!progress.degradedTemplates[language].includes(key)) progress.degradedTemplates[language].push(key);
    }
    templates[key] = placeholders.reduce((text, placeholder, index) =>
      text.replaceAll(placeholder, `$${index + 1}`), value);
  }
  progress.translations[language] = pack;
  progress.templates[language] = templates;
  delete progress.partialTranslations[language];
  await saveProgress(progress);
  process.stdout.write(`completed ${language} (${Object.keys(pack).length} strings)\n`);
}

async function worker(queue, entries, progress) {
  while (queue.length) {
    const language = queue.shift();
    await translateLanguage(language, entries, progress);
  }
}

function sortedObject(value) {
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right, 'en')));
}

const i18nSource = await readFile(i18nPath, 'utf8');
const rows = vm.runInNewContext(arrayExpression(i18nSource, 'const ROWS ='));
const languageCodes = listExpression(i18nSource, 'const SUPPORTED_LANGUAGE_CODES =');
const selected = process.argv.slice(2).length ? process.argv.slice(2) : languageCodes.filter((code) => !HUMAN_LANGUAGES.has(code));
const entries = rows.map((row) => ({ key: row[0], english: row[1] })).filter(({ english }) => Boolean(english));
const progress = await loadProgress();
progress.partialTranslations ||= {};
progress.degradedTemplates ||= {};
await mkdir(promptRoot, { recursive: true });
const queue = selected.filter((language) => !HUMAN_LANGUAGES.has(language));
await Promise.all(Array.from({ length: Math.min(CONCURRENCY, queue.length) }, () => worker(queue, entries, progress)));
for (const [language, overrides] of Object.entries(TEMPLATE_OVERRIDES)) {
  if (!progress.templates[language]) continue;
  for (const [key, value] of Object.entries(overrides)) {
    progress.templates[language][key] = [1, 2, 3, 4].reduce(
      (rendered, position) => rendered.replaceAll(`__NSVALUE${position}__`, `$${position}`),
      value,
    );
    if (progress.degradedTemplates[language]) {
      progress.degradedTemplates[language] = progress.degradedTemplates[language].filter((id) => id !== key);
      if (!progress.degradedTemplates[language].length) delete progress.degradedTemplates[language];
    }
  }
}
for (const [language, overrides] of Object.entries(TRANSLATION_OVERRIDES)) {
  if (!progress.translations[language]) continue;
  Object.assign(progress.translations[language], overrides);
}
await saveProgress(progress);
const translations = sortedObject(Object.fromEntries(
  languageCodes.filter((code) => progress.translations[code]).map((code) => [code, progress.translations[code]]),
));
const templates = sortedObject(Object.fromEntries(
  languageCodes.filter((code) => progress.templates[code]).map((code) => [code, progress.templates[code]]),
));
const output = `// Generated by scripts/generate-locales.mjs. Do not edit by hand.\n`
  + `export const MACHINE_TRANSLATIONS = Object.freeze(${JSON.stringify(translations)});\n`
  + `export const MACHINE_TEMPLATES = Object.freeze(${JSON.stringify(templates)});\n`;
await writeFile(outputPath, output, 'utf8');
await rm(promptRoot, { recursive: true, force: true });
process.stdout.write(`wrote ${Object.keys(translations).length} local static language packs to web/locales.generated.js\n`);
