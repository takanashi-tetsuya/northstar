const DB_NAME = 'northstar-client';
const DB_VERSION = 2;
const STORES = ['crypto', 'messages', 'preferences'];

let databasePromise;

function database() {
  if (!databasePromise) {
    databasePromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = () => {
        for (const name of STORES) {
          if (!request.result.objectStoreNames.contains(name)) request.result.createObjectStore(name);
        }
        // Version 1 cached decrypted message bodies. Purge them: durable history must
        // be reloaded as ciphertext from MAM and decrypted only in memory.
        request.transaction.objectStore('messages').clear();
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error('无法打开本机安全存储'));
    });
  }
  return databasePromise;
}

async function transact(storeName, mode, operation) {
  const db = await database();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(storeName, mode);
    const store = transaction.objectStore(storeName);
    let result;
    try {
      result = operation(store);
    } catch (error) {
      reject(error);
      return;
    }
    transaction.oncomplete = () => resolve(result?.result);
    transaction.onerror = () => reject(transaction.error || result?.error || new Error('本机存储操作失败'));
    transaction.onabort = () => reject(transaction.error || new Error('本机存储操作被中止'));
  });
}

export function getValue(storeName, key) {
  return transact(storeName, 'readonly', (store) => store.get(key));
}

export function setValue(storeName, key, value) {
  return transact(storeName, 'readwrite', (store) => store.put(value, key));
}

export function deleteValue(storeName, key) {
  return transact(storeName, 'readwrite', (store) => store.delete(key));
}

export function getAllValues(storeName) {
  return transact(storeName, 'readonly', (store) => store.getAll());
}

export function getAllEntries(storeName) {
  return database().then((db) => new Promise((resolve, reject) => {
    const transaction = db.transaction(storeName, 'readonly');
    const request = transaction.objectStore(storeName).openCursor();
    const entries = [];
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) return;
      entries.push([cursor.key, cursor.value]);
      cursor.continue();
    };
    transaction.oncomplete = () => resolve(entries);
    transaction.onerror = () => reject(transaction.error || new Error('读取本机存储失败'));
  }));
}

export async function saveCachedMessage(account, peer, message) {
  // Do not persist decrypted chat bodies in IndexedDB. OMEMO identity/session
  // material remains durable, while message plaintext exists only in memory.
  return message.id || crypto.randomUUID();
}

export async function loadCachedMessages(account, peer, limit = 200) {
  return [];
}
