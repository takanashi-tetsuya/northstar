function decode(value) {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  return Uint8Array.from(atob(normalized), (character) => character.charCodeAt(0));
}

function encode(buffer) {
  if (buffer == null) return null;
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 8192) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  }
  return btoa(binary)
    .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

export function passkeysAvailable() {
  return globalThis.isSecureContext && !!globalThis.PublicKeyCredential && !!navigator.credentials;
}

export async function createPasskey(options, signal) {
  const publicKey = { ...options.publicKey, challenge: decode(options.publicKey.challenge),
    user: { ...options.publicKey.user, id: decode(options.publicKey.user.id) },
    excludeCredentials: (options.publicKey.excludeCredentials || []).map((entry) => ({ ...entry, id: decode(entry.id) })),
  };
  const credential = await navigator.credentials.create({ publicKey, signal });
  if (!credential) throw new Error('未创建通行密钥');
  return { id: credential.id, rawId: encode(credential.rawId), type: credential.type,
    response: { attestationObject: encode(credential.response.attestationObject),
      clientDataJSON: encode(credential.response.clientDataJSON),
      transports: credential.response.getTransports?.() || [], },
    extensions: credential.getClientExtensionResults(),
  };
}

export async function authenticatePasskey(options, signal) {
  const publicKey = { ...options.publicKey, challenge: decode(options.publicKey.challenge),
    allowCredentials: (options.publicKey.allowCredentials || []).map((entry) => ({ ...entry, id: decode(entry.id) })),
  };
  const credential = await navigator.credentials.get({ publicKey, signal });
  if (!credential) throw new Error('未完成通行密钥验证');
  return { id: credential.id, rawId: encode(credential.rawId), type: credential.type,
    response: { authenticatorData: encode(credential.response.authenticatorData),
      clientDataJSON: encode(credential.response.clientDataJSON),
      signature: encode(credential.response.signature), userHandle: encode(credential.response.userHandle), },
    extensions: credential.getClientExtensionResults(),
  };
}
