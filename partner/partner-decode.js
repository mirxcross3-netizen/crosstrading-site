/**
 * Opens a partner share in the browser (site/partner.html). Plain JavaScript
 * with no imports and no build step: the cipher is passed in, so the page can
 * load it from a CDN and the tests can pass the app's own copy
 * (tests/partner-share.test.ts runs this file against the app's encryption).
 *
 * Must match src/lib/partner-share.ts: the link format, the envelope and the
 * associated data.
 */

export const PARTNER_AAD = 'womens-tracker-partner-v1';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function base64ToBytes(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function base64UrlToBytes(text) {
  if (!/^[A-Za-z0-9_-]+$/.test(text)) throw new Error('Not base64url');
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/');
  return base64ToBytes(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
}

/**
 * Reads `#<share id>.<base64url key>` (with or without the `#`). Returns null
 * for anything else, including a key that isn't 32 bytes.
 */
export function parseShareFragment(fragment) {
  const text = String(fragment || '').replace(/^#/, '');
  const dot = text.indexOf('.');
  if (dot < 0) return null;
  const id = text.slice(0, dot);
  if (!UUID.test(id)) return null;
  let key;
  try {
    key = base64UrlToBytes(text.slice(dot + 1));
  } catch {
    return null;
  }
  if (key.length !== 32) return null;
  return { id: id.toLowerCase(), key };
}

/**
 * Decrypts the stored envelope with the key from the link and checks the
 * payload's shape. Throws on a wrong key, tampering or an unknown format.
 */
export function openPartnerShare(stored, key, xchacha20poly1305) {
  const envelope = JSON.parse(stored);
  if (!envelope || envelope.v !== 1) throw new Error('Unsupported share format.');
  const aad = new TextEncoder().encode(PARTNER_AAD);
  const plain = xchacha20poly1305(key, base64ToBytes(envelope.nonce), aad).decrypt(base64ToBytes(envelope.ciphertext));
  const payload = JSON.parse(new TextDecoder().decode(plain));
  if (
    !payload ||
    payload.v !== 1 ||
    typeof payload.updatedAt !== 'string' ||
    !payload.today ||
    typeof payload.today.onPeriod !== 'boolean' ||
    !Array.isArray(payload.periodDays)
  ) {
    throw new Error('Unsupported share format.');
  }
  return payload;
}
