// Runtime-neutral encoding helpers (no Buffer): Node >= 20, browsers and Workers.

const B64URL = /^[A-Za-z0-9_-]*$/;
const B64 = /^[A-Za-z0-9+/]*={0,2}$/;

function binaryToBytes(binary: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Strict unpadded base64url (RFC 7515 §2) to bytes; null when malformed. Non-canonical input
 * (non-zero padding bits in the last character) is rejected, so one signature has one encoding.
 */
export function base64UrlToBytes(input: string): Uint8Array<ArrayBuffer> | null {
  if (!B64URL.test(input) || input.length % 4 === 1) return null;
  const rem = input.length % 4;
  if (rem !== 0 && B64URL_ALPHABET.indexOf(input[input.length - 1] as string) & (rem === 2 ? 0x0f : 0x03)) return null;
  const b64 = input.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (input.length % 4)) % 4);
  try {
    return binaryToBytes(atob(b64));
  } catch {
    return null;
  }
}

/** Standard (padded or unpadded) base64 to bytes; null when malformed. */
export function base64ToBytes(input: string): Uint8Array<ArrayBuffer> | null {
  const trimmed = input.trim();
  if (!B64.test(trimmed)) return null;
  const bare = trimmed.replace(/=+$/, "");
  if (bare.length % 4 === 1) return null;
  try {
    return binaryToBytes(atob(bare + "=".repeat((4 - (bare.length % 4)) % 4)));
  } catch {
    return null;
  }
}

/** Strict UTF-8 decoding; null on invalid sequences. */
export function utf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** JSON.parse that returns undefined instead of throwing. */
export function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/** Decodes a base64url segment holding a JSON object; null when anything is off. */
export function decodeJsonSegment(segment: string): Record<string, unknown> | null {
  const bytes = base64UrlToBytes(segment);
  if (!bytes) return null;
  const text = utf8(bytes);
  if (text === null) return null;
  const value = parseJson(text);
  return isRecord(value) ? value : null;
}
