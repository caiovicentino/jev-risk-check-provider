// `request_hash`: SHA-256 of the RFC 8785 (JCS) canonical JSON of the request fields exactly
// as the API received them. The provider signs it, so a client can recompute it from the request
// it sent and detect an intermediary that altered or dropped any field, `context` and
// `interaction.unlimited` included. Mirrors `canonicalJson` / `requestHash` in the provider.

/** The request fields `request_hash` covers, as sent. */
export const REQUEST_HASH_FIELDS = ["wallet", "chain", "domain", "context", "aud", "screening", "authorization", "payment", "interaction", "transaction"] as const;

/**
 * RFC 8785 (JCS) canonical JSON: object keys sorted by UTF-16 code units at every depth,
 * ECMAScript number and string serialization, undefined members dropped, undefined array items
 * as null. Non-finite numbers and non-JSON values (functions, symbols, bigint) throw.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("canonicalJson: non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((v) => (v === undefined ? "null" : canonicalJson(v))).join(",")}]`;
  if (typeof value !== "object") throw new TypeError(`canonicalJson: unsupported ${typeof value}`);
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

function hex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * The `request_hash` the provider signs for this request (the object passed to `check()`, or
 * one item of `checkBatch()`). The request goes through a JSON round-trip first, exactly as
 * it travels to the API, so `undefined` members, `toJSON()` values and the like hash the way the
 * server saw them. Uses WebCrypto SHA-256. Throws when the request is not a JSON object.
 */
export async function requestHash(request: object): Promise<string> {
  const sent: unknown = JSON.parse(JSON.stringify(request) ?? "null");
  if (typeof sent !== "object" || sent === null || Array.isArray(sent)) throw new TypeError("requestHash: the request must be a JSON object");
  const received = sent as Record<string, unknown>;
  const picked: Record<string, unknown> = {};
  for (const key of REQUEST_HASH_FIELDS) if (received[key] !== undefined) picked[key] = received[key];
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new TypeError("requestHash: crypto.subtle is unavailable");
  return hex(await subtle.digest("SHA-256", new TextEncoder().encode(canonicalJson(picked))));
}
