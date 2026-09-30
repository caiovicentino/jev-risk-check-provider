import { PROVIDER_VERSION } from "../src/provider.js";

// Coinbase CDP's x402 facilitator. Every call carries a short-lived JWT signed with the
// owner's CDP Secret API Key: the token @coinbase/x402 builds with @coinbase/cdp-sdk
// (header alg ES256 or EdDSA, kid = key id, random nonce; claims iss "cdp", sub = key id,
// uris ["POST api.cdp.coinbase.com/platform/v2/x402/settle"], 120 s), made here with
// WebCrypto so the Worker bundles neither SDK.
//
//   wrangler secret put CDP_API_KEY_ID       the key's id
//   wrangler secret put CDP_API_KEY_SECRET   base64 Ed25519 (the default), or an EC key in PEM
//
// Pricing (docs.cdp.coinbase.com/x402): the first 1,000 on-chain settlements a month are
// free, then $0.001 each; verification is free. Networks: Base, Polygon, Arbitrum, World
// and Solana. The secret never leaves this module: not in /status, not in an error.

export const CDP_FACILITATOR_URL = "https://api.cdp.coinbase.com/platform/v2/x402";
/** What one settlement through CDP costs us beyond the monthly free 1,000: routing uses the paid rate. */
export const CDP_FEE_USD = 0.001;
const HOST = "api.cdp.coinbase.com";
const ROUTE = "/platform/v2/x402";
const TTL_S = 120;

type WebKey = Awaited<ReturnType<typeof crypto.subtle.importKey>>;
type Signer = { alg: "EdDSA" | "ES256"; key: WebKey };
export type CdpAuthHeaders = { verify: Record<string, string>; settle: Record<string, string>; supported: Record<string, string> };

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const hex = (h: string): Uint8Array => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}
function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64decode(s: string): Uint8Array {
  const bin = atob(s.replace(/\s+/g, ""));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
/** A DER TLV (definite length). */
function der(tag: number, body: Uint8Array): Uint8Array {
  const n = body.length;
  const len = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
  return concat(Uint8Array.of(tag, ...len), body);
}

/** PKCS#8 for an Ed25519 seed: SEQUENCE { 0, { id-Ed25519 }, OCTET STRING { OCTET STRING seed } }. */
const ED25519_PKCS8_PREFIX = hex("302e020100300506032b657004220420");
/** AlgorithmIdentifier { id-ecPublicKey, prime256v1 }. */
const EC_P256_ALGORITHM = hex("301306072a8648ce3d020106082a8648ce3d030107");

/**
 * The signing key in a CDP secret: 64 bytes of base64 (Ed25519 seed + public key, what the
 * CDP portal issues by default), or a P-256 key in PEM, PKCS#8 or SEC1 ("EC PRIVATE KEY").
 * A PEM pasted with literal "\n" escapes (copied out of the key's JSON file) is accepted.
 */
export async function importCdpSecret(secret: string): Promise<Signer> {
  const s = secret.trim().replace(/\\n/g, "\n");
  if (s.startsWith("-----BEGIN")) {
    const body = b64decode(s.replace(/-----[A-Z ]+-----/g, ""));
    const pkcs8 = /-----BEGIN EC PRIVATE KEY-----/.test(s) ? der(0x30, concat(hex("020100"), EC_P256_ALGORITHM, der(0x04, body))) : body;
    return { alg: "ES256", key: await crypto.subtle.importKey("pkcs8", pkcs8, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]) };
  }
  let raw: Uint8Array;
  try {
    raw = b64decode(s);
  } catch {
    raw = new Uint8Array(0);
  }
  if (raw.length !== 64) throw new Error("CDP_API_KEY_SECRET must be a base64 Ed25519 key (64 bytes) or a P-256 key in PEM");
  return { alg: "EdDSA", key: await crypto.subtle.importKey("pkcs8", concat(ED25519_PKCS8_PREFIX, raw.slice(0, 32)), { name: "Ed25519" }, false, ["sign"]) };
}

/** One request's JWT: bound to the method and path, valid 120 s, with a fresh nonce. */
export async function cdpJwt(keyId: string, signer: Signer, method: "GET" | "POST", path: string, now = Math.floor(Date.now() / 1000)): Promise<string> {
  const nonce = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
  const header = { alg: signer.alg, kid: keyId, typ: "JWT", nonce };
  const claims = { sub: keyId, iss: "cdp", uris: [`${method} ${HOST}${ROUTE}${path}`], iat: now, nbf: now, exp: now + TTL_S };
  const input = `${b64url(utf8(JSON.stringify(header)))}.${b64url(utf8(JSON.stringify(claims)))}`;
  const algorithm = signer.alg === "EdDSA" ? { name: "Ed25519" } : { name: "ECDSA", hash: "SHA-256" };
  const signature = new Uint8Array(await crypto.subtle.sign(algorithm, signer.key, utf8(input)));
  return `${input}.${b64url(signature)}`;
}

/**
 * The facilitator client's `createAuthHeaders`: a fresh JWT for each endpoint, every call
 * (the client picks the one for the request it is making). The key is imported once.
 */
export function cdpAuthHeaders(keyId: string, secret: string): () => Promise<CdpAuthHeaders> {
  let signer: Promise<Signer> | null = null;
  const correlation = `sdk_language=typescript,source=x402check,source_version=${PROVIDER_VERSION}`;
  return async () => {
    signer ??= importCdpSecret(secret);
    let s: Signer;
    try {
      s = await signer;
    } catch (err) {
      signer = null;
      throw err;
    }
    const [verify, settle, supported] = await Promise.all([cdpJwt(keyId, s, "POST", "/verify"), cdpJwt(keyId, s, "POST", "/settle"), cdpJwt(keyId, s, "GET", "/supported")]);
    const headers = (jwt: string) => ({ Authorization: `Bearer ${jwt}`, "Correlation-Context": correlation });
    return { verify: headers(verify), settle: headers(settle), supported: headers(supported) };
  };
}
