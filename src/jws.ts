import { createHash, sign as nodeSign, verify as nodeVerify, generateKeyPairSync, type JsonWebKey } from "node:crypto";

export type Jwk = {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  kid: string;
  alg: "ES256";
  use: "sig";
};

export type KeyPair = {
  privatePem: string;
  publicJwk: Jwk;
};

function base64url(input: Buffer | string): string {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64url(input: string): Buffer {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(padded, "base64");
}

export function generateKeyPair(kid: string): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string; y: string };
  return {
    // PKCS#8 is the most portable PEM (workerd rejects an ephemeral SEC1 export).
    privatePem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
    publicJwk: {
      kty: "EC",
      crv: "P-256",
      x: jwk.x,
      y: jwk.y,
      kid,
      alg: "ES256",
      use: "sig",
    },
  };
}

/** JWK members that hold private key material: a key carrying any of them is never published. */
export const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"] as const;

/** A key's public members only: a private `d` pasted by mistake is never published. */
export function publicJwkOf(jwk: Record<string, unknown>): Jwk {
  const out: Record<string, unknown> = {};
  for (const k of ["kty", "crv", "x", "y", "kid", "alg", "use"]) if (typeof jwk[k] === "string") out[k] = jwk[k];
  return out as Jwk;
}

export function jwksDocument(kid: string, jwk: Jwk): { keys: Jwk[] } {
  return { keys: [{ ...publicJwkOf(jwk), kid }] };
}

export type AttestationChecks = {
  /** `digest` (since provider 0.6.1): "sha256:<hex>" of the source artifact (OFAC's SDN.XML). */
  sanctions: { list: string; as_of: string; digest?: string | undefined; status: string };
  domain?: { host: string; impersonation: string } | undefined;
  onchain: { status: string; network?: string | undefined; activity?: string | undefined };
  /** Threat feeds consulted, as "source@as_of:status". */
  feeds?: string[] | undefined;
  /** `at_block` (since provider 0.6.1): the block whose state was simulated. */
  simulation?: { status: string; network?: string | undefined; findings?: string[] | undefined; at_block?: number | undefined } | undefined;
  /** The kit watch, when it was consulted (since provider 0.6.1): its scan clock and coverage clock. */
  kit_watch?: { as_of: string; status: string; complete_through?: Record<string, number> | undefined; gaps?: Record<string, number> | undefined } | undefined;
  model: string;
  /** The model revision that answered (the vendor's alias can change underneath). */
  model_id?: string | undefined;
};

export type JwsClaims = {
  iss: string;
  sub: string;
  score: number;
  tier: string;
  iat: number;
  exp: number;
  jti?: string | undefined;
  aud?: string | undefined;
  categories?: string[] | undefined;
  input_hash?: string | undefined;
  /** What the provider itself verified for this verdict. */
  checks?: AttestationChecks | undefined;
  /** Self-reported by the caller; NOT verified by the provider. */
  asserted?: { screening?: string; pre_authorized?: boolean } | undefined;
  /** The concrete payment this verdict was issued for, when the caller bound one. */
  payment?: Record<string, string> | undefined;
  /** Interaction type the verdict was issued for (wallet integrations). */
  interaction?: string | undefined;
  /** requestHash() of the request as the caller sent it (see REQUEST_HASH_FIELDS). */
  request_hash?: string | undefined;
};

export function signJws(claims: JwsClaims, kid: string, privatePem: string): string {
  const header = { alg: "ES256", typ: "risk-check+jwt", kid };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;
  // Pass the PEM string (workerd's node:crypto does not accept KeyObjects here) with the
  // encoding taken from its header: SEC1 "EC PRIVATE KEY" (production secret) or PKCS#8.
  const signature = nodeSign("SHA256", Buffer.from(signingInput), {
    key: privatePem,
    format: "pem",
    type: privatePem.includes("BEGIN EC PRIVATE KEY") ? "sec1" : "pkcs8",
    dsaEncoding: "ieee-p1363",
  });
  return `${signingInput}.${base64url(signature)}`;
}

export function verifyJws(jws: string, jwk: Jwk): JwsClaims | null {
  const parts = jws.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, signatureB64] = parts;
  if (!headerB64 || !payloadB64 || !signatureB64) return null;
  let header: { alg?: string; kid?: string };
  try {
    header = JSON.parse(fromBase64url(headerB64).toString("utf8"));
  } catch {
    return null;
  }
  if (header.alg !== "ES256") return null;
  if (header.kid && header.kid !== jwk.kid) return null;
  let valid = false;
  try {
    valid = nodeVerify(
      "SHA256",
      Buffer.from(`${headerB64}.${payloadB64}`),
      { key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } as JsonWebKey, format: "jwk", dsaEncoding: "ieee-p1363" },
      fromBase64url(signatureB64),
    );
  } catch {
    return null;
  }
  if (!valid) return null;
  try {
    return JSON.parse(fromBase64url(payloadB64).toString("utf8")) as JwsClaims;
  } catch {
    return null;
  }
}

/**
 * RFC 8785 (JCS) canonical JSON: object keys sorted by UTF-16 code units at every
 * depth, ECMAScript number and string serialization, undefined members dropped.
 * Non-finite numbers and non-JSON values (functions, symbols, bigint) throw instead
 * of silently collapsing to null.
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
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

export function inputHash(input: Record<string, unknown>): string {
  return createHash("sha256").update(canonicalJson(input)).digest("hex");
}

/** The request fields a caller sends; `request_hash` covers exactly these, as sent. */
export const REQUEST_HASH_FIELDS = ["wallet", "chain", "domain", "context", "aud", "screening", "authorization", "payment", "interaction", "transaction"] as const;

/**
 * SHA-256 of the RFC 8785 canonical JSON of the request fields exactly as the caller
 * sent them (before server-side normalization), so any client can recompute it from
 * its own request object and detect an intermediary that altered or dropped a field
 * (e.g. `context`, which carries the injected content the model must see).
 */
export function requestHash(raw: Record<string, unknown>): string {
  const picked: Record<string, unknown> = {};
  for (const k of REQUEST_HASH_FIELDS) if (raw[k] !== undefined) picked[k] = raw[k];
  return createHash("sha256").update(canonicalJson(picked)).digest("hex");
}
