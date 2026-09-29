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
    privatePem: privateKey.export({ format: "pem", type: "sec1" }).toString(),
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

export function jwksDocument(kid: string, jwk: Jwk): { keys: Jwk[] } {
  return { keys: [{ ...jwk, kid }] };
}

export type JwsClaims = {
  iss: string;
  sub: string;
  score: number;
  tier: string;
  iat: number;
  exp: number;
  aud?: string | undefined;
  categories?: string[] | undefined;
  input_hash?: string | undefined;
  asserted?: { screening?: string; pre_authorized?: boolean } | undefined;
};

export function signJws(claims: JwsClaims, kid: string, privatePem: string): string {
  const header = { alg: "ES256", typ: "risk-check+jwt", kid };
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;
  const signature = nodeSign("SHA256", Buffer.from(signingInput), {
    key: privatePem,
    format: "pem",
    type: "sec1",
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

export function inputHash(input: Record<string, unknown>): string {
  const canonical = JSON.stringify(input, Object.keys(input).sort());
  return createHash("sha256").update(canonical).digest("hex");
}
