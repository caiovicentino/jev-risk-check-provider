import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import type { FetchInitLike, FetchLike } from "../src/types.js";

export const ISSUER = "did:web:x402check.xyz";
export const DID_URL = "https://x402check.xyz/.well-known/did.json";
export const KID = "jev-attest-v1";
export const EVM = "0x7a3e8f0c2b1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f";
export const SOL = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";

export type PublicJwk = { kty: "EC"; crv: "P-256"; x: string; y: string; kid: string; alg: "ES256"; use: "sig" };
export type IssuerKey = { privateKey: CryptoKey; publicJwk: PublicJwk };

export function b64url(input: Uint8Array | string): string {
  return Buffer.from(typeof input === "string" ? new TextEncoder().encode(input) : input).toString("base64url");
}

/** A fresh P-256 key pair generated with WebCrypto. */
export async function makeIssuerKey(kid = KID): Promise<IssuerKey> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return { privateKey: pair.privateKey, publicJwk: { kty: "EC", crv: "P-256", x: jwk.x as string, y: jwk.y as string, kid, alg: "ES256", use: "sig" } };
}

export const DEFAULT_HEADER = { alg: "ES256", typ: "risk-check+jwt", kid: KID };

/** Compact JWS signed with WebCrypto (ES256, IEEE P1363 signature). */
export async function signJws(claims: Record<string, unknown>, privateKey: CryptoKey, header: Record<string, unknown> = DEFAULT_HEADER): Promise<string> {
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, new TextEncoder().encode(input));
  return `${input}.${b64url(new Uint8Array(signature))}`;
}

/** Signs exactly the way the provider does (node:crypto, PEM key, dsaEncoding ieee-p1363). */
export function providerStyleSigner(kid = KID): { publicJwk: PublicJwk; sign: (claims: Record<string, unknown>) => string } {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  return {
    publicJwk: { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, kid, alg: "ES256", use: "sig" },
    sign: (claims) => {
      const input = `${b64url(JSON.stringify({ alg: "ES256", typ: "risk-check+jwt", kid }))}.${b64url(JSON.stringify(claims))}`;
      const signature = nodeSign("SHA256", Buffer.from(input), { key: pem, format: "pem", type: "pkcs8", dsaEncoding: "ieee-p1363" });
      return `${input}.${b64url(signature)}`;
    },
  };
}

/** The DID document shape production serves at /.well-known/did.json. */
export function didDocument(jwk: PublicJwk, opts: { did?: string; inAssertion?: boolean; extraMethods?: unknown[] } = {}): Record<string, unknown> {
  const did = opts.did ?? ISSUER;
  const keyId = `${did}#${jwk.kid}`;
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
    id: did,
    verificationMethod: [{ id: keyId, type: "JsonWebKey2020", controller: did, publicKeyJwk: jwk }, ...(opts.extraMethods ?? [])],
    assertionMethod: opts.inAssertion === false ? [] : [keyId],
    authentication: [keyId],
  };
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Flips the case of every letter whose flipped form is still base58 (the alphabet has no
 * 0/O/I/l), so the result is a VALID base58 string that differs only in case.
 */
export function flipBase58Case(address: string): string {
  const flipped = [...address]
    .map((c) => {
      const f = c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase();
      return BASE58_ALPHABET.includes(f) ? f : c;
    })
    .join("");
  if (flipped === address) throw new Error("nothing to flip");
  return flipped;
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** Claims shaped like a production attestation. */
export function claims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const iat = nowSeconds();
  return {
    iss: ISSUER,
    sub: EVM,
    score: 40,
    tier: "high",
    iat,
    exp: iat + 3600,
    jti: "4f9d1c2e-8a7b-4c3d-9e1f-0a2b3c4d5e6f",
    categories: ["intent_risk", "behavioral", "approval_to_eoa", "new_address"],
    input_hash: "a".repeat(64),
    checks: {
      sanctions: { list: "ofac-sdn", as_of: "2026-09-23", status: "not_listed" },
      onchain: { status: "ok", network: "eip155:1", activity: "none" },
      feeds: ["metamask-phishing-detect@2026-09-29:not_applicable", "scamsniffer-addresses@2026-09-22:clear"],
      model: "jev-wallet-risk/v6",
    },
    interaction: "permit_signature",
    ...overrides,
  };
}

export type Call = { url: string; init: FetchInitLike };

/** A recording fetch. The handler returns a Response (or throws, to simulate a network error). */
export function mockFetch(handler: (url: string, init: FetchInitLike) => Response | Promise<Response>): { fetch: FetchLike; calls: Call[] } {
  const calls: Call[] = [];
  const fetch: FetchLike = async (url, init) => {
    calls.push({ url, init });
    return handler(url, init);
  };
  return { fetch, calls };
}

export function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

/** A fetch serving only the issuer's DID document (anything else is a test failure). */
export function didFetch(doc: unknown, status = 200): { fetch: FetchLike; calls: Call[] } {
  return mockFetch((url) => {
    if (url !== DID_URL) throw new Error(`unexpected fetch: ${url}`);
    return json(status, doc);
  });
}

/**
 * A provider stub that signs, for each request, claims bound exactly as the real provider binds
 * them (subject, interaction, payment, domain, chain, simulation, request_hash), plus optional
 * extra routes (e.g. a Solana RPC). `decide` picks the verdict per request.
 */
export function boundProvider(
  decide: (request: import("../src/types.js").RiskCheckRequest) => { tier: "low" | "medium" | "high" | "critical"; score: number; categories: string[] },
  extra?: (url: string, init: FetchInitLike) => Response | Promise<Response> | undefined,
) {
  const signer = providerStyleSigner();
  const seen: import("../src/types.js").RiskCheckRequest[] = [];
  const sign = async (request: import("../src/types.js").RiskCheckRequest) => {
    seen.push(request);
    const v = decide(request);
    const { requestHash } = await import("../src/request-hash.js");
    const { toCaip2, normalizeHost } = await import("../src/normalize.js");
    const network = request.chain ? toCaip2(request.chain) : undefined;
    const c = claims({
      sub: request.wallet,
      score: v.score,
      tier: v.tier,
      categories: v.categories,
      request_hash: await requestHash(request),
      checks: {
        sanctions: { list: "ofac-sdn", as_of: "2026-09-23", status: "not_listed" },
        ...(network ? { onchain: { status: "ok", network, activity: "some" } } : {}),
        model: "jev-wallet-risk/v6",
        ...(request.transaction ? { simulation: { status: "ok", network } } : {}),
        ...(request.domain ? { domain: { host: normalizeHost(request.domain), registrable: normalizeHost(request.domain), official: false } } : {}),
      },
    });
    if (request.interaction) c.interaction = request.interaction.type;
    else delete c.interaction;
    if (request.payment) c.payment = request.payment;
    return { checked: true, score: v.score, tier: v.tier, categories: v.categories, jws: signer.sign(c), checked_at: new Date().toISOString(), expires_at: new Date((c.exp as number) * 1000).toISOString() };
  };
  const { fetch, calls } = mockFetch(async (url, init) => {
    if (url === DID_URL) return json(200, didDocument(signer.publicJwk));
    const routed = extra?.(url, init);
    if (routed) return routed;
    const body = JSON.parse(String(init.body ?? "{}")) as import("../src/types.js").RiskCheckRequest & { requests?: import("../src/types.js").RiskCheckRequest[] };
    if (url.endsWith("/v1/risk-check/batch")) return json(200, { results: await Promise.all((body.requests ?? []).map(sign)) });
    if (url.endsWith("/v1/risk-check")) return json(200, await sign(body));
    return json(404, { error: "not_found" });
  });
  return { fetch, calls, seen, publicJwk: signer.publicJwk };
}
