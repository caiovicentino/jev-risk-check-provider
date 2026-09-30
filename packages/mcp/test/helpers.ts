import type { webcrypto } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { jwkThumbprint, type FetchInitLike, type FetchLike, type RiskCheckResult } from "@x402check/client";
import { createX402CheckServer, type ServerConfig } from "../src/server.js";

export const ISSUER = "did:web:x402check.xyz";
export const DID_URL = "https://x402check.xyz/.well-known/did.json";
export const API = "https://x402check.xyz/v1/risk-check";
export const KID = "jev-attest-v1";
export const SPENDER = "0x7a3e8f0c2b1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f";
export const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

/** A throwaway attestation key, and its RFC 7638 thumbprint (what the server pins). */
export type Issuer = { privateKey: webcrypto.CryptoKey; jwk: Record<string, string>; thumbprint: string };

function b64url(input: Uint8Array | string): string {
  return Buffer.from(typeof input === "string" ? new TextEncoder().encode(input) : input).toString("base64url");
}

/** The thumbprints of every fixture issuer made so far: the keys the test servers pin by default. */
const FIXTURE_KEYS: string[] = [];

export async function makeIssuer(): Promise<Issuer> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
  const exported = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const jwk = { kty: "EC", crv: "P-256", x: exported.x as string, y: exported.y as string, kid: KID, alg: "ES256", use: "sig" };
  const thumbprint = await jwkThumbprint(jwk);
  FIXTURE_KEYS.push(thumbprint);
  return { privateKey: pair.privateKey, jwk, thumbprint };
}

/**
 * A test server's configuration: the fixture issuers' keys are pinned, as the production key is
 * pinned by default (a test about pinning sets `pinnedKeys` itself, even to undefined).
 */
export function pinned(config: ServerConfig): ServerConfig {
  return "pinnedKeys" in config ? config : { ...config, pinnedKeys: [...FIXTURE_KEYS] };
}

export async function sign(issuer: Issuer, claims: Record<string, unknown>): Promise<string> {
  const input = `${b64url(JSON.stringify({ alg: "ES256", typ: "risk-check+jwt", kid: KID }))}.${b64url(JSON.stringify(claims))}`;
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, issuer.privateKey, new TextEncoder().encode(input));
  return `${input}.${b64url(new Uint8Array(signature))}`;
}

export function didDocument(issuer: Issuer): Record<string, unknown> {
  const keyId = `${ISSUER}#${KID}`;
  return {
    id: ISSUER,
    verificationMethod: [{ id: keyId, type: "JsonWebKey2020", controller: ISSUER, publicKeyJwk: issuer.jwk }],
    assertionMethod: [keyId],
  };
}

/** The provider-verified `checks` claim for a request on Base without a domain or transaction. */
export const CHECKS = {
  sanctions: { list: "ofac-sdn", as_of: "2026-09-23", status: "not_listed" },
  onchain: { status: "ok", network: "eip155:8453", activity: "some" },
  model: "jev-wallet-risk/v6",
};

/** A signed, production-shaped result for `wallet` (override claims to mirror the request). */
export async function signedResult(
  issuer: Issuer,
  overrides: Partial<RiskCheckResult> & { sub?: string; claims?: Record<string, unknown>; iat?: number } = {},
): Promise<RiskCheckResult> {
  const { sub, claims: extraClaims, iat, ...rest } = overrides;
  const now = iat ?? Math.floor(Date.now() / 1000);
  const score = rest.score ?? 88;
  const tier = rest.tier ?? "low";
  const categories = rest.categories ?? ["intent_risk", "behavioral"];
  const jws = await sign(issuer, {
    iss: ISSUER,
    sub: sub ?? SPENDER,
    score,
    tier,
    iat: now,
    exp: now + 3600,
    jti: "7d0f3a52-1c4b-4e8a-9f6d-2b3c4d5e6f70",
    categories,
    input_hash: "b".repeat(64),
    checks: CHECKS,
    ...extraClaims,
  });
  return {
    checked: true,
    score,
    tier,
    provider: ISSUER,
    categories,
    jws,
    jwks_url: "https://x402check.xyz/.well-known/jwks.json",
    checked_at: new Date(now * 1000).toISOString(),
    expires_at: new Date((now + 3600) * 1000).toISOString(),
    evidence: {
      sanctions: { list: "ofac-sdn", as_of: "2026-09-23", status: "not_listed" },
      onchain: { status: "ok", network: "eip155:8453", is_contract: true, activity: "some", tx_count: 1200, verified: true },
      feeds: [{ source: "scamsniffer-addresses", kind: "address", as_of: "2026-09-22", status: "clear" }],
      model: "jev-wallet-risk/v6",
    },
    ...rest,
  };
}

export type Call = { url: string; init: FetchInitLike };

/** Routes the DID document to `issuer` and API calls to `api`. */
export function router(issuer: Issuer | null, api: (body: unknown, init: FetchInitLike) => Response | Promise<Response>): { fetch: FetchLike; calls: Call[] } {
  const calls: Call[] = [];
  const fetch: FetchLike = async (url, init) => {
    calls.push({ url, init });
    if (url === DID_URL) {
      if (!issuer) return json(404, { error: "not_found" });
      return json(200, didDocument(issuer));
    }
    if (url.endsWith("/v1/risk-check") || url.endsWith("/v1/risk-check/batch")) return api(JSON.parse(init.body ?? "null"), init);
    throw new Error(`unexpected fetch: ${url}`);
  };
  return { fetch, calls };
}

export function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

/** Server + client over the SDK's linked in-memory transports. */
export async function connect(config: ServerConfig): Promise<{ client: Client; close: () => Promise<void> }> {
  const server = createX402CheckServer(pinned(config));
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "x402check-test", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return {
    client,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

type ToolResult = { content: Array<{ type: string; text?: string }>; structuredContent?: Record<string, unknown>; isError?: boolean };

export async function callTool(client: Client, name: string, args: Record<string, unknown> = {}): Promise<ToolResult & { text: string; json: Record<string, unknown> | undefined }> {
  const result = (await client.callTool({ name, arguments: args })) as ToolResult;
  const texts = result.content.filter((c) => c.type === "text").map((c) => c.text ?? "");
  let parsed: Record<string, unknown> | undefined;
  try {
    parsed = texts[1] ? (JSON.parse(texts[1]) as Record<string, unknown>) : undefined;
  } catch {
    parsed = undefined;
  }
  return { ...result, text: texts[0] ?? "", json: parsed };
}
