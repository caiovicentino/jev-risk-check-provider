// Coinbase CDP as a facilitator (deploy/cdp.ts): the JWT each call carries, the key formats
// the CDP portal issues, and how routing uses CDP once the owner's API key is configured.
import { test } from "node:test";
import assert from "node:assert";
import { generateKeyPairSync, webcrypto } from "node:crypto";
import { cdpAuthHeaders, CDP_FACILITATOR_URL, importCdpSecret } from "../deploy/cdp.js";
import { facilitatorStatus, mainnetFacilitators, paymentRouting, routedFacilitators, type FacilitatorEntry } from "../deploy/protected.js";
import { HTTPFacilitatorClient } from "@x402/core/server";

const KEY_ID = "0b5c2f3e-1a2b-4c5d-8e9f-001122334455";
const SOL = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");
const parts = (jwt: string) => {
  const [h, c, s] = jwt.split(".") as [string, string, string];
  return { header: JSON.parse(Buffer.from(h, "base64url").toString()), claims: JSON.parse(Buffer.from(c, "base64url").toString()), input: `${h}.${c}`, signature: Buffer.from(s, "base64url") };
};
const bearer = (h: Record<string, string>) => (h.Authorization ?? "").replace(/^Bearer /, "");

/** A CDP-portal style Ed25519 secret (base64 of seed ‖ public key) and its public key. */
async function ed25519Secret(): Promise<{ secret: string; publicKey: webcrypto.CryptoKey }> {
  const kp = (await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as webcrypto.CryptoKeyPair;
  const pkcs8 = new Uint8Array(await webcrypto.subtle.exportKey("pkcs8", kp.privateKey));
  const raw = new Uint8Array(await webcrypto.subtle.exportKey("raw", kp.publicKey));
  return { secret: b64(new Uint8Array([...pkcs8.slice(-32), ...raw])), publicKey: kp.publicKey };
}

test("CDP JWT (Ed25519, the portal's default): one per endpoint, bound to method and path, 120 s, verifiable", async () => {
  const { secret, publicKey } = await ed25519Secret();
  const before = Math.floor(Date.now() / 1000);
  const headers = await cdpAuthHeaders(KEY_ID, secret)();
  const expected = { verify: "POST api.cdp.coinbase.com/platform/v2/x402/verify", settle: "POST api.cdp.coinbase.com/platform/v2/x402/settle", supported: "GET api.cdp.coinbase.com/platform/v2/x402/supported" };
  const nonces = new Set<string>();
  for (const [path, uri] of Object.entries(expected)) {
    const h = headers[path as keyof typeof headers];
    const { header, claims, input, signature } = parts(bearer(h));
    assert.deepEqual({ alg: header.alg, kid: header.kid, typ: header.typ }, { alg: "EdDSA", kid: KEY_ID, typ: "JWT" }, path);
    assert.match(header.nonce, /^[0-9a-f]{32}$/);
    nonces.add(header.nonce);
    assert.deepEqual([claims.sub, claims.iss, claims.uris], [KEY_ID, "cdp", [uri]], path);
    assert.ok(claims.iat >= before && claims.nbf === claims.iat && claims.exp === claims.iat + 120);
    assert.equal(claims.aud, undefined);
    assert.ok(await webcrypto.subtle.verify({ name: "Ed25519" }, publicKey, signature, new TextEncoder().encode(input)), `${path}: signature verifies`);
    assert.match(h["Correlation-Context"] ?? "", /source=x402check/);
  }
  assert.equal(nonces.size, 3, "a fresh nonce per token");
  const again = await cdpAuthHeaders(KEY_ID, secret)();
  assert.notEqual(bearer(again.settle), bearer(headers.settle), "a new token for every call");
});

test("CDP JWT (ES256): PKCS#8 PEM, legacy SEC1 PEM, and a PEM pasted with literal \\n escapes", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = publicKey.export({ type: "spki", format: "der" });
  const verifier = await webcrypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const sec1 = privateKey.export({ type: "sec1", format: "pem" }).toString();
  for (const [label, secret] of [["pkcs8", pkcs8], ["sec1", sec1], ["escaped", sec1.trim().replace(/\n/g, "\\n")]] as const) {
    const { header, claims, input, signature } = parts(bearer((await cdpAuthHeaders(KEY_ID, secret)()).settle));
    assert.equal(header.alg, "ES256", label);
    assert.deepEqual(claims.uris, ["POST api.cdp.coinbase.com/platform/v2/x402/settle"]);
    assert.equal(signature.length, 64, `${label}: JWS r‖s`);
    assert.ok(await webcrypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, verifier, signature, new TextEncoder().encode(input)), `${label}: signature verifies`);
  }
});

test("a malformed CDP secret fails without echoing it", async () => {
  for (const bad of ["not-a-key", "", b64(new Uint8Array(32))]) {
    await assert.rejects(importCdpSecret(bad), (err: Error) => /base64 Ed25519 key \(64 bytes\) or a P-256 key in PEM/.test(err.message) && (bad === "" || !err.message.includes(bad)));
  }
});

test("the x402 facilitator client sends CDP's JWT to the endpoint it signs for", async () => {
  const { secret } = await ed25519Secret();
  const seen: Array<{ url: string; auth: string }> = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    seen.push({ url: String(input), auth: headers.get("authorization") ?? "" });
    return new Response(JSON.stringify({ kinds: [{ x402Version: 2, scheme: "exact", network: "eip155:8453" }], extensions: [], signers: {} }), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  try {
    const client = new HTTPFacilitatorClient({ url: CDP_FACILITATOR_URL, createAuthHeaders: cdpAuthHeaders(KEY_ID, secret) });
    const supported = await client.getSupported();
    assert.equal(supported.kinds[0]?.network, "eip155:8453");
  } finally {
    globalThis.fetch = original;
  }
  assert.equal(seen[0]?.url, "https://api.cdp.coinbase.com/platform/v2/x402/supported");
  assert.deepEqual(parts(seen[0]?.auth.replace(/^Bearer /, "") ?? "").claims.uris, ["GET api.cdp.coinbase.com/platform/v2/x402/supported"]);
});

test("CDP is configured only with both parts of the key; routing then prefers it where it is cheapest", async () => {
  assert.deepEqual(mainnetFacilitators({}).map((f) => f.name), ["payai", "dexter"]);
  assert.deepEqual(mainnetFacilitators({ CDP_API_KEY_ID: KEY_ID }).map((f) => f.name), ["payai", "dexter"]);
  const { secret } = await ed25519Secret();
  const withCdp = mainnetFacilitators({ CDP_API_KEY_ID: KEY_ID, CDP_API_KEY_SECRET: secret });
  assert.deepEqual(withCdp.map((f) => [f.name, f.flatFee]), [["payai", undefined], ["dexter", 0], ["cdp", 0.001]]);

  const kind = (network: string, extra: Record<string, unknown> = {}) => ({ x402Version: 2, scheme: "exact", network, extra });
  const client = (kinds: ReturnType<typeof kind>[] | Error) => ({
    verify: async () => ({ isValid: true }),
    settle: async () => ({ success: true }),
    getSupported: async () => {
      if (kinds instanceof Error) throw kinds;
      return { kinds };
    },
  }) as never;
  const payai = { name: "payai", client: client([kind("eip155:8453"), kind("eip155:137"), kind("eip155:42161"), kind("eip155:43114"), kind("eip155:1329"), kind(SOL)]), fees: async () => new Map([["eip155:8453", 0.00231], ["eip155:137", 0.00489], ["eip155:42161", 0.00663], ["eip155:43114", 0.0001], ["eip155:1329", 0.00077], [SOL, 0.00162]]) };
  const dexter = { name: "dexter", client: client([kind("eip155:8453", { assetTransferMethod: "permit2" }), kind("eip155:143", { assetTransferMethod: "permit2" }), kind(SOL, { paymentFloorAvailable: true, minPaymentAmountUsd: 0.0013 })]), flatFee: 0 };
  // CDP's mainnets (docs.cdp.coinbase.com/x402): Base, Polygon, Arbitrum, World and Solana.
  const cdpKinds = [kind("eip155:8453"), kind("eip155:137"), kind("eip155:42161"), kind("eip155:480"), kind(SOL)];
  const entries = (cdp: FacilitatorEntry["client"]): FacilitatorEntry[] => [payai, dexter, { name: "cdp", client: cdp, flatFee: 0.001 }];

  const routes = Object.fromEntries((await paymentRouting({}, entries(client(cdpKinds)))).map((r) => [r.network, r]));
  // Base: $0.0035 − $0.001 settlement − ~$0.00007 model = $0.00243 (69%), was 32% through PayAI.
  assert.deepEqual([routes["eip155:8453"]?.facilitator, routes["eip155:8453"]?.transfer_method, routes["eip155:8453"]?.fee_usd, routes["eip155:8453"]?.margin_usd, routes["eip155:8453"]?.margin_pct], ["cdp", "eip3009", 0.001, 0.00243, 69.4]);
  assert.deepEqual([routes["eip155:137"]?.facilitator, routes["eip155:42161"]?.facilitator], ["cdp", "cdp"]);
  // Where another route costs less, it keeps the network: Avalanche and Sei (PayAI), Solana (Dexter, free).
  assert.deepEqual([routes["eip155:43114"]?.facilitator, routes["eip155:1329"]?.facilitator, routes[SOL]?.facilitator, routes["eip155:143"]?.facilitator], ["payai", "payai", "dexter", "dexter"]);

  // A key CDP rejects: CDP drops out of routing, Base goes back to PayAI, nothing fails.
  const rejected = entries(client(new Error("Facilitator getSupported failed (401): Unauthorized")));
  const fallback = Object.fromEntries((await paymentRouting({}, rejected)).map((r) => [r.network, r]));
  assert.equal(fallback["eip155:8453"]?.facilitator, "payai");
  const status = await facilitatorStatus({}, rejected);
  assert.deepEqual(status.map((f) => [f.name, f.ok, f.error ?? null]), [["payai", true, null], ["dexter", true, null], ["cdp", false, "HTTP 401"]]);
  const healthy = await facilitatorStatus({}, entries(client(cdpKinds)));
  assert.deepEqual(healthy[2]?.networks, ["eip155:8453", "eip155:137", "eip155:42161", SOL], "World is not a network x402check offers");
  // Published settlement signers pass through (public addresses), so a settlement can be attributed on-chain.
  const signer = "0x68A96F41ff1e9F2E7b591A931A4AD224e7C07863";
  const withSigners = { verify: async () => ({ isValid: true }), settle: async () => ({ success: true }), getSupported: async () => ({ kinds: cdpKinds, signers: { "eip155:*": [signer, signer, "not an address"] } }) } as never;
  const listed = await facilitatorStatus({}, [{ name: "cdp", client: withSigners, flatFee: 0.001 }]);
  assert.deepEqual(listed[0]?.signers, [signer]);

  // The resource server's list: routed facilitators first, then CDP, PayAI (EVM) and Dexter as the default order.
  const list = routedFacilitators(entries(client(cdpKinds)), await paymentRouting({}, entries(client(cdpKinds))));
  const firstFor = async (network: string) => {
    for (const [i, f] of list.entries()) if ((await f.getSupported()).kinds.some((k) => k.network === network)) return i;
    return -1;
  };
  assert.deepEqual([await firstFor("eip155:8453"), await firstFor("eip155:43114"), await firstFor(SOL)], [2, 0, 1], "CDP's, PayAI's and Dexter's scoped clients");
  const unrouted = routedFacilitators(entries(client(cdpKinds)), null);
  assert.equal(unrouted.length, 3, "no routing table: CDP (EVM), PayAI (EVM), Dexter");
});
