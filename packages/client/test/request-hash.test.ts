import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { canonicalJson, REQUEST_HASH_FIELDS, requestHash } from "../src/index.js";

// Computed with the provider's own requestHash (src/jws.ts) over the body as the server receives it.
const VECTORS = [
  { name: "minimal", request: { wallet: "0x7a3e8f0c2b1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f" }, request_hash: "2de247283101a6879829e0b7bdcee183bf72a2f57c22cc0dc0415612a01d45a1" },
  {
    name: "full",
    request: {
      wallet: "0x7A3E8F0C2B1D4E5F6A7B8C9D0E1F2A3B4C5D6E7F",
      chain: "base",
      domain: "https://App.Uniswap.org/swap?x=1",
      context: 'Permit2: unlimited USDC allowance — ünïcødé ✓ "quoted" \\ back\nslash',
      aud: "https://merchant.example/api",
      screening: { sanctions: "clean" },
      authorization: { pre_authorized: true, source: "policy-7" },
      payment: { resource: "https://merchant.example/report", pay_to: "0x7a3e8f0c2b1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f", amount: "1000000", network: "base", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" },
      interaction: { unlimited: true, type: "permit_signature" },
      transaction: { from: "0x1111111111111111111111111111111111111111", to: "0x2222222222222222222222222222222222222222", value: "0x0", data: "0x095ea7b3" },
    },
    request_hash: "434bfca92c85be09889cb94925bf3fc35d396a987e634797fd0619c448cd8775",
  },
  {
    name: "solana, CAIP-10, astral plane",
    request: { wallet: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM", context: "pay 😀 for the report" },
    request_hash: "4c5fe9fc0e755b6124ea95bc6a9cfb7441ec9fc58e8837e6a033ce5c8eba1f83",
  },
] as const;

test("request_hash matches vectors computed by the provider's implementation", async () => {
  for (const v of VECTORS) assert.equal(await requestHash(v.request), v.request_hash, v.name);
});

test("hashes the request as it travels: key order, undefined members, toJSON and extra fields do not matter", async () => {
  const full = VECTORS[1].request;
  const reordered = Object.fromEntries(Object.entries(full).reverse());
  assert.equal(await requestHash(reordered), VECTORS[1].request_hash, "key order");
  assert.equal(await requestHash({ ...VECTORS[0].request, aud: undefined, chain: undefined, notHashed: "ignored" }), VECTORS[0].request_hash, "undefined members dropped, non-request fields ignored");
  const withDate = { wallet: VECTORS[0].request.wallet, context: new Date("2026-09-29T12:00:00.000Z") };
  assert.equal(await requestHash(withDate), await requestHash({ wallet: VECTORS[0].request.wallet, context: "2026-09-29T12:00:00.000Z" }), "toJSON as JSON.stringify sends it");
});

test("any change to any field changes the hash (context and interaction.unlimited included)", async () => {
  const base = VECTORS[1].request;
  const hashes = new Set<string>([await requestHash(base)]);
  const variants: object[] = [
    { ...base, context: `${base.context} ` },
    { ...base, interaction: { type: "permit_signature" } },
    { ...base, interaction: { type: "permit_signature", unlimited: false } },
    { ...base, domain: "https://app.uniswap.org/swap?x=1" },
    { ...base, payment: { ...base.payment, amount: "1000001" } },
    { ...base, transaction: { ...base.transaction, data: "0x" } },
    { ...base, screening: undefined },
    { ...base, wallet: base.wallet.toLowerCase() },
  ];
  for (const v of variants) hashes.add(await requestHash(v));
  assert.equal(hashes.size, variants.length + 1);
  assert.deepEqual([...REQUEST_HASH_FIELDS], ["wallet", "chain", "domain", "context", "aud", "screening", "authorization", "payment", "interaction", "transaction"]);
});

test("canonicalJson follows RFC 8785 (the provider's sample)", () => {
  const sample = JSON.parse('{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}');
  assert.equal(canonicalJson(sample), '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}');
  assert.equal(canonicalJson({ "é": 1, e: 2, "😀": 3 }), '{"e":2,"é":1,"😀":3}');
  assert.throws(() => canonicalJson({ a: Number.NaN }));
  assert.throws(() => canonicalJson({ a: 10n }));
});

test("requestHash rejects what is not a JSON object", async () => {
  await assert.rejects(requestHash([] as unknown as object));
  await assert.rejects(requestHash(null as unknown as object));
});

// Live interop with the provider source when this package sits in its repository.
const PROVIDER_JWS = fileURLToPath(new URL("../../../src/jws.ts", import.meta.url));
test("live interop: identical to the provider's requestHash on random requests", { skip: !existsSync(PROVIDER_JWS) && "provider source not present" }, async () => {
  const provider = (await import(PROVIDER_JWS)) as { requestHash: (raw: Record<string, unknown>) => string };
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(Math.random() * xs.length)] as T;
  for (let i = 0; i < 200; i++) {
    const request: Record<string, unknown> = { wallet: pick(["0x7a3e8f0c2b1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f", "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"]) };
    if (Math.random() < 0.5) request.chain = pick(["base", "eip155:8453", "solana"]);
    if (Math.random() < 0.5) request.context = pick(["", "plain", "ünï 😀   \"q\" \\ \n\t", "x".repeat(300)]);
    if (Math.random() < 0.5) request.interaction = { type: pick(["token_approval", "permit_signature"]), ...(Math.random() < 0.5 ? { unlimited: Math.random() < 0.5 } : {}) };
    if (Math.random() < 0.5) request.payment = { amount: String(Math.floor(Math.random() * 1e12)), ...(Math.random() < 0.5 ? { network: "base" } : {}) };
    if (Math.random() < 0.3) request.aud = undefined;
    const received = JSON.parse(JSON.stringify(request)) as Record<string, unknown>;
    assert.equal(await requestHash(request), provider.requestHash(received), JSON.stringify(request));
  }
});
