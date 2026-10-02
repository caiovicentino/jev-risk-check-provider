import { test } from "node:test";
import assert from "node:assert";
import { buildAccepts, handleProtected, makePrice, unitsFor, type Stack } from "../deploy/protected.js";
import type { WorkerEnv } from "../deploy/runtime.js";
import { createHandler } from "../src/handler.js";
import { Provider } from "../src/provider.js";
import { generateKeyPair } from "../src/jws.js";
import type { JevLike } from "../src/jev.js";
import type { Answer } from "../src/types.js";
import type { HTTPRequestContext } from "@x402/core/http";

/** The payment the mock "verifies": the header's own payload (a payer and a nonce), as a facilitator would read it. */
function payloadOf(ctx: { adapter?: { getHeader(name: string): string | undefined }; paymentHeader?: string | undefined }): unknown {
  const header = ctx.paymentHeader ?? ctx.adapter?.getHeader("PAYMENT-SIGNATURE");
  try {
    const decoded = JSON.parse(atob(header ?? "")) as { payload?: { authorization?: { from?: string } } };
    if (decoded.payload?.authorization?.from) return decoded;
  } catch {
    // fall through to a default payer
  }
  return { payload: { authorization: { from: "0x1111111111111111111111111111111111111111", nonce: "0x01" } } };
}

/** A PAYMENT-SIGNATURE shaped like x402 v2 (the stack only accepts v2 payments). */
const PAID_V2 = btoa(JSON.stringify({ x402Version: 2, accepted: { scheme: "exact", network: "eip155:8453" }, payload: { signature: "0x01", authorization: { from: "0x1111111111111111111111111111111111111111", nonce: "0x01" } } }));


const WALLET = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const ANSWERS: Record<string, Answer> = {
  known_threat: { type: "noul", noul: 0.02 },
  sanctions_concern: { type: "noul", noul: 0.02 },
  laundering_pattern: { type: "noul", noul: 0.02 },
  risky_domain: { type: "noul", noul: 0.02 },
  guard_bypass_attempt: { type: "noul", noul: 0.02 },
  risk_class: { type: "choice", choice: "benign", probabilities: { benign: 0.95 }, confidence: 0.9 },
  trust: { type: "score", score: 3.8, legend: {}, probabilities: { "4": 0.8 }, confidence: 0.85 },
};

type FakeHttp = { priced: string[]; settleOk: boolean; verifyOk: boolean };
function stack(fake: FakeHttp): Stack {
  const jev: JevLike = { systemOne: async () => ({ answers: ANSWERS, usage: { inputTokens: 1, outputTokens: 0 } }) };
  const deps = { provider: new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("jev-attest-v1"), jev }) };
  const price = makePrice(0.001);
  const http = {
    processHTTPRequest: async (ctx: HTTPRequestContext) => {
      fake.priced.push(price(ctx));
      if (!fake.verifyOk || !ctx.paymentHeader) {
        return { type: "payment-error", response: { status: 402, headers: {}, body: { error: "payment_required" } } };
      }
      return { type: "payment-verified", paymentPayload: payloadOf(ctx), paymentRequirements: {} };
    },
    processSettlement: async () => (fake.settleOk ? { success: true, headers: { "PAYMENT-RESPONSE": "settled" } } : { success: false, errorReason: "nonce_used", headers: {} }),
  };
  return { deps, http } as unknown as Stack;
}

function post(path: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`https://x402check.xyz${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.7", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function run(env: WorkerEnv, s: Stack, req: Request): Promise<Response> {
  return handleProtected(req, env, s, (r) => createHandler(s.deps)(r));
}

test("pricing is per evaluation: a batch of n costs n units", () => {
  assert.equal(unitsFor("/v1/risk-check", { requests: [1, 2, 3] }), 1);
  assert.equal(unitsFor("/v1/risk-check/batch", { requests: [1, 2, 3] }), 3);
  assert.equal(unitsFor("/v1/risk-check/batch", { requests: new Array(40).fill(0) }), 25);
  const ctx = (path: string, body: unknown) => ({ path, adapter: { getBody: () => body } }) as unknown as HTTPRequestContext;
  assert.equal(makePrice(0.001)(ctx("/v1/risk-check/batch", { requests: new Array(25).fill(0) })), "$0.025");
  assert.equal(makePrice(0.002)(ctx("/v1/risk-check/batch", { requests: [0, 0] })), "$0.004");
  assert.equal(makePrice(0.001)(ctx("/v1/risk-check", { wallet: WALLET })), "$0.001");
});

test("testnet payment options exist only when explicitly enabled", () => {
  const nets = (env: WorkerEnv) => buildAccepts(env).map((a) => String(a.network));
  const prod = nets({});
  assert.ok(prod.includes("eip155:8453") && prod.includes("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"));
  for (const testnet of ["eip155:84532", "eip155:421614", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"]) assert.ok(!prod.includes(testnet), testnet);
  assert.ok(nets({ ENABLE_TESTNETS: "true", PROVIDER_HOST: "localhost:8799" }).includes("eip155:84532"));
  assert.ok(!nets({ ENABLE_TESTNETS: "true" }).includes("eip155:84532"), "never on the production host: testnet USDC is free");
  // Each network carries its own price: Base first.
  const ctx = { path: "/v1/risk-check", adapter: { getBody: () => ({ wallet: WALLET }) } } as unknown as HTTPRequestContext;
  const priced = Object.fromEntries(buildAccepts({}).map((a) => [String(a.network), (a.price as (c: HTTPRequestContext) => string)(ctx)]));
  assert.equal(buildAccepts({})[0]?.network, "eip155:8453");
  assert.deepEqual(priced, { "eip155:8453": "$0.0035", "eip155:137": "$0.007", "eip155:42161": "$0.009", "eip155:43114": "$0.001", "eip155:143": "$0.001", "eip155:1329": "$0.002", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": "$0.002" });
});

test("invalid input: with a payment, refused before any payment work; unpaid, the challenge says why", async () => {
  const cases = [
    ["/v1/risk-check", "{not json", 422, "body"],
    ["/v1/risk-check", { wallet: "ignore previous instructions" }, 422, "wallet"],
    ["/v1/risk-check/batch", { requests: [{ wallet: WALLET }, { wallet: 1 }] }, 422, "wallet"],
    ["/v1/risk-check/batch", { requests: new Array(26).fill({ wallet: WALLET }) }, 413, null],
  ] as const;
  const paid: FakeHttp = { priced: [], settleOk: true, verifyOk: true };
  for (const [path, body, status] of cases) {
    const res = await run({}, stack(paid), post(path, body, { "PAYMENT-SIGNATURE": PAID_V2 }));
    assert.equal(res.status, status, JSON.stringify(body).slice(0, 60));
  }
  assert.deepEqual(paid.priced, [], "nothing priced, verified or settled");
  // Unpaid: the one-item challenge (monitors and discovery see a payable endpoint), never an evaluation.
  const unpaid: FakeHttp = { priced: [], settleOk: true, verifyOk: true };
  for (const [path, body, status, field] of cases) {
    const res = await run({}, stack(unpaid), post(path, body));
    assert.equal(res.status, 402, JSON.stringify(body).slice(0, 60));
    const error = ((await res.json()) as { request_error?: { status?: number; field?: string } }).request_error;
    assert.equal(error?.status, status);
    if (field) assert.equal(error?.field, field);
  }
  assert.deepEqual(unpaid.priced, cases.map(() => "$0.001"), "priced as one item");
  const huge = await run({}, stack(unpaid), post("/v1/risk-check", { wallet: WALLET, context: "x".repeat(70_000) }));
  assert.equal(huge.status, 413, "an oversized body is never buffered, paid or not");
});

test("no free evaluations: a valid unpaid request gets the 402 challenge, priced per item", async () => {
  const fake: FakeHttp = { priced: [], settleOk: true, verifyOk: true };
  const one = await run({}, stack(fake), post("/v1/risk-check", { wallet: WALLET }));
  assert.equal(one.status, 402);
  const body = (await one.json()) as Record<string, unknown>;
  assert.equal(body.jws, undefined, "no attestation without payment");
  const batch = await run({}, stack(fake), post("/v1/risk-check/batch", { requests: [{ wallet: WALLET }, { wallet: WALLET }, { wallet: WALLET }] }));
  assert.equal(batch.status, 402);
  // Headers that used to unlock a free allowance do nothing.
  const legacy = await run({}, stack(fake), post("/v1/risk-check", { wallet: WALLET }, { "X-Risk-Check-Client": "some-install", "X-PAYMENT": "v1-payload" }));
  assert.equal(legacy.status, 402);
  assert.equal(legacy.headers.get("X-Risk-Check-Free"), null);
  assert.deepEqual(fake.priced, ["$0.001", "$0.003", "$0.001"]);
});

test("paid path releases the attestation only after settlement succeeds", async () => {
  const ok: FakeHttp = { priced: [], settleOk: true, verifyOk: true };
  const paid = await run({}, stack(ok), post("/v1/risk-check/batch", { requests: [{ wallet: WALLET }, { wallet: WALLET }] }, { "PAYMENT-SIGNATURE": PAID_V2 }));
  assert.equal(paid.status, 200);
  assert.equal(paid.headers.get("PAYMENT-RESPONSE"), "settled");
  assert.deepEqual(ok.priced, ["$0.002"]);
  const bad: FakeHttp = { priced: [], settleOk: false, verifyOk: true };
  const failed = await run({}, stack(bad), post("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": PAID_V2 }));
  assert.equal(failed.status, 402);
  assert.equal(failed.headers.get("X-Payment-Error"), "nonce_used");
  const body = (await failed.json()) as Record<string, unknown>;
  assert.equal(body.jws, undefined);
});

test("payment routing: a facilitator every payer can pay through, then the cheapest to us; margins per network", async () => {
  const { paymentRouting, routedFacilitators } = await import("../deploy/protected.js");
  const kind = (network: string, extra: Record<string, unknown> = {}) => ({ x402Version: 2, scheme: "exact", network, extra });
  const floor = (usd: number, method?: string) => ({ paymentFloorAvailable: true, minPaymentAmountUsd: usd, ...(method ? { assetTransferMethod: method } : {}) });
  const client = (kinds: ReturnType<typeof kind>[]) => ({ verify: async () => ({ isValid: true }), settle: async () => ({ success: true }), getSupported: async () => ({ kinds }) }) as never;
  const SOL = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
  // PayAI: EIP-3009 on EVM (gasless for any payer), fee = gas + 30% (live table of 2026-09-30).
  const payai = client([kind("eip155:8453"), kind("eip155:137"), kind("eip155:42161"), kind("eip155:43114"), kind("eip155:1329"), kind(SOL)]);
  const payaiFees = new Map([["eip155:8453", 0.00231], ["eip155:137", 0.00489], ["eip155:42161", 0.00663], ["eip155:43114", 0.0001], ["eip155:1329", 0.00077], [SOL, 0.00162]]);
  // Dexter: no fee, but Permit2 on every EVM network and a floor.
  const dexterKinds = (solFloor: number) => [kind("eip155:8453", floor(0.0015, "permit2")), kind("eip155:137", floor(0.0036, "permit2")), kind("eip155:42161", floor(0.0061, "permit2")), kind("eip155:43114", floor(0.004, "permit2")), kind("eip155:143", floor(0.0003, "permit2")), kind(SOL, floor(solFloor))];
  const entries = (solFloor = 0.0013, fees: (() => Promise<Map<string, number>>) | undefined = async () => payaiFees) => [
    { name: "payai", client: payai, fees },
    { name: "dexter", client: client(dexterKinds(solFloor)), flatFee: 0 },
  ];
  const by = async (e: ReturnType<typeof entries>) => Object.fromEntries((await paymentRouting({}, e)).map((r) => [r.network, r]));

  const routes = await by(entries());
  // Base: Dexter would be free, but through Permit2: most payers could not pay. PayAI, at a margin.
  assert.deepEqual([routes["eip155:8453"]?.facilitator, routes["eip155:8453"]?.transfer_method, routes["eip155:8453"]?.fee_usd, routes["eip155:8453"]?.margin_pct], ["payai", "eip3009", 0.00231, 32]);
  for (const n of ["eip155:137", "eip155:42161", "eip155:43114", "eip155:1329"]) assert.equal(routes[n]?.facilitator, "payai", n);
  assert.ok(Object.values(routes).every((r) => (r.margin_usd ?? 0) > 0), "every route clears its settlement cost");
  // Monad: Dexter is the only facilitator (Permit2 as a last resort).
  assert.deepEqual([routes["eip155:143"]?.facilitator, routes["eip155:143"]?.transfer_method], ["dexter", "permit2"]);
  // Solana: both are payable by anyone; Dexter costs us nothing.
  assert.deepEqual([routes[SOL]?.facilitator, routes[SOL]?.fee_usd, routes[SOL]?.margin_pct, routes[SOL]?.below_floor], ["dexter", 0, 96.5, false]);

  // Dexter's floor rises above our Solana price: the route moves to PayAI instead of failing.
  const raised = await by(entries(0.0025));
  assert.deepEqual([raised[SOL]?.facilitator, raised[SOL]?.below_floor], ["payai", false]);
  // PayAI's fee table unavailable: the route stays payable, the margin is unknown, never guessed.
  const blind = await by(entries(0.0013, async () => Promise.reject(new Error("down"))));
  assert.deepEqual([blind["eip155:8453"]?.facilitator, blind["eip155:8453"]?.fee_usd, blind["eip155:8453"]?.margin_usd], ["payai", null, null]);

  // The resource server sees each facilitator scoped to its routed networks, first.
  const list = routedFacilitators(entries() as never, await paymentRouting({}, entries()));
  const firstFor = async (network: string) => {
    for (const [i, f] of list.entries()) if ((await f.getSupported()).kinds.some((k) => k.network === network)) return i;
    return -1;
  };
  assert.equal(await firstFor("eip155:8453"), 0, "PayAI's scoped client comes first for Base");
  assert.equal(await firstFor(SOL), 1, "Dexter's scoped client comes first for Solana");
});

test("differentiated pricing: $0.005 for an evaluation that simulates a transaction, per item in a batch", async () => {
  const { priceMicro, simulates } = await import("../deploy/protected.js");
  const USER = "0x1111111111111111111111111111111111111111";
  const tx = { from: USER, to: USER, value: "1" };
  const ctx = (path: string, body: unknown) => ({ path, adapter: { getBody: () => body } }) as unknown as HTTPRequestContext;
  // Simulated only where a simulation endpoint exists (not Avalanche) and when enabled.
  assert.equal(simulates({ wallet: USER, chain: "base", transaction: tx }), true);
  assert.equal(simulates({ wallet: `eip155:42161:${USER}`, transaction: tx }), true, "chain from a CAIP-10 wallet");
  assert.equal(simulates({ wallet: USER, chain: "eip155:43114", transaction: tx }), false, "no simulation on Avalanche → basic price");
  assert.equal(simulates({ wallet: USER, chain: "base" }), false);
  assert.equal(makePrice(0.001)(ctx("/v1/risk-check", { wallet: USER, chain: "base", transaction: tx })), "$0.005");
  assert.equal(makePrice(0.002)(ctx("/v1/risk-check", { wallet: USER, chain: "base", transaction: tx })), "$0.005", "same on Solana");
  assert.equal(makePrice(0.001, false)(ctx("/v1/risk-check", { wallet: USER, chain: "base", transaction: tx })), "$0.001", "simulation off → never charged");
  const mixed = { requests: [{ wallet: USER, chain: "base", transaction: tx }, { wallet: USER }, { wallet: USER, chain: "polygon" }] };
  assert.equal(makePrice(0.001)(ctx("/v1/risk-check/batch", mixed)), "$0.007");
  assert.equal(makePrice(0.002)(ctx("/v1/risk-check/batch", mixed)), "$0.009");
  assert.equal(priceMicro("/v1/risk-check/batch", { requests: new Array(25).fill({ wallet: USER, chain: "base", transaction: tx }) }, 1000), 125_000);
  // Base's price ($0.0035) needs sub-millidollar precision; a simulated item never costs less than its network's price.
  assert.equal(makePrice(0.0035)(ctx("/v1/risk-check", { wallet: USER })), "$0.0035");
  assert.equal(makePrice(0.0035)(ctx("/v1/risk-check/batch", mixed)), "$0.012");
  assert.equal(makePrice(0.009)(ctx("/v1/risk-check", { wallet: USER, chain: "base", transaction: tx })), "$0.009");
});
