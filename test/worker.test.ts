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
      return { type: "payment-verified", paymentPayload: {}, paymentRequirements: {} };
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
  assert.ok(nets({ ENABLE_TESTNETS: "true" }).includes("eip155:84532"));
});

test("invalid input is rejected before any payment work", async () => {
  const fake: FakeHttp = { priced: [], settleOk: true, verifyOk: true };
  for (const [path, body, status] of [
    ["/v1/risk-check", "{not json", 422],
    ["/v1/risk-check", { wallet: "ignore previous instructions" }, 422],
    ["/v1/risk-check/batch", { requests: [{ wallet: WALLET }, { wallet: 1 }] }, 422],
    ["/v1/risk-check/batch", { requests: new Array(26).fill({ wallet: WALLET }) }, 413],
    ["/v1/risk-check", { wallet: WALLET, context: "x".repeat(70_000) }, 413],
  ] as const) {
    const res = await run({}, stack(fake), post(path, body));
    assert.equal(res.status, status, JSON.stringify(body).slice(0, 60));
  }
  assert.deepEqual(fake.priced, []);
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
  const paid = await run({}, stack(ok), post("/v1/risk-check/batch", { requests: [{ wallet: WALLET }, { wallet: WALLET }] }, { "PAYMENT-SIGNATURE": "sig" }));
  assert.equal(paid.status, 200);
  assert.equal(paid.headers.get("PAYMENT-RESPONSE"), "settled");
  assert.deepEqual(ok.priced, ["$0.002"]);
  const bad: FakeHttp = { priced: [], settleOk: false, verifyOk: true };
  const failed = await run({}, stack(bad), post("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": "sig" }));
  assert.equal(failed.status, 402);
  assert.equal(failed.headers.get("X-Payment-Error"), "nonce_used");
  const body = (await failed.json()) as Record<string, unknown>;
  assert.equal(body.jws, undefined);
});

test("payment routing: EVM networks settle through PayAI (below Dexter's gas floors), Solana and Monad through Dexter", async () => {
  const { scopedFacilitator, paymentRouting } = await import("../deploy/protected.js");
  const kind = (network: string, floor?: number) => ({ x402Version: 2, scheme: "exact", network, ...(floor !== undefined ? { extra: { paymentFloorAvailable: true, minPaymentAmountUsd: floor } } : {}) });
  const client = (kinds: ReturnType<typeof kind>[]) => ({ verify: async () => ({ isValid: true }), settle: async () => ({ success: true }), getSupported: async () => ({ kinds }) }) as never;
  const payai = client([kind("eip155:8453"), kind("eip155:137"), kind("eip155:42161"), kind("eip155:43114"), kind("eip155:1329"), kind("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")]);
  const dexter = client([kind("eip155:8453", 0.0015), kind("eip155:137", 0.0031), kind("eip155:143", 0.0003), kind("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", 0.0013)]);
  const routes = await paymentRouting({}, [
    { name: "payai", client: scopedFacilitator(payai, (n) => n.startsWith("eip155:")) },
    { name: "dexter", client: dexter },
  ]);
  const by = Object.fromEntries(routes.map((r) => [r.network, r]));
  assert.equal(by["eip155:8453"]?.facilitator, "payai");
  assert.equal(by["eip155:1329"]?.facilitator, "payai");
  assert.equal(by["eip155:143"]?.facilitator, "dexter");
  assert.equal(by["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"]?.facilitator, "dexter", "PayAI is scoped to EVM");
  assert.equal(by["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"]?.below_floor, false, "$0.002 clears Dexter's Solana floor");
  assert.ok(routes.every((r) => !r.below_floor));
  // The failure this routing fixes: Dexter alone settles Base below its gas-cost floor.
  const dexterOnly = await paymentRouting({}, [{ name: "dexter", client: dexter }]);
  assert.equal(dexterOnly.find((r) => r.network === "eip155:8453")?.below_floor, true);
});
