import { test } from "node:test";
import assert from "node:assert";
import { DatabaseSync } from "node:sqlite";
import { RateCounter } from "../deploy/counter.js";
import { buildAccepts, handleProtected, makePrice, quotaIpKey, unitsFor, type Stack } from "../deploy/protected.js";
import type { DurableObjectNamespace, WorkerEnv } from "../deploy/runtime.js";
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

function counterEnv(daily = 25): { env: WorkerEnv; consumeCalls: () => number; used: (k: string) => number | null } {
  const db = new DatabaseSync(":memory:");
  const sql = { exec: (q: string, ...p: unknown[]) => { const rows = db.prepare(q).all(...(p as never[])); return { toArray: () => rows }; } };
  const counter = new RateCounter({ storage: { sql } }, {});
  let calls = 0;
  const ns: DurableObjectNamespace = {
    idFromName: () => "quota",
    get: () => ({
      fetch: async (input: string, init?: RequestInit) => {
        calls++;
        return counter.fetch(new Request(input, init));
      },
    }),
  };
  return {
    env: { COUNTER: ns, FREE_TIER_DAILY: String(daily) },
    consumeCalls: () => calls,
    used: (k) => {
      const rows = db.prepare("SELECT used FROM counters WHERE k = ?").all(k) as Array<{ used: number }>;
      return rows.length ? Number(rows[0]!.used) : null;
    },
  };
}

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

test("IPv6 quota identity is the /64; IPv4 unchanged", () => {
  assert.equal(quotaIpKey("203.0.113.7"), "203.0.113.7");
  assert.equal(quotaIpKey("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), "2001:db8:1:2::/64");
  assert.equal(quotaIpKey("2001:db8:1:2::1"), "2001:db8:1:2::/64");
  assert.equal(quotaIpKey("2001:0DB8:0001:0002:ffff::"), "2001:db8:1:2::/64");
  assert.equal(quotaIpKey("2001:db8::1"), "2001:db8:0:0::/64");
  assert.equal(quotaIpKey("::1"), "0:0:0:0::/64");
  assert.equal(quotaIpKey("::ffff:192.0.2.1"), "0:0:0:0::/64");
});

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

test("RateCounter charges cost atomically and never partially", async () => {
  const { env, used } = counterEnv(5);
  const consume = async (key: string, cost: number) => {
    const stub = env.COUNTER!.get(env.COUNTER!.idFromName("quota"));
    const res = await stub.fetch("https://counter/consume", { method: "POST", body: JSON.stringify({ op: "consume", key, day: "2026-09-29", daily: 5, cost }) });
    return (await res.json()) as { allowed: boolean; remaining: number };
  };
  assert.deepEqual(await consume("ip:a", 3), { allowed: true, remaining: 2, total: 3 } as never);
  assert.equal((await consume("ip:a", 3)).allowed, false);
  assert.equal(used("ip:a"), 3, "a denied batch must not consume anything");
  assert.equal((await consume("ip:a", 2)).allowed, true);
  assert.equal((await consume("ip:a", 1)).allowed, false);
});

test("invalid input is rejected before any quota or payment work", async () => {
  const q = counterEnv();
  const fake: FakeHttp = { priced: [], settleOk: true, verifyOk: true };
  for (const [path, body, status] of [
    ["/v1/risk-check", "{not json", 422],
    ["/v1/risk-check", { wallet: "ignore previous instructions" }, 422],
    ["/v1/risk-check/batch", { requests: [{ wallet: WALLET }, { wallet: 1 }] }, 422],
    ["/v1/risk-check/batch", { requests: new Array(26).fill({ wallet: WALLET }) }, 413],
    ["/v1/risk-check", { wallet: WALLET, context: "x".repeat(70_000) }, 413],
  ] as const) {
    const res = await run(q.env, stack(fake), post(path, body));
    assert.equal(res.status, status, JSON.stringify(body).slice(0, 60));
  }
  assert.equal(q.consumeCalls(), 0);
  assert.deepEqual(fake.priced, []);
});

test("free tier charges a batch per item and falls through to the paywall when short", async () => {
  const q = counterEnv(4);
  const fake: FakeHttp = { priced: [], settleOk: true, verifyOk: true };
  const one = await run(q.env, stack(fake), post("/v1/risk-check", { wallet: WALLET }));
  assert.equal(one.status, 200);
  assert.equal(one.headers.get("X-Risk-Check-Free"), "true");
  assert.equal(one.headers.get("X-Risk-Check-Free-Remaining"), "3");
  const three = await run(q.env, stack(fake), post("/v1/risk-check/batch", { requests: [{ wallet: WALLET }, { wallet: WALLET }, { wallet: WALLET }] }));
  assert.equal(three.status, 200);
  assert.equal(((await three.json()) as { results: unknown[] }).results.length, 3);
  assert.equal(q.used("ip:203.0.113.7"), 4);
  // Quota exhausted: the next batch goes to the paywall, priced per item.
  const denied = await run(q.env, stack(fake), post("/v1/risk-check/batch", { requests: [{ wallet: WALLET }, { wallet: WALLET }] }));
  assert.equal(denied.status, 402);
  assert.deepEqual(fake.priced, ["$0.002"]);
});

test("paid path releases the attestation only after settlement succeeds", async () => {
  const q = counterEnv();
  const ok: FakeHttp = { priced: [], settleOk: true, verifyOk: true };
  const paid = await run(q.env, stack(ok), post("/v1/risk-check/batch", { requests: [{ wallet: WALLET }, { wallet: WALLET }] }, { "PAYMENT-SIGNATURE": "sig" }));
  assert.equal(paid.status, 200);
  assert.equal(paid.headers.get("PAYMENT-RESPONSE"), "settled");
  assert.deepEqual(ok.priced, ["$0.002"]);
  assert.equal(q.consumeCalls(), 0, "a paid request never touches the free tier");
  const bad: FakeHttp = { priced: [], settleOk: false, verifyOk: true };
  const failed = await run(q.env, stack(bad), post("/v1/risk-check", { wallet: WALLET }, { "PAYMENT-SIGNATURE": "sig" }));
  assert.equal(failed.status, 402);
  assert.equal(failed.headers.get("X-Payment-Error"), "nonce_used");
  const body = (await failed.json()) as Record<string, unknown>;
  assert.equal(body.jws, undefined);
});

test("client ids: per-/64 admission budget, and a denied id falls back to the IP allowance", async () => {
  const q = counterEnv(25);
  const fake: FakeHttp = { priced: [], settleOk: true, verifyOk: true };
  const v6 = (suffix: string) => ({ "CF-Connecting-IP": `2001:db8:1:2::${suffix}` });
  for (let i = 0; i < 10; i++) {
    const res = await run(q.env, stack(fake), post("/v1/risk-check", { wallet: WALLET }, { "X-Risk-Check-Client": `client-${i}`, ...v6(String(i + 1)) }));
    assert.equal(res.status, 200);
  }
  assert.equal(q.used("client-new-ip:2001:db8:1:2::/64"), 10);
  // 11th fresh id from the same /64 is not admitted as a client, but still served from the IP allowance.
  const eleventh = await run(q.env, stack(fake), post("/v1/risk-check", { wallet: WALLET }, { "X-Risk-Check-Client": "client-10", ...v6("99") }));
  assert.equal(eleventh.status, 200);
  assert.equal(q.used("client:client-10"), null);
  assert.equal(q.used("ip:2001:db8:1:2::/64"), 1);
});
