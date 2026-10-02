// Prepaid credits (deploy/credits.ts): a balance bought with one x402 payment, debited
// atomically per check, refunded when no verdict is produced.
import { test } from "node:test";
import assert from "node:assert";
import { CreditLedger, creditCostMicro, creditToken, handleCredits, newCreditToken, packMicro } from "../deploy/credits.js";
import { handleProtected, type Stack } from "../deploy/protected.js";
import type { DurableObjectNamespace, DurableObjectState, WorkerEnv } from "../deploy/runtime.js";
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
const USER = "0x1111111111111111111111111111111111111111";
const ANSWERS: Record<string, Answer> = {
  known_threat: { type: "noul", noul: 0.02 },
  sanctions_concern: { type: "noul", noul: 0.02 },
  laundering_pattern: { type: "noul", noul: 0.02 },
  risky_domain: { type: "noul", noul: 0.02 },
  guard_bypass_attempt: { type: "noul", noul: 0.02 },
  risk_class: { type: "choice", choice: "benign", probabilities: { benign: 0.95 }, confidence: 0.9 },
  trust: { type: "score", score: 3.8, legend: {}, probabilities: { "4": 0.8 }, confidence: 0.85 },
};

/** In-memory Durable Object namespace running the real ledger class. */
function memoryLedgers(): DurableObjectNamespace & { objects: Map<string, CreditLedger> } {
  const objects = new Map<string, CreditLedger>();
  return {
    objects,
    idFromName: (name: string) => ({ toString: () => name }),
    get: (id) => {
      const name = id.toString();
      let obj = objects.get(name);
      if (!obj) {
        const data = new Map<string, unknown>();
        const state: DurableObjectState = {
          storage: {
            get: async <T>(key: string) => data.get(key) as T | undefined,
            put: (async (a: string | Record<string, unknown>, b?: unknown) => {
              if (typeof a === "string") data.set(a, b);
              else for (const [k, v] of Object.entries(a)) data.set(k, v);
            }) as DurableObjectState["storage"]["put"],
            delete: async (key: string) => data.delete(key),
            deleteAll: async () => data.clear(),
            setAlarm: async () => undefined,
          },
        };
        obj = new CreditLedger(state);
        objects.set(name, obj);
      }
      return { fetch: (input: string | Request, init?: RequestInit) => (obj as CreditLedger).fetch(new Request(input, init)) };
    },
  };
}

type Fake = { priced: string[]; settleOk: boolean; tx: string };
function stack(fake: Fake, jev: JevLike | null = { systemOne: async () => ({ answers: ANSWERS, usage: { inputTokens: 1, outputTokens: 0 } }) }): Stack {
  const deps = { provider: new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("jev-attest-v1"), jev }) };
  const http = {
    processHTTPRequest: async (ctx: HTTPRequestContext) => {
      fake.priced.push(`${ctx.path} ${JSON.stringify(ctx.adapter.getBody?.())}`);
      if (!ctx.paymentHeader) return { type: "payment-error", response: { status: 402, headers: {}, body: { error: "payment_required" } } };
      return { type: "payment-verified", paymentPayload: payloadOf(ctx), paymentRequirements: {} };
    },
    processSettlement: async () =>
      fake.settleOk
        ? { success: true, headers: { "PAYMENT-RESPONSE": btoa(JSON.stringify({ success: true, transaction: fake.tx, network: "eip155:8453" })) } }
        : { success: false, errorReason: "nonce_used", headers: {} },
  };
  return { deps, http } as unknown as Stack;
}

const req = (method: string, path: string, body?: unknown, headers: Record<string, string> = {}) =>
  new Request(`https://x402check.xyz${path}`, { method, headers: { "Content-Type": "application/json", ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
const evaluate = (env: WorkerEnv, s: Stack, path: string, body: unknown, headers: Record<string, string>) => handleProtected(req("POST", path, body, headers), env, s, (r) => createHandler(s.deps)(r));

test("packs: $0.10 to $100 in whole cents; checks cost $0.001, $0.005 when simulated", () => {
  assert.equal(packMicro({ amount_usd: 1 }), 1_000_000);
  assert.equal(packMicro({ amount_usd: 0.1 }), 100_000);
  assert.equal(packMicro({ amount_usd: 100 }), 100_000_000);
  for (const bad of [{ amount_usd: 0.05 }, { amount_usd: 100.01 }, { amount_usd: 1.234 }, { amount_usd: "1" }, { amount_usd: null }]) assert.equal(packMicro(bad), null, JSON.stringify(bad));
  for (const none of [{}, null]) assert.equal(packMicro(none), 1_000_000, "no amount named: the $1 pack");
  assert.equal(creditCostMicro("/v1/risk-check", { wallet: WALLET }, true), 1000);
  assert.equal(creditCostMicro("/v1/risk-check", { wallet: USER, chain: "base", transaction: { from: USER, to: USER } }, true), 5000);
  assert.equal(creditCostMicro("/v1/risk-check/batch", { requests: [{ wallet: WALLET }, { wallet: WALLET }, { wallet: USER, chain: "base", transaction: { from: USER } }] }, true), 7000);
  const t = newCreditToken();
  assert.match(t, /^x402c_[A-Za-z0-9_-]{43}$/);
  assert.equal(creditToken(req("GET", "/v1/credits", undefined, { Authorization: `Bearer ${t}` })), t);
  assert.equal(creditToken(req("GET", "/v1/credits", undefined, { Authorization: "Bearer sk_live_nope" })), null);
});

test("buying credits: 402 first; after settlement a token and its balance; a repeated settlement never credits twice", async () => {
  const env: WorkerEnv = { CREDITS: memoryLedgers() };
  const fake: Fake = { priced: [], settleOk: true, tx: "0xabc" };
  const unpaid = await handleCredits(req("POST", "/v1/credits", { amount_usd: 1 }), env, stack(fake));
  assert.equal(unpaid.status, 402);
  assert.deepEqual(fake.priced, ['/v1/credits {"amount_usd":1}']);
  assert.equal((await handleCredits(req("POST", "/v1/credits", { amount_usd: 0.01 }), env, stack(fake))).status, 422, "below the minimum pack: rejected before any payment");

  const bought = await handleCredits(req("POST", "/v1/credits", { amount_usd: 1 }, { "PAYMENT-SIGNATURE": PAID_V2 }), env, stack(fake));
  assert.equal(bought.status, 200);
  const body = (await bought.json()) as { token: string; balance_usd: string; credited_usd: string };
  assert.match(body.token, /^x402c_/);
  assert.deepEqual([body.credited_usd, body.balance_usd], ["$1.00", "$1.00"]);
  assert.ok(bought.headers.get("PAYMENT-RESPONSE"), "the settlement receipt is returned");

  // Top-up the same token; the same settlement (same tx) replayed is a no-op.
  const auth = { Authorization: `Bearer ${body.token}` };
  fake.tx = "0xdef";
  const topped = (await (await handleCredits(req("POST", "/v1/credits", { amount_usd: 0.5 }, { ...auth, "PAYMENT-SIGNATURE": PAID_V2 }), env, stack(fake))).json()) as { token?: string; balance_usd: string };
  assert.deepEqual([topped.token, topped.balance_usd], [undefined, "$1.50"]);
  const replayed = (await (await handleCredits(req("POST", "/v1/credits", { amount_usd: 0.5 }, { ...auth, "PAYMENT-SIGNATURE": PAID_V2 }), env, stack(fake))).json()) as { balance_usd: string };
  assert.equal(replayed.balance_usd, "$1.50");
  const balance = (await (await handleCredits(req("GET", "/v1/credits", undefined, auth), env, stack(fake))).json()) as { balance_usd: string };
  assert.equal(balance.balance_usd, "$1.50");

  // A failed settlement credits nothing.
  const failed = await handleCredits(req("POST", "/v1/credits", { amount_usd: 1 }, { "PAYMENT-SIGNATURE": PAID_V2 }), env, stack({ ...fake, settleOk: false }));
  assert.equal(failed.status, 402);
  assert.equal(failed.headers.get("X-Payment-Error"), "nonce_used");
});

test("spending credits: no payment round trip; debited per item; insufficient balance refused; no verdict, no charge", async () => {
  const env: WorkerEnv = { CREDITS: memoryLedgers() };
  const fake: Fake = { priced: [], settleOk: true, tx: "0x01" };
  const { token } = (await (await handleCredits(req("POST", "/v1/credits", { amount_usd: 0.1 }, { "PAYMENT-SIGNATURE": PAID_V2 }), env, stack(fake))).json()) as { token: string };
  const auth = { Authorization: `Bearer ${token}` };
  fake.priced = [];

  const one = await evaluate(env, stack(fake), "/v1/risk-check", { wallet: WALLET }, auth);
  assert.equal(one.status, 200);
  assert.ok(((await one.json()) as { jws?: string }).jws, "a signed verdict");
  assert.deepEqual([one.headers.get("X-Credits-Charged"), one.headers.get("X-Credits-Balance")], ["$0.001", "$0.099"]);
  assert.deepEqual(fake.priced, [], "no 402, no settlement");

  const batch = await evaluate(env, stack(fake), "/v1/risk-check/batch", { requests: [{ wallet: WALLET }, { wallet: WALLET }] }, auth);
  assert.deepEqual([batch.status, batch.headers.get("X-Credits-Charged"), batch.headers.get("X-Credits-Balance")], [200, "$0.002", "$0.097"]);

  // The model is down: nothing is produced, nothing is charged.
  const down = await evaluate(env, stack(fake, null), "/v1/risk-check", { wallet: WALLET }, auth);
  assert.equal(down.status, 503);
  assert.equal(down.headers.get("X-Credits-Balance"), "$0.097");

  // More than the balance: refused before any work, balance untouched.
  const big = { requests: new Array(25).fill({ wallet: USER, chain: "base", transaction: { from: USER, to: USER } }) };
  const refused = await evaluate(env, stack(fake), "/v1/risk-check/batch", big, auth);
  assert.equal(refused.status, 402);
  assert.deepEqual((await refused.json()) as object, { error: "insufficient_credits", balance_usd: "$0.097", cost_usd: "$0.125", top_up: 'POST /v1/credits {"amount_usd": 1} with this token' });

  // A malformed bearer never falls through to an unpaid evaluation.
  const bad = await evaluate(env, stack(fake), "/v1/risk-check", { wallet: WALLET }, { Authorization: "Bearer x402c_short" });
  assert.equal(bad.status, 401);
  // Invalid input is rejected before any debit.
  const invalid = await evaluate(env, stack(fake), "/v1/risk-check", { wallet: "not an address" }, auth);
  assert.equal(invalid.status, 422);
  const after = (await (await handleCredits(req("GET", "/v1/credits", undefined, auth), env, stack(fake))).json()) as { balance_usd: string };
  assert.equal(after.balance_usd, "$0.097");
});

test("without the ledger binding, credits are unavailable, never free", async () => {
  const fake: Fake = { priced: [], settleOk: true, tx: "0x02" };
  assert.equal((await handleCredits(req("POST", "/v1/credits", { amount_usd: 1 }), {}, stack(fake))).status, 503);
  const res = await evaluate({}, stack(fake), "/v1/risk-check", { wallet: WALLET }, { Authorization: `Bearer ${newCreditToken()}` });
  assert.equal(res.status, 503);
});
