// A facilitator that throws during settlement (audit mc-14): no verdict is released, nothing is
// credited, and the payment's claim is released so the payer can retry the same payment.
import { test } from "node:test";
import assert from "node:assert";
import { CreditLedger, handleCredits } from "../deploy/credits.js";
import { handleProtected, type Stack } from "../deploy/protected.js";
import { PaymentClaim } from "../deploy/payment-claims.js";
import type { DurableObjectNamespace, DurableObjectState, WorkerEnv } from "../deploy/runtime.js";
import { createHandler } from "../src/handler.js";
import { Provider } from "../src/provider.js";
import { generateKeyPair } from "../src/jws.js";
import type { JevLike } from "../src/jev.js";
import type { Answer } from "../src/types.js";
import type { HTTPRequestContext } from "@x402/core/http";

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
const jev: JevLike = { systemOne: async () => ({ answers: ANSWERS, usage: { inputTokens: 1, outputTokens: 0 } }) };
const payment = btoa(JSON.stringify({ x402Version: 2, accepted: { scheme: "exact", network: "eip155:8453" }, payload: { signature: "0x01", authorization: { from: USER, nonce: "0x42" } } }));

function memoryState(): DurableObjectState {
  const data = new Map<string, unknown>();
  return {
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
}

function namespace<T extends { fetch(r: Request): Promise<Response> }>(make: (s: DurableObjectState) => T): DurableObjectNamespace {
  const objects = new Map<string, T>();
  return {
    idFromName: (name: string) => ({ toString: () => name }),
    get: (id) => {
      const name = id.toString();
      let obj = objects.get(name);
      if (!obj) objects.set(name, (obj = make(memoryState())));
      return { fetch: async (input: string | Request, init?: RequestInit) => (obj as T).fetch(new Request(input, init)) };
    },
  };
}

/** A stack whose settlement throws until `settle.throws` is cleared. */
function stack(settle: { throws: boolean; calls: number }): Stack {
  const deps = { provider: new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev }) };
  const http = {
    processHTTPRequest: async (ctx: HTTPRequestContext) =>
      ctx.paymentHeader ? { type: "payment-verified", paymentPayload: { payload: { authorization: { from: USER } } }, paymentRequirements: {} } : { type: "payment-error", response: { status: 402, headers: {}, body: {} } },
    processSettlement: async () => {
      settle.calls++;
      if (settle.throws) throw new Error("facilitator connection reset");
      return { success: true, headers: { "PAYMENT-RESPONSE": btoa(JSON.stringify({ success: true, transaction: "0xabc", network: "eip155:8453" })) } };
    },
  };
  return { deps, http, keyStatus: { ok: true, kid: "k", thumbprint: null } } as unknown as Stack;
}

const req = (path: string, body: unknown) => new Request(`https://x402check.xyz${path}`, { method: "POST", headers: { "Content-Type": "application/json", "PAYMENT-SIGNATURE": payment }, body: JSON.stringify(body) });

test("per call: a settlement that throws releases no verdict, and the same payment can be retried", async () => {
  const env: WorkerEnv = { PAYMENT_CLAIMS: namespace((s) => new PaymentClaim(s)) };
  const settle = { throws: true, calls: 0 };
  const s = stack(settle);
  const failed = await handleProtected(req("/v1/risk-check", { wallet: USER, chain: "base" }), env, s, (r) => createHandler(s.deps)(r));
  assert.equal(failed.status, 402);
  assert.equal(((await failed.json()) as { error: string; jws?: string }).jws, undefined, "no attestation without settlement");
  settle.throws = false;
  const retried = await handleProtected(req("/v1/risk-check", { wallet: USER, chain: "base" }), env, s, (r) => createHandler(s.deps)(r));
  assert.equal(retried.status, 200, "the claim was released");
  assert.equal(settle.calls, 2);
});

test("credit pack: a settlement that throws credits nothing and mints no token; the retry buys the pack once", async () => {
  const env: WorkerEnv = { PAYMENT_CLAIMS: namespace((s) => new PaymentClaim(s)), CREDITS: namespace((s) => new CreditLedger(s)) };
  const settle = { throws: true, calls: 0 };
  const failed = await handleCredits(req("/v1/credits", { amount_usd: 1 }), env, stack(settle));
  assert.equal(failed.status, 402);
  assert.equal(((await failed.json()) as { token?: string }).token, undefined);
  settle.throws = false;
  const bought = await handleCredits(req("/v1/credits", { amount_usd: 1 }), env, stack(settle));
  assert.equal(bought.status, 200);
  assert.match(((await bought.json()) as { token: string }).token, /^x402c_/);
  const again = await handleCredits(req("/v1/credits", { amount_usd: 1 }), env, stack(settle));
  assert.equal(again.status, 409, "one payment buys one pack");
});
