// Regressions for the independent adversarial review of v0.2.0 (2026-09-29).
import { test } from "node:test";
import assert from "node:assert";
import { DatabaseSync } from "node:sqlite";
import { parseSubject, sameSubject } from "../src/address.js";
import { screenSubject } from "../src/sanctions.js";
import { base58Decode } from "../src/address-codec.js";
import { OFAC_SDN_ADDRESSES } from "../src/data/ofac-sdn.js";
import { analyzeDomain } from "../src/domain-analysis.js";
import { validateRequest } from "../src/validate.js";
import { Provider } from "../src/provider.js";
import { generateKeyPair } from "../src/jws.js";
import { createHandler } from "../src/handler.js";
import type { JevLike } from "../src/jev.js";
import type { Answer, RiskCheckRequest } from "../src/types.js";
import { handleProtected, type Stack } from "../deploy/protected.js";
import type { WorkerEnv } from "../deploy/runtime.js";
/** A PAYMENT-SIGNATURE shaped like x402 v2 (the stack only accepts v2 payments). */
const PAID_V2 = btoa(JSON.stringify({ x402Version: 2, accepted: { scheme: "exact", network: "eip155:8453" }, payload: { signature: "0x01", authorization: { from: "0x1111111111111111111111111111111111111111", nonce: "0x01" } } }));


const LAZARUS = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96";
const WALLET = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const answers = (over: Partial<Record<string, Answer>> = {}): Record<string, Answer> => ({
  known_threat: { type: "noul", noul: 0.02 },
  sanctions_concern: { type: "noul", noul: 0.02 },
  laundering_pattern: { type: "noul", noul: 0.02 },
  risky_domain: { type: "noul", noul: 0.02 },
  guard_bypass_attempt: { type: "noul", noul: 0.02 },
  risk_class: { type: "choice", choice: "benign", probabilities: { benign: 0.9 }, confidence: 0.9 },
  trust: { type: "score", score: 3.5, legend: {}, probabilities: { "4": 0.8 }, confidence: 0.85 },
  ...over,
});
const jev = (ans: Record<string, Answer> = answers()): JevLike => ({ systemOne: async () => ({ answers: ans, usage: { inputTokens: 1, outputTokens: 0 } }) });
const provider = (j: JevLike | null = jev()) => new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("jev-attest-v1"), jev: j });
const req = (body: Record<string, unknown>): RiskCheckRequest => {
  const v = validateRequest(body);
  assert.ok(v.ok, JSON.stringify(body));
  return v.value;
};

test("R1 checksummed base58: case-flipped variants of listed addresses are rejected, not screened as 'unlisted'", () => {
  let tried = 0;
  for (const [address, ticker] of OFAC_SDN_ADDRESSES) {
    if (!["TRX", "XBT", "LTC", "DOGE", "DASH"].includes(ticker) || address.includes("1q")) continue;
    const i = [...address].findIndex((c, k) => k > 0 && /[A-HJ-NP-Za-km-z]/.test(c) && /[A-HJ-NP-Za-km-z]/.test(c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase()));
    if (i < 0) continue;
    const c = address[i] as string;
    const flipped = address.slice(0, i) + (c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase()) + address.slice(i + 1);
    assert.equal(parseSubject(flipped), null, flipped);
    if (++tried >= 50) break;
  }
  assert.ok(tried >= 50);
});

test("R1 same key in another encoding is listed (BCH legacy ↔ cashaddr, EVM ↔ TRX)", () => {
  const legacy = screenSubject(parseSubject("18Y8VPic2pZsvyLaYVdSLQdCuT2nAJJ3hd")!);
  assert.equal(legacy.status, "listed");
  assert.equal(legacy.match, "same_key");
  const trx = OFAC_SDN_ADDRESSES.find((r) => r[1] === "TRX")![0];
  const hash = Buffer.from(base58Decode(trx)!.subarray(1, 21)).toString("hex");
  const evm = screenSubject(parseSubject(`0x${hash}`)!);
  assert.equal(evm.status, "listed");
  assert.equal(evm.listed_address, trx);
});

test("R1 verifier subject comparison: canonical for EVM, case-sensitive for base58", () => {
  assert.ok(sameSubject(LAZARUS, LAZARUS.toLowerCase()));
  assert.ok(sameSubject(`eip155:1:${LAZARUS}`, LAZARUS));
  assert.ok(!sameSubject("42RLPACwZPx3vYYmxSueqsogfynBDqXK298EDsNoyoHi", "42rLPACwZPx3vYYmxSueqsogfynBDqXK298EDsNoyoHi"));
});

test("R2 hostile punycode never throws; a listed subject stays critical whatever the domain", async () => {
  for (const d of ["xn---s73m.com", "xn--zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.com", "xn--99999999999.com", "xn--a-.com"]) {
    assert.doesNotThrow(() => analyzeDomain(d), d);
  }
  const e = await provider().evaluate(req({ wallet: LAZARUS, domain: "xn---s73m.com" }));
  assert.equal(e.result.tier, "critical");
  assert.equal(e.result.score, 0);
});

test("R3 self-asserted pre-authorization does not raise the score", async () => {
  const lowTrust = answers({ trust: { type: "score", score: 0, legend: {}, probabilities: { "0": 0.9 }, confidence: 0.9 }, risk_class: { type: "choice", choice: "fraud_signal", probabilities: { fraud_signal: 0.5 }, confidence: 0.5 } });
  const plain = (await provider(jev(lowTrust)).evaluate(req({ wallet: WALLET }))).result.score as number;
  const asserted = (await provider(jev(lowTrust)).evaluate(req({ wallet: WALLET, authorization: { pre_authorized: true } }))).result.score as number;
  assert.equal(asserted, plain);
});

test("R4 a CAIP-10 chain or payment.network that disagrees with `chain` is rejected", () => {
  const caip = validateRequest({ wallet: `eip155:1:${LAZARUS}`, chain: "base" });
  assert.ok(!caip.ok && caip.field === "chain");
  const pay = validateRequest({ wallet: WALLET, chain: "solana", payment: { network: "base" } });
  assert.ok(!pay.ok && pay.field === "payment.network");
  assert.ok(validateRequest({ wallet: `eip155:8453:${LAZARUS}`, chain: "base" }).ok);
});

test("R5 prototype keys are not chains; an unknown risk class fails closed", async () => {
  for (const chain of ["constructor", "__proto__", "toString", "hasOwnProperty"]) {
    const v = validateRequest({ wallet: WALLET, chain });
    assert.ok(!v.ok, chain);
    const p = validateRequest({ wallet: WALLET, payment: { network: chain } });
    assert.ok(!p.ok, `payment.network ${chain}`);
  }
  const weird = answers({ risk_class: { type: "choice", choice: "constructor", probabilities: { constructor: 1 }, confidence: 1 } });
  const e = await provider(jev(weird)).evaluate(req({ wallet: WALLET }));
  assert.equal(e.result.checked, false);
});

function stack(j: JevLike, settles: { n: number }): Stack {
  const deps = { provider: provider(j) };
  const http = {
    processHTTPRequest: async (ctx: { paymentHeader?: string }) =>
      ctx.paymentHeader ? { type: "payment-verified", paymentPayload: {}, paymentRequirements: {} } : { type: "payment-error", response: { status: 402, headers: {}, body: {} } },
    processSettlement: async () => {
      settles.n++;
      return { success: true, headers: {} };
    },
  };
  return { deps, http } as unknown as Stack;
}

const run = (env: WorkerEnv, s: Stack, r: Request) => handleProtected(r, env, s, (x) => createHandler(s.deps)(x));
const post = (path: string, body: string, headers: Record<string, string> = {}) =>
  new Request(`https://x402check.xyz${path}`, { method: "POST", headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.1", ...headers }, body });

test("R6 the body cap is in bytes and checked before buffering", async () => {
  const env: WorkerEnv = {};
  const s = stack(jev(), { n: 0 });
  const multibyte = JSON.stringify({ wallet: WALLET, context: "€".repeat(30_000) }); // ~90 KB, < 64K chars
  assert.ok(multibyte.length < 64 * 1024 && Buffer.byteLength(multibyte) > 64 * 1024);
  assert.equal((await run(env, s, post("/v1/risk-check", multibyte))).status, 413);
  const declared = post("/v1/risk-check", JSON.stringify({ wallet: WALLET }), { "Content-Length": String(10 * 1024 * 1024) });
  assert.equal((await run(env, s, declared)).status, 413);
});

test("R7 a paid request is not settled when the evaluation could not be produced", async () => {
  const env: WorkerEnv = {};
  const settles = { n: 0 };
  const failing: JevLike = { systemOne: async () => { throw new Error("model down"); } };
  const res = await run(env, stack(failing, settles), post("/v1/risk-check/batch", JSON.stringify({ requests: [{ wallet: WALLET }, { wallet: WALLET }] }), { "PAYMENT-SIGNATURE": PAID_V2 }));
  assert.equal(res.status, 503);
  assert.equal(settles.n, 0);
  const ok = await run(env, stack(jev(), settles), post("/v1/risk-check", JSON.stringify({ wallet: WALLET }), { "PAYMENT-SIGNATURE": PAID_V2 }));
  assert.equal(ok.status, 200);
  assert.equal(settles.n, 1);
});

test("R9 an X-PAYMENT-only (x402 v1) request gets the v2 402 challenge, never an unpaid evaluation", async () => {
  const res = await run({}, stack(jev(), { n: 0 }), post("/v1/risk-check", JSON.stringify({ wallet: WALLET }), { "X-PAYMENT": "v1-payload" }));
  assert.equal(res.status, 402);
});
