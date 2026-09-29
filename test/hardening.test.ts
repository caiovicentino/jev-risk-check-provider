import { test } from "node:test";
import assert from "node:assert";
import { createHandler } from "../src/handler.js";
import { Provider } from "../src/provider.js";
import { buildQuestions, type JevLike } from "../src/jev.js";
import { generateKeyPair, verifyJws } from "../src/jws.js";
import type { Answer, RiskCheckResult } from "../src/types.js";

const FULL: Record<string, Answer> = {
  known_threat: { type: "noul", noul: 0.02 },
  sanctions_concern: { type: "noul", noul: 0.02 },
  laundering_pattern: { type: "noul", noul: 0.02 },
  risky_domain: { type: "noul", noul: 0.02 },
  guard_bypass_attempt: { type: "noul", noul: 0.02 },
  risk_class: { type: "choice", choice: "benign", probabilities: { benign: 0.95 }, confidence: 0.9 },
  trust: { type: "score", score: 3.5, legend: {}, probabilities: { "4": 0.6 }, confidence: 0.8 },
};

const WALLET = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";

function stub(answers: unknown): JevLike {
  return { systemOne: async () => ({ answers: answers as Record<string, Answer>, usage: { inputTokens: 1, outputTokens: 1 } }) };
}

function handlerWith(jev: JevLike) {
  const keyPair = generateKeyPair("jev-attest-v1");
  return { keyPair, handle: createHandler({ provider: new Provider({ host: "paysol.test", keyPair, jev }) }) };
}

function post(path: string, body: unknown): Request {
  return new Request(`http://paysol.test${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
}

test("partial or malformed model answers fail closed (no signed low-risk verdict)", async () => {
  const cases: unknown[] = [
    {},
    undefined,
    { ...FULL, guard_bypass_attempt: undefined },
    { ...FULL, known_threat: { type: "noul", noul: Number.NaN } },
    { ...FULL, known_threat: { type: "noul", noul: -3 } },
    { ...FULL, trust: { type: "score", score: 99, legend: {}, probabilities: {}, confidence: 1 } },
    { ...FULL, risk_class: { type: "noul", noul: 0 } },
  ];
  for (const answers of cases) {
    const { handle } = handlerWith(stub(answers));
    const res = await handle(post("/v1/risk-check", { wallet: WALLET }));
    assert.equal(res.status, 200);
    const body = (await res.json()) as RiskCheckResult;
    assert.equal(body.checked, false, JSON.stringify(answers));
    assert.equal(body.jws, undefined);
  }
  assert.deepEqual(Object.keys(FULL).sort(), Object.keys(buildQuestions()).sort());
});

test("batch with any invalid item is rejected wholesale with its index", async () => {
  const { handle } = handlerWith(stub(FULL));
  const res = await handle(post("/v1/risk-check/batch", { requests: [{ wallet: WALLET }, { wallet: 123 }, { wallet: WALLET }] }));
  assert.equal(res.status, 422);
  assert.deepEqual(await res.json(), { error: "invalid_request", field: "wallet", index: 1 });
  const big = await handle(post("/v1/risk-check/batch", { requests: Array.from({ length: 26 }, () => ({ wallet: 1 })) }));
  assert.equal(big.status, 413);
});

test("oversized string fields are rejected before evaluation", async () => {
  let calls = 0;
  const { handle } = handlerWith({ systemOne: async () => { calls++; return { answers: FULL, usage: { inputTokens: 1, outputTokens: 1 } }; } });
  for (const extra of [
    { context: "x".repeat(4097) },
    { domain: `${"a".repeat(250)}.com` },
    { chain: "c".repeat(65) },
    { aud: "a".repeat(257) },
    { authorization: { pre_authorized: true, source: "s".repeat(129) } },
  ]) {
    const res = await handle(post("/v1/risk-check", { wallet: WALLET, ...extra }));
    assert.equal(res.status, 422, JSON.stringify(Object.keys(extra)));
  }
  assert.equal(calls, 0);
  const ok = await handle(post("/v1/risk-check", { wallet: WALLET, context: "x".repeat(4096) }));
  assert.equal(((await ok.json()) as RiskCheckResult).checked, true);
});

test("caller-asserted screening/authorization are bound into the signed claims", async () => {
  const { handle, keyPair } = handlerWith(stub(FULL));
  const plain = (await (await handle(post("/v1/risk-check", { wallet: WALLET }))).json()) as RiskCheckResult;
  const asserted = (await (
    await handle(post("/v1/risk-check", { wallet: WALLET, screening: { sanctions: "clean" }, authorization: { pre_authorized: true, source: "ops" } }))
  ).json()) as RiskCheckResult;
  const c1 = verifyJws(plain.jws as string, keyPair.publicJwk);
  const c2 = verifyJws(asserted.jws as string, keyPair.publicJwk);
  assert.ok(c1 && c2);
  assert.equal(c1.asserted, undefined);
  assert.deepEqual(c2.asserted, { screening: "clean", pre_authorized: true });
  assert.notEqual(c1.input_hash, c2.input_hash);
});
