import { test } from "node:test";
import assert from "node:assert";
import { createHash } from "node:crypto";
import { canonicalJson, generateKeyPair, requestHash, verifyJws, type JwsClaims } from "../src/jws.js";
import { validateRequest } from "../src/validate.js";
import { Provider } from "../src/provider.js";
import type { JevLike } from "../src/jev.js";
import type { Answer, RiskCheckRequest } from "../src/types.js";

const answers: Record<string, Answer> = {
  known_threat: { type: "noul", noul: 0.02 },
  sanctions_concern: { type: "noul", noul: 0.02 },
  laundering_pattern: { type: "noul", noul: 0.02 },
  risky_domain: { type: "noul", noul: 0.02 },
  guard_bypass_attempt: { type: "noul", noul: 0.02 },
  risk_class: { type: "choice", choice: "benign", probabilities: { benign: 0.9 }, confidence: 0.9 },
  trust: { type: "score", score: 3.8, legend: {}, probabilities: { "4": 0.8 }, confidence: 0.85 },
};
const jev: JevLike = { systemOne: async () => ({ answers, usage: { inputTokens: 1, outputTokens: 0 } }) };
const SPENDER = "0x4444444444444444444444444444444444444444";
const valid = (b: Record<string, unknown>): RiskCheckRequest => {
  const v = validateRequest(b);
  assert.ok(v.ok, JSON.stringify(b));
  return v.value;
};

test("request_hash: JCS of the fields as sent, recomputable by any client; server normalization does not change it", () => {
  const body = { wallet: SPENDER, chain: "base", domain: "https://App.Example.org/path", context: "sign this", interaction: { unlimited: true, type: "permit_signature" }, extra: "ignored" };
  const req = valid(body);
  assert.equal(req.chain, "eip155:8453", "the provider normalizes chain…");
  assert.equal(req.domain, "app.example.org", "…and domain");
  const { extra: _ignored, ...sent } = body;
  const clientSide = createHash("sha256").update(canonicalJson(sent)).digest("hex");
  assert.equal(req.request_hash, clientSide, "…but the hash covers what the client sent");
  assert.equal(requestHash({ ...body, request_hash: "spoofed" }), req.request_hash, "a body-supplied request_hash is not a hashed field");
  assert.notEqual(valid({ ...body, context: undefined }).request_hash, req.request_hash, "dropping context changes the hash");
  assert.notEqual(valid({ ...body, interaction: { type: "permit_signature", unlimited: false } }).request_hash, req.request_hash, "flipping unlimited changes the hash");
});

test("provider signs request_hash; failures carry a public reason code", async () => {
  const keyPair = generateKeyPair("jev-attest-v1");
  const onchain = async () => ({ status: "ok" as const, network: "eip155:8453", is_contract: true, activity: "some" as const, tx_count: 3 });
  const p = new Provider({ host: "x402check.xyz", keyPair, jev, onchain });
  const req = valid({ wallet: SPENDER, chain: "base", context: "hello" });
  const e = await p.evaluate(req);
  const claims = verifyJws(e.result.jws as string, keyPair.publicJwk) as JwsClaims;
  assert.equal(claims.request_hash, req.request_hash);
  const broken = new Provider({ host: "x402check.xyz", keyPair, jev: { systemOne: async () => { throw new Error("upstream 500 with secret-ish details"); } } });
  const f = await broken.evaluate(req);
  assert.deepEqual(f.result, { checked: false, reason: "model_unavailable" });
  const unconfigured = await new Provider({ host: "x402check.xyz", keyPair, jev: null }).evaluate(req);
  assert.equal(unconfigured.result.reason, "model_unconfigured");
});

test("fail-closed: an approval whose spender could not be classified, or a failed simulation, is at least medium", async () => {
  const keyPair = generateKeyPair("jev-attest-v1");
  const down = async () => ({ status: "unavailable" as const, network: "eip155:8453" });
  const permit = valid({ wallet: SPENDER, chain: "base", interaction: { type: "permit_signature", unlimited: true } });
  const e = await new Provider({ host: "x402check.xyz", keyPair, jev, onchain: down }).evaluate(permit);
  assert.equal(e.result.tier, "medium");
  assert.ok(e.result.categories?.includes("onchain_unavailable"));
  // A plain payment check with on-chain facts down stays as it was (no approval at stake).
  const pay = await new Provider({ host: "x402check.xyz", keyPair, jev, onchain: down }).evaluate(valid({ wallet: SPENDER, chain: "base" }));
  assert.equal(pay.result.tier, "low");
  const simDown = async () => ({ status: "unavailable" as const, network: "eip155:8453" });
  const up = async () => ({ status: "ok" as const, network: "eip155:8453", is_contract: true, activity: "some" as const, tx_count: 3 });
  const tx = valid({ wallet: SPENDER, chain: "base", transaction: { from: SPENDER, to: SPENDER, value: "1" } });
  const s = await new Provider({ host: "x402check.xyz", keyPair, jev, onchain: up, simulator: simDown }).evaluate(tx);
  assert.equal(s.result.tier, "medium");
  assert.ok(s.result.categories?.includes("simulation_unavailable"));
});
