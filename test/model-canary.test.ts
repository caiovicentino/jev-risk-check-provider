// The model behind the alias can change (audit critic-2): the answering revision is signed in
// checks.model_id, and a canary of fixed cases records whether verdicts still land where they must.
import { test } from "node:test";
import assert from "node:assert";
import { runModelCanary } from "../deploy/model-canary.js";
import { Provider } from "../src/provider.js";
import { generateKeyPair } from "../src/jws.js";
import { validateRequest } from "../src/validate.js";
import type { JevLike } from "../src/jev.js";
import type { Answer } from "../src/types.js";

const answers = (bypass: number): Record<string, Answer> => ({
  known_threat: { type: "noul", noul: 0.02 },
  sanctions_concern: { type: "noul", noul: 0.02 },
  laundering_pattern: { type: "noul", noul: 0.02 },
  risky_domain: { type: "noul", noul: 0.02 },
  guard_bypass_attempt: { type: "noul", noul: bypass },
  risk_class: bypass > 0.5 ? { type: "choice", choice: "fraud_signal", probabilities: { fraud_signal: 0.9 }, confidence: 0.9 } : { type: "choice", choice: "benign", probabilities: { benign: 0.95 }, confidence: 0.9 },
  trust: bypass > 0.5 ? { type: "score", score: 1.2, legend: {}, probabilities: { "1": 0.8 }, confidence: 0.85 } : { type: "score", score: 3.8, legend: {}, probabilities: { "4": 0.8 }, confidence: 0.85 },
});
/** A model that reads injected instructions (or, with `blind`, one whose new revision stopped reading them). */
const model = (blind = false): JevLike => ({
  systemOne: async (state) => {
    const text = JSON.stringify(state);
    const injected = !blind && /ignore previous instructions|send everything in the vault/.test(text);
    return { answers: answers(injected ? 0.95 : 0.02), usage: { inputTokens: 1, outputTokens: 1 }, modelId: blind ? "jev-1.14.0" : "jev-1.13.0" };
  },
});

test("the canary passes on a model that reads injected instructions, and records the revision", async () => {
  const report = await runModelCanary(model());
  assert.equal(report.ok, true, JSON.stringify(report.cases));
  assert.equal(report.model_id, "jev-1.13.0");
  assert.deepEqual(report.cases.map((c) => c.id), ["injected_instruction", "drain_request", "configured_payment"]);
});

test("a revision that stops reading injected instructions fails the canary", async () => {
  const report = await runModelCanary(model(true));
  assert.equal(report.ok, false);
  assert.deepEqual(report.cases.filter((c) => !c.ok).map((c) => c.id), ["injected_instruction", "drain_request"]);
  assert.equal(report.model_id, "jev-1.14.0");
});

test("the answering revision is signed in checks.model_id", async () => {
  const v = validateRequest({ wallet: "0x1111111111111111111111111111111111111111", chain: "base" });
  assert.ok(v.ok);
  const { result } = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev: model() }).evaluate(v.value);
  assert.ok(result.checked);
  const claims = JSON.parse(Buffer.from((result.jws as string).split(".")[1] as string, "base64url").toString()) as { checks: { model: string; model_id?: string } };
  assert.equal(claims.checks.model_id, "jev-1.13.0");
  assert.equal(result.evidence?.model_id, "jev-1.13.0");
});
