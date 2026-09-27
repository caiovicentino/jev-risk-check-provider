import { test } from "node:test";
import assert from "node:assert";
import { GatewayJevClient, type EvaluateFn } from "../src/backends/gateway.js";
import { buildQuestions, buildState } from "../src/jev.js";

const fakeEvaluate: EvaluateFn = async ({ questions }) => ({
  answers: {
    known_threat: { type: "boolean", probability: 0.9 },
    guard_bypass_attempt: { type: "boolean", probability: 0.95 },
    risk_class: { type: "choice", choice: "fraud_signal", probabilities: { benign: 0.1, fraud_signal: 0.85 } },
    trust: { type: "score", score: 1.2, probabilities: { "0": 0.5, "1": 0.4, "2": 0.1 } },
  },
  usage: { inputTokens: 123, outputTokens: 0 },
});

test("gateway maps boolean to noul and marks score uncalibrated", async () => {
  const client = new GatewayJevClient({ evaluateImpl: fakeEvaluate });
  const { answers } = await client.systemOne(buildState({ wallet: "w" }), buildQuestions());
  assert.equal(answers["known_threat"]?.type, "noul");
  if (answers["known_threat"]?.type === "noul") assert.equal(answers["known_threat"].noul, 0.9);
  const risk = answers["risk_class"];
  assert.ok(risk && risk.type === "choice");
  if (risk.type === "choice") assert.equal(risk.confidence, 0.85);
  const trust = answers["trust"];
  assert.ok(trust && trust.type === "score");
  if (trust.type === "score") {
    assert.equal(trust.noCalibration, true);
    assert.equal(trust.score, 1.2);
  }
});

test("gateway passes normalized state with domain analysis", async () => {
  let capturedState: object | null = null;
  const capturing: EvaluateFn = async (args) => {
    capturedState = args.state;
    return { answers: {}, usage: {} };
  };
  const client = new GatewayJevClient({ evaluateImpl: capturing });
  await client.systemOne(
    buildState({ wallet: "w", domain: "jup1ter-audit-attest.click", chain: "solana" }),
    buildQuestions(),
  );
  const analysis = (capturedState as unknown as { domain_analysis?: { leet_substitution: boolean; brand_tokens: string[]; suspicious_tld: boolean } }).domain_analysis;
  assert.ok(analysis);
  assert.equal(analysis.leet_substitution, true);
  assert.deepEqual(analysis.brand_tokens, ["jupiter"]);
  assert.equal(analysis.suspicious_tld, true);
});
