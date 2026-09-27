import { test } from "node:test";
import assert from "node:assert";
import { computeScore, extractInputs, tierFor, DEFAULT_WEIGHTS } from "../src/scoring.js";
import type { Answer } from "../src/types.js";

function answers(overrides: Record<string, Answer>): Record<string, Answer> {
  return overrides;
}

const BENIGN: Record<string, Answer> = {
  known_threat: { type: "noul", noul: 0.02 },
  sanctions_concern: { type: "noul", noul: 0.01 },
  laundering_pattern: { type: "noul", noul: 0.03 },
  risky_domain: { type: "noul", noul: 0.02 },
  risk_class: {
    type: "choice",
    choice: "benign",
    probabilities: { benign: 0.97, automated_abuse: 0.02, fraud_signal: 0.01, unclassifiable: 0.0 },
    confidence: 0.95,
  },
  trust: {
    type: "score",
    score: 4,
    legend: {},
    probabilities: { "0": 0, "1": 0, "2": 0.02, "3": 0.13, "4": 0.85 },
    confidence: 0.9,
  },
};

test("benign inputs produce low tier", () => {
  const inputs = extractInputs({ wallet: "w" }, BENIGN);
  const breakdown = computeScore(inputs);
  assert.equal(breakdown.tier, "low");
  assert.ok(breakdown.score >= 80);
  assert.equal(breakdown.cappedByLowConfidence, false);
});

test("known threat caps score at 20", () => {
  const inputs = { ...extractInputs({ wallet: "w" }, BENIGN), knownThreat: 0.9 };
  const breakdown = computeScore(inputs);
  assert.ok(breakdown.score <= 20);
  assert.equal(breakdown.tier, "critical");
});

test("sanctions caps score at 30", () => {
  const inputs = { ...extractInputs({ wallet: "w" }, BENIGN), sanctionsConcern: 0.9 };
  const breakdown = computeScore(inputs);
  assert.ok(breakdown.score <= 30);
});

test("low trust confidence caps at 55", () => {
  const inputs = { ...extractInputs({ wallet: "w" }, BENIGN), trustConfidence: 0.2 };
  const breakdown = computeScore(inputs);
  assert.ok(breakdown.score <= 55);
  assert.equal(breakdown.cappedByLowConfidence, true);
});

test("gateway-mode answers without calibration skip the confidence cap but keep hard caps", () => {
  const uncalibrated: Record<string, Answer> = {
    ...BENIGN,
    trust: { type: "score", score: 3.8, legend: {}, probabilities: {}, confidence: 0, noCalibration: true },
    risk_class: { type: "choice", choice: "benign", probabilities: {}, confidence: 0, noCalibration: true },
  };
  const inputs = extractInputs({ wallet: "w" }, uncalibrated);
  assert.equal(inputs.trustCalibrated, false);
  const breakdown = computeScore(inputs);
  assert.ok(breakdown.score >= 80);
  assert.equal(breakdown.cappedByLowConfidence, false);
});

test("fraud signal class with high probability lowers score", () => {
  const inputs = {
    ...extractInputs({ wallet: "w" }, BENIGN),
    riskClass: "fraud_signal",
    riskClassProbability: 0.9,
  };
  const breakdown = computeScore(inputs);
  assert.ok(breakdown.score < 80);
  assert.notEqual(breakdown.tier, "low");
});

test("tier boundaries follow spec", () => {
  assert.equal(tierFor(100), "low");
  assert.equal(tierFor(80), "low");
  assert.equal(tierFor(79), "medium");
  assert.equal(tierFor(60), "medium");
  assert.equal(tierFor(59), "high");
  assert.equal(tierFor(30), "high");
  assert.equal(tierFor(29), "critical");
  assert.equal(tierFor(0), "critical");
});

test("score is clamped to 0..100", () => {
  const worst = {
    knownThreat: 1,
    sanctionsConcern: 1,
    launderingPattern: 1,
    riskyDomain: 1,
    guardBypassAttempt: 1,
    riskClass: "fraud_signal",
    riskClassProbability: 1,
    trust: 0,
    trustConfidence: 1,
    trustCalibrated: true,
  };
  const breakdown = computeScore(worst);
  assert.ok(breakdown.score >= 0 && breakdown.score <= 100);
});

test("weights are code-controlled, not prompt-controlled", () => {
  const custom = { ...DEFAULT_WEIGHTS, knownThreat: 100 };
  const inputs = { ...extractInputs({ wallet: "w" }, BENIGN), knownThreat: 0.5 };
  const breakdown = computeScore(inputs, custom);
  assert.ok(breakdown.score < 60);
});
