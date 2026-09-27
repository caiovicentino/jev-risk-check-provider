import { test } from "node:test";
import assert from "node:assert";
import { deriveDecision, evaluateGate } from "../eval/gate.js";
import { baselineDecision } from "../eval/baseline.js";
import { CASES } from "../eval/cases.js";
import { syntheticFixturesFor } from "../eval/fixtures.js";
import { buildProvider, runCases, SYNTHETIC_LOG, appendEntries } from "../eval/harness.js";
import { rmSync } from "node:fs";

test("deriveDecision boundaries", () => {
  assert.equal(deriveDecision(60, true), "safe");
  assert.equal(deriveDecision(59, true), "risky");
  assert.equal(deriveDecision(null, false), "unchecked");
});

test("synthetic pipeline: all cases checked and labeled correctly", async () => {
  const provider = buildProvider(syntheticFixturesFor(CASES));
  const entries = await runCases(provider, CASES);
  for (const entry of entries) {
    const decision = deriveDecision(entry.score, entry.checked);
    assert.equal(decision, entry.expected, `${entry.case_id}: expected ${entry.expected}, got ${decision} (score=${entry.score})`);
  }
});

test("baseline flags impersonation and keyword contexts", () => {
  const impersonation = CASES.find((c) => c.id === "risky-impersonation-domain");
  assert.ok(impersonation);
  assert.equal(baselineDecision(impersonation).decision, "risky");
  const sanctions = CASES.find((c) => c.id === "risky-sanctions-mention");
  assert.ok(sanctions);
  assert.equal(baselineDecision(sanctions).decision, "risky");
  const benign = CASES.find((c) => c.id === "benign-api-micropayment");
  assert.ok(benign);
  assert.equal(baselineDecision(benign).decision, "safe");
});

test("baseline misses mass-request abuse where JEV should win", () => {
  const abuse = CASES.find((c) => c.id === "risky-fresh-wallet-bulk");
  assert.ok(abuse);
  assert.equal(baselineDecision(abuse).decision, "safe");
});

test("empty log yields NOT READY with failure reasons", () => {
  const report = evaluateGate("eval/evidence/nonexistent-log.jsonl");
  assert.equal(report.ready, false);
  assert.ok(report.failures.length >= 2);
});

test("gate is ready after synthetic run is fully verified", async () => {
  rmSync(SYNTHETIC_LOG, { force: true });
  const provider = buildProvider(syntheticFixturesFor(CASES));
  const entries = await runCases(provider, CASES);
  appendEntries(SYNTHETIC_LOG, entries, "synthetic");
  const labeled: Record<string, "real" | "fp"> = {};
  for (const c of CASES) {
    labeled[c.id] = "real";
  }
  appendEntries(
    SYNTHETIC_LOG,
    entries.map((e) => ({ ...e, verified: labeled[e.case_id] ?? null })),
    "synthetic",
  );
  const report = evaluateGate(SYNTHETIC_LOG, {
    minVerifiedChecks: CASES.length,
    minRealRiskyVerified: 5,
    maxDismissedReal: 0,
    maxReviewShare: 0.2,
  });
  assert.equal(report.ready, true, `gate should be ready, failures: ${report.failures.join("; ")}`);
});
