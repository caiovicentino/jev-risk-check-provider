import { appendEntries, buildProvider, runCases, SYNTHETIC_LOG, DECISION_THRESHOLD } from "./harness.js";
import { syntheticFixturesFor } from "./fixtures.js";
import { CASES } from "./cases.js";
import { baselineDecision } from "./baseline.js";

async function main(): Promise<void> {
  const provider = buildProvider(syntheticFixturesFor(CASES));
  const entries = await runCases(provider, CASES);
  appendEntries(SYNTHETIC_LOG, entries, "synthetic");

  console.log("== synthetic run (mock JEV, offline pipeline validation) ==");
  let correct = 0;
  let unchecked = 0;
  const misses: string[] = [];

  for (const entry of entries) {
    if (!entry.checked) {
      unchecked++;
      continue;
    }
    const decision = entry.score !== null && entry.score >= DECISION_THRESHOLD ? "safe" : "risky";
    if (decision === entry.expected) correct++;
    else misses.push(`${entry.case_id}: expected=${entry.expected} score=${entry.score} tier=${entry.tier}`);
  }

  let baselineCorrect = 0;
  const baselineMisses: string[] = [];
  for (const c of CASES) {
    const verdict = baselineDecision(c);
    if (verdict.decision === c.expected) baselineCorrect++;
    else baselineMisses.push(`${c.id}: expected=${c.expected} baseline=${verdict.decision} (${verdict.reasons.join(", ")})`);
  }

  console.log(`cases: ${entries.length} | jev-correct: ${correct} | unchecked: ${unchecked}`);
  if (misses.length > 0) {
    console.log("jev misses:");
    for (const m of misses) console.log(`  ${m}`);
  }
  console.log(`baseline: ${baselineCorrect}/${CASES.length} correct`);
  if (baselineMisses.length > 0) {
    console.log("baseline misses:");
    for (const m of baselineMisses) console.log(`  ${m}`);
  }
  console.log(`evidence appended to ${SYNTHETIC_LOG}`);
  if (unchecked > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
