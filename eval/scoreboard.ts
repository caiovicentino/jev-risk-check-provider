import { readLatestEntries, upsertLabel, LIVE_LOG, costFrom } from "./harness.js";
import { evaluateGate, deriveDecision } from "./gate.js";
import { CASES } from "./cases.js";
import { baselineDecision } from "./baseline.js";

const [command, caseId, verdict] = process.argv.slice(2);

if (command === "todo") {
  const latest = readLatestEntries(LIVE_LOG);
  const unverified = CASES.filter((c) => !latest.get(c.id)?.verified);
  const disagreements = unverified.filter((c) => {
    const entry = latest.get(c.id);
    if (!entry) return false;
    const decision = deriveDecision(entry.score, entry.checked);
    return decision !== "unchecked" && decision !== c.expected;
  });
  const ordered = [...disagreements, ...unverified.filter((c) => !disagreements.includes(c))];
  console.log(`unlabeled: ${ordered.length} (disagreements first)`);
  for (const c of ordered) {
    const entry = latest.get(c.id);
    const marker = disagreements.includes(c) ? "⚡" : " ";
    console.log(`${marker} ${c.id.padEnd(32)} expected=${c.expected} score=${entry?.score ?? "-"} tier=${entry?.tier ?? "-"} (${c.note})`);
  }
  process.exit(0);
}

if (command === "label") {
  if (!caseId || (verdict !== "real" && verdict !== "fp")) {
    console.error("usage: tsx eval/scoreboard.ts label <case_id> real|fp");
    process.exit(1);
  }
  const ok = upsertLabel(LIVE_LOG, caseId, verdict);
  if (!ok) {
    console.error(`no entry for case_id ${caseId} — run 'npm run shadow' first`);
    process.exit(1);
  }
  console.log(`labeled ${caseId} as ${verdict}`);
  process.exit(0);
}

if (command === "report") {
  const latest = readLatestEntries(LIVE_LOG);
  console.log("== scoreboard report ==");
  const perCategory = new Map<string, { total: number; correct: number }>();
  let correct = 0;
  let checked = 0;
  let inputTokens = 0;
  for (const c of CASES) {
    const entry = latest.get(c.id);
    if (!entry) continue;
    checked++;
    inputTokens += entry.input_tokens ?? 0;
    const decision = deriveDecision(entry.score, entry.checked);
    const bucket = perCategory.get(entry.category) ?? { total: 0, correct: 0 };
    bucket.total++;
    if (decision === entry.expected) {
      correct++;
      bucket.correct++;
    }
    perCategory.set(entry.category, bucket);
  }
  console.log(`checked entries: ${checked} | accuracy: ${checked > 0 ? Math.round((correct / checked) * 100) : 0}%`);
  for (const [cat, s] of [...perCategory.entries()].sort()) {
    console.log(`  ${cat.padEnd(14)} ${s.correct}/${s.total}`);
  }
  const baselineFlags = CASES.filter((c) => c.expected === "safe" && baselineDecision(c).decision === "risky").length;
  console.log(`baseline false flags: ${baselineFlags} | est. cost so far: $${costFrom(inputTokens).toFixed(6)}`);
  const gate = evaluateGate(LIVE_LOG);
  console.log(`verified: ${gate.verifiedChecks} checks, ${gate.realRiskyVerified} risky-real, ${gate.dismissedReal} dismissed-real, ${gate.jevFalseConfirms} jev-false-confirms, review ${Math.round(gate.reviewShare * 100)}%`);
  console.log(`switch-over gate: ${gate.ready ? "READY" : "NOT READY"}${gate.failures.length > 0 ? ` (${gate.failures.join("; ")})` : ""}`);
  process.exit(0);
}

console.error("usage: tsx eval/scoreboard.ts todo|label <case_id> real|fp|report");
process.exit(1);
