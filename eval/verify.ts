import { readLatestEntries, upsertLabel, LIVE_LOG, DECISION_THRESHOLD } from "./harness.js";
import { CASES } from "./cases.js";
import { deriveDecision } from "../eval/gate.js";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";

const latest = readLatestEntries(LIVE_LOG);

if (latest.size === 0) {
  console.error("no live shadow entries — run `npm run shadow` first");
  process.exit(1);
}

const pending = CASES.filter((c) => !latest.get(c.id)?.verified);
const disagreements = pending.filter((c) => {
  const entry = latest.get(c.id);
  if (!entry) return false;
  const decision = deriveDecision(entry.score, entry.checked);
  return decision !== "unchecked" && decision !== c.expected;
});
const queue = [...disagreements, ...pending.filter((c) => !disagreements.includes(c))];

if (queue.length === 0) {
  console.log("all cases labeled — run `npm run shadow` for a fresh run, or `npm run board report`");
  process.exit(0);
}

console.log(`labeling session: ${queue.length} pending (${disagreements.length} disagreements first)`);
console.log("for each case: [r]eal (label is correct) / [f]p (label is wrong) / [s]kip\n");

const argv = process.argv.slice(2);
const sheetOnly = argv.includes("--sheet");
const answersIdx = argv.indexOf("--answers");
if (sheetOnly) {
  for (let i = 0; i < queue.length; i++) {
    const c = queue[i]!;
    const entry = latest.get(c.id);
    const decision = entry ? deriveDecision(entry.score, entry.checked) : "unchecked";
    console.log(`[${String(i).padStart(2, "0")}] ${c.id}`);
    console.log(`     category: ${c.category}`);
    console.log(`     wallet:   ${c.request.wallet}`);
    if (c.request.domain) console.log(`     domain:   ${c.request.domain}`);
    console.log(`     context:  ${c.request.context ?? "(none)"}`);
    console.log(`     authored label: ${c.expected.toUpperCase()} | JEV: ${decision.toUpperCase()} (score=${entry?.score ?? "-"}, tier=${entry?.tier ?? "-"})`);
    if (c.note) console.log(`     note:     ${c.note}`);
  }
  console.log(`\nrespond with --answers <string> (${queue.length} chars: r/f/s in order)`);
  process.exit(0);
}
if (answersIdx !== -1) {
  const answers = argv[answersIdx + 1] ?? "";
  if (answers.length !== queue.length) {
    console.error(`need ${queue.length} answers (r/f/s), got ${answers.length}`);
    process.exit(1);
  }
  let labeled = 0;
  for (let i = 0; i < queue.length; i++) {
    const c = queue[i]!;
    const a = answers[i]!.toLowerCase();
    if (a !== "r" && a !== "f") continue;
    upsertLabel(LIVE_LOG, c.id, a === "r" ? "real" : "fp");
    console.log(`${c.id} → ${a === "r" ? "real" : "fp"}`);
    labeled++;
  }
  console.log(`\n${labeled} labels applied — run \`npm run board report\` for the gate`);
  process.exit(0);
}

const rl = createInterface({ input: stdin, output: stdout });
let labeled = 0;

for (const c of queue) {
  const entry = latest.get(c.id);
  const decision = entry ? deriveDecision(entry.score, entry.checked) : "unchecked";
  const marker = disagreements.includes(c) ? "⚡ DISAGREEMENT" : "";
  console.log(`── ${c.id} ${marker}`);
  console.log(`   category: ${c.category}`);
  console.log(`   wallet:   ${c.request.wallet.slice(0, 20)}…`);
  if (c.request.domain) console.log(`   domain:   ${c.request.domain}`);
  console.log(`   context:  ${(c.request.context ?? "(none)").slice(0, 140)}`);
  console.log(`   authored label: ${c.expected.toUpperCase()} | JEV decision: ${decision.toUpperCase()} (score=${entry?.score ?? "-"}, tier=${entry?.tier ?? "-"})`);
  const answer = (await rl.question("   verdict? [r]eal / [f]p / [s]kip: ")).trim().toLowerCase();
  if (answer === "r" || answer === "f") {
    upsertLabel(LIVE_LOG, c.id, answer === "r" ? "real" : "fp");
    labeled++;
    console.log(`   → labeled ${answer === "r" ? "real" : "fp"}\n`);
  } else {
    console.log("   → skipped\n");
  }
}

rl.close();
console.log(`session complete: ${labeled} labeled, ${queue.length - labeled} skipped`);
console.log("run `npm run board report` to see the updated switch-over gate");
