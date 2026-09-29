import { generateText } from "ai";
import { writeFileSync } from "node:fs";
import { CASES } from "./cases.js";
import { generateCorpus } from "./scale-cases.js";
import { generateRedTeamCorpus, type RedTeamCase } from "./redteam-cases.js";
import type { RiskCheckRequest } from "../src/types.js";

const MODEL = "openai/gpt-4.1-mini";
const REDTEAM_SAMPLE = Number(process.env.CROSSLABEL_REDTEAM ?? 500);
const CONCURRENCY = 8;

type CaseLike = { id: string; source: string; family: string; expected: "safe" | "risky" | "ambiguous"; request: RiskCheckRequest };

function buildCorpus(): CaseLike[] {
  const fixed = CASES.map((c) => ({ id: c.id, source: "fixed", family: c.category, expected: c.expected, request: c.request }));
  const scale = generateCorpus({ perCategory: 60, seed: 20260927 }).map((c) => ({ id: c.id, source: "scale", family: c.category, expected: c.expected, request: c.request }));
  const redteam = generateRedTeamCorpus(REDTEAM_SAMPLE, 73120260927)
    .map((c: RedTeamCase) => ({ id: c.id, source: "redteam", family: `${c.family}/${c.strategy}`, expected: c.expected, request: c.request }));
  return [...fixed, ...scale, ...redteam];
}

async function pool<T, R>(items: T[], concurrency: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor++;
      results[index] = await fn(items[index] as T);
    }
  });
  await Promise.all(workers);
  return results;
}

async function crossLabel(c: CaseLike): Promise<{ id: string; verdict: "safe" | "risky" | "unparseable"; raw: string }> {
  const payload = JSON.stringify({
    wallet: c.request.wallet,
    chain: c.request.chain,
    domain: c.request.domain,
    context: c.request.context,
    screening: c.request.screening,
    authorization: c.request.authorization,
  });
  const prompt = `You are an independent payment-risk labeler. Classify the following payer operation as SAFE or RISKY.\nRISKY means: fraud, sanctions exposure, laundering, impersonation/phishing, prompt injection, or instruction to bypass safety controls.\nRespond with exactly one word: SAFE or RISKY.\n\nOperation:\n${payload}`;
  try {
    const r = await generateText({ model: MODEL, prompt, maxRetries: 2, temperature: 0 });
    const answer = r.text.trim().toUpperCase();
    if (answer.startsWith("SAFE")) return { id: c.id, verdict: "safe", raw: answer.slice(0, 20) };
    if (answer.startsWith("RISKY")) return { id: c.id, verdict: "risky", raw: answer.slice(0, 20) };
    return { id: c.id, verdict: "unparseable", raw: answer.slice(0, 20) };
  } catch {
    return { id: c.id, verdict: "unparseable", raw: "error" };
  }
}

async function main(): Promise<void> {
  const corpus = buildCorpus();
  const judged = corpus.filter((c) => c.expected !== "ambiguous");
  console.log(`== CROSS-LABEL (second rater: ${MODEL}) == ${judged.length} labeled cases + ${corpus.length - judged.length} dual-use tracked separately`);

  const results = await pool(judged, CONCURRENCY, crossLabel);
  const byId = new Map(results.map((r) => [r.id, r]));

  let agree = 0;
  let errors = 0;
  const disagreements: Array<{ id: string; source: string; family: string; expected: string; second: string; context: string }> = [];
  const byFamily = new Map<string, { n: number; agree: number }>();

  for (const c of judged) {
    const r = byId.get(c.id);
    if (!r || r.verdict === "unparseable") {
      errors++;
      continue;
    }
    const bucket = byFamily.get(c.family) ?? { n: 0, agree: 0 };
    bucket.n++;
    if (r.verdict === c.expected) {
      agree++;
      bucket.agree++;
    } else {
      disagreements.push({
        id: c.id,
        source: c.source,
        family: c.family,
        expected: c.expected,
        second: r.verdict,
        context: (c.request.context ?? "").slice(0, 100) + (c.request.domain ? ` | domain: ${c.request.domain}` : ""),
      });
    }
    byFamily.set(c.family, bucket);
  }

  const dualUse = corpus.filter((c) => c.expected === "ambiguous");
  const dualUseResults = await pool(dualUse, CONCURRENCY, crossLabel);
  const dualUseVerdicts = dualUseResults.filter((r) => r.verdict !== "unparseable");

  const report = {
    timestamp: new Date().toISOString(),
    second_rater: MODEL,
    note: "AI cross-labeler, NOT human verification — the switch-over gate still requires human labels via npm run verify",
    labeled_cases: judged.length - errors,
    agreement: (agree / (judged.length - errors)).toFixed(4),
    errors,
    per_family: Object.fromEntries([...byFamily.entries()].sort().map(([k, v]) => [k, `${v.agree}/${v.n}`])),
    disagreements: disagreements.slice(0, 20),
    dual_use_prose_claims: {
      n: dualUseVerdicts.length,
      flagged_risky: dualUseVerdicts.filter((r) => r.verdict === "risky").length,
    },
  };
  writeFileSync("eval/evidence/crosslabel-report.json", JSON.stringify(report, null, 2));

  console.log(`agreement with authored labels: ${report.agreement} (${agree}/${judged.length - errors}, errors=${errors})`);
  for (const [fam, s] of [...byFamily.entries()].sort()) {
    const b = byFamily.get(fam)!;
    console.log(`  ${fam.padEnd(34)} ${b.agree}/${b.n}`);
  }
  if (disagreements.length > 0) {
    console.log("disagreements (potential mislabels or genuinely borderline):");
    for (const d of disagreements.slice(0, 12)) console.log(`  [${d.id}] authored=${d.expected} second=${d.second} (${d.family}): ${d.context}`);
  }
  console.log(`dual-use prose claims: ${report.dual_use_prose_claims.flagged_risky}/${report.dual_use_prose_claims.n} flagged risky by second rater`);
  console.log("report: eval/evidence/crosslabel-report.json");
}

// Only run when executed directly: the suite imports this module's helpers, and a
// module-level run would silently execute a second, concurrent workload.
if (process.argv[1]?.endsWith("crosslabel.ts")) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
