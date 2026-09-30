// Rewrites the committed evidence reports with every ScamSniffer-only address and domain replaced
// by its hash (eval/redact.ts). The lists are fetched at run time and held in memory only; only
// counts are printed.
//
//   npx tsx scripts/redact-evidence.ts [--check]   (--check: exit 1 if anything would change)
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { redactScamSniffer, scamSnifferOnly } from "../eval/redact.js";

const DIR = "eval/evidence";
const check = process.argv.includes("--check");
const lists = await scamSnifferOnly();
let changed = 0;
for (const name of readdirSync(DIR).filter((f) => f.endsWith("-report.json")).sort()) {
  const path = `${DIR}/${name}`;
  const raw = readFileSync(path, "utf8");
  const counter = { n: 0 };
  const redacted = redactScamSniffer(JSON.parse(raw) as unknown, lists, counter);
  if (counter.n === 0) continue;
  changed++;
  console.log(`${path}: ${counter.n} occurrence(s) ${check ? "would be" : ""} redacted`);
  if (!check) writeFileSync(path, JSON.stringify(redacted, null, 2) + (raw.endsWith("\n") ? "\n" : ""));
}
console.log(changed ? `${changed} report(s) ${check ? "carry" : "redacted"} ScamSniffer-only entries` : "no ScamSniffer-only entries in the reports");
if (check && changed) process.exit(1);
