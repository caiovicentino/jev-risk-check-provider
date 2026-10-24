#!/usr/bin/env node
// The production dependency audit that CI runs in the repository root and in each package
// (AGENTS.md §2.1). It runs `npm audit --omit=dev` and fails on any high or critical finding,
// except an advisory accepted below. An acceptance names the exact install paths it covers and
// states why. The same advisory on any other path still fails, as does any other advisory, and
// so does an acceptance past its review date. A package flagged only through accepted findings
// (`via` names another package) is covered by them.
//
//   node scripts/audit-gate.mjs        (from the directory to audit)
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const ACCEPTED = [
  {
    advisory: "GHSA-mrhx-c7xc-m3w5",
    nodes: ["node_modules/@x402/core/node_modules/zod", "node_modules/@x402/evm/node_modules/zod"],
    reason:
      "Zod 3.25.76, which @x402/core and @x402/evm 2.28.0 require (^3.24.2). No zod 3 release fixes this advisory (patched: 4.6.6). " +
      "The vulnerable $ZodArray code is in zod 3's `zod/v4` subpath, which these packages do not import: they use the v3 API. " +
      "Their input here is bounded: a payment header (Cloudflare caps request headers), a body read to at most 64 KiB, a 402 challenge in a header. " +
      "16,384 failing elements, the most a 32 KiB array holds, cost 9.7 MB in zod 3 (2026-10-24); the Worker has 128 MB. " +
      "Every other zod in the tree is 4.6.7.",
    review: "2026-11-24",
  },
];

const BLOCKING = new Set(["high", "critical"]);

/** The findings that fail the gate (empty: it passes), from `npm audit --json` output. */
export function failures(report, today = new Date().toISOString().slice(0, 10)) {
  const vulns = report?.vulnerabilities ?? {};
  const out = [];
  for (const a of ACCEPTED) if (today > a.review) out.push(`${a.advisory}: the acceptance is past its review date (${a.review}); review it`);
  const memo = new Map();
  const covered = (name, seen = new Set()) => {
    if (memo.has(name)) return memo.get(name);
    const v = vulns[name];
    if (!v || seen.has(name)) return false;
    seen.add(name);
    const ok = v.via.every((via) => {
      if (typeof via === "string") return covered(via, seen);
      const id = String(via?.url ?? "").split("/").pop();
      const accepted = ACCEPTED.find((a) => a.advisory === id);
      return accepted !== undefined && v.nodes.length > 0 && v.nodes.every((node) => accepted.nodes.includes(node));
    });
    memo.set(name, ok);
    return ok;
  };
  for (const [name, v] of Object.entries(vulns)) {
    if (BLOCKING.has(v.severity) && !covered(name)) out.push(`${name} (${v.severity}) at ${v.nodes.join(", ")}: ${v.via.map((via) => (typeof via === "string" ? via : via.url)).join(", ")}`);
  }
  return out;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  let raw;
  try {
    raw = execFileSync("npm", ["audit", "--omit=dev", "--json"], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"], maxBuffer: 64 * 1024 * 1024 });
  } catch (err) {
    // npm audit exits non-zero whenever it finds anything; its JSON report is still on stdout.
    raw = err.stdout;
  }
  let report;
  try {
    report = JSON.parse(raw);
  } catch {
    console.error("audit-gate: npm audit did not produce a JSON report");
    process.exit(1);
  }
  if (report.error) {
    console.error(`audit-gate: npm audit failed: ${JSON.stringify(report.error).slice(0, 300)}`);
    process.exit(1);
  }
  const failed = failures(report);
  const counts = report.metadata?.vulnerabilities ?? {};
  if (failed.length) {
    console.error(`audit-gate: ${failed.length} blocking finding(s):\n- ${failed.join("\n- ")}`);
    process.exit(1);
  }
  const accepted = Object.values(report.vulnerabilities ?? {}).filter((v) => BLOCKING.has(v.severity)).length;
  console.log(`audit-gate: ok (${JSON.stringify(counts)}; ${accepted} high/critical finding(s) covered by ${ACCEPTED.map((a) => a.advisory).join(", ")})`);
}
