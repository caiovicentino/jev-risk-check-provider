#!/usr/bin/env node
// The production dependency audit that CI runs in the repository root and in each package
// (AGENTS.md §2.1). It runs `npm audit --omit=dev` and fails on any high or critical finding,
// except an advisory accepted below. An acceptance names the exact install paths it covers, the
// versions installed there, and why. The same advisory on any other path or at any other version
// still fails, as does any other high or critical advisory, an acceptance past its review date,
// and an audit that failed or gave a report in a format it does not read. A package flagged only through accepted or lesser findings (`via` names another
// package) is covered by them.
//
//   node scripts/audit-gate.mjs        (from the directory to audit)
import { execFileSync } from "node:child_process";
import { readFileSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const ACCEPTED = [
  {
    advisory: "GHSA-mrhx-c7xc-m3w5",
    nodes: ["node_modules/@x402/core/node_modules/zod", "node_modules/@x402/evm/node_modules/zod"],
    versions: ["3.25.76"],
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
// An advisory below the gate's bar needs no acceptance. Anything else does, a missing severity included.
const LESSER = new Set(["info", "low", "moderate"]);

/** The installed version of each lockfile path, from the package-lock.json in the current directory. */
function lockfileVersions() {
  let packages;
  return (node) => {
    packages ??= JSON.parse(readFileSync("package-lock.json", "utf8")).packages ?? {};
    return packages[node]?.version;
  };
}

/**
 * The findings that fail the gate (empty: it passes), from `npm audit --json` output. `installed`
 * gives the version at a lockfile path (default: this directory's package-lock.json).
 */
export function failures(report, today = new Date().toISOString().slice(0, 10), installed = lockfileVersions()) {
  const vulns = report?.vulnerabilities ?? {};
  const out = [];
  for (const a of ACCEPTED) if (today > a.review) out.push(`${a.advisory}: the acceptance is past its review date (${a.review}); review it`);
  // A package's own advisories are all lesser or accepted at exactly the paths and versions installed.
  const own = (v) =>
    v.via.every((via) => {
      if (typeof via === "string" || LESSER.has(via?.severity)) return true;
      const id = String(via?.url ?? "").split("/").pop();
      const a = ACCEPTED.find((x) => x.advisory === id);
      return a !== undefined && v.nodes.length > 0 && v.nodes.every((node) => a.nodes.includes(node) && a.versions.includes(installed(node)));
    });
  // Covered: every package it is flagged through (a cycle included) passes `own`.
  const covered = (name) => {
    const seen = new Set();
    const queue = [name];
    while (queue.length > 0) {
      const n = queue.pop();
      if (seen.has(n)) continue;
      seen.add(n);
      const v = vulns[n];
      if (!v || !own(v)) return false;
      for (const via of v.via) if (typeof via === "string") queue.push(via);
    }
    return true;
  };
  for (const [name, v] of Object.entries(vulns)) {
    if (BLOCKING.has(v.severity) && !covered(name)) out.push(`${name} (${v.severity}) at ${v.nodes.join(", ")}: ${v.via.map((via) => (typeof via === "string" ? via : via.url)).join(", ")}`);
  }
  return out;
}

// Run as a script. Both sides are resolved through symlinks: a guard that never matched would exit 0 without auditing.
const realpath = (p) => {
  try {
    return realpathSync(p);
  } catch {
    return p;
  }
};
if (process.argv[1] && realpath(fileURLToPath(import.meta.url)) === realpath(process.argv[1])) {
  let raw;
  try {
    // --offline=false: an offline npm (.npmrc or npm_config_offline) returns an empty report with no error.
    raw = execFileSync("npm", ["audit", "--omit=dev", "--json", "--offline=false"], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"], maxBuffer: 64 * 1024 * 1024 });
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
  if (report?.error) {
    console.error(`audit-gate: npm audit failed: ${JSON.stringify(report.error).slice(0, 300)}`);
    process.exit(1);
  }
  // Only the format this gate reads: any other report (a future npm's) would have no `vulnerabilities` and pass.
  if (report?.auditReportVersion !== 2 || typeof report.vulnerabilities !== "object" || report.vulnerabilities === null) {
    console.error(`audit-gate: unexpected npm audit report (auditReportVersion ${JSON.stringify(report?.auditReportVersion)}); update the gate to read it`);
    process.exit(1);
  }
  let failed;
  try {
    failed = failures(report);
  } catch (err) {
    console.error(`audit-gate: could not check the report: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }
  const counts = report.metadata?.vulnerabilities ?? {};
  if (failed.length) {
    console.error(`audit-gate: ${failed.length} blocking finding(s):\n- ${failed.join("\n- ")}`);
    process.exit(1);
  }
  const accepted = Object.values(report.vulnerabilities ?? {}).filter((v) => BLOCKING.has(v.severity)).length;
  console.log(`audit-gate: ok (${JSON.stringify(counts)}; ${accepted} high/critical finding(s) covered by ${ACCEPTED.map((a) => a.advisory).join(", ")})`);
}
