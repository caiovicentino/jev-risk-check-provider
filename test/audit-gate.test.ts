// CI's production dependency audit (scripts/audit-gate.mjs): high and critical findings fail, except
// an advisory accepted for exact install paths and versions, with a reason and a review date.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { ACCEPTED, failures, type AuditReport } from "../scripts/audit-gate.mjs";

const ZOD = "https://github.com/advisories/GHSA-mrhx-c7xc-m3w5";
const TODAY = "2026-10-24";
const X402_ZOD = ["node_modules/@x402/core/node_modules/zod", "node_modules/@x402/evm/node_modules/zod"];
// The versions in the lockfile: x402's zod 3 copies, and the top-level zod.
const lock: Record<string, string> = { [X402_ZOD[0]!]: "3.25.76", [X402_ZOD[1]!]: "3.25.76", "node_modules/zod": "4.6.5" };
const installed = (node: string) => lock[node];
// The shape npm audit --json gave on 2026-10-24 once the top-level zod was 4.6.7.
const accepted: AuditReport = {
  vulnerabilities: {
    zod: { severity: "high", nodes: [...X402_ZOD], via: [{ url: ZOD, severity: "high" }] },
    "@x402/core": { severity: "high", nodes: ["node_modules/@x402/core"], via: ["zod"] },
    "@x402/evm": { severity: "high", nodes: ["node_modules/@x402/evm"], via: ["@x402/core", "zod"] },
    "@x402/fetch": { severity: "high", nodes: ["node_modules/@x402/fetch"], via: ["@x402/core"] },
  },
};

test("the accepted advisory on its own paths passes, packages flagged only through it included", () => {
  assert.deepEqual(failures(accepted, TODAY, installed), []);
  assert.deepEqual(failures({ vulnerabilities: {} }, TODAY, installed), []);
});

test("the same advisory on another path fails: the top-level zod is not covered", () => {
  const report = structuredClone(accepted);
  report.vulnerabilities!.zod!.nodes.push("node_modules/zod");
  const failed = failures(report, TODAY, installed);
  assert.equal(failed.length, 4, `zod and the three x402 packages flagged through it\n${failed.join("\n")}`);
  assert.match(failed.join("\n"), /zod \(high\) at .*node_modules\/zod: .*GHSA-mrhx-c7xc-m3w5/);
});

test("the same advisory at an accepted path fails when another version is installed there", () => {
  const failed = failures(accepted, TODAY, (node) => (node === X402_ZOD[1] ? "4.5.0" : installed(node)));
  assert.equal(failed.length, 4, failed.join("\n"));
  assert.equal(failures(accepted, TODAY, () => undefined).length, 4, "a path the lockfile does not hold is not accepted");
});

test("any other high or critical advisory fails, also through an accepted package; moderate and low do not", () => {
  const other = structuredClone(accepted);
  other.vulnerabilities!["body-parser"] = { severity: "high", nodes: ["node_modules/body-parser"], via: [{ url: "https://github.com/advisories/GHSA-27r3-jxmh-p828", severity: "high" }] };
  assert.deepEqual(failures(other, TODAY, installed), ["body-parser (high) at node_modules/body-parser: https://github.com/advisories/GHSA-27r3-jxmh-p828"]);
  const mixed = structuredClone(accepted);
  mixed.vulnerabilities!["@x402/core"]!.via.push({ url: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz", severity: "critical" });
  assert.equal(failures(mixed, TODAY, installed).length, 3, "@x402/core and the two in the report flagged through it");
  const unrated = structuredClone(accepted);
  unrated.vulnerabilities!["@x402/core"]!.via.push({ url: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz" });
  assert.equal(failures(unrated, TODAY, installed).length, 3, "an advisory with no severity needs an acceptance too");
  const moderate = structuredClone(accepted);
  moderate.vulnerabilities!["fast-uri"] = { severity: "moderate", nodes: ["node_modules/fast-uri"], via: [{ url: "https://github.com/advisories/GHSA-w74x-v6f9-j3xg", severity: "moderate" }] };
  assert.deepEqual(failures(moderate, TODAY, installed), []);
});

test("a lesser advisory next to the accepted one, and a cycle among covered packages, pass", () => {
  const lesser = structuredClone(accepted);
  lesser.vulnerabilities!.zod!.via.push({ url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", severity: "moderate" });
  assert.deepEqual(failures(lesser, TODAY, installed), []);
  const cycle = structuredClone(accepted);
  cycle.vulnerabilities!["@x402/core"]!.via.push("@x402/evm");
  assert.deepEqual(failures(cycle, TODAY, installed), []);
  // The same cycle with an unaccepted advisory on one side fails on both sides and everything flagged through them.
  cycle.vulnerabilities!["@x402/evm"]!.via.push({ url: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz", severity: "high" });
  assert.equal(failures(cycle, TODAY, installed).length, 3, failures(cycle, TODAY, installed).join("\n"));
});

test("an acceptance past its review date fails, so it is looked at again", () => {
  const [zod] = ACCEPTED;
  assert.ok(zod && zod.reason.length > 100 && /^\d{4}-\d{2}-\d{2}$/.test(zod.review) && zod.versions.length > 0);
  assert.match(failures(accepted, "2099-01-01", installed).join("\n"), /past its review date/);
});

test("run through a symlink, the gate still audits: it never exits 0 without a report", () => {
  const dir = mkdtempSync(join(tmpdir(), "audit-gate-"));
  try {
    // No lockfile here, so npm audit answers ENOLOCK without the network, and the gate must fail on it.
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "audit-gate-test", version: "1.0.0" }));
    const link = join(dir, "gate.mjs");
    symlinkSync(fileURLToPath(new URL("../scripts/audit-gate.mjs", import.meta.url)), link);
    const run = spawnSync(process.execPath, [link], { cwd: dir, encoding: "utf8" });
    assert.equal(run.status, 1, run.stdout + run.stderr);
    assert.match(run.stderr, /audit-gate: npm audit failed: .*ENOLOCK/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a report in a format the gate does not read fails: it never passes on an empty reading", () => {
  const dir = mkdtempSync(join(tmpdir(), "audit-gate-"));
  try {
    // An npm on PATH that prints a given report, the way a future npm with another format would.
    const bin = join(dir, "bin");
    mkdirSync(bin);
    const gate = fileURLToPath(new URL("../scripts/audit-gate.mjs", import.meta.url));
    const run = (report: string) => {
      writeFileSync(join(bin, "npm"), `#!/bin/sh\necho '${report}'\n`, { mode: 0o755 });
      return spawnSync(process.execPath, [gate], { cwd: dir, encoding: "utf8", env: { ...process.env, PATH: `${bin}:${process.env.PATH}` } });
    };
    for (const report of ['{"auditReportVersion":3,"advisories":{}}', "{}", "null", '{"auditReportVersion":2}']) {
      const r = run(report);
      assert.equal(r.status, 1, `${report}: ${r.stdout}${r.stderr}`);
      assert.match(r.stderr, /audit-gate: unexpected npm audit report/, report);
    }
    const ok = run('{"auditReportVersion":2,"vulnerabilities":{},"metadata":{"vulnerabilities":{"total":0}}}');
    assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CI runs the gate, not a bare npm audit, in the root and in every package", () => {
  const ci = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
  assert.doesNotMatch(ci, /npm audit --omit=dev --audit-level/);
  assert.match(ci, /run: node scripts\/audit-gate\.mjs/);
  assert.match(ci, /run: node \.\.\/\.\.\/scripts\/audit-gate\.mjs/);
  // An offline npm (.npmrc or npm_config_offline) would return an empty report with no error.
  assert.match(readFileSync(new URL("../scripts/audit-gate.mjs", import.meta.url), "utf8"), /"--offline=false"/);
});
