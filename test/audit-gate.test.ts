// CI's production dependency audit (scripts/audit-gate.mjs): high and critical findings fail, except
// an advisory accepted for exact install paths, with a reason and a review date.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ACCEPTED, failures, type AuditReport } from "../scripts/audit-gate.mjs";

const ZOD = "https://github.com/advisories/GHSA-mrhx-c7xc-m3w5";
const TODAY = "2026-10-24";
// The shape npm audit --json gave on 2026-10-24 once the top-level zod was 4.6.7.
const accepted: AuditReport = {
  vulnerabilities: {
    zod: { severity: "high", nodes: ["node_modules/@x402/core/node_modules/zod", "node_modules/@x402/evm/node_modules/zod"], via: [{ url: ZOD }] },
    "@x402/core": { severity: "high", nodes: ["node_modules/@x402/core"], via: ["zod"] },
    "@x402/evm": { severity: "high", nodes: ["node_modules/@x402/evm"], via: ["@x402/core", "zod"] },
    "@x402/fetch": { severity: "high", nodes: ["node_modules/@x402/fetch"], via: ["@x402/core"] },
  },
};

test("the accepted advisory on its own paths passes, packages flagged only through it included", () => {
  assert.deepEqual(failures(accepted, TODAY), []);
  assert.deepEqual(failures({ vulnerabilities: {} }, TODAY), []);
});

test("the same advisory on another path fails: the top-level zod is not covered", () => {
  const report = structuredClone(accepted);
  report.vulnerabilities!.zod!.nodes.push("node_modules/zod");
  const failed = failures(report, TODAY);
  assert.equal(failed.length, 4, `zod and the three x402 packages flagged through it\n${failed.join("\n")}`);
  assert.match(failed.join("\n"), /zod \(high\) at .*node_modules\/zod: .*GHSA-mrhx-c7xc-m3w5/);
});

test("any other high or critical advisory fails, also through an accepted package; moderate and low do not", () => {
  const other = structuredClone(accepted);
  other.vulnerabilities!["body-parser"] = { severity: "high", nodes: ["node_modules/body-parser"], via: [{ url: "https://github.com/advisories/GHSA-27r3-jxmh-p828" }] };
  assert.deepEqual(failures(other, TODAY), ["body-parser (high) at node_modules/body-parser: https://github.com/advisories/GHSA-27r3-jxmh-p828"]);
  const mixed = structuredClone(accepted);
  mixed.vulnerabilities!["@x402/core"]!.via.push({ url: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz" });
  assert.equal(failures(mixed, TODAY).length, 3, "@x402/core and the two in the report flagged through it");
  const moderate = structuredClone(accepted);
  moderate.vulnerabilities!["fast-uri"] = { severity: "moderate", nodes: ["node_modules/fast-uri"], via: [{ url: "https://github.com/advisories/GHSA-w74x-v6f9-j3xg" }] };
  assert.deepEqual(failures(moderate, TODAY), []);
});

test("an acceptance past its review date fails, so it is looked at again", () => {
  const [zod] = ACCEPTED;
  assert.ok(zod && zod.reason.length > 100 && /^\d{4}-\d{2}-\d{2}$/.test(zod.review));
  assert.match(failures(accepted, "2099-01-01").join("\n"), /past its review date/);
});

test("CI runs the gate, not a bare npm audit, in the root and in every package", () => {
  const ci = readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
  assert.doesNotMatch(ci, /npm audit --omit=dev --audit-level/);
  assert.match(ci, /run: node scripts\/audit-gate\.mjs/);
  assert.match(ci, /run: node \.\.\/\.\.\/scripts\/audit-gate\.mjs/);
});
