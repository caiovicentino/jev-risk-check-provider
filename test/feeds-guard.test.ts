// The feeds workflow's guard (security review F7a): a manifest that changed implausibly since the
// published one is not signed. The decision function, the CLI's exit codes, and the workflow's
// wiring: the guard comes from the run's own checkout and runs before the signing step.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { feedsGuard, LIMITS } from "../scripts/feeds-guard.mjs";

const NOW = Date.parse("2026-10-02T12:00:00Z");
const PUBLISHED = {
  format: 1,
  generated_at: "2026-10-01T05:20:00.000Z",
  metamask: { as_of: "2026-10-01", commit: "a".repeat(40), entries: 100_000, bin_sha256: "0".repeat(64), json_sha256: "1".repeat(64) },
  ofac: { publish_date: "2026-09-30", addresses: 1000, json_sha256: "2".repeat(64), xml_sha256: "3".repeat(64) },
};
type Manifest = typeof PUBLISHED;

/** The next day's manifest, with `patch` applied. */
function next(patch: { generated_at?: string; metamask?: Partial<Manifest["metamask"]>; ofac?: Partial<Manifest["ofac"]> } = {}): Manifest {
  return {
    ...PUBLISHED,
    generated_at: patch.generated_at ?? "2026-10-02T05:20:00.000Z",
    metamask: { ...PUBLISHED.metamask, as_of: "2026-10-02", ...patch.metamask },
    ofac: { ...PUBLISHED.ofac, publish_date: "2026-10-01", ...patch.ofac },
  };
}

test("the bounds are the documented ones", () => {
  assert.deepEqual({ ...LIMITS }, { ofacMaxShrink: 0.05, ofacMaxGrowth: 0.5, metamaskMaxChange: 0.2, maxAheadMs: 86_400_000 });
});

test("an ordinary day is signed, and so is a re-run on the same dates", () => {
  assert.deepEqual(feedsGuard(next(), PUBLISHED, NOW), []);
  assert.deepEqual(feedsGuard(next({ metamask: { as_of: "2026-10-01", entries: 100_150 }, ofac: { publish_date: "2026-09-30" } }), PUBLISHED, NOW), []);
});

test("OFAC: more than 5% fewer addresses or more than 50% more is refused; the bounds themselves pass", () => {
  const at = (addresses: number) => feedsGuard(next({ ofac: { addresses } }), PUBLISHED, NOW);
  assert.deepEqual(at(950), []);
  assert.deepEqual(at(949), ["OFAC addresses shrank by 5.1% (1000 → 949), more than 5.0%"]);
  assert.deepEqual(at(1500), []);
  assert.deepEqual(at(1501), ["OFAC addresses grew by 50.1% (1000 → 1501), more than 50.0%"]);
});

test("MetaMask: a move of more than 20% either way is refused", () => {
  const at = (entries: number) => feedsGuard(next({ metamask: { entries } }), PUBLISHED, NOW);
  assert.deepEqual(at(120_000), []);
  assert.deepEqual(at(80_000), []);
  assert.deepEqual(at(125_000), ["MetaMask entries moved by 25.0% (100000 → 125000), more than 20.0%"]);
  assert.deepEqual(at(79_000), ["MetaMask entries moved by -21.0% (100000 → 79000), more than 20.0%"]);
});

test("a date that goes backwards, or runs ahead of the clock, is refused", () => {
  assert.deepEqual(feedsGuard(next({ metamask: { as_of: "2026-09-30" } }), PUBLISHED, NOW), ["metamask.as_of went backwards: 2026-10-01 → 2026-09-30"]);
  assert.deepEqual(feedsGuard(next({ ofac: { publish_date: "2026-09-29" } }), PUBLISHED, NOW), ["ofac.publish_date went backwards: 2026-09-30 → 2026-09-29"]);
  assert.deepEqual(feedsGuard(next({ generated_at: "2026-10-01T05:19:59.000Z" }), PUBLISHED, NOW), ["generated_at went backwards: 2026-10-01T05:20:00.000Z → 2026-10-01T05:19:59.000Z"]);
  // Signing a future date would make every later, correct publish look like it went backwards.
  assert.deepEqual(feedsGuard(next({ metamask: { as_of: "2026-10-03" } }), PUBLISHED, NOW), [], "a day ahead (time zones) passes");
  assert.deepEqual(feedsGuard(next({ ofac: { publish_date: "2099-01-01" } }), PUBLISHED, NOW), ["ofac.publish_date 2099-01-01 is in the future"]);
  assert.deepEqual(feedsGuard(next({ metamask: { as_of: "2026-10-04" } }), null, NOW), ["metamask.as_of 2026-10-04 is in the future", "no published manifest to compare with"]);
});

test("fail closed: no published manifest, or a missing or malformed field in either, is a refusal", () => {
  assert.deepEqual(feedsGuard(next(), null, NOW), ["no published manifest to compare with"]);
  assert.deepEqual(feedsGuard(null, PUBLISHED, NOW), ["new manifest: generated_at, metamask.as_of, ofac.publish_date, metamask.entries, ofac.addresses missing or invalid"]);
  assert.deepEqual(feedsGuard(next({ metamask: { entries: 0 } }), PUBLISHED, NOW), ["new manifest: metamask.entries missing or invalid"]);
  assert.deepEqual(feedsGuard({ ...next(), ofac: { ...next().ofac, addresses: "1000" } }, PUBLISHED, NOW), ["new manifest: ofac.addresses missing or invalid"]);
  assert.deepEqual(feedsGuard(next(), { ...PUBLISHED, metamask: { ...PUBLISHED.metamask, as_of: "2026-10-1" } }, NOW), ["published manifest: metamask.as_of missing or invalid"]);
  // Values are printed as workflow commands: one that is not in the strict format is never echoed.
  const injected = feedsGuard(next({ generated_at: "2026-10-02T05:20:00.000Z\n::warning::x" }), PUBLISHED, NOW);
  assert.deepEqual(injected, ["new manifest: generated_at missing or invalid"]);
});

test("the CLI: exit 0 to sign, 1 when refused, 0 with the reasons as warnings under the manual override", () => {
  const dir = mkdtempSync(join(tmpdir(), "feeds-guard-"));
  const write = (name: string, value: unknown) => {
    writeFileSync(join(dir, name), JSON.stringify(value));
    return join(dir, name);
  };
  const run = (nextPath: string, publishedPath: string, env: Record<string, string> = {}) =>
    spawnSync(process.execPath, ["scripts/feeds-guard.mjs", nextPath, publishedPath], { encoding: "utf8", env: { PATH: process.env.PATH ?? "", ...env } });
  // A real run compares with today's clock: the fixture's dates are in the past by then.
  const ok = run(write("next.json", next()), write("published.json", PUBLISHED));
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  assert.match(ok.stdout, /^feeds guard: ok/);
  const shrunk = write("shrunk.json", next({ ofac: { addresses: 900 } }));
  const refused = run(shrunk, join(dir, "published.json"));
  assert.equal(refused.status, 1);
  assert.match(refused.stdout, /^::error title=feeds guard::OFAC addresses shrank by 10\.0%/m);
  assert.equal(run(write("missing-published.json", next()), join(dir, "nothing-here.json")).status, 1, "no published manifest");
  const overridden = run(shrunk, join(dir, "published.json"), { FEEDS_GUARD_OVERRIDE: "1" });
  assert.equal(overridden.status, 0);
  assert.match(overridden.stdout, /^::warning title=feeds guard \(overridden\)::OFAC addresses shrank/m);
});

test("the workflow runs the guard from its own checkout before signing, with plain node and SHA-pinned actions", () => {
  const workflow = readFileSync(new URL("../.github/workflows/feeds.yml", import.meta.url), "utf8");
  const publish = workflow.slice(workflow.indexOf("\n  publish:"));
  assert.ok(publish.length > 0 && publish.length < workflow.length, "the publish job");
  const guard = publish.indexOf("node trusted/scripts/feeds-guard.mjs feeds-out/manifest.json published-manifest.json");
  const sign = publish.indexOf("c.sign(null,");
  assert.ok(guard > 0 && sign > guard, "the guard runs before the signing step");
  assert.match(publish, /sparse-checkout: scripts\/feeds-guard\.mjs\n\s+sparse-checkout-cone-mode: false\n\s+path: trusted/);
  assert.doesNotMatch(publish, /npm (ci|install)|npx /, "nothing is installed in the publish job");
  for (const [, ref] of workflow.matchAll(/uses: [\w.-]+\/[\w.-]+@(\S+)/g)) assert.match(ref ?? "", /^[0-9a-f]{40}$/, "pinned to a commit SHA");
  const script = readFileSync(new URL("../scripts/feeds-guard.mjs", import.meta.url), "utf8");
  const imports = [...script.matchAll(/^import .* from "([^"]+)";$/gm)].map((m) => m[1]);
  assert.ok(imports.length > 0 && imports.every((m) => m?.startsWith("node:")), `only node:* imports: ${imports.join(", ")}`);
  assert.doesNotMatch(script, /\brequire\(|\bimport\(/);
});
