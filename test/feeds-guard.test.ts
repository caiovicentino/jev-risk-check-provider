// The feeds workflow's guard (security review F7a): a manifest that changed implausibly since the
// published one is not signed. The decision function, the CLI's exit codes, and the workflow's
// wiring: the guard comes from the run's own checkout and runs before the signing step.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { feedsGuard, LIMITS, ofacSetGuard } from "../scripts/feeds-guard.mjs";

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

/** An ofac-sdn.json snapshot (exact text) and a manifest naming it. */
function ofac(addresses: string[]) {
  const text = JSON.stringify({ meta: { publish_date: "2026-10-01" }, rows: addresses.map((a, i) => [a, "ETH", i, "X"]) });
  return { text, manifest: { ofac: { json_sha256: createHash("sha256").update(text).digest("hex") } } };
}
const A = "0x" + "a".repeat(40);
const B = "0x" + "b".repeat(40);
const C = "0x" + "c".repeat(40);

test("OFAC address sets: additions pass; any published address missing from the new list is refused (counts only)", () => {
  const before = ofac([A, B]);
  assert.deepEqual(ofacSetGuard(ofac([A, B, C]).manifest, before.manifest, ofac([A, B, C]).text, before.text), []);
  // A tampered build that drops one sanctioned address and adds a junk one keeps the count: still refused.
  const swapped = ofac([A, C]);
  const reasons = ofacSetGuard(swapped.manifest, before.manifest, swapped.text, before.text);
  assert.deepEqual(reasons, ["OFAC: 1 address(es) of the published list are missing from the new one (a delisting must be reviewed; publish it with override)"]);
  assert.ok(!reasons.join(" ").includes(B), "no address is ever printed");
});

test("OFAC address sets fail closed: each snapshot must be the one its manifest names, and well formed", () => {
  const before = ofac([A, B]);
  const next = ofac([A, B]);
  assert.deepEqual(ofacSetGuard(next.manifest, before.manifest, null, before.text), ["new OFAC snapshot: missing, or not the one the manifest names"]);
  assert.deepEqual(ofacSetGuard(before.manifest, before.manifest, next.text.replace("ETH", "XBT"), before.text), ["new OFAC snapshot: missing, or not the one the manifest names"]);
  assert.deepEqual(ofacSetGuard(next.manifest, before.manifest, next.text, null), ["no published OFAC snapshot to compare with"]);
  assert.deepEqual(ofacSetGuard(next.manifest, ofac([A]).manifest, next.text, before.text), ["published OFAC snapshot: not the one the published manifest names"]);
  const bad = '{"rows":[[1,"ETH",0,"X"]]}';
  assert.deepEqual(ofacSetGuard({ ofac: { json_sha256: createHash("sha256").update(bad).digest("hex") } }, before.manifest, bad, before.text), ["new OFAC snapshot: malformed rows"]);
});

test("the CLI with both OFAC snapshots refuses a delisting and passes an addition", () => {
  const dir = mkdtempSync(join(tmpdir(), "feeds-guard-ofac-"));
  const write = (name: string, value: string) => {
    writeFileSync(join(dir, name), value);
    return join(dir, name);
  };
  const before = ofac([A, B]);
  const after = ofac([A, B, C]);
  const dropped = ofac([A, C]);
  const published = write("published.json", JSON.stringify({ ...PUBLISHED, ofac: { ...PUBLISHED.ofac, ...before.manifest.ofac } }));
  const run = (snapshot: { text: string; manifest: { ofac: { json_sha256: string } } }) => {
    const m = next({ ofac: { ...snapshot.manifest.ofac } });
    return spawnSync(process.execPath, ["scripts/feeds-guard.mjs", write("next.json", JSON.stringify(m)), published, write("next-ofac.json", snapshot.text), write("published-ofac.json", before.text)], { encoding: "utf8", env: { PATH: process.env.PATH ?? "" } });
  };
  const ok = run(after);
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  assert.match(ok.stdout, /none delisted/);
  const refused = run(dropped);
  assert.equal(refused.status, 1);
  assert.match(refused.stdout, /^::error title=feeds guard::OFAC: 1 address\(es\) of the published list are missing/m);
});

test("the publish job's staging step takes exactly the expected regular files: a planted .git, a symlink or an extra file is refused", () => {
  const workflow = readFileSync(new URL("../.github/workflows/feeds.yml", import.meta.url), "utf8");
  const step = workflow.slice(workflow.indexOf("- name: Stage the expected files"));
  const script = step.slice(step.indexOf("run: |") + "run: |".length, step.indexOf("\n      - name:")).replace(/^ {10}/gm, "");
  const expected = ["README.md", "manifest.json", "metamask-phishing.bin", "metamask.json", "ofac-sdn.json"];
  const stage = (prepare: (out: string) => void) => {
    const dir = mkdtempSync(join(tmpdir(), "feeds-stage-"));
    const out = join(dir, "feeds-out");
    mkdirSync(out);
    for (const f of expected) writeFileSync(join(out, f), f);
    prepare(out);
    return { run: spawnSync("bash", ["-c", script], { cwd: dir, encoding: "utf8" }), dir };
  };
  const clean = stage(() => undefined);
  assert.equal(clean.run.status, 0, clean.run.stdout + clean.run.stderr);
  assert.deepEqual(readdirSync(join(clean.dir, "staged")).sort(), [...expected].sort());
  const planted = stage((out) => {
    mkdirSync(join(out, ".git"));
    writeFileSync(join(out, ".git", "config"), "[core]\n\tfsmonitor = touch pwned\n");
  });
  assert.equal(planted.run.status, 1);
  assert.match(planted.run.stdout, /does not hold exactly the 5 expected files/);
  assert.ok(!existsSync(join(planted.dir, "staged")), "nothing staged");
  const linked = stage((out) => {
    rmSync(join(out, "README.md"));
    symlinkSync("/etc/hosts", join(out, "README.md"));
  });
  assert.equal(linked.run.status, 1);
  assert.match(linked.run.stdout, /not a regular file/);
  const extra = stage((out) => writeFileSync(join(out, "extra.txt"), "x"));
  assert.equal(extra.run.status, 1);
});

test("the workflow runs the guard from its own checkout before signing, with plain node and SHA-pinned actions", () => {
  const workflow = readFileSync(new URL("../.github/workflows/feeds.yml", import.meta.url), "utf8");
  const publish = workflow.slice(workflow.indexOf("\n  publish:"));
  assert.ok(publish.length > 0 && publish.length < workflow.length, "the publish job");
  const stage = publish.indexOf("name: Stage the expected files");
  const guard = publish.indexOf("node trusted/scripts/feeds-guard.mjs staged/manifest.json published-manifest.json staged/ofac-sdn.json published-ofac-sdn.json");
  const sign = publish.indexOf("c.sign(null,");
  assert.ok(stage > 0 && guard > stage && sign > guard, "stage, then the guard, then the signing step");
  // Git never runs over the artifact: only over the staged copies, with no inherited config, hook or fsmonitor.
  assert.match(publish, /working-directory: staged/);
  assert.match(publish, /GIT_CONFIG_NOSYSTEM: "1"\n\s+GIT_CONFIG_GLOBAL: \/dev\/null/);
  assert.match(publish, /-c core\.fsmonitor=false -c core\.hooksPath=\/dev\/null/);
  assert.doesNotMatch(publish, /git add -A|cd feeds-out/);
  assert.match(publish, /readFileSync\("staged\/manifest\.json"\)/);
  assert.match(publish, /sparse-checkout: scripts\/feeds-guard\.mjs\n\s+sparse-checkout-cone-mode: false\n\s+path: trusted/);
  assert.doesNotMatch(publish, /npm (ci|install)|npx /, "nothing is installed in the publish job");
  for (const [, ref] of workflow.matchAll(/uses: [\w.-]+\/[\w.-]+@(\S+)/g)) assert.match(ref ?? "", /^[0-9a-f]{40}$/, "pinned to a commit SHA");
  const script = readFileSync(new URL("../scripts/feeds-guard.mjs", import.meta.url), "utf8");
  const imports = [...script.matchAll(/^import .* from "([^"]+)";$/gm)].map((m) => m[1]);
  assert.ok(imports.length > 0 && imports.every((m) => m?.startsWith("node:")), `only node:* imports: ${imports.join(", ")}`);
  assert.doesNotMatch(script, /\brequire\(|\bimport\(/);
});
