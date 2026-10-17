// The 2026-10-17 review (low): scripts/publish-npm.sh took the tarball's name from the last line
// `npm pack --silent` printed. A lifecycle script writes to that same stdout (npm runs prepack with
// its stdio inherited), so build output printed after the name handed check-publish and `npm
// publish` the wrong file. `npm pack --json` alone is no cure: the build's output comes first, on
// the same stdout, and the report cannot be parsed. The script now runs each package's prepack
// itself, packs with --json --ignore-scripts (its stdout is then the report alone), and reads
// `filename` from the JSON with node. Local only: fixtures packed in a temp dir, never published.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT = fileURLToPath(new URL("../../../scripts/publish-npm.sh", import.meta.url));
const source = readFileSync(SCRIPT, "utf8");
const TEMP = mkdtempSync(join(tmpdir(), "x402check-publish-script-"));
after(() => rmSync(TEMP, { recursive: true, force: true }));

/** The script's own packed_tgz function, as its source defines it. */
const helper = /^packed_tgz\(\) \{\n[\s\S]*?\n\}\n/m.exec(source)?.[0] ?? "";
const PACK_LINE = "tgz=$(npm pack --json --ignore-scripts | packed_tgz)";
const TGZ = "x402check-pack-probe-1.0.0.tgz";

/** A package whose build (prepack) prints, and leaves a process that prints after npm is done. */
function noisyPackage(): string {
  const dir = mkdtempSync(join(TEMP, "pkg-"));
  mkdirSync(join(dir, "dist"));
  writeFileSync(join(dir, "dist", "index.js"), "export {};\n");
  const prepack = "echo built; echo '[]'; (sleep 0.5; echo late-build-output) &";
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@x402check/pack-probe", version: "1.0.0", files: ["dist"], scripts: { prepack } }));
  return dir;
}

test("bash -n: the script parses", () => {
  const r = spawnSync("bash", ["-n", SCRIPT], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
});

test("each pack runs the package's prepack, then npm pack --json --ignore-scripts, and reads the name from the report", () => {
  assert.doesNotMatch(source, /\| *tail\b/, "never the last line of npm's output");
  assert.ok(helper.includes("node -e"), "packed_tgz reads the JSON with node");
  const packs = source.match(/^\s*tgz=.*$/gm) ?? [];
  assert.deepEqual(
    packs.map((line) => line.trim()),
    [PACK_LINE, PACK_LINE],
    "the client and the MCP server",
  );
  assert.equal(source.split(`npm run prepack\n`).length - 1, 2, "prepack runs right before each pack");
  assert.equal((source.match(/npm run prepack\n\s*tgz=\$\(npm pack --json --ignore-scripts \| packed_tgz\)/g) ?? []).length, 2);
});

test("the packages have no other pack-time script, which --ignore-scripts would skip", () => {
  for (const pkg of ["client", "mcp"]) {
    const scripts = (JSON.parse(readFileSync(new URL(`../../${pkg}/package.json`, import.meta.url), "utf8")) as { scripts: Record<string, string> }).scripts;
    assert.equal(scripts.prepack, "npm run build", pkg);
    for (const name of ["prepare", "postpack"]) assert.equal(scripts[name], undefined, `${pkg}: npm pack would run ${name}, and publish-npm.sh does not`);
  }
});

test("with a build that prints around the pack, the old pipeline names the wrong file; the script's names the tarball", () => {
  const dir = noisyPackage();
  // What the script did before: the last line npm pack printed.
  const old = execFileSync("bash", ["-c", "set -euo pipefail\nnpm pack --silent | tail -n 1"], { cwd: dir, encoding: "utf8" }).trim();
  assert.equal(old, "late-build-output", "the build's late line, not the tarball");
  rmSync(join(dir, TGZ));
  // --json alone: the build's output comes first on the same stdout, so the report cannot be parsed.
  const jsonOnly = execFileSync("npm", ["pack", "--json"], { cwd: dir, encoding: "utf8" });
  assert.throws(() => JSON.parse(jsonOnly) as unknown, SyntaxError);
  rmSync(join(dir, TGZ));
  // What the script does now (its prepack's output goes to the terminal, never into the name).
  const now = execFileSync("bash", ["-c", `set -euo pipefail\n${helper}npm run prepack >&2\n${PACK_LINE}\nprintf %s "$tgz"`], { cwd: dir, encoding: "utf8" });
  assert.equal(now, TGZ);
});

test("packed_tgz refuses anything but one .tgz that the report names in the current directory", () => {
  const dir = mkdtempSync(join(TEMP, "reports-"));
  writeFileSync(join(dir, "a-1.0.0.tgz"), "");
  const run = (report: string) => spawnSync("bash", ["-c", `${helper}packed_tgz`], { cwd: dir, input: report, encoding: "utf8" });
  const good = run(JSON.stringify([{ filename: "a-1.0.0.tgz" }]));
  assert.deepEqual([good.status, good.stdout], [0, "a-1.0.0.tgz"]);
  for (const report of [
    `built\n${JSON.stringify([{ filename: "a-1.0.0.tgz" }])}`,
    JSON.stringify([]),
    JSON.stringify([{ filename: "a-1.0.0.tgz" }, { filename: "a-1.0.0.tgz" }]),
    JSON.stringify({ filename: "a-1.0.0.tgz" }),
    JSON.stringify([{ filename: "../a-1.0.0.tgz" }]),
    JSON.stringify([{ filename: "missing-1.0.0.tgz" }]),
    JSON.stringify([{ filename: "a-1.0.0.tar" }]),
    JSON.stringify([null]),
    "",
  ]) {
    const r = run(report);
    assert.deepEqual([r.status, r.stdout], [1, ""], report);
    assert.match(r.stderr, /npm pack --json did not report exactly one \.tgz in this directory/, report);
  }
});
