// The 2026-10-16 review of the MCP package, findings M4 and L3: the npm-shrinkwrap.json a publish
// needs is in the tarball npm packs. Local only: a fixture package in a temp dir, nothing published.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { packedFiles } from "../scripts/check-publish.mjs";

const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { files: string[] };

/** A package laid out as the MCP's is at publish time, with the MCP's `files`, in a temp dir. */
function fixture(files: readonly string[]): string {
  const dir = mkdtempSync(join(tmpdir(), "x402check-mcp-pack-"));
  const name = "x402check-pack-fixture";
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name, version: "1.0.0", files }));
  writeFileSync(join(dir, "npm-shrinkwrap.json"), JSON.stringify({ name, version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": { name, version: "1.0.0" } } }));
  writeFileSync(join(dir, "README.md"), "fixture\n");
  writeFileSync(join(dir, "LICENSE"), "fixture\n");
  mkdirSync(join(dir, "dist"));
  writeFileSync(join(dir, "dist", "index.js"), "export {};\n");
  return dir;
}

test("M4: npm pack keeps the npm-shrinkwrap.json, because package.json `files` lists it", () => {
  // npm 10 packs a shrinkwrap only when `files` names it; check-publish requires it in the tarball.
  const dir = fixture(manifest.files);
  try {
    assert.deepEqual(packedFiles(dir), ["LICENSE", "README.md", "dist/index.js", "npm-shrinkwrap.json", "package.json"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
