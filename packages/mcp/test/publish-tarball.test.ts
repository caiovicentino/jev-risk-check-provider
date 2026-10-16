// The 2026-10-16 review of the MCP package, findings M4 and L3: the npm-shrinkwrap.json a publish
// needs is in the tarball npm packs; the packed .tgz itself is what is checked (`npm publish <tgz>`
// runs no prepublishOnly); and the shrinkwrap pins every package to its canonical registry tarball
// with a sha512 hash. Local only: fixtures in a temp dir, nothing installed or published.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, describe, test } from "node:test";
import { fileURLToPath } from "node:url";
import { packedFiles, packedTarballProblems, registryTarball, shrinkwrapProblems, tarballEntries } from "../scripts/check-publish.mjs";

const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { files: string[]; dependencies: Record<string, string> };
const CHECK_PUBLISH = fileURLToPath(new URL("../scripts/check-publish.mjs", import.meta.url));
const NAME = "x402check-pack-fixture";
const TEMP = mkdtempSync(join(tmpdir(), "x402check-mcp-pack-"));
after(() => rmSync(TEMP, { recursive: true, force: true }));

/** One sha512 integrity of the right length (the content is not what is checked here). */
const sri = (c: string): string => `sha512-${c.repeat(86)}==`;

/** A package laid out as the MCP's is at publish time (with the MCP's `files`), in a fresh temp dir. */
function fixture(options: { files?: readonly string[]; dependencies?: Record<string, string>; shrinkwrap?: unknown; dist?: string } = {}): string {
  const dir = mkdtempSync(join(TEMP, "pkg-"));
  const dependencies = options.dependencies ?? {};
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: NAME, version: "1.0.0", files: options.files ?? manifest.files, dependencies }));
  const shrinkwrap = options.shrinkwrap ?? { name: NAME, version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": { name: NAME, version: "1.0.0", dependencies } } };
  if (shrinkwrap !== null) writeFileSync(join(dir, "npm-shrinkwrap.json"), typeof shrinkwrap === "string" ? shrinkwrap : JSON.stringify(shrinkwrap));
  writeFileSync(join(dir, "README.md"), "fixture\n");
  writeFileSync(join(dir, "LICENSE"), "fixture\n");
  if (options.dist) cpSync(options.dist, join(dir, "dist"), { recursive: true });
  else {
    mkdirSync(join(dir, "dist"));
    for (const file of ["index.js", "index.d.ts", "server.js", "server.d.ts"]) writeFileSync(join(dir, "dist", file), "export {};\n");
  }
  return dir;
}

/** `npm pack` of a fixture: the .tgz npm would publish. */
function pack(dir: string): string {
  execFileSync("npm", ["pack", "--ignore-scripts", "--silent", "--pack-destination", dir], { cwd: dir, stdio: ["ignore", "ignore", "pipe"] });
  return join(dir, `${NAME}-1.0.0.tgz`);
}

/** A tarball holding exactly `entries` of `dir` (no directory entries, as npm packs). */
function tarOf(dir: string, entries: readonly string[]): string {
  const out = join(dir, "crafted.tgz");
  // COPYFILE_DISABLE: macOS tar would add AppleDouble (._*) entries for extended attributes.
  execFileSync("tar", ["-czf", out, "-C", dir, ...entries], { env: { ...process.env, COPYFILE_DISABLE: "1" } });
  return out;
}

test("M4: npm pack keeps the npm-shrinkwrap.json, because package.json `files` lists it", () => {
  // npm 10 packs a shrinkwrap only when `files` names it; check-publish requires it in the tarball.
  const dir = fixture();
  assert.deepEqual(packedFiles(dir), ["LICENSE", "README.md", "dist/index.d.ts", "dist/index.js", "dist/server.d.ts", "dist/server.js", "npm-shrinkwrap.json", "package.json"]);
});

describe("L3: the shrinkwrap pins every package to its registry tarball", () => {
  const MCP = { name: "@x402check/mcp", version: "0.3.1", dependencies: { "@x402check/client": "^0.5.0", viem: "2.57.4" } };
  const viem = { version: "2.57.4", resolved: "https://registry.npmjs.org/viem/-/viem-2.57.4.tgz", integrity: sri("B"), dependencies: { abitype: "1.2.3" } };
  /** A shrinkwrap shaped as `npm shrinkwrap` writes it, with entries (and top-level fields) overridden. */
  const shrinkwrap = (over: Record<string, unknown> = {}, top: Record<string, unknown> = {}) => ({
    name: MCP.name,
    version: MCP.version,
    lockfileVersion: 3,
    requires: true,
    ...top,
    packages: {
      "": { name: MCP.name, version: MCP.version, dependencies: MCP.dependencies, devDependencies: { tsx: "^4.19.0" } },
      "node_modules/@x402check/client": { version: "0.5.0", resolved: "https://registry.npmjs.org/@x402check/client/-/client-0.5.0.tgz", integrity: sri("A") },
      "node_modules/viem": viem,
      "node_modules/abitype": { version: "1.2.3", resolved: "https://registry.npmjs.org/abitype/-/abitype-1.2.3.tgz", integrity: sri("C") },
      "node_modules/tsx": { version: "4.19.0", resolved: "https://registry.npmjs.org/tsx/-/tsx-4.19.0.tgz", integrity: sri("D"), dev: true, dependencies: { esbuild: "0.28.2" } },
      "node_modules/esbuild": { version: "0.28.2", resolved: "https://registry.npmjs.org/esbuild/-/esbuild-0.28.2.tgz", integrity: sri("E"), dev: true, hasInstallScript: true },
      ...over,
    },
  });
  const problems = (sw: Record<string, unknown>): string => shrinkwrapProblems(sw, MCP).join("\n");

  test("the canonical tarball URL, scoped names included", () => {
    assert.equal(registryTarball("viem", "2.57.4"), "https://registry.npmjs.org/viem/-/viem-2.57.4.tgz");
    assert.equal(registryTarball("@x402check/client", "0.5.0"), "https://registry.npmjs.org/@x402check/client/-/client-0.5.0.tgz");
    assert.equal(problems(shrinkwrap()), "");
  });

  test("real npm output passes: the committed package-lock.json (what npm shrinkwrap renames) fails only on the local client", () => {
    // 2026-10-16: the same tree with "@x402check/client": "^0.4.0", run through npm install
    // --package-lock-only and npm shrinkwrap, passed with no problem (146 entries).
    const lock = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8")) as Record<string, unknown>;
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as typeof MCP;
    assert.deepEqual(shrinkwrapProblems(lock, pkg), [
      "../client is not pinned to the registry: it is not an installed package (node_modules/<name>)",
      "node_modules/@x402check/client is not pinned to the registry: it is a link to ../client",
    ]);
  });

  test("an integrity that is not one sha512 hash is refused", () => {
    for (const integrity of [undefined, "", "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=", `${sri("B")} sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=`, "sha512-short==", "sha384-" + "A".repeat(64)]) {
      assert.match(problems(shrinkwrap({ "node_modules/viem": { ...viem, integrity } })), /^node_modules\/viem is not pinned to the registry: its integrity is not one sha512 hash$/, String(integrity));
    }
  });

  test("a resolved URL other than that package's own registry tarball is refused", () => {
    for (const resolved of [
      "https://registry.npmjs.org/evil-viem/-/evil-viem-6.6.6.tgz",
      "https://registry.npmjs.org/viem/-/viem-2.57.5.tgz",
      "https://registry.npmjs.org.evil.com/viem/-/viem-2.57.4.tgz",
      "http://registry.npmjs.org/viem/-/viem-2.57.4.tgz",
      "git+https://github.com/x/viem.git#abc",
      "file:../viem",
      undefined,
    ]) {
      assert.match(problems(shrinkwrap({ "node_modules/viem": { ...viem, resolved } })), /^node_modules\/viem is not pinned to the registry: it resolves to .+, not https:\/\/registry\.npmjs\.org\/viem\/-\/viem-2\.57\.4\.tgz$/, String(resolved));
    }
    // A version cannot walk the URL's path to another package.
    const walk = { ...viem, version: "2.57.4/../../evil/-/evil-1.0.0", resolved: "https://registry.npmjs.org/viem/-/viem-2.57.4/../../evil/-/evil-1.0.0.tgz" };
    assert.match(problems(shrinkwrap({ "node_modules/viem": walk })), /node_modules\/viem is not pinned to the registry: its name or version is not a registry package's/);
    // An alias entry names the package it installs: its own tarball is the canonical one.
    assert.equal(problems(shrinkwrap({ "node_modules/viem-alias": { ...viem, name: "viem" } })), "");
  });

  test("development entries are held to the same rules", () => {
    assert.match(problems(shrinkwrap({ "node_modules/tsx": { version: "4.19.0", resolved: "git+ssh://git@evil.example/tsx.git", dev: true } })), /node_modules\/tsx is not pinned to the registry: it resolves to git\+ssh/);
    assert.match(problems(shrinkwrap({ "node_modules/tsx": { version: "4.19.0", resolved: "https://registry.npmjs.org/tsx/-/tsx-4.19.0.tgz", dev: true } })), /node_modules\/tsx is not pinned to the registry: its integrity/);
  });

  test("an install script is refused, except esbuild's and fsevents' as development entries", () => {
    assert.match(problems(shrinkwrap({ "node_modules/viem": { ...viem, hasInstallScript: true } })), /^node_modules\/viem runs an install script \(hasInstallScript\), and only these development entries may: esbuild, fsevents$/);
    const esbuild = { version: "0.28.2", resolved: "https://registry.npmjs.org/esbuild/-/esbuild-0.28.2.tgz", integrity: sri("E"), hasInstallScript: true };
    assert.match(problems(shrinkwrap({ "node_modules/esbuild": esbuild })), /node_modules\/esbuild runs an install script/, "not as a production entry");
    assert.match(problems(shrinkwrap({ "node_modules/esbuild": { ...esbuild, devOptional: true } })), /node_modules\/esbuild runs an install script/, "devOptional is installed for users");
    const fsevents = { version: "2.3.3", resolved: "https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz", integrity: sri("F"), dev: true, optional: true, hasInstallScript: true };
    assert.equal(problems(shrinkwrap({ "node_modules/fsevents": fsevents })), "");
  });

  test("lockfileVersion 3 only, with no legacy section; the message names the version", () => {
    const v2 = problems(shrinkwrap({}, { lockfileVersion: 2, dependencies: { viem: { version: "git+https://evil.example/viem.git" } } }));
    assert.match(v2, /npm-shrinkwrap\.json has lockfileVersion 2: a publish needs lockfileVersion 3/);
    assert.match(v2, /legacy "dependencies" section/);
    const v1 = problems({ name: MCP.name, version: MCP.version, lockfileVersion: 1, dependencies: {} });
    assert.match(v1, /lockfileVersion 1: a publish needs lockfileVersion 3/);
    assert.match(v1, /no "packages" section/);
    assert.doesNotMatch(v1, /is for @x402check\/mcp@0\.3\.1, not/, "it is for this package: the old message said otherwise");
  });

  test("the root asks for exactly package.json's dependencies", () => {
    const root = { name: MCP.name, version: MCP.version, dependencies: { ...MCP.dependencies, "left-pad": "1.3.0" } };
    assert.match(problems(shrinkwrap({ "": root })), /npm-shrinkwrap\.json asks for left-pad, which package\.json does not/);
  });

  test("what users install is never marked dev, and everything it needs is pinned", () => {
    assert.match(problems(shrinkwrap({ "node_modules/viem": { ...viem, dev: true } })), /node_modules\/viem is installed for users, but npm-shrinkwrap\.json marks it dev/);
    const abitype = { version: "1.2.3", resolved: "https://registry.npmjs.org/abitype/-/abitype-1.2.3.tgz", integrity: sri("C") };
    assert.match(problems(shrinkwrap({ "node_modules/abitype": { ...abitype, dev: true } })), /node_modules\/abitype is installed for users, but npm-shrinkwrap\.json marks it dev/, "a dependency of a dependency");
    const { "node_modules/abitype": _dropped, ...packages } = shrinkwrap().packages;
    assert.match(problems({ ...shrinkwrap(), packages }), /node_modules\/viem needs abitype, which npm-shrinkwrap\.json does not pin/);
    // Resolved as Node does: a nested copy is the one viem uses, so the top-level one may be dev.
    assert.equal(problems(shrinkwrap({ "node_modules/viem/node_modules/abitype": abitype, "node_modules/abitype": { ...abitype, dev: true } })), "");
    // Optional dependencies and optional peers may be absent (another platform's); required peers may not.
    const peers = { ...viem, optionalDependencies: { "@esbuild/aix-ppc64": "0.28.2" }, peerDependencies: { typescript: ">=5", zod: "^4" }, peerDependenciesMeta: { typescript: { optional: true } } };
    assert.match(problems(shrinkwrap({ "node_modules/viem": peers })), /^node_modules\/viem needs zod, which npm-shrinkwrap\.json does not pin$/);
  });

  test("a bundled entry is pinned by the package it is bundled in", () => {
    assert.equal(problems(shrinkwrap({ "node_modules/viem/node_modules/b": { version: "1.0.0", inBundle: true } })), "");
    assert.match(problems(shrinkwrap({ "node_modules/b": { version: "1.0.0", inBundle: true } })), /node_modules\/b is not pinned to the registry: it is bundled, but not inside a package/);
    assert.match(problems(shrinkwrap({ "node_modules/viem/node_modules/b": { version: "1.0.0", inBundle: true, hasInstallScript: true } })), /node_modules\/viem\/node_modules\/b runs an install script/);
  });
});

describe("L3: --tarball checks the packed .tgz itself", () => {
  test("a tarball npm packed, with a shrinkwrap that pins its tree, passes", () => {
    const tgz = pack(fixture());
    assert.ok(tarballEntries(tgz).every((entry) => entry.startsWith("package/")));
    assert.deepEqual(packedTarballProblems(tgz, ["index", "server"]), []);
  });

  test("what it holds is checked: a local dependency, no shrinkwrap, an unpinned shrinkwrap, a stale build", () => {
    const local = { "@x402check/client": "file:../client" };
    const linked = { name: NAME, version: "1.0.0", lockfileVersion: 3, packages: { "": { name: NAME, version: "1.0.0", dependencies: local }, "node_modules/@x402check/client": { resolved: "../client", link: true } } };
    const withLocal = packedTarballProblems(pack(fixture({ dependencies: local, shrinkwrap: linked })), ["index", "server"]).join("\n");
    assert.match(withLocal, /the tarball's package\.json has a local dependency: @x402check\/client@file:\.\.\/client/);
    assert.match(withLocal, /node_modules\/@x402check\/client is not pinned to the registry: it is a link to \.\.\/client/);
    assert.match(packedTarballProblems(pack(fixture({ files: ["dist", "README.md", "LICENSE"] })), ["index", "server"]).join("\n"), /missing from the tarball: npm-shrinkwrap\.json/);
    assert.match(packedTarballProblems(pack(fixture({ shrinkwrap: "{ not json" })), ["index", "server"]).join("\n"), /package\/npm-shrinkwrap\.json cannot be read as JSON/);
    assert.match(packedTarballProblems(pack(fixture()), ["index", "server", "payer"]).join("\n"), /src\/payer\.ts is not built into dist\/payer\.js/);
  });

  test("an entry outside package/, a file listed twice, or an unexpected file is refused", () => {
    // The fixture's files under package/, as npm lays them out, then packed by tar with chosen entries.
    const dir = fixture();
    mkdirSync(join(dir, "package"));
    for (const f of ["package.json", "README.md", "LICENSE", "npm-shrinkwrap.json", "dist"]) cpSync(join(dir, f), join(dir, "package", f), { recursive: true });
    const files = ["package/package.json", "package/README.md", "package/LICENSE", "package/npm-shrinkwrap.json", ...["index.js", "index.d.ts", "server.js", "server.d.ts"].map((f) => `package/dist/${f}`)];
    const content = (entries: readonly string[]): string => packedTarballProblems(tarOf(dir, entries), ["index", "server"]).join("\n");
    assert.equal(content(files), "", "the same files, packed by tar, pass");
    writeFileSync(join(dir, "package", ".npmrc"), "registry=https://evil.example/\n");
    mkdirSync(join(dir, "other"));
    writeFileSync(join(dir, "other", "x.js"), "\n");
    assert.match(content([...files, "package/.npmrc"]), /unexpected file in the tarball: \.npmrc/);
    assert.match(content([...files, "other/x.js"]), /unexpected entry in the tarball, outside package\/: other\/x\.js/);
    const twice = content([...files, "package/package.json"]);
    assert.match(twice, /the tarball holds package\/package\.json more than once/);
    assert.match(twice, /package\/package\.json cannot be read as JSON/, "tar prints both copies");
  });

  test("the command: exit 0 for a tarball that passes, 1 for one that does not, 2 for a usage error", () => {
    // The MCP's own dist/ (`npm test` builds it first), so the command's default modules (src/) match.
    const dist = fileURLToPath(new URL("../dist", import.meta.url));
    const run = (...args: string[]) => spawnSync(process.execPath, [CHECK_PUBLISH, ...args], { encoding: "utf8" });
    const good = run("--tarball", pack(fixture({ dist })));
    assert.equal(good.status, 0, good.stderr);
    assert.match(good.stdout, /x402check-pack-fixture-1\.0\.0\.tgz \(x402check-pack-fixture@1\.0\.0\): no local dependency/);
    const bad = run("--tarball", pack(fixture()));
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /Refusing to publish x402check-pack-fixture-1\.0\.0\.tgz/);
    assert.match(bad.stderr, /- src\/payer\.ts is not built into dist\/payer\.js/);
    for (const args of [["--tarbal", "x.tgz"], ["--tarball"], ["--tarball", "a.tgz", "b.tgz"]]) assert.equal(run(...args).status, 2, args.join(" "));
    assert.equal(run("--tarball", join(TEMP, "missing.tgz")).status, 1);
  });
});
