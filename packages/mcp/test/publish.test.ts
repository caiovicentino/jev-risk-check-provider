// The prepublishOnly guard (scripts/check-publish.mjs, SDK review finding 8): no local dependency,
// and a tarball that holds only package.json, README.md, LICENSE and a dist/ built from src/.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { localDependencies, packedFiles, sourceModules, tarballProblems } from "../scripts/check-publish.mjs";

test("the tarball npm would publish now holds only the package, its docs and dist/ built from src/", () => {
  // `npm test` builds first (pretest), so dist/ is current.
  assert.deepEqual(tarballProblems(packedFiles(), sourceModules()), []);
});

test("anything else, a missing entry point, or a stale build is refused", () => {
  const good = ["LICENSE", "README.md", "package.json", "dist/index.js", "dist/index.d.ts", "dist/server.js", "dist/server.d.ts"];
  assert.deepEqual(tarballProblems(good, ["index", "server"]), []);
  for (const extra of ["src/server.ts", ".env", "test/pay.test.ts", "x402check-mcp-0.3.1.tgz", "dist/server.js.map", "scripts/check-publish.mjs", "dist/nested/x.js"]) {
    assert.match(tarballProblems([...good, extra]).join("\n"), /unexpected file/, extra);
  }
  assert.match(tarballProblems(good.filter((f) => f !== "dist/index.js")).join("\n"), /missing from the tarball: dist\/index\.js/);
  assert.match(tarballProblems(good, ["index", "server", "payer"]).join("\n"), /src\/payer\.ts is not built/);
  assert.match(tarballProblems([...good, "dist/old.js"], ["index", "server"]).join("\n"), /dist\/old\.js has no source in src\/ \(a stale build\)/);
});

test("a local dependency is refused; in this checkout the client is one, so publishing first pins a range", () => {
  assert.deepEqual(localDependencies({ dependencies: { a: "^1.0.0", b: "file:../b" }, peerDependencies: { c: "workspace:*" } }), ["b@file:../b", "c@workspace:*"]);
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { dependencies: Record<string, string> };
  assert.deepEqual(localDependencies(pkg), ["@x402check/client@file:../client"]);
  // The x402 packages, the core included, are pinned exactly: what was tested is what is installed.
  for (const name of ["@x402/core", "@x402/evm", "@x402/fetch"]) assert.match(pkg.dependencies[name] ?? "", /^\d+\.\d+\.\d+$/, name);
});
