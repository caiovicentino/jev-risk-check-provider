// The signing guard in @x402check/client uses the MetaMask Snap's decoders, vendored into
// packages/client/src/decode by scripts/sync-decoders.mjs. The Snap's source is the truth:
// this fails when the copies drift (fix: edit snap/src, run the script).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

test("the guard's vendored decoders match the Snap's source", () => {
  const r = spawnSync(process.execPath, ["scripts/sync-decoders.mjs", "--check"], { encoding: "utf8" });
  assert.equal(r.status, 0, `${r.stderr}${r.stdout}\nRun: node scripts/sync-decoders.mjs`);
});
