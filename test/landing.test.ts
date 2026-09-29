import { test } from "node:test";
import assert from "node:assert";
import { landingPage } from "../src/landing.js";

// Public copy must match what the evidence supports (independent review, 2026-09-29).
test("landing page carries no stale or unsupported claims", () => {
  const page = landingPage();
  for (const stale of [
    "wallet_requestSnaps", // the Snap is not published on npm: no one-click install
    "first 100 calls",
    "plus testnets",
    "0</b><span>false negatives",
    "53/53</b>",
    "Peel chains, mixer hops",
  ]) {
    assert.ok(!page.includes(stale), `stale claim present: ${stale}`);
  }
  for (const required of ["OFAC SDN", "Not detected:", "asserted", "did:web:x402check.xyz", "25 evaluations per day"]) {
    assert.ok(page.includes(required), `missing: ${required}`);
  }
});
