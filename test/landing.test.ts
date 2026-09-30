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
    "free per day", // no free tier since v0.3: every evaluation is paid
    "Free tier",
    "evaluations per day",
    "X-Risk-Check-Free",
    "0/9,625", // v0.3's collision figure: its corpus held no exchange deposit fleets (EVIDENCE.md §0)
    "MEUCIQ", // a DER signature prefix: a JWS ES256 signature is raw r||s
    "paid per call and a Snap cannot pay", // every check is paid, per call or from prepaid credits
  ]) {
    assert.ok(!page.includes(stale), `stale claim present: ${stale}`);
  }
  // Evidence figures must match docs/EVIDENCE.md (canonical run, seed 200).
  for (const required of ["OFAC SDN", "Not detected:", "asserted", "did:web:x402check.xyz", "$0.001 per evaluation", "$0.0035 on Base", "27/30", "0&ndash;4/60", "24/24", "0/62", "18/25", "0/84", "40/82", "6,831", "4,672", "0.011%", "/v1/credits", "Authorization: Bearer x402c_", "Kit watch &middot; live", "og.png?v="]) {
    assert.ok(page.includes(required), `missing: ${required}`);
  }
});
