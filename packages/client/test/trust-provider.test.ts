// x402check as a trust provider for the x402 trust-provider extension (x402-foundation/x402#2300):
// a seller screens the payer before settling; anything unverifiable is UNCERTAIN, never PASS.
import assert from "node:assert/strict";
import { test } from "node:test";
import { x402checkTrustProvider, type TrustQuery } from "../src/trust-provider.js";
import { jwkThumbprint } from "../src/verify.js";
import { boundProvider, EVM, json, mockFetch } from "./helpers.js";

const query = (wallet?: string): TrustQuery => ({
  schema: "x402-trust-query-v0.1",
  payer: { ...(wallet ? { wallet } : {}), agent_id: "agent-7" },
  resource: { url: "https://api.weather.example/v1/forecast", method: "GET", amount: { value: "10000", currency: "USDC", chain: "base" } },
  requested_at: new Date().toISOString(),
});

test("a clean payer passes, with the signed attestation as evidence", async () => {
  const api = boundProvider(() => ({ tier: "low", score: 92, categories: [] }));
  const provider = x402checkTrustProvider({ fetch: api.fetch, pinnedKeys: [await jwkThumbprint(api.publicJwk)] });
  const e = await provider.evaluate(query(EVM));
  assert.equal(provider.name, "x402check");
  assert.equal(e.decision, "PASS");
  assert.equal(e.score, 92);
  assert.equal(e.reason_code, "tier_low");
  assert.match(e.evidence_uri ?? "", /^data:application\/jose,eyJ/);
  assert.ok((e.ttl_seconds ?? 0) > 3000);
  assert.equal(api.seen[0]?.wallet, EVM);
  assert.equal(api.seen[0]?.chain, "eip155:8453", "the payment's chain is screened");
});

test("a sanctioned payer fails with the hard-block category; a review-level verdict is UNCERTAIN", async () => {
  const api = boundProvider((r) => (r.wallet === EVM ? { tier: "critical", score: 0, categories: ["sanctioned_address", "compliance_risk"] } : { tier: "medium", score: 55, categories: ["new_address"] }));
  const provider = x402checkTrustProvider({ fetch: api.fetch, pinnedKeys: [await jwkThumbprint(api.publicJwk)] });
  const fail = await provider.evaluate(query(EVM));
  assert.deepEqual([fail.decision, fail.reason_code], ["FAIL", "sanctioned_address"]);
  const review = await provider.evaluate(query("0x1111111111111111111111111111111111111111"));
  assert.equal(review.decision, "UNCERTAIN");
});

test("never PASS without a verified attestation: unknown key, unreachable API, no payer wallet", async () => {
  const api = boundProvider(() => ({ tier: "low", score: 92, categories: [] }));
  const pinnedElsewhere = await x402checkTrustProvider({ fetch: api.fetch }).evaluate(query(EVM));
  assert.deepEqual([pinnedElsewhere.decision, pinnedElsewhere.reason_code], ["UNCERTAIN", "attestation_invalid"], "the default pins x402check's own key");
  assert.equal(pinnedElsewhere.evidence_uri, undefined);
  const down = await x402checkTrustProvider({ fetch: mockFetch(() => json(503, { error: "evaluation_unavailable" })).fetch, pinnedKeys: false }).evaluate(query(EVM));
  assert.equal(down.decision, "UNCERTAIN");
  const notChecked = await x402checkTrustProvider({ fetch: mockFetch(() => json(200, { checked: false, reason: "model_unavailable" })).fetch, pinnedKeys: false }).evaluate(query(EVM));
  assert.deepEqual([notChecked.decision, notChecked.reason_code], ["UNCERTAIN", "not_checked:model_unavailable"]);
  const noWallet = await x402checkTrustProvider({ fetch: api.fetch, pinnedKeys: false }).evaluate(query());
  assert.deepEqual([noWallet.decision, noWallet.reason_code], ["UNCERTAIN", "no_payer_wallet"]);
  assert.equal(api.seen.length, 1, "no check is bought without a wallet");
});
