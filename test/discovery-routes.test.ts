// Discovery lists exactly the networks the 402 challenge offers, with the challenge's own fallback:
// every facilitator down on a cold isolate used to publish `networks: []` while the 402 offered
// all seven (2026-10-16 maintenance review). Its own file: routing state is per module.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildAccepts, ensureDeps, paymentRouting, routingKnown } from "../deploy/protected.js";
import { createHandler } from "../src/handler.js";

test("every facilitator down: discovery lists what the 402 offers, never none", async () => {
  // Nothing listens on port 9: every /supported and /pricing fails at once.
  const env = { X402_FACILITATOR_URL_PAYAI: "http://127.0.0.1:9/payai", X402_FACILITATOR_URL_MAINNET: "http://127.0.0.1:9/dexter", PROVIDER_HOST: "localhost:8799" };
  await routingKnown(env, 5000);
  const routes = await paymentRouting(env);
  assert.ok(routes.every((r) => r.reason === "no_facilitator"), JSON.stringify(routes.map((r) => r.reason)));
  const challenge = buildAccepts(env, undefined, routes).map((a) => String(a.network));
  assert.equal(challenge.length, 7);
  const res = await createHandler(ensureDeps(env).deps)(new Request("https://localhost:8799/.well-known/risk-check.json"));
  const doc = (await res.json()) as { pricing: { networks: string[]; amounts_by_network: Record<string, string> } };
  assert.deepEqual(doc.pricing.networks, challenge);
  assert.deepEqual(Object.keys(doc.pricing.amounts_by_network), challenge);
  // Known: answered at once, and the table is refreshed in the background (never left to age).
  const handed: Promise<unknown>[] = [];
  const t = Date.now();
  await routingKnown(env, 5000, { waitUntil: (p) => void handed.push(p) });
  assert.ok(Date.now() - t < 100);
  assert.equal(handed.length, 1);
});
