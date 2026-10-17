// The 2026-10-17 review of the MCP package (low): a payment counted as accepted on a 2xx with no
// settlement receipt, or with a receipt whose `success` was anything but the boolean false ("false",
// 0, null, no field at all). The outcome said PAID and the payee's record was cleared, so a resource
// that answers 200 and keeps each authorization to settle later collected a new one on every call.
// A payment is accepted only on a 2xx whose decoded PAYMENT-RESPONSE (or X-PAYMENT-RESPONSE) receipt
// says `success: true`; anything else is unconfirmed, and the record stays until the authorization
// expires (x402check_pay's side: test/unconfirmed.test.ts and test/outstanding.test.ts). Stubs only:
// throwaway keys, no network, no money.
import assert from "node:assert/strict";
import { test } from "node:test";
import { generatePrivateKey } from "viem/accounts";
import { createPayer, PaymentRefused, paymentAccepted } from "../src/payer.js";
import { json } from "./helpers.js";
import { b64, paymentRequired, RESOURCE } from "./merchant.js";

const receipt = (fields: Record<string, unknown>): string => b64({ transaction: `0x${"7a".repeat(32)}`, network: "eip155:8453", ...fields });

test("paymentAccepted: a 2xx whose receipt says success: true, and nothing else", () => {
  const cases: Array<[string, number, Record<string, string>, boolean]> = [
    ["200, PAYMENT-RESPONSE success: true", 200, { "PAYMENT-RESPONSE": receipt({ success: true }) }, true],
    ["201, PAYMENT-RESPONSE success: true", 201, { "PAYMENT-RESPONSE": receipt({ success: true }) }, true],
    ["200, X-PAYMENT-RESPONSE success: true", 200, { "X-PAYMENT-RESPONSE": receipt({ success: true }) }, true],
    ["200, x-payment-response (lowercase) success: true", 200, { "x-payment-response": receipt({ success: true }) }, true],
    ["200, no receipt", 200, {}, false],
    ["204, no receipt", 204, {}, false],
    ["200, success: false", 200, { "PAYMENT-RESPONSE": receipt({ success: false }) }, false],
    ['200, success: "false"', 200, { "PAYMENT-RESPONSE": receipt({ success: "false" }) }, false],
    ['200, success: "true"', 200, { "PAYMENT-RESPONSE": receipt({ success: "true" }) }, false],
    ["200, success: 1", 200, { "PAYMENT-RESPONSE": receipt({ success: 1 }) }, false],
    ["200, success: 0", 200, { "PAYMENT-RESPONSE": receipt({ success: 0 }) }, false],
    ["200, success: null", 200, { "PAYMENT-RESPONSE": receipt({ success: null }) }, false],
    ["200, a receipt without success", 200, { "PAYMENT-RESPONSE": b64({}) }, false],
    ["200, an unreadable receipt", 200, { "PAYMENT-RESPONSE": "!!not-b64-json!!" }, false],
    ["200, a receipt that is a string", 200, { "PAYMENT-RESPONSE": b64("ok") }, false],
    ["200, a receipt that is an array", 200, { "PAYMENT-RESPONSE": b64([{ success: true }]) }, false],
    ["200, X-PAYMENT-RESPONSE success: false", 200, { "X-PAYMENT-RESPONSE": receipt({ success: false }) }, false],
    // PAYMENT-RESPONSE is read first (as @x402/fetch reads it): a success in the legacy header does not override it.
    ["200, PAYMENT-RESPONSE false and X-PAYMENT-RESPONSE true", 200, { "PAYMENT-RESPONSE": receipt({ success: false }), "X-PAYMENT-RESPONSE": receipt({ success: true }) }, false],
    ["302, success: true", 302, { "PAYMENT-RESPONSE": receipt({ success: true }) }, false],
    ["402, success: true", 402, { "PAYMENT-RESPONSE": receipt({ success: true }) }, false],
    ["500, success: true", 500, { "PAYMENT-RESPONSE": receipt({ success: true }) }, false],
  ];
  for (const [label, status, headers, accepted] of cases) {
    assert.equal(paymentAccepted(new Response(null, { status, headers })), accepted, label);
  }
});

test("a resource that answers 200 without a receipt gets one authorization, not one per call", async () => {
  // The reviewer's reproduction: a 200 with no PAYMENT-RESPONSE, three calls in a row. Before, each
  // call signed a new authorization (three distinct nonces the resource could settle).
  const nonces: string[] = [];
  const fetch: typeof globalThis.fetch = async (input) => {
    const signature = (input as Request).headers.get("payment-signature");
    if (!signature) return paymentRequired();
    const payload = JSON.parse(Buffer.from(signature, "base64").toString("utf8")) as { payload?: { authorization?: { nonce?: string } } };
    nonces.push(String(payload.payload?.authorization?.nonce));
    return json(200, { ok: true });
  };
  const payer = createPayer({ privateKey: generatePrivateKey(), fetch });
  const pay = () => payer.payResource(RESOURCE, { method: "GET", redirect: "manual" }, { authorize: async () => undefined });
  assert.equal((await pay()).status, 200);
  for (let i = 0; i < 2; i++) {
    await assert.rejects(pay(), (err: unknown) => err instanceof PaymentRefused && err.kind === "authorization_outstanding", `call ${i + 2}`);
  }
  assert.equal(nonces.length, 1, "one signed authorization ever reached the resource");
  assert.equal(payer.spentUsd(), 0.01);
});
