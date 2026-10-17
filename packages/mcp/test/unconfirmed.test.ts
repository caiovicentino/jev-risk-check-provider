// The 2026-10-16 review of the MCP package, finding L4: a 3xx answering the signed request was
// reported PAID while the payer kept the authorization outstanding. x402check_pay now reports
// "paid" exactly when the payer counts the payment accepted; a redirect, or a 2xx without a
// receipt that says `success: true` (none, unreadable, or saying otherwise: the 2026-10-17
// review), is unconfirmed, and the authorization stays valid until it expires. Stubs only:
// throwaway keys, no network, no money.
import assert from "node:assert/strict";
import { before, test } from "node:test";
import { generatePrivateKey } from "viem/accounts";
import { json, makeIssuer, type Issuer } from "./helpers.js";
import { authorizationOf, b64, call, errorCode, paymentRequired, RESOURCE, session, world } from "./merchant.js";

let issuer: Issuer;
before(async () => {
  issuer = await makeIssuer();
});

/** When the one signed authorization a merchant received expires (ISO 8601). */
const untilOf = (w: ReturnType<typeof world>): string => new Date(Number(authorizationOf(w.payments()[0]).validBefore) * 1000).toISOString();
const errorMessage = (structured: Record<string, unknown> | undefined): string => String((structured?.error as { message?: string } | undefined)?.message);

test("a redirect answering the signed payment is unconfirmed, not PAID, and the next call waits", async () => {
  for (const status of [301, 302, 303, 307, 308]) {
    const w = world(issuer, { merchant: (c) => (c.paid ? new Response(null, { status, headers: { Location: "https://api.weather.example/login" } }) : paymentRequired()) });
    const s = await session({ payerKey: generatePrivateKey(), fetch: w.fetch });
    try {
      const r = await call(s.client, "x402check_pay", { url: RESOURCE });
      const until = untilOf(w);
      assert.deepEqual([r.structuredContent?.outcome, r.structuredContent?.payment_sent, errorCode(r), r.isError], ["failed", true, "payment_unconfirmed", true], String(status));
      assert.match(r.text, /^x402check_pay: FAILED\. A signed payment was sent\./);
      assert.doesNotMatch(r.text, /PAID/);
      assert.equal(errorMessage(r.structuredContent), `the resource answered the signed payment with a redirect (HTTP ${status}), which this server does not follow, so the payment is not confirmed`);
      assert.ok(r.text.includes(`It can be settled until ${until}, when the signed authorization expires: do not pay this resource again before then.`), r.text);
      assert.doesNotMatch(r.text, /call again with that URL/, "a paid redirect is no invitation to pay elsewhere");
      assert.equal((r.structuredContent?.payment as { valid_until?: string }).valid_until, until);
      const response = r.structuredContent?.response as { status: number; location?: string };
      assert.deepEqual([response.status, response.location], [status, "https://api.weather.example/login"]);
      // What the payer does agrees with what was said: the authorization is still outstanding.
      assert.equal(errorCode(await call(s.client, "x402check_pay", { url: RESOURCE })), "authorization_outstanding");
      assert.equal(w.payments().length, 1);
    } finally {
      await s.close();
    }
  }
});

test("a 2xx without a receipt that says success: true is unconfirmed too; one that says it is PAID", async () => {
  // A 2xx with no receipt, or one whose `success` is not the boolean true, counted as PAID until
  // the 2026-10-17 review (test/payment-accepted.test.ts).
  const notSaid = "the resource answered HTTP 200, but its settlement receipt does not say the payment was settled (success: true), so the payment is not confirmed";
  const cases: Array<[string, (from: string) => Record<string, string>, string | undefined]> = [
    [
      "success: false",
      (from) => ({ "PAYMENT-RESPONSE": b64({ success: false, errorReason: "nonce", transaction: "", network: "eip155:8453", payer: from }) }),
      "the resource answered HTTP 200, but its settlement receipt says the payment was not settled",
    ],
    ["unreadable", () => ({ "PAYMENT-RESPONSE": "not base64 json!" }), "the resource answered HTTP 200, but its settlement receipt could not be read, so the payment is not confirmed"],
    ["no receipt", () => ({}), "the resource answered HTTP 200 without a settlement receipt (PAYMENT-RESPONSE), so the payment is not confirmed"],
    ['success: "true"', (from) => ({ "PAYMENT-RESPONSE": b64({ success: "true", transaction: `0x${"7a".repeat(32)}`, network: "eip155:8453", payer: from }) }), notSaid],
    ["no success field", (from) => ({ "PAYMENT-RESPONSE": b64({ transaction: `0x${"7a".repeat(32)}`, network: "eip155:8453", payer: from }) }), notSaid],
    ["success: true", (from) => ({ "PAYMENT-RESPONSE": b64({ success: true, transaction: `0x${"7a".repeat(32)}`, network: "eip155:8453", payer: from }) }), undefined],
  ];
  for (const [label, headers, why] of cases) {
    const w = world(issuer, { merchant: (c) => (c.paid ? json(200, { note: "payment failed: please retry" }, headers(authorizationOf(c).from ?? "")) : paymentRequired()) });
    const s = await session({ payerKey: generatePrivateKey(), fetch: w.fetch });
    try {
      const r = await call(s.client, "x402check_pay", { url: RESOURCE });
      const response = r.structuredContent?.response as { status: number; body?: string };
      assert.equal(response.status, 200, label);
      assert.match(String(response.body), /payment failed: please retry/, "the body is shown either way");
      if (why === undefined) {
        assert.deepEqual([r.structuredContent?.outcome, errorCode(r), r.isError], ["paid", undefined, undefined], label);
        assert.equal((r.structuredContent?.payment as { valid_until?: string }).valid_until, undefined);
        assert.match(r.text, /Settlement: settled on eip155:8453 · tx 0x(?:7a){32}/);
        continue;
      }
      const until = untilOf(w);
      assert.deepEqual([r.structuredContent?.outcome, r.structuredContent?.payment_sent, errorCode(r)], ["failed", true, "payment_unconfirmed"], label);
      assert.equal(errorMessage(r.structuredContent), why);
      assert.ok(r.text.includes(`It can be settled until ${until}, when the signed authorization expires`), r.text);
      if (label === "success: false") assert.match(r.text, /Settlement: NOT settled on eip155:8453/);
      // A receipt that names a transaction without saying success: true is not shown as settled.
      if (why === notSaid) assert.match(r.text, /Settlement: not confirmed \(the receipt does not say success: true\) on eip155:8453 · tx 0x(?:7a){32}/, label);
      assert.doesNotMatch(r.text, /Settlement: settled/, label);
      assert.doesNotMatch(r.text, /PAID/, label);
      assert.equal(errorCode(await call(s.client, "x402check_pay", { url: RESOURCE })), "authorization_outstanding", label);
    } finally {
      await s.close();
    }
  }
});
