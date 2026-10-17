// The 2026-10-16 review of the MCP package, finding M3: no new authorization to a payee while an
// earlier one the resource did not accept can still be settled (`authorization_outstanding`). It
// could be bypassed by another spelling of the path, another network, parallel calls, a 2xx whose
// receipt says the payment failed, and a success that cleared another call's record. Stubs only:
// throwaway keys, no network, no money.
import assert from "node:assert/strict";
import { before, describe, test } from "node:test";
import { generatePrivateKey } from "viem/accounts";
import { createPayer, PaymentRefused } from "../src/payer.js";
import { json, makeIssuer, type Issuer } from "./helpers.js";
import { authorizationOf, b64, call, challenge, errorCode, MERCHANT, option, ORIGIN, paymentRequired, RESOURCE, session, waitFor, world, type ToolResult } from "./merchant.js";

const MERCHANT2 = "0x1111111111111111111111111111111111111111";
const USDC_POLYGON = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359";
const NOT_ACCEPTED = /^an authorization this server signed for this payee and resource was not accepted, and it can still be settled until \d{4}-\d{2}-\d{2}T[\d:.]+Z: nothing new is signed until then$/;
const IN_FLIGHT = /^an authorization this server signed for this payee and resource is still awaiting the resource's answer \(another call\), and it can be settled until \d{4}-\d{2}-\d{2}T[\d:.]+Z: nothing new is signed until it is accepted or expires$/;

let issuer: Issuer;
before(async () => {
  issuer = await makeIssuer();
});

const message = (r: ToolResult): string => String((r.structuredContent?.error as { message?: string } | undefined)?.message);
const outcome = (r: ToolResult): string => `${String(r.structuredContent?.outcome)}${errorCode(r) ? `/${errorCode(r)}` : ""}`;
const receipt = (fields: Record<string, unknown>, from = ""): string => b64({ transaction: `0x${"7a".repeat(32)}`, network: "eip155:8453", payer: from, ...fields });

/** A merchant that never accepts a signed payment: it answers 402 again (`accepts` per unpaid request). */
function withholding(accepts: (n: number) => unknown[] = () => [option()]) {
  let n = 0;
  return world(issuer, {
    merchant: (c) => (c.paid ? json(402, { error: "nonce error: retry at another URL" }, { "PAYMENT-REQUIRED": b64(challenge()) }) : json(402, {}, { "PAYMENT-REQUIRED": b64(challenge(accepts(n++))) })),
  });
}

/** A latch: `wait` resolves once `open` is called. */
function latch(): { open: () => void; wait: Promise<void> } {
  let open = (): void => undefined;
  const wait = new Promise<void>((resolve) => (open = resolve));
  return { open, wait };
}

describe("finding M3: one settleable authorization per payee and site", () => {
  test("every spelling of the endpoint, and every other resource on the site, waits", async () => {
    const w = withholding();
    const s = await session({ payerKey: generatePrivateKey(), fetch: w.fetch });
    try {
      assert.equal(outcome(await call(s.client, "x402check_pay", { url: RESOURCE })), "payment_rejected");
      for (const url of [
        `${RESOURCE}?retry=1`,
        `${RESOURCE}/`,
        `${ORIGIN}/v1/%66orecast`,
        `${ORIGIN}//v1/forecast`,
        `${ORIGIN}/v1/./forecast`,
        "https://API.weather.example:443/v1/forecast",
        "https://api.weather.example./v1/forecast",
        `${ORIGIN}/v1/other`,
      ]) {
        const r = await call(s.client, "x402check_pay", { url });
        assert.equal(outcome(r), "refused/authorization_outstanding", url);
        assert.match(message(r), NOT_ACCEPTED, url);
      }
      assert.equal(w.payments().length, 1, "one signed authorization ever reached the payee");
      assert.equal(w.checks.length, 1, "no check is bought for a payment that cannot be made");
    } finally {
      await s.close();
    }
  });

  test("the same payee on another network waits; another payee does not", async () => {
    const w = withholding((n) => (n === 0 ? [option()] : n === 1 ? [option({ network: "eip155:137", asset: USDC_POLYGON })] : [option({ payTo: MERCHANT2 })]));
    const s = await session({ payerKey: generatePrivateKey(), fetch: w.fetch });
    try {
      assert.equal(outcome(await call(s.client, "x402check_pay", { url: RESOURCE })), "payment_rejected");
      assert.equal(outcome(await call(s.client, "x402check_pay", { url: RESOURCE })), "refused/authorization_outstanding", "Polygon, same payee");
      // Another payee cannot settle the first authorization.
      assert.equal(outcome(await call(s.client, "x402check_pay", { url: RESOURCE })), "payment_rejected");
      assert.deepEqual(
        w.payments().map((p) => (p.payload?.accepted as { payTo: string }).payTo),
        [MERCHANT, MERCHANT2],
      );
    } finally {
      await s.close();
    }
  });

  test("calls made while one call's payment awaits its answer are refused, without a check, until it is answered", async () => {
    // Calls made together, while the first one's check runs, are in test/concurrent-pay.test.ts.
    const answer = latch();
    const w = world(issuer, {
      merchant: async (c) => {
        if (!c.paid) return paymentRequired();
        await answer.wait;
        return json(402, {}, { "PAYMENT-REQUIRED": b64(challenge()) });
      },
    });
    const s = await session({ payerKey: generatePrivateKey(), fetch: w.fetch });
    try {
      const first = call(s.client, "x402check_pay", { url: RESOURCE });
      let others: ToolResult[] = [];
      try {
        // The signed one is held by the merchant; two calls made meanwhile must return without signing.
        await waitFor(() => w.payments().length === 1, "the first call's payment to reach the merchant", 5000);
        others = await Promise.all([0, 1].map(() => call(s.client, "x402check_pay", { url: RESOURCE })));
      } finally {
        answer.open();
      }
      for (const r of others) {
        assert.equal(outcome(r), "refused/authorization_outstanding");
        assert.match(message(r), IN_FLIGHT);
      }
      assert.equal(outcome(await first), "payment_rejected");
      const later = await call(s.client, "x402check_pay", { url: RESOURCE });
      assert.equal(outcome(later), "refused/authorization_outstanding");
      assert.match(message(later), NOT_ACCEPTED);
      assert.equal(w.payments().length, 1);
      assert.equal(w.checks.length, 1, "only the first call bought a check");
    } finally {
      await s.close();
    }
  });

  test("a call made while one is in flight signs nothing; after that one's success, the next call pays", async () => {
    const answer = latch();
    const w = world(issuer, {
      merchant: async (c) => {
        if (!c.paid) return paymentRequired();
        await answer.wait;
        return json(200, { ok: true }, { "PAYMENT-RESPONSE": receipt({ success: true }, authorizationOf(c).from) });
      },
    });
    const s = await session({ payerKey: generatePrivateKey(), fetch: w.fetch });
    try {
      const first = call(s.client, "x402check_pay", { url: RESOURCE });
      let during: ToolResult;
      try {
        await waitFor(() => w.payments().length === 1, "the first call's payment to reach the merchant", 5000);
        during = await call(s.client, "x402check_pay", { url: RESOURCE });
      } finally {
        answer.open();
      }
      assert.equal(outcome(during), "refused/authorization_outstanding");
      assert.match(message(during), IN_FLIGHT);
      assert.equal(outcome(await first), "paid");
      assert.equal(outcome(await call(s.client, "x402check_pay", { url: RESOURCE })), "paid", "accepted: the record is gone");
      assert.equal(w.payments().length, 2);
    } finally {
      await s.close();
    }
  });

  test("a 2xx without a receipt that says success: true leaves it settleable", async () => {
    // Until the 2026-10-17 review, a 2xx with no receipt, or with a `success` other than the
    // boolean false, cleared the record (test/payment-accepted.test.ts).
    const cases: Array<[string, (from: string) => Record<string, string>, boolean]> = [
      ["PAYMENT-RESPONSE success: false", (from) => ({ "PAYMENT-RESPONSE": receipt({ success: false, errorReason: "nonce" }, from) }), false],
      ["X-PAYMENT-RESPONSE success: false", (from) => ({ "X-PAYMENT-RESPONSE": receipt({ success: false }, from) }), false],
      ["an unreadable PAYMENT-RESPONSE", () => ({ "PAYMENT-RESPONSE": "not base64 json!" }), false],
      ["a PAYMENT-RESPONSE that is not an object", () => ({ "PAYMENT-RESPONSE": b64("ok") }), false],
      ["no receipt", () => ({}), false],
      ['PAYMENT-RESPONSE success: "false"', (from) => ({ "PAYMENT-RESPONSE": receipt({ success: "false" }, from) }), false],
      ["PAYMENT-RESPONSE success: null", (from) => ({ "PAYMENT-RESPONSE": receipt({ success: null }, from) }), false],
      ["a PAYMENT-RESPONSE without success", (from) => ({ "PAYMENT-RESPONSE": receipt({}, from) }), false],
      ["PAYMENT-RESPONSE success: true", (from) => ({ "PAYMENT-RESPONSE": receipt({ success: true }, from) }), true],
      ["X-PAYMENT-RESPONSE success: true", (from) => ({ "X-PAYMENT-RESPONSE": receipt({ success: true }, from) }), true],
    ];
    for (const [label, headers, accepted] of cases) {
      const w = world(issuer, { merchant: (c) => (c.paid ? json(200, { error: "payment failed: please retry" }, headers(authorizationOf(c).from ?? "")) : paymentRequired()) });
      const s = await session({ payerKey: generatePrivateKey(), fetch: w.fetch });
      try {
        const first = await call(s.client, "x402check_pay", { url: RESOURCE });
        assert.equal(first.structuredContent?.payment_sent, true, label);
        const second = await call(s.client, "x402check_pay", { url: RESOURCE });
        if (accepted) assert.equal(second.structuredContent?.payment_sent, true, label);
        else {
          assert.equal(outcome(second), "refused/authorization_outstanding", label);
          assert.match(message(second), NOT_ACCEPTED, label);
        }
        assert.equal(w.payments().length, accepted ? 2 : 1, label);
      } finally {
        await s.close();
      }
    }
  });

  test("a success racing an unaccepted payment cannot clear its record: the racing call never signs", async () => {
    // The reviewer's race: the first paid request is answered 402 after 20 ms, a second one 200
    // after 80 ms. Before, both signed, the success deleted the shared record, and a third call
    // signed again while the first authorization could still be settled.
    let paid = 0;
    const w = world(issuer, {
      merchant: async (c) => {
        if (!c.paid) return paymentRequired();
        const k = paid++;
        await new Promise((resolve) => setTimeout(resolve, k === 0 ? 20 : 80));
        return k === 0 ? json(402, {}, { "PAYMENT-REQUIRED": b64(challenge()) }) : json(200, { ok: true }, { "PAYMENT-RESPONSE": receipt({ success: true }, authorizationOf(c).from) });
      },
    });
    const s = await session({ payerKey: generatePrivateKey(), fetch: w.fetch });
    try {
      const both = await Promise.all([call(s.client, "x402check_pay", { url: RESOURCE }), call(s.client, "x402check_pay", { url: RESOURCE })]);
      assert.deepEqual(both.map(outcome).sort(), ["payment_rejected", "refused/authorization_outstanding"]);
      const third = await call(s.client, "x402check_pay", { url: RESOURCE });
      assert.equal(outcome(third), "refused/authorization_outstanding");
      assert.equal(w.payments().length, 1);
    } finally {
      await s.close();
    }
  });

  test("a late success clears only its own record, never the one another call made after it expired", async () => {
    // Call A signs an authorization valid 1 s, and its answer is held past that. Call B then signs
    // (A's can no longer be settled), and B's is not accepted. A's late success must leave B's record.
    const answerA = latch();
    let unpaid = 0;
    let paid = 0;
    const w = world(issuer, {
      merchant: async (c) => {
        if (!c.paid) return paymentRequired([option({ maxTimeoutSeconds: unpaid++ === 0 ? 1 : 300 })]);
        if (paid++ === 0) {
          await answerA.wait;
          return json(200, { ok: true }, { "PAYMENT-RESPONSE": receipt({ success: true }, authorizationOf(c).from) });
        }
        return json(402, {}, { "PAYMENT-REQUIRED": b64(challenge()) });
      },
    });
    const s = await session({ payerKey: generatePrivateKey(), fetch: w.fetch });
    try {
      const a = call(s.client, "x402check_pay", { url: RESOURCE });
      let b: ToolResult;
      try {
        await waitFor(() => w.payments().length === 1, "A's payment to reach the merchant");
        const expiry = Number(authorizationOf(w.payments()[0]).validBefore);
        await waitFor(() => Math.floor(Date.now() / 1000) >= expiry, "A's authorization to expire", 5000);
        b = await call(s.client, "x402check_pay", { url: RESOURCE });
      } finally {
        answerA.open();
      }
      assert.equal(outcome(b), "payment_rejected");
      assert.equal((await a).structuredContent?.payment_sent, true);
      const c = await call(s.client, "x402check_pay", { url: RESOURCE });
      assert.equal(outcome(c), "refused/authorization_outstanding", "B's record is still there");
      assert.match(message(c), NOT_ACCEPTED);
      assert.equal(w.payments().length, 2);
    } finally {
      await s.close();
    }
  });
});

describe("finding M3: nothing signed, or nothing sent, leaves no record", () => {
  test("signed, then cancelled before it was sent: the next payment to that payee is not held back", async () => {
    const seen: boolean[] = [];
    const fetch: typeof globalThis.fetch = async (input) => {
      const paid = (input as Request).headers.has("payment-signature");
      seen.push(paid);
      return paid ? json(402, {}, { "PAYMENT-REQUIRED": b64(challenge()) }) : paymentRequired();
    };
    const payer = createPayer({ privateKey: generatePrivateKey(), fetch });
    const controller = new AbortController();
    await assert.rejects(
      payer.payResource(RESOURCE, { method: "GET", redirect: "manual" }, { authorize: async () => undefined, onSigned: () => controller.abort(), signal: controller.signal }),
      (err: unknown) => err instanceof PaymentRefused && err.kind === "cancelled",
    );
    assert.deepEqual(seen, [false], "never sent");
    const res = await payer.payResource(RESOURCE, { method: "GET", redirect: "manual" }, { authorize: async () => undefined });
    assert.equal(res.status, 402);
    assert.deepEqual(seen, [false, false, true], "the next call signed and sent its own");
  });

  test("a signature that could not be made, or a payee the check refused, records nothing", async () => {
    let unpaid = 0;
    const fetch: typeof globalThis.fetch = async (input) => {
      if ((input as Request).headers.has("payment-signature")) return json(200, {});
      // The first 402 lacks the EIP-712 domain the signature needs, so signing fails.
      return paymentRequired([option(unpaid++ === 0 ? { extra: {} } : {})]);
    };
    const payer = createPayer({ privateKey: generatePrivateKey(), fetch });
    await assert.rejects(payer.payResource(RESOURCE, { method: "GET", redirect: "manual" }, { authorize: async () => undefined }));
    await assert.rejects(
      payer.payResource(RESOURCE, { method: "GET", redirect: "manual" }, { authorize: async () => "block" }),
      (err: unknown) => err instanceof PaymentRefused && err.kind === "not_authorized",
    );
    const res = await payer.payResource(RESOURCE, { method: "GET", redirect: "manual" }, { authorize: async () => undefined });
    assert.equal(res.status, 200, "neither left a record behind");
    assert.equal(payer.spentUsd(), 0.01, "only the payment that was sent is spent");
  });
});
