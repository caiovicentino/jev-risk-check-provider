// Prepaid credits within X402CHECK_BUDGET_USD (mcp-10): what this process spends from credits is
// tallied from the API's X-Credits-Charged header, and once the budget cannot cover a check, the
// check is refused before anything is sent.
import assert from "node:assert/strict";
import { before, describe, test } from "node:test";
import { generatePrivateKey } from "viem/accounts";
import { createX402CheckServer } from "../src/server.js";
import { json, makeIssuer, SPENDER, type Issuer } from "./helpers.js";
import { assertNoSecret, call, errorCode, option, paymentRequired, RESOURCE, session, TOKEN, world } from "./merchant.js";

let issuer: Issuer;
before(async () => {
  issuer = await makeIssuer();
});

const CHECK = { wallet: SPENDER, chain: "base" };

describe("X402CHECK_BUDGET_USD bounds prepaid credits", () => {
  test("checks are refused once the credit budget is spent, without calling the API", async () => {
    const w = world(issuer);
    const s = await session({ fetch: w.fetch, creditToken: TOKEN, budgetUsd: 0.002 });
    try {
      const first = await call(s.client, "x402check_check", CHECK);
      assert.match(first.text, /^x402check: ALLOW/);
      assert.match(first.text, /Paid from prepaid credits: \$0\.001 \(balance \$0\.412\) · \$0\.001 of this server's \$0\.002 credit budget spent/);
      assert.match((await call(s.client, "x402check_check", CHECK)).text, /^x402check: ALLOW/);

      const refused = await call(s.client, "x402check_check", CHECK);
      assert.equal(refused.isError, true);
      assert.match(refused.text, /^x402check: NOT VERIFIED/);
      assert.match(refused.text, /The check did not run: the prepaid-credit budget of this server is exhausted \(X402CHECK_BUDGET_USD\)/);
      assert.match(refused.text, /Next: this server's budget for prepaid credits is used up \(\$0\.002 of \$0\.002 spent from credits by this process; X402CHECK_BUDGET_USD\)/);
      assert.equal(refused.structuredContent?.action, "not_verified");
      assert.deepEqual(refused.structuredContent?.error, { code: "budget_exhausted", status: 0, message: "the prepaid-credit budget of this server is exhausted (X402CHECK_BUDGET_USD)" });
      assert.equal(w.checks.length, 2, "the third check never reached the API");
      assertNoSecret([first, refused], [TOKEN]);
    } finally {
      await s.close();
    }
  });

  test("a check that simulates a transaction costs more, and is refused when the budget cannot cover it", async () => {
    const w = world(issuer);
    const s = await session({ fetch: w.fetch, creditToken: TOKEN, budgetUsd: 0.004 });
    try {
      const r = await call(s.client, "x402check_check", { ...CHECK, transaction: { from: "0x1111111111111111111111111111111111111111", to: SPENDER, value: "0" } });
      assert.equal(errorCode(r), "budget_exhausted");
      assert.equal(w.checks.length, 0);
    } finally {
      await s.close();
    }
  });

  test("the charge the API reports is what counts", async () => {
    // $0.0005 a check: a $0.0025 budget covers four, where the $0.001 estimate alone would allow two.
    const w = world(issuer, { charged: "$0.0005" });
    const s = await session({ fetch: w.fetch, creditToken: TOKEN, budgetUsd: 0.0025 });
    try {
      const outcomes: unknown[] = [];
      for (let i = 0; i < 5; i++) outcomes.push((await call(s.client, "x402check_check", CHECK)).structuredContent?.action);
      assert.deepEqual(outcomes, ["allow", "allow", "allow", "allow", "not_verified"]);
      assert.equal(w.checks.length, 4);
    } finally {
      await s.close();
    }
  });

  test("an HTTP error is not counted (the API does not charge it); a check with no answer is", async () => {
    let answer: "error" | "hang" | "ok" = "error";
    const w = world(issuer, {
      onCheck: (_request, init) =>
        answer === "error"
          ? json(503, { error: "evaluation_unavailable" })
          : answer === "hang"
            ? new Promise<Response>((_resolve, reject) => init.signal?.addEventListener("abort", () => reject(init.signal?.reason)))
            : undefined,
    });
    const s = await session({ fetch: w.fetch, creditToken: TOKEN, budgetUsd: 0.001, timeoutMs: 100 });
    try {
      assert.match((await call(s.client, "x402check_check", CHECK)).text, /^x402check: NOT VERIFIED/);
      answer = "hang";
      assert.match((await call(s.client, "x402check_check", CHECK)).text, /No response from the provider in time/);
      assert.equal(w.checks.length, 2, "the 503 was not counted, so the second check was sent");
      answer = "ok";
      const third = await call(s.client, "x402check_check", CHECK);
      assert.equal(errorCode(third), "budget_exhausted", "a check with no answer may have been charged: it stays counted");
      assert.equal(w.checks.length, 2);
    } finally {
      await s.close();
    }
  });

  test("x402check_pay: once the credit budget cannot buy the check, nothing is checked or signed", async () => {
    // $0.0001 a payment: the payer's budget (the same $0.0015, counted separately) covers both payments.
    const w = world(issuer, { merchant: (c) => (c.paid ? json(200, { ok: true }) : paymentRequired([option({ amount: "100" })])) });
    const s = await session({ fetch: w.fetch, creditToken: TOKEN, payerKey: generatePrivateKey(), budgetUsd: 0.0015 });
    try {
      assert.equal((await call(s.client, "x402check_pay", { url: RESOURCE })).structuredContent?.outcome, "paid");
      const r = await call(s.client, "x402check_pay", { url: RESOURCE });
      assert.deepEqual([r.structuredContent?.outcome, r.structuredContent?.payment_sent, errorCode(r)], ["refused", false, "budget_exhausted"]);
      assert.match(r.text, /Error: the prepaid-credit budget of this server is exhausted \(X402CHECK_BUDGET_USD\): the payee could not be checked/);
      assert.match(r.text, /Next: nothing was paid\. The operator can raise X402CHECK_BUDGET_USD or restart this server; never pay without a verified check\./);
      assert.equal(w.checks.length, 1);
      assert.equal(w.payments().length, 1, "only the first payment");
    } finally {
      await s.close();
    }
  });

  test("an unusable budget fails at startup, also with credits only", () => {
    assert.throws(() => createX402CheckServer({ creditToken: TOKEN, budgetUsd: Number.NaN }), /X402CHECK_BUDGET_USD must be a USD amount/);
    assert.throws(() => createX402CheckServer({ creditToken: TOKEN, budgetUsd: 0 }), /X402CHECK_BUDGET_USD/);
    assert.doesNotThrow(() => createX402CheckServer({ creditToken: TOKEN }));
  });
});
