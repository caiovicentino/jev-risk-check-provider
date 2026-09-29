// Paid checks: every evaluation is paid via x402 v2 (PAYMENT-SIGNATURE). A stub provider answers
// 402 with a production-shaped PAYMENT-REQUIRED challenge, and the result once a payment arrives.
import assert from "node:assert/strict";
import { before, describe, test } from "node:test";
import { requestHash, type FetchInitLike } from "@x402check/client";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { verifyTypedData } from "viem";
import { createPayer } from "../src/payer.js";
import { createX402CheckServer } from "../src/server.js";
import { API, callTool, CHECKS, connect, DID_URL, didDocument, json, makeIssuer, signedResult, SPENDER, USDC_BASE, type Issuer } from "./helpers.js";

const USDC_POLYGON = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359";
const PAY_TO = "0xbF88b1F49B5e8Ec386289341c4a5ee00bB0E0178";
const TX = `0x${"5e".repeat(32)}`;

function challenge(amount = "1000"): Record<string, unknown> {
  const option = (network: string, asset: string) => ({ scheme: "exact", network, amount, asset, payTo: PAY_TO, maxTimeoutSeconds: 300, extra: { name: "USD Coin", version: "2" } });
  // Polygon listed first on purpose: the payer must still pick Base.
  return {
    x402Version: 2,
    error: "Payment required",
    resource: { url: API, description: "x402check risk check with signed attestation", mimeType: "application/json" },
    accepts: [option("eip155:137", USDC_POLYGON), option("eip155:8453", USDC_BASE)],
  };
}

const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString("base64");

type Paid = { header: string; payload: Record<string, unknown> };

/** A stub provider behind x402: 402 until PAYMENT-SIGNATURE is present, then `paid(payment)`. */
function provider(issuer: Issuer, paid: (payment: Paid, body: Record<string, unknown>) => Response | Promise<Response>, amount?: string) {
  const calls: Array<{ url: string; init: FetchInitLike; paid: boolean }> = [];
  const payments: Paid[] = [];
  const fetch = async (url: string, init: FetchInitLike): Promise<Response> => {
    const header = init.headers["payment-signature"] ?? init.headers["PAYMENT-SIGNATURE"];
    calls.push({ url, init, paid: header !== undefined });
    if (url === DID_URL) return json(200, didDocument(issuer));
    if (!url.endsWith("/v1/risk-check")) throw new Error(`unexpected fetch: ${url}`);
    if (!header) return json(402, {}, { "PAYMENT-REQUIRED": b64(challenge(amount)) });
    const payment = { header, payload: JSON.parse(Buffer.from(header, "base64").toString("utf8")) as Record<string, unknown> };
    payments.push(payment);
    return paid(payment, JSON.parse(init.body ?? "{}") as Record<string, unknown>);
  };
  return { fetch, calls, payments };
}

async function settledResult(issuer: Issuer, body: Record<string, unknown>, payer: string): Promise<Response> {
  const result = await signedResult(issuer, { claims: { checks: CHECKS, request_hash: await requestHash(body) } });
  return json(200, result, { "PAYMENT-RESPONSE": b64({ success: true, transaction: TX, network: "eip155:8453", payer }) });
}

function assertNoKey(outputs: unknown[], key: string): void {
  const hex = key.slice(2).toLowerCase();
  for (const out of outputs) {
    const s = (typeof out === "string" ? out : JSON.stringify(out)).toLowerCase();
    assert.ok(!s.includes(hex), "the private key must never appear in any output");
  }
}

let issuer: Issuer;
before(async () => {
  issuer = await makeIssuer();
});

describe("paid checks (x402 v2)", () => {
  test("402 → a real gasless USDC authorization on Base → 200: verdict, receipt and budget", async () => {
    const key = generatePrivateKey();
    const address = privateKeyToAccount(key).address;
    const upstream = provider(issuer, (_p, body) => settledResult(issuer, body, address));
    const session = await connect({ fetch: upstream.fetch, payerKey: key });
    try {
      const r = await callTool(session.client, "x402check_check", { wallet: SPENDER, chain: "base" });
      assert.match(r.text, /^x402check: ALLOW\./);
      assert.match(r.text, new RegExp(`Payment: settled on eip155:8453 · tx ${TX}`));
      assert.match(r.text, /Payer budget: \$0\.001 of \$1\.00 spent by this server/);
      assert.deepEqual(r.structuredContent?.payment, { settled: true, network: "eip155:8453", transaction: TX, payer: address, spent_usd: 0.001, budget_usd: 1 });
      assert.equal((r.structuredContent?.attestation as { verified: boolean }).verified, true);

      // Exactly one unpaid request, then one paid retry, then the DID document.
      assert.deepEqual(upstream.calls.map((c) => [c.url, c.paid]), [[API, false], [API, true], [DID_URL, false]]);
      const [payment] = upstream.payments;
      const accepted = payment!.payload.accepted as { network: string; amount: string; asset: string; payTo: string };
      assert.equal(payment!.payload.x402Version, 2);
      assert.deepEqual([accepted.network, accepted.amount, accepted.asset, accepted.payTo], ["eip155:8453", "1000", USDC_BASE, PAY_TO], "Base first, exactly $0.001");
      // The payment is a valid EIP-3009 transferWithAuthorization signed by the payer: gasless for it.
      const { authorization, signature } = payment!.payload.payload as { authorization: Record<string, string>; signature: `0x${string}` };
      assert.equal(authorization.from, address);
      assert.equal(authorization.to, PAY_TO);
      assert.equal(authorization.value, "1000");
      const valid = await verifyTypedData({
        address,
        domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: USDC_BASE as `0x${string}` },
        types: {
          TransferWithAuthorization: [
            { name: "from", type: "address" },
            { name: "to", type: "address" },
            { name: "value", type: "uint256" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
            { name: "nonce", type: "bytes32" },
          ],
        },
        primaryType: "TransferWithAuthorization",
        message: {
          from: authorization.from as `0x${string}`,
          to: authorization.to as `0x${string}`,
          value: BigInt(authorization.value as string),
          validAfter: BigInt(authorization.validAfter as string),
          validBefore: BigInt(authorization.validBefore as string),
          nonce: authorization.nonce as `0x${string}`,
        },
        signature,
      });
      assert.equal(valid, true, "the PAYMENT-SIGNATURE carries a valid USDC authorization");
      assertNoKey([r.text, r.json, r.structuredContent, ...upstream.calls.map((c) => c.init)], key);
    } finally {
      await session.close();
    }
  });

  test("without a payer key: not_verified with the instruction to configure one", async () => {
    const upstream = provider(issuer, () => assert.fail("nothing is paid without a payer"));
    const session = await connect({ fetch: upstream.fetch });
    try {
      const r = await callTool(session.client, "x402check_check", { wallet: SPENDER, chain: "base" });
      assert.equal(r.isError, true);
      assert.match(r.text, /^x402check: NOT VERIFIED/);
      assert.match(r.text, /payment required \(every evaluation is paid via x402\)/);
      assert.match(r.text, /Next: every check is paid via x402 \(\$0\.001 in USDC\)\. Set X402CHECK_PAYER_KEY to the private key of a dedicated, low-balance wallet funded with a little USDC on Base \(the x402 exact scheme is gasless for the payer\)/);
      assert.match(String(r.structuredContent?.next ?? ""), /^every check is paid via x402/);
      assert.equal((r.structuredContent?.error as { code: string }).code, "payment_required");
      assert.equal(upstream.payments.length, 0);
    } finally {
      await session.close();
    }
  });

  test("the budget is enforced: pre-flight once it cannot buy a check, and before signing a payment it cannot cover", async () => {
    const key = generatePrivateKey();
    const address = privateKeyToAccount(key).address;
    // $0.003 per check, $0.004 budget: the first check pays, the second would exceed the budget.
    const upstream = provider(issuer, (_p, body) => settledResult(issuer, body, address), "3000");
    const session = await connect({ fetch: upstream.fetch, payerKey: key, budgetUsd: 0.004 });
    try {
      const first = await callTool(session.client, "x402check_check", { wallet: SPENDER, chain: "base" });
      assert.match(first.text, /^x402check: ALLOW/);
      assert.match(first.text, /Payer budget: \$0\.003 of \$0\.004 spent/);
      const second = await callTool(session.client, "x402check_check", { wallet: SPENDER, chain: "base" });
      assert.match(second.text, /^x402check: NOT VERIFIED/);
      assert.match(second.text, /The check did not run: the payment budget of this server is exhausted/);
      assert.match(second.text, /Next: this server's payment budget is used up \(\$0\.003 of \$0\.004; X402CHECK_BUDGET_USD\)/);
      assert.equal((second.structuredContent?.error as { code: string }).code, "budget_exhausted");
      assert.equal(upstream.payments.length, 1, "nothing was signed for the refused check");
    } finally {
      await session.close();
    }

    const exact = provider(issuer, (_p, body) => settledResult(issuer, body, address));
    const tiny = await connect({ fetch: exact.fetch, payerKey: key, budgetUsd: 0.001 });
    try {
      assert.match((await callTool(tiny.client, "x402check_check", { wallet: SPENDER, chain: "base" })).text, /^x402check: ALLOW/);
      const calls = exact.calls.length;
      const refused = await callTool(tiny.client, "x402check_check", { wallet: SPENDER, chain: "base" });
      assert.match(refused.text, /budget of this server is exhausted/);
      assert.equal(exact.calls.length, calls, "refused before calling the API at all");
    } finally {
      await tiny.close();
    }
  });

  test("a price above X402CHECK_MAX_PAYMENT_USD is refused, nothing signed", async () => {
    const key = generatePrivateKey();
    const upstream = provider(issuer, () => assert.fail("nothing is paid above the cap"), "100000");
    const session = await connect({ fetch: upstream.fetch, payerKey: key, maxPaymentUsd: 0.05 });
    try {
      const r = await callTool(session.client, "x402check_check", { wallet: SPENDER, chain: "base" });
      assert.match(r.text, /^x402check: NOT VERIFIED/);
      assert.match(r.text, /the price exceeds the per-payment cap \(X402CHECK_MAX_PAYMENT_USD\)/);
      assert.match(r.text, /Next: the price exceeds this server's per-payment cap \(\$0\.050; X402CHECK_MAX_PAYMENT_USD\)/);
      assert.equal((r.structuredContent?.error as { code: string }).code, "over_max_payment");
      assert.equal(upstream.payments.length, 0);
      assert.deepEqual((r.structuredContent?.payment as { spent_usd: number }).spent_usd, 0);
    } finally {
      await session.close();
    }
  });

  test("a settlement the provider rejects is not_verified with the payer to check", async () => {
    const key = generatePrivateKey();
    const address = privateKeyToAccount(key).address;
    const upstream = provider(issuer, () => json(402, { error: "payment_settlement_failed" }, { "X-Payment-Error": "insufficient_funds" }));
    const session = await connect({ fetch: upstream.fetch, payerKey: key });
    try {
      const r = await callTool(session.client, "x402check_check", { wallet: SPENDER, chain: "base" });
      assert.match(r.text, /^x402check: NOT VERIFIED/);
      assert.match(r.text, /the x402 payment failed \(insufficient_funds\)/);
      assert.match(r.text, new RegExp(`Next: the payment was not accepted \\(insufficient_funds\\)\\. Check the USDC balance of the payer ${address} on Base`));
    } finally {
      await session.close();
    }
  });

  test("the private key never appears in any output, even inside an error message", async () => {
    const key = generatePrivateKey();
    // A hostile or buggy transport that puts the key into an error message.
    const leaky = async (): Promise<Response> => {
      throw new Error(`upstream failure while handling ${key} / ${key.slice(2).toUpperCase()}`);
    };
    const session = await connect({ fetch: leaky, payerKey: key });
    try {
      const check = await callTool(session.client, "x402check_check", { wallet: SPENDER, chain: "base" });
      assert.match(check.text, /^x402check: NOT VERIFIED/);
      const methodology = await callTool(session.client, "x402check_methodology");
      const tools = await session.client.listTools();
      assertNoKey([check.text, check.json, check.structuredContent, methodology.text, tools], key);
      assert.match(JSON.stringify(check.structuredContent), /\[redacted\]/, "the leaked value was scrubbed");
    } finally {
      await session.close();
    }
  });

  test("invalid payer configuration fails at startup without echoing the key", () => {
    const secret = `0x${"a".repeat(63)}z`;
    assert.throws(
      () => createX402CheckServer({ payerKey: secret }),
      (err: Error) => err instanceof TypeError && /X402CHECK_PAYER_KEY must be an EVM private key/.test(err.message) && !err.message.includes("a".repeat(20)),
    );
    assert.throws(() => createX402CheckServer({ payerKey: generatePrivateKey(), budgetUsd: Number.NaN }), /X402CHECK_BUDGET_USD/);
    assert.throws(() => createX402CheckServer({ payerKey: generatePrivateKey(), maxPaymentUsd: -1 }), /X402CHECK_MAX_PAYMENT_USD/);
    const payer = createPayer({ privateKey: generatePrivateKey() });
    assert.deepEqual([payer.maxPaymentUsd, payer.budgetUsd, payer.spentUsd(), payer.canAfford()], [0.05, 1, 0, true]);
  });
});
