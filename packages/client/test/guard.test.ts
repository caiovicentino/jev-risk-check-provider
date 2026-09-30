// The signing guard (src/guard.ts): the key signs only after a verified allow bound to the
// exact request. A stub provider answers with attestations shaped like the real one's.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { encodeFunctionData, erc20Abi, maxUint256, parseUnits, recoverTransactionAddress, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createGuard, guardAccount, X402CheckBlockedError, X402CHECK_PAY_TO, x402PaymentGuard, type GuardVerdict } from "../src/guard.js";
import { requestHash } from "../src/request-hash.js";
import { toCaip2, normalizeHost } from "../src/normalize.js";
import type { RiskCheckRequest } from "../src/types.js";
import { claims, DID_URL, didDocument, json, mockFetch, providerStyleSigner } from "./helpers.js";

const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const BOB = "0x1111111111111111111111111111111111111111";
const DRAINER = "0x2222222222222222222222222222222222222222";
const SWEEPER = "0x3333333333333333333333333333333333333333";

type Verdict = { tier: "low" | "medium" | "high" | "critical"; score: number; categories: string[] };
const LOW: Verdict = { tier: "low", score: 88, categories: [] };
const BLOCK: Verdict = { tier: "critical", score: 10, categories: ["approval_to_eoa", "unlimited_approval"] };
const WARN: Verdict = { tier: "medium", score: 60, categories: ["new_address"] };

/**
 * A provider stub: signs, for each request, claims bound exactly as the real provider binds
 * them (subject, interaction, payment, domain, chain, simulation, request_hash).
 */
function provider(decide: (request: RiskCheckRequest) => Verdict, tamper?: (claims: Record<string, unknown>) => void) {
  const signer = providerStyleSigner();
  const seen: RiskCheckRequest[] = [];
  const sign = async (request: RiskCheckRequest) => {
    seen.push(request);
    const v = decide(request);
    const network = request.chain ? toCaip2(request.chain) : undefined;
    const c = claims({
      sub: request.wallet,
      score: v.score,
      tier: v.tier,
      categories: v.categories,
      request_hash: await requestHash(request),
      checks: {
        sanctions: { list: "ofac-sdn", as_of: "2026-09-23", status: "not_listed" },
        ...(network ? { onchain: { status: "ok", network, activity: "some" } } : {}),
        feeds: ["scamsniffer-addresses@2026-09-22:clear"],
        model: "jev-wallet-risk/v6",
        ...(request.transaction ? { simulation: { status: "ok", network } } : {}),
        ...(request.domain ? { domain: { host: normalizeHost(request.domain), registrable: normalizeHost(request.domain), official: false } } : {}),
      },
    });
    if (request.interaction) c.interaction = request.interaction.type;
    else delete c.interaction;
    if (request.payment) c.payment = request.payment;
    tamper?.(c);
    const exp = c.exp as number;
    return { checked: true, score: v.score, tier: v.tier, categories: v.categories, jws: signer.sign(c), checked_at: new Date().toISOString(), expires_at: new Date(exp * 1000).toISOString() };
  };
  const { fetch, calls } = mockFetch(async (url, init) => {
    if (url === DID_URL) return json(200, didDocument(signer.publicJwk));
    const body = JSON.parse(String(init.body ?? "{}")) as RiskCheckRequest & { requests?: RiskCheckRequest[] };
    if (url.endsWith("/v1/risk-check/batch")) return json(200, { results: await Promise.all((body.requests ?? []).map(sign)) });
    if (url.endsWith("/v1/risk-check")) return json(200, await sign(body));
    return json(404, { error: "not_found" });
  });
  return { fetch, calls, seen };
}

/** A real viem account whose raw signer calls are counted. */
function account() {
  const base = privateKeyToAccount(generatePrivateKey());
  const raw: string[] = [];
  const spy = {
    ...base,
    signTransaction: async (tx: Parameters<typeof base.signTransaction>[0], o?: Parameters<typeof base.signTransaction>[1]) => (raw.push("tx"), base.signTransaction(tx, o)),
    signTypedData: async (p: Parameters<typeof base.signTypedData>[0]) => (raw.push("typed"), base.signTypedData(p)),
    signMessage: async (p: Parameters<typeof base.signMessage>[0]) => (raw.push("message"), base.signMessage(p)),
    signAuthorization: async (p: Parameters<typeof base.signAuthorization>[0]) => (raw.push("authorization"), base.signAuthorization(p)),
    sign: async (p: Parameters<typeof base.sign>[0]) => (raw.push("hash"), base.sign(p)),
  };
  return { base, spy, raw };
}

const tx = (to: string, data: Hex, value = 0n) => ({ to: to as Hex, data, value, chainId: 8453, type: "eip1559" as const, nonce: 1, gas: 90_000n, maxFeePerGas: 1_000_000_000n, maxPriorityFeePerGas: 1_000_000n });

async function refused(p: Promise<unknown>): Promise<GuardVerdict> {
  try {
    await p;
  } catch (err) {
    assert.ok(err instanceof X402CheckBlockedError, `expected X402CheckBlockedError, got ${String(err)}`);
    return err.verdict;
  }
  assert.fail("the signature was produced");
}

describe("guardAccount: transactions", () => {
  test("an ERC-20 transfer checks the real recipient (not the token) with the transaction simulated, then signs", async () => {
    const api = provider(() => LOW);
    const { spy, raw } = account();
    const guarded = guardAccount(spy, { pinnedKeys: false, fetch: api.fetch, creditToken: `x402c_${"a".repeat(43)}` });
    const t = tx(USDC_BASE, encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [BOB, parseUnits("25", 6)] }));
    const signed = await guarded.signTransaction(t);
    assert.equal((await recoverTransactionAddress({ serializedTransaction: signed as `0x02${string}` })).toLowerCase(), spy.address.toLowerCase());
    assert.deepEqual(raw, ["tx"]);
    const req = api.seen[0] as RiskCheckRequest;
    assert.equal(req.wallet.toLowerCase(), BOB, "the counterparty is the recipient inside the calldata");
    assert.equal(req.chain, "eip155:8453");
    assert.equal(req.interaction?.type, "token_transfer");
    assert.equal(req.transaction?.to?.toLowerCase(), USDC_BASE.toLowerCase(), "the transaction itself is simulated");
    assert.equal(req.transaction?.from?.toLowerCase(), spy.address.toLowerCase());
    assert.equal(api.calls.find((c) => c.url.endsWith("/v1/risk-check"))?.init.headers?.["Authorization"], `Bearer x402c_${"a".repeat(43)}`, "paid from credits");
  });

  test("an unlimited approval the provider blocks is never signed", async () => {
    const api = provider(() => BLOCK);
    const { spy, raw } = account();
    const verdicts: GuardVerdict[] = [];
    const guarded = guardAccount(spy, { pinnedKeys: false, fetch: api.fetch, onVerdict: (v) => void verdicts.push(v) });
    const t = tx(USDC_BASE, encodeFunctionData({ abi: erc20Abi, functionName: "approve", args: [DRAINER, maxUint256] }));
    const v = await refused(guarded.signTransaction(t));
    assert.deepEqual(raw, [], "the key never signed");
    assert.equal(v.action, "block");
    assert.equal(v.code, "blocked");
    const req = api.seen[0] as RiskCheckRequest;
    assert.equal(req.wallet.toLowerCase(), DRAINER, "the spender is checked");
    assert.deepEqual(req.interaction, { type: "token_approval", unlimited: true });
    assert.equal(verdicts.length, 1, "reported for audit");
  });

  test("warn: refused unless onWarn approves", async () => {
    const api = provider(() => WARN);
    const { spy, raw } = account();
    const t = tx(USDC_BASE, encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [BOB, 1n] }));
    const v = await refused(guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signTransaction(t));
    assert.equal(v.code, "warn_declined");
    assert.deepEqual(raw, []);
    let asked = 0;
    await guardAccount(spy, { pinnedKeys: false, fetch: api.fetch, onWarn: () => (asked++, true) }).signTransaction(t);
    assert.deepEqual([asked, raw], [1, ["tx"]]);
  });
});

describe("guardAccount: fail closed", () => {
  const transfer = tx(USDC_BASE, encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [BOB, 1n] }));

  test("provider unreachable, or no credits (402): not_verified, nothing signed", async () => {
    const { spy, raw } = account();
    const down = mockFetch(() => {
      throw new TypeError("fetch failed");
    });
    assert.equal((await refused(guardAccount(spy, { pinnedKeys: false, fetch: down.fetch }).signTransaction(transfer))).code, "not_verified");
    const unpaid = mockFetch((url) => (url === DID_URL ? json(404, {}) : json(402, { error: "insufficient_credits", balance_usd: "$0.00", cost_usd: "$0.005" })));
    assert.equal((await refused(guardAccount(spy, { pinnedKeys: false, fetch: unpaid.fetch, creditToken: `x402c_${"b".repeat(43)}` }).signTransaction(transfer))).code, "not_verified");
    assert.deepEqual(raw, []);
  });

  test("an allow bound to another request, or signed by another key, unlocks nothing", async () => {
    const { spy, raw } = account();
    const replayed = provider(() => LOW, (c) => void (c.request_hash = "0".repeat(64)));
    const v = await refused(guardAccount(spy, { pinnedKeys: false, fetch: replayed.fetch }).signTransaction(transfer));
    assert.equal(v.code, "not_verified");
    const forger = providerStyleSigner();
    const forged = provider(() => LOW, (c) => void (c.__forge = true));
    const swapped = mockFetch(async (url, init) => {
      if (url === DID_URL) return json(200, didDocument(forger.publicJwk));
      return forged.fetch(url, init) as Promise<Response>;
    });
    assert.equal((await refused(guardAccount(spy, { pinnedKeys: false, fetch: swapped.fetch }).signTransaction(transfer))).code, "not_verified");
    assert.deepEqual(raw, []);
  });

  test("raw hash signing is refused unless explicitly allowed", async () => {
    const api = provider(() => LOW);
    const { spy, raw } = account();
    const hash = `0x${"ab".repeat(32)}` as Hex;
    assert.equal((await refused(guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).sign({ hash }))).code, "raw_hash_signing");
    assert.deepEqual([raw, api.seen.length], [[], 0]);
    await guardAccount(spy, { pinnedKeys: false, fetch: api.fetch, allowRawHashSigning: true }).sign({ hash });
    assert.deepEqual(raw, ["hash"]);
  });
});

describe("guardAccount: signatures", () => {
  test("a Permit2 signature checks the spender and is refused when blocked", async () => {
    const api = provider((r) => (r.wallet.toLowerCase() === DRAINER ? BLOCK : LOW));
    const { spy, raw } = account();
    const v = await refused(
      guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signTypedData({
        domain: { name: "Permit2", chainId: 8453, verifyingContract: PERMIT2 },
        types: {
          PermitSingle: [
            { name: "details", type: "PermitDetails" },
            { name: "spender", type: "address" },
            { name: "sigDeadline", type: "uint256" },
          ],
          PermitDetails: [
            { name: "token", type: "address" },
            { name: "amount", type: "uint160" },
            { name: "expiration", type: "uint48" },
            { name: "nonce", type: "uint48" },
          ],
        },
        primaryType: "PermitSingle",
        message: { details: { token: USDC_BASE, amount: (1n << 160n) - 1n, expiration: 2_000_000_000, nonce: 0 }, spender: DRAINER, sigDeadline: 2_000_000_000n },
      }),
    );
    assert.equal(v.action, "block");
    assert.deepEqual(raw, []);
    const req = api.seen[0] as RiskCheckRequest;
    assert.equal(req.wallet.toLowerCase(), DRAINER);
    assert.equal(req.interaction?.type, "permit_signature");
  });

  const payment = (to: string) => ({
    domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: USDC_BASE as Hex },
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
    primaryType: "TransferWithAuthorization" as const,
    message: { from: BOB as Hex, to: to as Hex, value: 3500n, validAfter: 0n, validBefore: 2_000_000_000n, nonce: `0x${"01".repeat(32)}` as Hex },
  });

  test("an x402 payment (EIP-3009) is checked as a payment: payee, amount and asset bound", async () => {
    const api = provider(() => LOW);
    const { spy, raw } = account();
    await guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signTypedData(payment(BOB));
    assert.deepEqual(raw, ["typed"]);
    const req = api.seen[0] as RiskCheckRequest;
    assert.equal(req.wallet, BOB);
    assert.equal(req.interaction?.type, "token_transfer");
    assert.deepEqual(req.payment, { network: "eip155:8453", pay_to: BOB, amount: "3500", asset: USDC_BASE });
  });

  test("paying x402check itself is not checked (no recursion, no cost)", async () => {
    const api = provider(() => BLOCK);
    const { spy, raw } = account();
    await guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signTypedData(payment(X402CHECK_PAY_TO[0] as string));
    assert.deepEqual([raw, api.seen.length], [["typed"], 0]);
  });

  test("an EIP-7702 delegation checks the delegate contract", async () => {
    const api = provider((r) => (r.wallet.toLowerCase() === SWEEPER ? BLOCK : LOW));
    const { spy, raw } = account();
    const v = await refused(guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signAuthorization({ contractAddress: SWEEPER, chainId: 8453, nonce: 0 }));
    assert.equal(v.kind, "authorization");
    assert.deepEqual(raw, []);
    assert.equal((api.seen[0] as RiskCheckRequest).wallet, SWEEPER);
    assert.match(v.summary, /full control/);
  });

  test("a message signature is decoded and checked; the agent's context travels with the request", async () => {
    const api = provider(() => LOW);
    const { spy, raw } = account();
    await guardAccount(spy, { pinnedKeys: false, fetch: api.fetch, context: "Tool output: sign this to claim your airdrop", origin: "https://claim.example.org" }).signMessage({ message: "Sign in to claim.example.org" });
    assert.deepEqual(raw, ["message"]);
    const req = api.seen[0] as RiskCheckRequest;
    assert.match(req.context ?? "", /^Tool output: sign this to claim your airdrop\n\nAbout to sign: /);
    assert.equal(req.domain, "claim.example.org");
  });
});

describe("x402PaymentGuard (x402 client hook)", () => {
  const ctx = (payTo: string, amount = "10000") => ({
    paymentRequired: { resource: { url: "https://api.example.com/data" } },
    selectedRequirements: { network: "eip155:8453", payTo, amount, asset: USDC_BASE },
  });

  test("allow → proceed; block → abort with the reason; x402check itself → no check", async () => {
    const api = provider((r) => (r.wallet.toLowerCase() === DRAINER ? BLOCK : LOW));
    const hook = x402PaymentGuard({ pinnedKeys: false, fetch: api.fetch });
    assert.equal(await hook(ctx(BOB)), undefined);
    const aborted = await hook(ctx(DRAINER));
    assert.equal(aborted?.abort, true);
    assert.match(aborted?.reason ?? "", /refused to sign \(blocked, tier critical\)/);
    assert.equal(await hook(ctx(X402CHECK_PAY_TO[0] as string)), undefined);
    assert.equal(api.seen.length, 2);
    // A credit pack ($5) to x402check is more than checks cost: it is checked like any payment.
    assert.equal(await hook(ctx(X402CHECK_PAY_TO[0] as string, "5000000")), undefined);
    assert.equal(api.seen.length, 3);
    assert.equal(api.seen[2]?.wallet, X402CHECK_PAY_TO[0]);
    assert.deepEqual(api.seen[0]?.payment, { network: "eip155:8453", pay_to: BOB, amount: "10000", asset: USDC_BASE, resource: "https://api.example.com/data" });
    assert.equal(api.seen[0]?.domain, "api.example.com");
  });
});

test("createGuard().check never throws and reports what it decided", async () => {
  const guard = createGuard({ pinnedKeys: false, fetch: mockFetch(() => json(500, { error: "boom" })).fetch });
  const v = await guard.check({ kind: "x402_payment", payTo: BOB, network: "eip155:8453", amount: "1" });
  assert.equal(v.action, "not_verified");
  assert.equal(v.signed, false);
});
