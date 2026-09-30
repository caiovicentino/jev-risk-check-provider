// The signing guard's fail-closed rules from the 2026-09-30 audit: what the guard cannot read,
// simulate or bind is never signed, and only pinned attestation keys are trusted.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { encodeFunctionData, erc20Abi, parseUnits, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createGuard, guardAccount, X402CheckBlockedError, X402CHECK_KEY_THUMBPRINTS, X402_PERMIT2_PROXIES, type GuardVerdict } from "../src/guard.js";
import { jwkThumbprint } from "../src/verify.js";
import { boundProvider } from "./helpers.js";

const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const BOB = "0x1111111111111111111111111111111111111111";
const DRAINER = "0x2222222222222222222222222222222222222222";
const SWEEPER = "0x3333333333333333333333333333333333333333";
const LOW = { tier: "low" as const, score: 88, categories: [] };
const BLOCK = { tier: "critical" as const, score: 5, categories: ["known_scam_address"] };

function spied() {
  const base = privateKeyToAccount(generatePrivateKey());
  const raw: unknown[] = [];
  const spy = {
    ...base,
    signTransaction: async (tx: Parameters<typeof base.signTransaction>[0]) => (raw.push(tx), base.signTransaction(tx)),
    signTypedData: async (p: Parameters<typeof base.signTypedData>[0]) => (raw.push(p), base.signTypedData(p)),
    signMessage: async (p: Parameters<typeof base.signMessage>[0]) => (raw.push(p), base.signMessage(p)),
    signAuthorization: async (p: Parameters<typeof base.signAuthorization>[0]) => (raw.push(p), base.signAuthorization(p)),
  };
  return { base, spy, raw };
}

const tx = (to: string | undefined, data: Hex = "0x", value = 0n, extra: Record<string, unknown> = {}) => ({
  ...(to ? { to: to as Hex } : {}),
  data,
  value,
  chainId: 8453,
  type: "eip1559" as const,
  nonce: 0,
  gas: 90_000n,
  maxFeePerGas: 1_000_000_000n,
  maxPriorityFeePerGas: 1_000_000n,
  ...extra,
});

async function refused(p: Promise<unknown>): Promise<GuardVerdict> {
  try {
    await p;
  } catch (err) {
    assert.ok(err instanceof X402CheckBlockedError, `expected X402CheckBlockedError, got ${String(err)}`);
    return err.verdict;
  }
  assert.fail("expected a refusal");
}

describe("attestation keys are pinned by default", () => {
  test("a DID document serving another key (a compromised deployment) is refused; pinning its thumbprint accepts it", async () => {
    const api = boundProvider(() => LOW);
    const { base, spy, raw } = spied();
    const t = tx(USDC_BASE, encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [BOB, parseUnits("1", 6)] }));
    const v = await refused(guardAccount(spy, { fetch: api.fetch }).signTransaction(t));
    assert.equal(v.action, "not_verified");
    assert.match(v.reasons.join(" "), /key_not_pinned/);
    assert.equal(raw.length, 0);
    const own = await jwkThumbprint(api.publicJwk);
    await guardAccount(spy, { fetch: api.fetch, pinnedKeys: [own] }).signTransaction(t);
    assert.equal(raw.length, 1);
    assert.deepEqual(X402CHECK_KEY_THUMBPRINTS, ["J8BVKKyWmMP2WVzlxa4gi_1D0znFMZLcxs-BDlYeS8c"], "production's key is the default pin");
    void base;
  });
});

describe("guardAccount: what cannot be read is not signed", () => {
  test("an x402 payment through Permit2 is checked against its payee (the witness `to`), with amount and asset bound", async () => {
    const api = boundProvider((r) => (r.wallet.toLowerCase() === DRAINER ? BLOCK : LOW));
    const { spy, raw } = spied();
    const permit = (to: string) => ({
      domain: { name: "Permit2", chainId: 8453, verifyingContract: PERMIT2 as Hex },
      types: {
        PermitWitnessTransferFrom: [
          { name: "permitted", type: "TokenPermissions" },
          { name: "spender", type: "address" },
          { name: "nonce", type: "uint256" },
          { name: "deadline", type: "uint256" },
          { name: "witness", type: "Witness" },
        ],
        TokenPermissions: [
          { name: "token", type: "address" },
          { name: "amount", type: "uint256" },
        ],
        Witness: [
          { name: "to", type: "address" },
          { name: "validAfter", type: "uint256" },
          { name: "extra", type: "bytes" },
        ],
      },
      primaryType: "PermitWitnessTransferFrom" as const,
      message: { permitted: { token: USDC_BASE as Hex, amount: 10_000n }, spender: X402_PERMIT2_PROXIES[0] as Hex, nonce: 7n, deadline: 2_000_000_000n, witness: { to: to as Hex, validAfter: 0n, extra: "0x" as Hex } },
    });
    const v = await refused(guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signTypedData(permit(DRAINER)));
    assert.equal(v.kind, "x402_payment");
    assert.equal(v.action, "block");
    assert.deepEqual(api.seen[0]?.payment, { network: "eip155:8453", pay_to: DRAINER, amount: "10000", asset: USDC_BASE });
    await guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signTypedData(permit(BOB));
    assert.equal(raw.length, 1);
  });

  test("a message of opaque bytes (a 32-byte hash authorizes user operations and Safe transactions) is refused like sign({ hash })", async () => {
    const api = boundProvider(() => LOW);
    const { spy, raw } = spied();
    const hash = `0x${"ab".repeat(32)}` as Hex;
    const v = await refused(guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signMessage({ message: { raw: hash } }));
    assert.deepEqual([v.action, v.code], ["block", "raw_hash_signing"]);
    assert.equal(api.seen.length, 0, "refused before any check is bought");
    await refused(guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signMessage({ message: { raw: new Uint8Array([0, 1, 2, 250]) } }));
    // Readable text sent as raw bytes is still a text message; opting in lets opaque bytes through (checked as a message).
    await guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signMessage({ message: { raw: `0x${Buffer.from("Sign in to example.org").toString("hex")}` as Hex } });
    await guardAccount(spy, { pinnedKeys: false, fetch: api.fetch, allowRawHashSigning: true }).signMessage({ message: { raw: hash } });
    assert.equal(raw.length, 2);
  });

  test("deployments with value, undecoded self-calls and unsimulatable calldata are not signed on an address check", async () => {
    const api = boundProvider(() => LOW);
    const { base, spy, raw } = spied();
    const g = guardAccount(spy, { pinnedKeys: false, fetch: api.fetch });
    const deploy = await refused(g.signTransaction(tx(undefined, "0x6080604052", 10n ** 18n)));
    assert.deepEqual([deploy.action, deploy.code], ["not_verified", "not_simulated"]);
    const self = await refused(g.signTransaction(tx(base.address, "0x9517e29f00000000000000000000000000000000000000000000000000000000000000010000000000000000000000002222222222222222222222222222222222222222")));
    assert.deepEqual([self.action, self.code], ["not_verified", "unreadable_self_call"]);
    const padded = await refused(g.signTransaction(tx(SWEEPER, `0x4e71d92d${"00".repeat(25_000)}` as Hex)));
    assert.deepEqual([padded.action, padded.code], ["not_verified", "not_simulated"]);
    assert.equal(raw.length, 0);
    assert.equal(api.seen.length, 0);
    // Inert: a zero-value deployment has nothing to check.
    await g.signTransaction(tx(undefined, "0x6080604052"));
    assert.equal(raw.length, 1);
  });

  test("delegations and transactions valid on every chain", async () => {
    const api = boundProvider(() => LOW);
    const { spy, raw } = spied();
    const every = await refused(guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signAuthorization({ contractAddress: SWEEPER as Hex, chainId: 0, nonce: 0 }));
    assert.deepEqual([every.action, every.code], ["block", "every_chain_authorization"]);
    await guardAccount(spy, { pinnedKeys: false, fetch: api.fetch, allowEveryChainAuthorization: true }).signAuthorization({ contractAddress: SWEEPER as Hex, chainId: 0, nonce: 0 });
    assert.deepEqual(api.seen.map((r) => [r.wallet, r.chain]), [[SWEEPER, "eip155:1"], [SWEEPER, "eip155:8453"]], "checked on each kit-watch chain");
    const noChain = await refused(createGuard({ pinnedKeys: false, fetch: api.fetch }).enforce({ kind: "transaction", from: BOB, transaction: { to: USDC_BASE, value: 0n, data: "0x" } }));
    assert.deepEqual([noChain.action, noChain.code], ["not_verified", "no_chain"]);
    assert.equal(raw.length, 1);
  });

  test("a fee cap in wei, when set", async () => {
    const api = boundProvider(() => LOW);
    const { spy } = spied();
    const v = await refused(guardAccount(spy, { pinnedKeys: false, fetch: api.fetch, maxFeeWei: 10n ** 13n }).signTransaction(tx(BOB, "0x", 1n)));
    assert.deepEqual([v.action, v.code], ["block", "fee_cap"]);
  });

  test("signing members the guard does not intercept refuse (a smart account's signUserOperation), unless passed through", async () => {
    const api = boundProvider(() => LOW);
    const { base } = spied();
    let userOps = 0;
    const smart = { ...base, getAddress: async () => base.address, signUserOperation: async () => (userOps++, "0xsig") };
    const guarded = guardAccount(smart, { pinnedKeys: false, fetch: api.fetch });
    const v = await refused(guarded.signUserOperation());
    assert.deepEqual([v.kind, v.code], ["unguarded_method", "unguarded_method"]);
    assert.equal(userOps, 0);
    assert.equal(await guarded.getAddress(), base.address, "members that do not sign are kept");
    await guardAccount(smart, { pinnedKeys: false, fetch: api.fetch, passthrough: ["signUserOperation"] }).signUserOperation();
    assert.equal(userOps, 1);
  });

  test("the request is copied before the check, and the copy is what gets signed", async () => {
    const api = boundProvider(() => LOW);
    const { spy, raw } = spied();
    let reads = 0;
    const t = tx(USDC_BASE, encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [BOB, 1n] }));
    // A getter that would swap the recipient after the check.
    const tricky = Object.defineProperty({ ...t }, "data", {
      enumerable: true,
      get: () => (reads++ === 0 ? t.data : encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [DRAINER, 10n ** 12n] })),
    });
    await guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signTransaction(tricky);
    assert.equal((raw[0] as { data: string }).data, t.data, "the checked calldata is the signed calldata");
    assert.equal(api.seen[0]?.wallet.toLowerCase(), BOB);
  });

  test("x402 v1 network names are mapped, and a resource host the provider rejects is omitted", async () => {
    const api = boundProvider(() => LOW);
    const g = createGuard({ pinnedKeys: false, fetch: api.fetch });
    const v = await g.check({ kind: "x402_payment", payTo: BOB, network: "base", amount: "1000", asset: USDC_BASE, resource: "https://my_app.example.com/v1/data" });
    assert.equal(v.action, "allow", v.reasons.join("; "));
    assert.equal(api.seen[0]?.chain, "eip155:8453");
    assert.equal(api.seen[0]?.domain, undefined);
  });
});
