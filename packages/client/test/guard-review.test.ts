// The SDK review of 2026-10-16, EVM: what the guard checks is what the key signs (a transaction
// is normalized as viem serializes it), every counterparty is checked or nothing is signed, a
// transaction is signed on its simulation only, and an unrecognized grant is checked as a permit.
// Stubs only: throwaway keys, no network.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { concatHex, encodeAbiParameters, encodeFunctionData, encodePacked, erc20Abi, maxUint256, parseTransaction, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createGuard, guardAccount, X402CheckBlockedError, type GuardVerdict } from "../src/guard.js";
import { boundProvider } from "./helpers.js";

const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const BOB = "0x1111111111111111111111111111111111111111";
const DRAINER = "0x2222222222222222222222222222222222222222";
const UNKNOWN_CONTRACT = "0x5555555555555555555555555555555555555555" as Hex;
const LOW = { tier: "low" as const, score: 88, categories: [] };
const BLOCK = { tier: "critical" as const, score: 2, categories: ["known_scam_address"] };
/** PUSH20 drainer; SELFDESTRUCT: init code that forwards the deployment's value. */
const INIT = `0x73${DRAINER.slice(2)}ff` as Hex;
const FEES = { chainId: 8453, type: "eip1559" as const, nonce: 0, gas: 90_000n, maxFeePerGas: 1_000_000_000n, maxPriorityFeePerGas: 1_000_000n };

const pay = (to: string, amount = 1n) => encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [to as Hex, amount] });

function evmSigner() {
  const base = privateKeyToAccount(generatePrivateKey());
  const signed: Hex[] = [];
  let typed = 0;
  const spy = {
    ...base,
    signTransaction: async (tx: Parameters<typeof base.signTransaction>[0], opts?: Parameters<typeof base.signTransaction>[1]) => {
      const raw = await base.signTransaction(tx, opts);
      signed.push(raw);
      return raw;
    },
    signTypedData: async (p: Parameters<typeof base.signTypedData>[0]) => (typed++, base.signTypedData(p)),
  };
  return { spy, signed, typedCount: () => typed };
}

async function refused(p: Promise<unknown>): Promise<GuardVerdict> {
  try {
    await p;
  } catch (err) {
    assert.ok(err instanceof X402CheckBlockedError, `expected X402CheckBlockedError, got ${String(err)}`);
    return err.verdict;
  }
  assert.fail("expected a refusal");
}

describe("finding 1: a transaction is checked exactly as viem will sign it", () => {
  test("a creation that carries value is refused however `to` and `value` are spelled", async () => {
    const api = boundProvider(() => LOW);
    const { spy, signed } = evmSigner();
    const g = guardAccount(spy, { pinnedKeys: false, fetch: api.fetch });
    // viem serializes `to: ""` as a creation, and reads these values with BigInt().
    for (const variant of [{ to: "", value: 10n ** 18n }, { to: "0x", value: 10n ** 18n }, { value: "0XDE0B6B3A7640000" }, { value: " 1000000000000000000" }]) {
      const v = await refused(g.signTransaction({ ...FEES, data: INIT, ...variant } as never));
      assert.deepEqual([v.action, v.code], ["not_verified", "not_simulated"], JSON.stringify(variant, (_k, x) => (typeof x === "bigint" ? `${x}n` : x)));
    }
    assert.equal(signed.length, 0);
    assert.equal(api.seen.length, 0);
    // A zero-value creation is inert: signed, as a creation.
    await g.signTransaction({ ...FEES, to: "", data: "0x6080604052", value: 0n } as never);
    assert.equal(parseTransaction(signed[0] as Hex).to, undefined);
  });

  test("amounts are read with BigInt semantics, and that bigint is what is checked and signed", async () => {
    const api = boundProvider(() => LOW);
    const { spy, signed } = evmSigner();
    await guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signTransaction({ ...FEES, to: BOB, value: " 0X10" } as never);
    assert.equal(api.seen[0]?.payment?.amount, "16");
    assert.equal(api.seen[0]?.transaction?.value, "0x10");
    assert.equal(parseTransaction(signed[0] as Hex).value, 16n);
  });

  test("the fee cap applies to what is signed: a gas limit written as a string counts", async () => {
    const api = boundProvider(() => LOW);
    const { spy, signed } = evmSigner();
    const v = await refused(guardAccount(spy, { pinnedKeys: false, fetch: api.fetch, maxFeeWei: 10n ** 13n }).signTransaction({ ...FEES, to: BOB, value: 1n, gas: " 90000", maxFeePerGas: 10n ** 12n } as never));
    assert.deepEqual([v.action, v.code], ["block", "fee_cap"]);
    assert.equal(signed.length, 0);
  });

  test("calldata viem would read differently, or a field it would refuse, is not signed", async () => {
    const api = boundProvider(() => LOW);
    const { spy, signed } = evmSigner();
    const g = guardAccount(spy, { pinnedKeys: false, fetch: api.fetch });
    for (const variant of [
      { to: USDC_BASE, data: pay(BOB).slice(2) }, // no 0x: viem would drop its first byte
      { to: ` ${USDC_BASE}`, data: pay(BOB) }, // a recipient viem refuses
      { to: USDC_BASE, data: pay(BOB), value: 1e18 }, // an unsafe number
      { to: USDC_BASE, data: pay(BOB), type: "cip64" }, // a format the guard does not read
    ]) {
      const v = await refused(g.signTransaction({ ...FEES, value: 0n, ...variant } as never));
      assert.deepEqual([v.action, v.code], ["not_verified", "invalid_transaction"], JSON.stringify(variant));
    }
    assert.equal(signed.length, 0);
    assert.equal(api.seen.length, 0);
  });

  test("`input` is signed as the calldata it was checked as", async () => {
    const api = boundProvider((r) => (r.wallet.toLowerCase() === DRAINER ? BLOCK : LOW));
    const { spy, signed } = evmSigner();
    const g = guardAccount(spy, { pinnedKeys: false, fetch: api.fetch });
    await refused(g.signTransaction({ ...FEES, to: USDC_BASE, value: 0n, input: pay(DRAINER) } as never));
    await g.signTransaction({ ...FEES, to: USDC_BASE, value: 0n, input: pay(BOB) } as never);
    assert.equal(signed.length, 1);
    assert.equal(parseTransaction(signed[0] as Hex).data, pay(BOB));
  });

  test("a legacy transaction without chainId is signed for the chain it was checked on, never for every chain", async () => {
    const api = boundProvider(() => LOW);
    const { spy, signed } = evmSigner();
    await guardAccount(spy, { pinnedKeys: false, fetch: api.fetch, chainId: 8453 }).signTransaction({ type: "legacy", to: BOB, value: 1n, nonce: 0, gas: 21_000n, gasPrice: 10n ** 9n } as never);
    assert.equal(api.seen[0]?.chain, "eip155:8453");
    assert.equal(parseTransaction(signed[0] as Hex).chainId, 8453);
  });
});

describe("finding 2: every counterparty is checked, or nothing is signed", () => {
  const MULTISEND = "0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761"; // Safe MultiSend 1.3.0
  const SAFE = "0x5afe5afE5afE5afE5afE5aFe5aFe5Afe5Afe5AfE";
  const ZERO = `0x${"0".repeat(40)}` as Hex;
  const address20 = (n: number) => `0x${n.toString(16).padStart(40, "0").replace(/^0/, "9")}`;
  const packed = (to: string, value: bigint, data: Hex) => encodePacked(["uint8", "address", "uint256", "uint256", "bytes"], [0, to as Hex, value, BigInt((data.length - 2) / 2), data]);
  const safeTx = (calls: Hex[]) => ({
    domain: { chainId: 8453, verifyingContract: SAFE as Hex },
    types: {
      SafeTx: [
        { name: "to", type: "address" },
        { name: "value", type: "uint256" },
        { name: "data", type: "bytes" },
        { name: "operation", type: "uint8" },
        { name: "safeTxGas", type: "uint256" },
        { name: "baseGas", type: "uint256" },
        { name: "gasPrice", type: "uint256" },
        { name: "gasToken", type: "address" },
        { name: "refundReceiver", type: "address" },
        { name: "nonce", type: "uint256" },
      ],
    },
    primaryType: "SafeTx" as const,
    message: {
      to: MULTISEND as Hex,
      value: 0n,
      data: concatHex(["0x8d80ff0a", encodeAbiParameters([{ type: "bytes" }], [concatHex(calls)])]),
      operation: 1,
      safeTxGas: 0n,
      baseGas: 0n,
      gasPrice: 0n,
      gasToken: ZERO,
      refundReceiver: ZERO,
      nonce: 7n,
    },
  });
  const decoys = [BOB, "0x3333333333333333333333333333333333333333", "0x4444444444444444444444444444444444444444"];

  test("a SafeTx whose fourth transfer pays a blocked address: all four are checked, and it is blocked", async () => {
    const api = boundProvider((r) => (r.wallet.toLowerCase() === DRAINER ? BLOCK : LOW));
    const { spy, typedCount } = evmSigner();
    const calls = [...decoys.map((d) => packed(USDC_BASE, 0n, pay(d))), packed(USDC_BASE, 0n, pay(DRAINER, 10n ** 12n))];
    const v = await refused(guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signTypedData(safeTx(calls)));
    assert.equal(v.action, "block");
    assert.equal(api.seen.length, 4);
    assert.ok(api.seen.some((r) => r.wallet.toLowerCase() === DRAINER));
    assert.equal(typedCount(), 0);
  });

  test("a SafeTx whose 33rd call is not decoded is not signed, and nothing is bought", async () => {
    const api = boundProvider(() => LOW);
    const { spy, typedCount } = evmSigner();
    const calls = [...Array.from({ length: 32 }, () => packed(SAFE, 0n, "0x")), packed(USDC_BASE, 0n, pay(DRAINER, 10n ** 12n))];
    const v = await refused(guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signTypedData(safeTx(calls)));
    assert.deepEqual([v.action, v.code], ["not_verified", "opaque_signature"]);
    assert.match(v.reasons[0] as string, /more than 32 calls/);
    assert.equal(api.seen.length, 0);
    assert.equal(typedCount(), 0);
  });

  test("30 recipients are checked in two batch calls (25 + 5); more than 50 counterparties are refused unchecked", async () => {
    const api = boundProvider(() => LOW);
    const { spy, typedCount } = evmSigner();
    const g = guardAccount(spy, { pinnedKeys: false, fetch: api.fetch });
    await g.signTypedData(safeTx(Array.from({ length: 30 }, (_v, i) => packed(USDC_BASE, 0n, pay(address20(i + 1))))));
    assert.equal(api.seen.length, 30);
    assert.equal(api.calls.filter((c) => c.url.endsWith("/v1/risk-check/batch")).length, 2);
    assert.equal(typedCount(), 1);
    // 26 calls that each pay a token contract (value) and a recipient: 52 counterparties.
    const many = Array.from({ length: 26 }, (_v, i) => packed(address20(100 + i), 1n, pay(address20(200 + i))));
    const v = await refused(g.signTypedData(safeTx(many)));
    assert.deepEqual([v.action, v.code], ["not_verified", "too_many_counterparties"]);
    assert.equal(api.seen.length, 30, "nothing more was bought");
  });
});

describe("finding 4: a transaction is signed on its simulation, not on an address check", () => {
  const call = { ...FEES, chainId: 43114, to: UNKNOWN_CONTRACT, data: `0xdeadbeef${"00".repeat(64)}` as Hex, value: 0n };

  for (const [status, action, code] of [
    ["unsupported", "not_verified", "not_simulated"],
    ["unavailable", "not_verified", "not_simulated"],
    ["reverted", "block", "simulation_reverted"],
  ] as const) {
    test(`simulation "${status}" → ${action} (${code})`, async () => {
      const api = boundProvider(() => LOW, undefined, status);
      const { spy, signed } = evmSigner();
      const v = await refused(guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signTransaction(call));
      assert.deepEqual([v.action, v.code], [action, code]);
      assert.equal(api.seen[0]?.transaction?.to, UNKNOWN_CONTRACT, "a simulation was asked for");
      assert.equal(signed.length, 0);
    });
  }

  test('"ok" signs; x402 payments and typed data do not need a simulation', async () => {
    const { spy, signed } = evmSigner();
    await guardAccount(spy, { pinnedKeys: false, fetch: boundProvider(() => LOW).fetch }).signTransaction(call);
    assert.equal(signed.length, 1);
    const unsupported = boundProvider(() => LOW, undefined, "unsupported");
    const v = await createGuard({ pinnedKeys: false, fetch: unsupported.fetch }).check({ kind: "x402_payment", payTo: BOB, network: "eip155:43114", amount: "1000", asset: "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E" });
    assert.equal(v.action, "allow");
  });
});

describe("finding 5: an unrecognized grant is checked as a permit", () => {
  test("Aave credit delegation of 2^256-1 to a wallet is checked as an UNLIMITED permit", async () => {
    const api = boundProvider((r) => (r.interaction?.type === "permit_signature" && r.interaction.unlimited ? BLOCK : LOW));
    const { spy, typedCount } = evmSigner();
    const delegation = {
      domain: { name: "Aave Base Variable Debt USDC", version: "1", chainId: 8453, verifyingContract: "0x59dca05b6c26dbd64b5381374aaac5cd05644c28" as Hex },
      types: {
        DelegationWithSig: [
          { name: "delegatee", type: "address" },
          { name: "value", type: "uint256" },
          { name: "nonce", type: "uint256" },
          { name: "deadline", type: "uint256" },
        ],
      },
      primaryType: "DelegationWithSig" as const,
      message: { delegatee: DRAINER as Hex, value: maxUint256, nonce: 0n, deadline: 1_790_000_000n },
    };
    const v = await refused(guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signTypedData(delegation));
    assert.equal(v.action, "block");
    assert.deepEqual(api.seen[0]?.interaction, { type: "permit_signature", unlimited: true });
    assert.equal(typedCount(), 0);
  });
});
