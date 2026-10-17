// The daily maintenance review of 2026-10-17 (client 0.5.0): a caller's serializer, a list field that
// is not an array, withdrawals to L1 behind Multicall3 or through the OP Stack's bridges, and a domain
// chainId viem does not sign. C1 (custodian and nonce signers) is in solana-custodian-signers and
// solana-nonce-signers; C2 (numbers written as booleans or arrays) is below. Stubs only.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { encodeFunctionData, parseAbi, serializeTransaction, type Hex, type TransactionSerializable } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { guardAccount, X402CheckBlockedError, type GuardVerdict } from "../src/guard.js";
import { boundProvider } from "./helpers.js";

const BOB = "0x1111111111111111111111111111111111111111";
const DRAINER = "0x2222222222222222222222222222222222222222";
const LOW = { tier: "low" as const, score: 90, categories: [] };
const BLOCK = { tier: "critical" as const, score: 1, categories: ["known_scam_address"] };
const flagDrainer = (r: { wallet: string }) => (r.wallet.toLowerCase() === DRAINER ? BLOCK : LOW);
const FEES = { nonce: 7, gas: 200_000n, maxFeePerGas: 10n ** 9n, maxPriorityFeePerGas: 1n } as const;

async function refused(p: Promise<unknown>): Promise<GuardVerdict> {
  try {
    await p;
  } catch (err) {
    assert.ok(err instanceof X402CheckBlockedError, String(err));
    return err.verdict;
  }
  assert.fail("it was signed");
}

function signer() {
  const key = privateKeyToAccount(generatePrivateKey());
  const signed: Hex[] = [];
  const spy = {
    ...key,
    signTransaction: async (tx: Parameters<typeof key.signTransaction>[0], opts?: Parameters<typeof key.signTransaction>[1]) => {
      const raw = await key.signTransaction(tx, opts);
      signed.push(raw);
      return raw;
    },
  };
  return { key, spy, signed };
}
type Spy = ReturnType<typeof signer>["spy"];
const signTx = (account: Spy, options: Parameters<typeof guardAccount>[1]) => guardAccount(account, options).signTransaction as NonNullable<Spy["signTransaction"]>;

describe("a caller's serializer is read back before the key signs", () => {
  test("one that writes another transaction (a drain) is refused; nothing is signed", async () => {
    const api = boundProvider(flagDrainer);
    const { spy, signed } = signer();
    const drain: TransactionSerializable = { chainId: 8453, ...FEES, to: DRAINER, value: 10n ** 18n, type: "eip1559" };
    const evil = (_tx: unknown, signature?: Parameters<typeof serializeTransaction>[1]) => serializeTransaction(drain, signature);
    const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: 8453, ...FEES, to: BOB, value: 1n } as never, { serializer: evil } as never));
    assert.deepEqual([v.code, signed.length], ["invalid_transaction", 0]);
  });
  test("one that writes the transaction checked (the standard serializer, or the OP Stack's on Base) signs", async () => {
    const api = boundProvider(flagDrainer);
    const { spy, signed } = signer();
    await signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: 8453, ...FEES, to: BOB, value: 1n } as never, { serializer: serializeTransaction } as never);
    assert.equal(signed.length, 1);
  });
});

describe("list fields are arrays", () => {
  test("an authorizationList given as a Set is refused (it was serialized as a type-4 delegation)", async () => {
    const api = boundProvider(flagDrainer);
    const { key, spy, signed } = signer();
    const authorization = await key.signAuthorization({ contractAddress: DRAINER, chainId: 8453, nonce: 8 });
    const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: 8453, ...FEES, to: BOB, value: 1n, authorizationList: new Set([authorization]) } as never));
    assert.deepEqual([v.code, signed.length], ["invalid_transaction", 0]);
  });
});

describe("withdrawals to L1", () => {
  test("Multicall3.aggregate3Value sending ETH to Arbitrum's ArbSys is unread, not signed", async () => {
    const api = boundProvider(flagDrainer);
    const { spy, signed } = signer();
    const withdraw = encodeFunctionData({ abi: parseAbi(["function withdrawEth(address destination) payable returns (uint256)"]), functionName: "withdrawEth", args: [DRAINER] });
    const data = encodeFunctionData({
      abi: parseAbi(["function aggregate3Value((address target, bool allowFailure, uint256 value, bytes callData)[] calls) payable returns ((bool success, bytes returnData)[])"]),
      functionName: "aggregate3Value",
      args: [[{ target: "0x0000000000000000000000000000000000000064", allowFailure: false, value: 5n * 10n ** 18n, callData: withdraw }]],
    });
    const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: 42161, ...FEES, to: "0xcA11bde05977b3631167028862bE2a173976CA11", value: 5n * 10n ** 18n, data } as never));
    assert.deepEqual([v.action, signed.length], ["not_verified", 0]);
  });
  for (const [name, to, data] of [
    ["L2StandardBridge.bridgeETHTo", "0x4200000000000000000000000000000000000010", encodeFunctionData({ abi: parseAbi(["function bridgeETHTo(address _to, uint32 _minGasLimit, bytes _extraData) payable"]), functionName: "bridgeETHTo", args: [DRAINER, 200_000, "0x"] })],
    ["L2ToL1MessagePasser.initiateWithdrawal", "0x4200000000000000000000000000000000000016", encodeFunctionData({ abi: parseAbi(["function initiateWithdrawal(address _target, uint256 _gasLimit, bytes _data) payable"]), functionName: "initiateWithdrawal", args: [DRAINER, 100_000n, "0x"] })],
  ] as const) {
    test(`${name} to a known drainer on Base: the L1 recipient is checked, and blocked`, async () => {
      const api = boundProvider(flagDrainer);
      const { spy, signed } = signer();
      const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: 8453, ...FEES, to, value: 10n ** 17n, data } as never));
      assert.deepEqual([v.action, signed.length], ["block", 0]);
      assert.ok(api.seen.some((r) => r.wallet.toLowerCase() === DRAINER));
    });
  }
});

describe("typed data is read as viem signs it", () => {
  test("a uint written as `true` or `[1]` (viem hashes it as 1) is malformed, not a missing field", async () => {
    const api = boundProvider(flagDrainer);
    const key = privateKeyToAccount(generatePrivateKey());
    const safeTx = (operation: unknown) => ({
      domain: { chainId: 8453, verifyingContract: "0x5555555555555555555555555555555555555555" as Hex },
      types: {
        SafeTx: [
          { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "data", type: "bytes" }, { name: "operation", type: "uint8" },
          { name: "safeTxGas", type: "uint256" }, { name: "baseGas", type: "uint256" }, { name: "gasPrice", type: "uint256" },
          { name: "gasToken", type: "address" }, { name: "refundReceiver", type: "address" }, { name: "nonce", type: "uint256" },
        ],
      },
      primaryType: "SafeTx" as const,
      message: { to: BOB, value: 0n, data: "0x", operation, safeTxGas: 0n, baseGas: 0n, gasPrice: 0n, gasToken: "0x0000000000000000000000000000000000000000", refundReceiver: "0x0000000000000000000000000000000000000000", nonce: 0n },
    });
    for (const operation of [true, [1]]) {
      const v = await refused(guardAccount(key, { pinnedKeys: false, fetch: api.fetch }).signTypedData(safeTx(operation) as never));
      assert.deepEqual([v.action, v.code], ["not_verified", "malformed"], JSON.stringify(operation));
    }
  });
  test("a domain chainId given as a string with no EIP712Domain declared is not read as a chain (viem does not sign it)", async () => {
    const api = boundProvider(flagDrainer);
    const key = privateKeyToAccount(generatePrivateKey());
    const permit = {
      domain: { name: "USD Coin", version: "2", chainId: "8453", verifyingContract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" as Hex },
      types: { Permit: [{ name: "owner", type: "address" }, { name: "spender", type: "address" }, { name: "value", type: "uint256" }, { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }] },
      primaryType: "Permit" as const,
      message: { owner: key.address, spender: BOB, value: 1n, nonce: 0n, deadline: 2n ** 40n },
    };
    try {
      await guardAccount(key, { pinnedKeys: false, fetch: api.fetch }).signTypedData(permit as never);
    } catch {
      // refused or signed, it is never checked as Base
    }
    assert.ok(api.seen.every((r) => r.chain !== "eip155:8453"), JSON.stringify(api.seen.map((r) => r.chain)));
  });
  test("a payee written as a string (Hyperliquid usdSend) is checked", async () => {
    const api = boundProvider(flagDrainer);
    const key = privateKeyToAccount(generatePrivateKey());
    const usdSend = {
      domain: { name: "HyperliquidSignTransaction", version: "1", chainId: 42161, verifyingContract: "0x0000000000000000000000000000000000000000" as Hex },
      types: { "HyperliquidTransaction:UsdSend": [{ name: "hyperliquidChain", type: "string" }, { name: "destination", type: "string" }, { name: "amount", type: "string" }, { name: "time", type: "uint64" }] },
      primaryType: "HyperliquidTransaction:UsdSend" as const,
      message: { hyperliquidChain: "Mainnet", destination: DRAINER, amount: "250000", time: 1n },
    };
    const v = await refused(guardAccount(key, { pinnedKeys: false, fetch: api.fetch }).signTypedData(usdSend as never));
    assert.equal(v.action, "block");
  });
});

