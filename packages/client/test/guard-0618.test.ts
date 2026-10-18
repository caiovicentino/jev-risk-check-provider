// The daily maintenance review of 2026-10-18 (client 0.5.1 before its publish): a string field given as
// bytes, a serializer that rewrites what it is given or returns a thenable, a synchronous serializer
// (viem before 2.37.11), and bridges other than the OP Stack's L2 to L1 path. Stubs only.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { encodeFunctionData, pad, parseAbi, parseTransaction, serializeTransaction, toBytes, type Hex, type TransactionSerializable } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { guardAccount, X402CheckBlockedError, type GuardVerdict } from "../src/guard.js";
import { boundProvider } from "./helpers.js";

const BOB = "0x1111111111111111111111111111111111111111";
const DRAINER = "0x2222222222222222222222222222222222222222";
const LOW = { tier: "low" as const, score: 90, categories: [] };
const BLOCK = { tier: "critical" as const, score: 1, categories: ["known_scam_address"] };
const flagDrainer = (r: { wallet: string }) => (r.wallet.toLowerCase() === DRAINER ? BLOCK : LOW);
const FEES = { nonce: 7, gas: 300_000n, maxFeePerGas: 10n ** 9n, maxPriorityFeePerGas: 1n } as const;

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

describe("a string field is read as viem signs it", () => {
  const usdSend = (destination: unknown) => ({
    domain: { name: "HyperliquidSignTransaction", version: "1", chainId: 42161, verifyingContract: "0x0000000000000000000000000000000000000000" as Hex },
    types: { "HyperliquidTransaction:UsdSend": [{ name: "hyperliquidChain", type: "string" }, { name: "destination", type: "string" }, { name: "amount", type: "string" }, { name: "time", type: "uint64" }] },
    primaryType: "HyperliquidTransaction:UsdSend" as const,
    message: { hyperliquidChain: "Mainnet", destination, amount: "250000", time: 1n },
  });
  test("a payee given as bytes, a byte array or a bigint (viem hashes the same text) is malformed, never signed", async () => {
    const api = boundProvider(flagDrainer);
    const key = privateKeyToAccount(generatePrivateKey());
    const bytes = toBytes(DRAINER);
    for (const destination of [bytes, Array.from(bytes), BigInt(`0x${Buffer.from(DRAINER).toString("hex")}`)]) {
      const v = await refused(guardAccount(key, { pinnedKeys: false, fetch: api.fetch }).signTypedData(usdSend(destination) as never));
      assert.deepEqual([v.action, v.code], ["not_verified", "malformed"], typeof destination);
    }
  });
  test("the same payee as a string is checked and blocked; a clean one signs", async () => {
    const api = boundProvider(flagDrainer);
    const key = privateKeyToAccount(generatePrivateKey());
    assert.equal((await refused(guardAccount(key, { pinnedKeys: false, fetch: api.fetch }).signTypedData(usdSend(DRAINER) as never))).action, "block");
    assert.match(await guardAccount(key, { pinnedKeys: false, fetch: api.fetch }).signTypedData(usdSend(BOB) as never), /^0x[0-9a-f]{130}$/u);
  });
});

describe("a caller's serializer cannot sign another transaction", () => {
  test("one that rewrites the transaction it is handed is compared with what was checked, and refused", async () => {
    const api = boundProvider(flagDrainer);
    const { spy, signed } = signer();
    const rewrite = (tx: Record<string, unknown>, signature?: Parameters<typeof serializeTransaction>[1]) => {
      tx.to = DRAINER;
      tx.value = 10n ** 18n;
      return serializeTransaction(tx as TransactionSerializable, signature);
    };
    const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: 8453, ...FEES, to: BOB, value: 1n } as never, { serializer: rewrite } as never));
    assert.deepEqual([v.code, signed.length], ["invalid_transaction", 0]);
  });
  test("a thenable whose own then hands back other bytes: the key signs only what was checked", async () => {
    const api = boundProvider(flagDrainer);
    const { spy, signed } = signer();
    const drain: TransactionSerializable = { chainId: 8453, ...FEES, to: DRAINER, value: 10n ** 18n, type: "eip1559" };
    const sneaky = (tx: TransactionSerializable, signature?: Parameters<typeof serializeTransaction>[1]) => ({
      then(resolve: (value: unknown) => void) {
        resolve(serializeTransaction(tx, signature));
        return Promise.resolve(serializeTransaction(drain, signature));
      },
    });
    await signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: 8453, ...FEES, to: BOB, value: 1n } as never, { serializer: sneaky } as never);
    assert.equal(signed.length, 1);
    assert.equal(parseTransaction(signed[0] as Hex).to?.toLowerCase(), BOB);
  });
  test("a synchronous serializer stays synchronous (viem before 2.37.11 hashes its return value directly)", async () => {
    const api = boundProvider(flagDrainer);
    const key = privateKeyToAccount(generatePrivateKey());
    let seen: unknown;
    const oldViem = {
      ...key,
      signTransaction: async (tx: TransactionSerializable, opts?: { serializer?: (t: TransactionSerializable) => unknown }) => {
        seen = opts?.serializer?.(tx);
        if (typeof seen !== "string") throw new Error("Uint8Array expected");
        return key.signTransaction(tx);
      },
    };
    const guarded = guardAccount(oldViem as unknown as Spy, { pinnedKeys: false, fetch: api.fetch }) as unknown as { signTransaction: (tx: unknown, opts: unknown) => Promise<Hex> };
    const raw = await guarded.signTransaction({ chainId: 8453, ...FEES, to: BOB, value: 1n }, { serializer: serializeTransaction });
    assert.equal(typeof seen, "string");
    assert.equal(parseTransaction(raw).to?.toLowerCase(), BOB);
  });
});

describe("bridges: the recipient on the other chain is checked", () => {
  const l1Bridge = parseAbi(["function bridgeETHTo(address _to, uint32 _minGasLimit, bytes _extraData) payable"]);
  const portal = parseAbi(["function depositTransaction(address _to, uint256 _value, uint64 _gasLimit, bool _isCreation, bytes _data) payable"]);
  const inbox = parseAbi(["function createRetryableTicket(address to, uint256 l2CallValue, uint256 maxSubmissionCost, address excessFeeRefundAddress, address callValueRefundAddress, uint256 gasLimit, uint256 maxFeePerGas, bytes data) payable returns (uint256)"]);
  const across = parseAbi(["function depositV3(address depositor, address recipient, address inputToken, address outputToken, uint256 inputAmount, uint256 outputAmount, uint256 destinationChainId, address exclusiveRelayer, uint32 quoteTimestamp, uint32 fillDeadline, uint32 exclusivityDeadline, bytes message) payable"]);
  const cctp = parseAbi(["function depositForBurn(uint256 amount, uint32 destinationDomain, bytes32 mintRecipient, address burnToken) returns (uint64)"]);
  const BASE_L1_BRIDGE = "0x3154Cf16ccdb4C6d922629664174b904d80F2C35";
  const BASE_PORTAL = "0x49048044D57e1C92A77f79988d21Fa8fAF74E97e";
  const ARB_INBOX = "0x4Dbd4fc535Ac27206064B68FfCf827b0A60BAB3f";
  const ACROSS_BASE = "0x09aea4b2242abC8bb4BB78D537A67a245A7bEC64";
  const CCTP_ETH = "0xBd3fa81B58Ba92a82136038B25aDec7066af3155";
  const USDC_ETH = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
  const value = 10n ** 17n;
  const acrossDeposit = (depositor: Hex, recipient: Hex, message: Hex = "0x") =>
    encodeFunctionData({ abi: across, functionName: "depositV3", args: [depositor, recipient, "0x4200000000000000000000000000000000000006", "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", value, (value * 99n) / 100n, 42161n, "0x0000000000000000000000000000000000000000", 1_700_000_000, 1_700_003_600, 0, message] });
  const cases = (to: Hex): Array<[string, number, Hex, bigint, Hex]> => [
    ["Ethereum: Base's L1StandardBridge.bridgeETHTo", 1, BASE_L1_BRIDGE, value, encodeFunctionData({ abi: l1Bridge, functionName: "bridgeETHTo", args: [to, 200_000, "0x"] })],
    ["Ethereum: Base's OptimismPortal.depositTransaction", 1, BASE_PORTAL, value, encodeFunctionData({ abi: portal, functionName: "depositTransaction", args: [to, value, 100_000n, false, "0x"] })],
    ["Ethereum: Arbitrum's Inbox.createRetryableTicket", 1, ARB_INBOX, value + 10n ** 15n, encodeFunctionData({ abi: inbox, functionName: "createRetryableTicket", args: [to, value, 10n ** 15n, to, to, 100_000n, 10n ** 9n, "0x"] })],
    ["Base: Across SpokePool.depositV3", 8453, ACROSS_BASE, value, acrossDeposit(to, to)],
    ["Ethereum: CCTP TokenMessenger.depositForBurn", 1, CCTP_ETH, 0n, encodeFunctionData({ abi: cctp, functionName: "depositForBurn", args: [1_000_000n, 6, pad(to), USDC_ETH] })],
  ];
  for (const [name, chainId, to, sent, data] of cases(DRAINER)) {
    test(`${name} to a known drainer: blocked, and nothing is signed`, async () => {
      const api = boundProvider(flagDrainer);
      const { spy, signed } = signer();
      const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId, ...FEES, to, value: sent, data } as never));
      assert.deepEqual([v.action, signed.length], ["block", 0]);
      assert.ok(api.seen.some((r) => r.wallet.toLowerCase() === DRAINER));
      assert.ok(api.seen.some((r) => r.wallet.toLowerCase() === to.toLowerCase()), "the bridge contract is checked too");
    });
  }
  test("the same bridges to the sender's own address sign (each recipient and the bridge are checked)", async () => {
    const api = boundProvider(flagDrainer);
    const { key, spy, signed } = signer();
    for (const [, chainId, to, sent, data] of cases(key.address)) await signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId, ...FEES, to, value: sent, data } as never);
    assert.equal(signed.length, 5);
  });
  test("a refund address on the other chain is a recipient too (Arbitrum retryable, Across depositor)", async () => {
    const api = boundProvider(flagDrainer);
    const { key, spy, signed } = signer();
    const retryable = encodeFunctionData({ abi: inbox, functionName: "createRetryableTicket", args: [key.address, value, 10n ** 15n, DRAINER, key.address, 100_000n, 10n ** 9n, "0x"] });
    assert.equal((await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: 1, ...FEES, to: ARB_INBOX, value: value + 10n ** 15n, data: retryable } as never))).action, "block");
    assert.equal((await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: 8453, ...FEES, to: ACROSS_BASE, value, data: acrossDeposit(DRAINER, key.address) } as never))).action, "block");
    assert.equal(signed.length, 0);
  });
  test("what a bridge runs or pays on the other chain that cannot be read is never signed", async () => {
    const api = boundProvider(flagDrainer);
    const { key, spy, signed } = signer();
    const unread: Array<[string, number, Hex, bigint, Hex]> = [
      ["CCTP to a 32-byte (non-EVM) recipient", 1, CCTP_ETH, 0n, encodeFunctionData({ abi: cctp, functionName: "depositForBurn", args: [1_000_000n, 5, `0x${"8f".repeat(32)}`, USDC_ETH] })],
      ["CCTP to an EVM address with a dirty top (its low 20 bytes are paid)", 1, CCTP_ETH, 0n, encodeFunctionData({ abi: cctp, functionName: "depositForBurn", args: [1_000_000n, 6, `0x${"01".repeat(12)}${key.address.slice(2)}`, USDC_ETH] })],
      ["Across with a message run by the recipient", 8453, ACROSS_BASE, value, acrossDeposit(key.address, key.address, "0x1234")],
      ["OptimismPortal deploying a contract", 1, BASE_PORTAL, value, encodeFunctionData({ abi: portal, functionName: "depositTransaction", args: [key.address, value, 100_000n, true, "0x"] })],
      ["OptimismPortal calling an L2 contract with calldata", 1, BASE_PORTAL, value, encodeFunctionData({ abi: portal, functionName: "depositTransaction", args: [key.address, value, 100_000n, false, "0x1234"] })],
      ["a retryable ticket that calls its recipient", 1, ARB_INBOX, value + 10n ** 15n, encodeFunctionData({ abi: inbox, functionName: "createRetryableTicket", args: [key.address, value, 10n ** 15n, key.address, key.address, 100_000n, 10n ** 9n, "0x1234"] })],
    ];
    for (const [name, chainId, to, sent, data] of unread) {
      const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId, ...FEES, to, value: sent, data } as never));
      assert.equal(v.action, "not_verified", name);
    }
    assert.equal(signed.length, 0);
  });
});

describe("the low findings of the same review", () => {
  const flag = (r: { wallet: string }) => (r.wallet.toLowerCase() === DRAINER ? BLOCK : LOW);
  test("a Permit2 witness payee is checked whoever the order names as its swapper (an address or a string)", async () => {
    const SPENDER = "0x5555555555555555555555555555555555555555";
    const td = (swapperType: "address" | "string") => ({
      domain: { name: "Permit2", chainId: 8453, verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" as Hex },
      types: {
        PermitWitnessTransferFrom: [{ name: "permitted", type: "TokenPermissions" }, { name: "spender", type: "address" }, { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }, { name: "witness", type: "Payment" }],
        TokenPermissions: [{ name: "token", type: "address" }, { name: "amount", type: "uint256" }],
        Payment: [{ name: "to", type: "address" }, { name: "swapper", type: swapperType }, { name: "validAfter", type: "uint256" }],
      },
      primaryType: "PermitWitnessTransferFrom" as const,
      message: { permitted: { token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", amount: 1_000_000_000n }, spender: SPENDER, nonce: 1n, deadline: 1_900_000_000n, witness: { to: DRAINER, swapper: DRAINER, validAfter: 0n } },
    });
    for (const swapperType of ["address", "string"] as const) {
      const api = boundProvider(flag);
      const key = privateKeyToAccount(generatePrivateKey());
      const v = await refused(guardAccount(key, { pinnedKeys: false, fetch: api.fetch }).signTypedData(td(swapperType) as never));
      assert.equal(v.action, "block", swapperType);
      assert.ok(api.seen.some((r) => r.wallet.toLowerCase() === DRAINER), swapperType);
    }
  });
  test("generic typed data checks its verifying contract, whatever addresses the message names", async () => {
    for (const recipient of [{ type: "address", value: BOB }, { type: "string", value: BOB }] as const) {
      const api = boundProvider(flag);
      const key = privateKeyToAccount(generatePrivateKey());
      const td = {
        domain: { name: "Some App", version: "1", chainId: 8453, verifyingContract: DRAINER as Hex },
        types: { Order: [{ name: "memo", type: "string" }, { name: "recipient", type: recipient.type }, { name: "amount", type: "uint256" }] },
        primaryType: "Order" as const,
        message: { memo: "thanks", recipient: recipient.value, amount: 5n },
      };
      const v = await refused(guardAccount(key, { pinnedKeys: false, fetch: api.fetch }).signTypedData(td as never));
      assert.equal(v.action, "block", recipient.type);
      assert.ok(api.seen.some((r) => r.wallet.toLowerCase() === BOB), "the message's address is checked too");
    }
  });
  test("a Multicall3 selector sent to a flagged contract with no value: the contract is checked", async () => {
    const api = boundProvider(flag);
    const { key, spy, signed } = signer();
    const balanceOf = encodeFunctionData({ abi: parseAbi(["function balanceOf(address) view returns (uint256)"]), functionName: "balanceOf", args: [key.address] });
    const data = encodeFunctionData({
      abi: parseAbi(["function aggregate3((address target, bool allowFailure, bytes callData)[] calls) payable returns ((bool success, bytes returnData)[])"]),
      functionName: "aggregate3",
      args: [[{ target: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", allowFailure: false, callData: balanceOf }]],
    });
    const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: 8453, ...FEES, to: DRAINER, value: 0n, data } as never));
    assert.deepEqual([v.action, signed.length], ["block", 0]);
  });
  test("a list of numbers longer than 64 items is read (nothing there can hold calldata); a list of bytes is not", async () => {
    const api = boundProvider(flag);
    const key = privateKeyToAccount(generatePrivateKey());
    const td = (type: "uint256[]" | "bytes[]", values: unknown[]) => ({
      domain: { name: "Batch", version: "1", chainId: 8453, verifyingContract: "0x7777777777777777777777777777777777777777" as Hex },
      types: { Batch: [{ name: "owner", type: "address" }, { name: "values", type }] },
      primaryType: "Batch" as const,
      message: { owner: BOB, values },
    });
    assert.match(await guardAccount(key, { pinnedKeys: false, fetch: api.fetch }).signTypedData(td("uint256[]", Array.from({ length: 65 }, (_, i) => BigInt(i))) as never), /^0x[0-9a-f]{130}$/u);
    const v = await refused(guardAccount(key, { pinnedKeys: false, fetch: api.fetch }).signTypedData(td("bytes[]", Array.from({ length: 65 }, () => "0x")) as never));
    assert.equal(v.action, "not_verified");
  });
  test("past 2048 characters: an address padded with whitespace is still read; plain long text stays readable", async () => {
    const api = boundProvider(flag);
    const key = privateKeyToAccount(generatePrivateKey());
    const send = (destination: string, note: string) => ({
      domain: { name: "HyperliquidSignTransaction", version: "1", chainId: 42161, verifyingContract: "0x0000000000000000000000000000000000000000" as Hex },
      types: { "HyperliquidTransaction:UsdSend": [{ name: "hyperliquidChain", type: "string" }, { name: "destination", type: "string" }, { name: "amount", type: "string" }, { name: "note", type: "string" }, { name: "time", type: "uint64" }] },
      primaryType: "HyperliquidTransaction:UsdSend" as const,
      message: { hyperliquidChain: "Mainnet", destination, amount: "250000", note, time: 1n },
    });
    assert.equal((await refused(guardAccount(key, { pinnedKeys: false, fetch: api.fetch }).signTypedData(send(`${" ".repeat(3000)}${DRAINER}`, "") as never))).action, "block");
    assert.match(await guardAccount(key, { pinnedKeys: false, fetch: api.fetch }).signTypedData(send(BOB, "a".repeat(5000)) as never), /^0x[0-9a-f]{130}$/u);
  });
});
