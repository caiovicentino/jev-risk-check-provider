// Client 0.5.2, the follow-ups of the 2026-10-18 review: four more bridges whose recipient on the other
// chain is only in calldata (Polygon's unified bridge, Celer cBridge, Gnosis Chain's OmniBridge and xDAI
// bridge, zkSync Era), and an Across deposit's amounts (one that pays out 1 wei was signed: the relayer
// that fills it is repaid the whole deposit). Stubs only.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { encodeFunctionData, getAddress, pad, parseAbi, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { decodeTransaction } from "../src/decode/tx.js";
import { createGuard, guardAccount, X402CheckBlockedError, type GuardVerdict } from "../src/guard.js";
import { boundProvider } from "./helpers.js";

const BOB = "0x1111111111111111111111111111111111111111";
const DRAINER = "0x2222222222222222222222222222222222222222";
const ZERO = "0x0000000000000000000000000000000000000000";
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
type Case = [name: string, chainId: number, to: Hex, value: bigint, data: Hex];
const seen = (api: ReturnType<typeof boundProvider>, address: string) => api.seen.some((r) => r.wallet.toLowerCase() === address.toLowerCase());

// Ethereum deployments (each bridge is matched by selector on any contract).
const POLYGON_BRIDGE = getAddress("0x2a3dd3eb832af982ec71669e178424b10dca2ede");
const CELER = getAddress("0x5427fefa711eff984124bfbb1ab6fbf5e3da1820");
const OMNIBRIDGE = getAddress("0x88ad09518695c6c3712ac10a214be5109a655671");
const WETH_ROUTER = getAddress("0xa6439ca0fcba1d0f80df0be6a17220fed9c9038a");
const XDAI_BRIDGE = getAddress("0x4aa42145aa6ebf72e164c9bbc74fbd3788045016");
const BRIDGEHUB = getAddress("0x303a465b659cbb0ab36ee643ea362c509eeb5213");
const ERA_DIAMOND = getAddress("0x32400084c286cf3e17e7b677ea9583e60a000324");
const USDC_ETH = getAddress("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
const value = 10n ** 17n;

const polygon = parseAbi([
  "function bridgeAsset(uint32 destinationNetwork, address destinationAddress, uint256 amount, address token, bool forceUpdateGlobalExitRoot, bytes permitData) payable",
  "function bridgeMessage(uint32 destinationNetwork, address destinationAddress, bool forceUpdateGlobalExitRoot, bytes metadata) payable",
]);
const permit = parseAbi(["function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)"]);
const celer = parseAbi([
  "function sendNative(address _receiver, uint256 _amount, uint64 _dstChainId, uint64 _nonce, uint32 _maxSlippage) payable",
  "function send(address _receiver, address _token, uint256 _amount, uint64 _dstChainId, uint64 _nonce, uint32 _maxSlippage)",
]);
const omni = parseAbi(["function relayTokens(address token, address _receiver, uint256 _value)", "function relayTokensAndCall(address token, address _receiver, uint256 _value, bytes _data)"]);
const omniToSender = parseAbi(["function relayTokens(address token, uint256 _value)"]);
const xdai = parseAbi(["function relayTokens(address _receiver, uint256 _amount)"]);
const wrapOne = parseAbi(["function wrapAndRelayTokens(address _receiver) payable"]);
const wrapTwo = parseAbi(["function wrapAndRelayTokens(address _receiver, bytes _data) payable"]);
const bridgehub = parseAbi([
  "struct L2TransactionRequestDirect { uint256 chainId; uint256 mintValue; address l2Contract; uint256 l2Value; bytes l2Calldata; uint256 l2GasLimit; uint256 l2GasPerPubdataByteLimit; bytes[] factoryDeps; address refundRecipient; }",
  "struct L2TransactionRequestTwoBridgesOuter { uint256 chainId; uint256 mintValue; uint256 l2Value; uint256 l2GasLimit; uint256 l2GasPerPubdataByteLimit; address refundRecipient; address secondBridgeAddress; uint256 secondBridgeValue; bytes secondBridgeCalldata; }",
  "function requestL2TransactionDirect(L2TransactionRequestDirect _request) payable returns (bytes32)",
  "function requestL2TransactionTwoBridges(L2TransactionRequestTwoBridgesOuter _request) payable returns (bytes32)",
]);
const mailbox = parseAbi([
  "function requestL2Transaction(address _contractL2, uint256 _l2Value, bytes _calldata, uint256 _l2GasLimit, uint256 _l2GasPerPubdataByteLimit, bytes[] _factoryDeps, address _refundRecipient) payable returns (bytes32)",
]);
const BYTECODE = `0x${"00".repeat(32)}` as Hex;
const direct = (l2Contract: Hex, refundRecipient: Hex, l2Calldata: Hex = "0x", factoryDeps: Hex[] = []) =>
  encodeFunctionData({
    abi: bridgehub,
    functionName: "requestL2TransactionDirect",
    args: [{ chainId: 324n, mintValue: value, l2Contract, l2Value: value / 2n, l2Calldata, l2GasLimit: 300_000n, l2GasPerPubdataByteLimit: 800n, factoryDeps, refundRecipient }],
  });
const legacy = (contractL2: Hex, refundRecipient: Hex, calldata: Hex = "0x", factoryDeps: Hex[] = []) =>
  encodeFunctionData({ abi: mailbox, functionName: "requestL2Transaction", args: [contractL2, value / 2n, calldata, 300_000n, 800n, factoryDeps, refundRecipient] });

const cases = (to: Hex): Case[] => [
  ["Polygon unified bridge: bridgeAsset of ETH", 1, POLYGON_BRIDGE, value, encodeFunctionData({ abi: polygon, functionName: "bridgeAsset", args: [1, to, value, ZERO, true, "0x"] })],
  [
    "Polygon unified bridge: bridgeAsset of USDC with a permit (used on this chain)",
    1,
    POLYGON_BRIDGE,
    0n,
    encodeFunctionData({
      abi: polygon,
      functionName: "bridgeAsset",
      args: [1, to, 1_000_000n, USDC_ETH, true, encodeFunctionData({ abi: permit, functionName: "permit", args: [to, POLYGON_BRIDGE, 1_000_000n, 1_900_000_000n, 27, pad("0x01"), pad("0x02")] })],
    }),
  ],
  ["Polygon unified bridge: bridgeMessage with no metadata", 1, POLYGON_BRIDGE, value, encodeFunctionData({ abi: polygon, functionName: "bridgeMessage", args: [1, to, true, "0x"] })],
  ["Celer cBridge: sendNative", 1, CELER, value, encodeFunctionData({ abi: celer, functionName: "sendNative", args: [to, value, 42161n, 1n, 5000] })],
  ["Celer cBridge: send of USDC", 1, CELER, 0n, encodeFunctionData({ abi: celer, functionName: "send", args: [to, USDC_ETH, 1_000_000n, 42161n, 1n, 5000] })],
  ["OmniBridge: relayTokens(token, receiver, value)", 1, OMNIBRIDGE, 0n, encodeFunctionData({ abi: omni, functionName: "relayTokens", args: [USDC_ETH, to, 1_000_000n] })],
  ["OmniBridge: relayTokensAndCall with no data", 1, OMNIBRIDGE, 0n, encodeFunctionData({ abi: omni, functionName: "relayTokensAndCall", args: [USDC_ETH, to, 1_000_000n, "0x"] })],
  ["OmniBridge WETH router: wrapAndRelayTokens(receiver)", 1, WETH_ROUTER, value, encodeFunctionData({ abi: wrapOne, functionName: "wrapAndRelayTokens", args: [to] })],
  ["OmniBridge WETH router: wrapAndRelayTokens(receiver, data) with no data", 1, WETH_ROUTER, value, encodeFunctionData({ abi: wrapTwo, functionName: "wrapAndRelayTokens", args: [to, "0x"] })],
  ["xDAI bridge: relayTokens(receiver, amount)", 1, XDAI_BRIDGE, 0n, encodeFunctionData({ abi: xdai, functionName: "relayTokens", args: [to, 10n ** 18n] })],
  ["zkSync Bridgehub: requestL2TransactionDirect", 1, BRIDGEHUB, value, direct(to, to)],
  ["zkSync Era diamond: requestL2Transaction (legacy Mailbox)", 1, ERA_DIAMOND, value, legacy(to, to)],
];

describe("bridges whose recipient on the other chain is only in calldata", () => {
  for (const [name, chainId, to, sent, data] of cases(DRAINER)) {
    test(`${name} to a known drainer: blocked, and nothing is signed`, async () => {
      const api = boundProvider(flagDrainer);
      const { spy, signed } = signer();
      const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId, ...FEES, to, value: sent, data } as never));
      assert.deepEqual([v.action, signed.length], ["block", 0]);
      assert.ok(seen(api, DRAINER));
      assert.ok(seen(api, to), "the bridge contract is checked too");
    });
  }
  test("the same bridges to the sender's own address, or to a clean one, sign (the recipient and the bridge are checked)", async () => {
    const { key, spy, signed } = signer();
    for (const [, chainId, to, sent, data] of cases(key.address)) await signTx(spy, { pinnedKeys: false, fetch: boundProvider(flagDrainer).fetch })({ chainId, ...FEES, to, value: sent, data } as never);
    assert.equal(signed.length, cases(key.address).length);
    for (const [name, chainId, to, sent, data] of cases(BOB)) {
      const api = boundProvider(flagDrainer);
      await signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId, ...FEES, to, value: sent, data } as never);
      assert.ok(seen(api, BOB), `${name}: the recipient on the other chain is checked`);
      assert.ok(seen(api, to), `${name}: the bridge is checked`);
    }
    assert.equal(signed.length, 2 * cases(key.address).length);
  });
  test("zkSync's refund recipient receives on L2 what the deposit leaves over: it is checked", async () => {
    const { key, spy, signed } = signer();
    for (const [to, data] of [
      [BRIDGEHUB, direct(key.address, DRAINER)],
      [ERA_DIAMOND, legacy(key.address, DRAINER)],
    ] as const) {
      const api = boundProvider(flagDrainer);
      assert.equal((await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: 1, ...FEES, to, value, data } as never))).action, "block");
      assert.ok(seen(api, DRAINER));
    }
    assert.equal(signed.length, 0);
  });
  test("relayTokens(address,uint256) is two functions: the xDAI bridge's receiver is checked, and the OmniBridge's token too (it pays the sender)", async () => {
    const { spy, signed } = signer();
    const xdaiApi = boundProvider(flagDrainer);
    const drain = encodeFunctionData({ abi: xdai, functionName: "relayTokens", args: [DRAINER, 10n ** 18n] });
    assert.equal((await refused(signTx(spy, { pinnedKeys: false, fetch: xdaiApi.fetch })({ chainId: 1, ...FEES, to: XDAI_BRIDGE, value: 0n, data: drain } as never))).action, "block");
    const omniApi = boundProvider(flagDrainer);
    const toSender = encodeFunctionData({ abi: omniToSender, functionName: "relayTokens", args: [USDC_ETH, 1_000_000n] });
    await signTx(spy, { pinnedKeys: false, fetch: omniApi.fetch })({ chainId: 1, ...FEES, to: OMNIBRIDGE, value: 0n, data: toSender } as never);
    assert.ok(seen(omniApi, USDC_ETH) && seen(omniApi, OMNIBRIDGE));
    assert.equal(signed.length, 1);
  });
  test("what these bridges run or deploy on the other chain, or name outside EVM form, is never signed", async () => {
    const api = boundProvider(flagDrainer);
    const { key, spy, signed } = signer();
    const me = key.address;
    const across = parseAbi([
      "function deposit(bytes32 depositor, bytes32 recipient, bytes32 inputToken, bytes32 outputToken, uint256 inputAmount, uint256 outputAmount, uint256 destinationChainId, bytes32 exclusiveRelayer, uint32 quoteTimestamp, uint32 fillDeadline, uint32 exclusivityParameter, bytes message) payable",
    ]);
    const SOLANA_USDC = `0x${"c6".repeat(32)}` as Hex;
    const BASE_USDC = getAddress("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913");
    const unread: Case[] = [
      ["Polygon bridgeMessage with metadata run by its recipient", 1, POLYGON_BRIDGE, value, encodeFunctionData({ abi: polygon, functionName: "bridgeMessage", args: [1, me, true, "0x1234"] })],
      ["OmniBridge relayTokensAndCall with data", 1, OMNIBRIDGE, 0n, encodeFunctionData({ abi: omni, functionName: "relayTokensAndCall", args: [USDC_ETH, me, 1_000_000n, "0x1234"] })],
      ["WETH router wrapAndRelayTokens with data", 1, WETH_ROUTER, value, encodeFunctionData({ abi: wrapTwo, functionName: "wrapAndRelayTokens", args: [me, "0x1234"] })],
      ["Bridgehub calling an L2 contract with calldata", 1, BRIDGEHUB, value, direct(me, me, "0x1234")],
      ["Bridgehub deploying code (factory dependencies)", 1, BRIDGEHUB, value, direct(me, me, "0x", [BYTECODE])],
      ["the legacy Mailbox calling an L2 contract with calldata", 1, ERA_DIAMOND, value, legacy(me, me, "0x1234")],
      ["the legacy Mailbox deploying code (factory dependencies)", 1, ERA_DIAMOND, value, legacy(me, me, "0x", [BYTECODE])],
      [
        "Bridgehub requestL2TransactionTwoBridges (the recipient is in the second bridge's calldata)",
        1,
        BRIDGEHUB,
        value,
        encodeFunctionData({
          abi: bridgehub,
          functionName: "requestL2TransactionTwoBridges",
          args: [{ chainId: 324n, mintValue: value, l2Value: 0n, l2GasLimit: 300_000n, l2GasPerPubdataByteLimit: 800n, refundRecipient: me, secondBridgeAddress: BOB, secondBridgeValue: 0n, secondBridgeCalldata: "0x1234" }],
        }),
      ],
      [
        "an Across deposit to a Solana recipient (not an EVM address)",
        8453,
        getAddress("0x09aea4b2242abc8bb4bb78d537a67a245a7bec64"),
        0n,
        encodeFunctionData({ abi: across, functionName: "deposit", args: [pad(me), `0x${"8f".repeat(32)}`, pad(BASE_USDC), SOLANA_USDC, 1_000_000n, 990_000n, 34268394551451n, pad(ZERO), 1_700_000_000, 1_700_003_600, 0, "0x"] }),
      ],
    ];
    for (const [name, chainId, to, sent, data] of unread) {
      const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId, ...FEES, to, value: sent, data } as never));
      assert.deepEqual([v.action, v.code], ["not_verified", "opaque_signature"], name);
    }
    assert.equal(signed.length, 0);
  });
  test("a bridge selector sent to the signer's own account runs the account's code: it is not read as a bridge", async () => {
    const api = boundProvider(flagDrainer);
    const { key, spy, signed } = signer();
    const opBridge = parseAbi(["function bridgeETHTo(address _to, uint32 _minGasLimit, bytes _extraData) payable"]);
    for (const data of [
      encodeFunctionData({ abi: opBridge, functionName: "bridgeETHTo", args: [BOB, 200_000, "0x"] }),
      encodeFunctionData({ abi: celer, functionName: "send", args: [BOB, USDC_ETH, 1_000_000n, 42161n, 1n, 5000] }),
    ]) {
      const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: 1, ...FEES, to: key.address, value: 0n, data } as never));
      assert.deepEqual([v.action, v.code], ["not_verified", "unreadable_self_call"], data.slice(0, 10));
    }
    assert.equal(signed.length, 0);
  });
});

describe("Across: what a deposit pays on the other chain is read", () => {
  const abi = parseAbi([
    "function depositV3(address depositor, address recipient, address inputToken, address outputToken, uint256 inputAmount, uint256 outputAmount, uint256 destinationChainId, address exclusiveRelayer, uint32 quoteTimestamp, uint32 fillDeadline, uint32 exclusivityDeadline, bytes message) payable",
    "function depositV3Now(address depositor, address recipient, address inputToken, address outputToken, uint256 inputAmount, uint256 outputAmount, uint256 destinationChainId, address exclusiveRelayer, uint32 fillDeadlineOffset, uint32 exclusivityDeadline, bytes message) payable",
    "function deposit(bytes32 depositor, bytes32 recipient, bytes32 inputToken, bytes32 outputToken, uint256 inputAmount, uint256 outputAmount, uint256 destinationChainId, bytes32 exclusiveRelayer, uint32 quoteTimestamp, uint32 fillDeadline, uint32 exclusivityParameter, bytes message) payable",
    "function depositNow(bytes32 depositor, bytes32 recipient, bytes32 inputToken, bytes32 outputToken, uint256 inputAmount, uint256 outputAmount, uint256 destinationChainId, bytes32 exclusiveRelayer, uint32 fillDeadlineOffset, uint32 exclusivityParameter, bytes message) payable",
  ]);
  const SPOKE = {
    1: getAddress("0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5"),
    56: getAddress("0x4e8e101924ede233c13e2d8622dc8aed2872d505"),
    8453: getAddress("0x09aea4b2242abc8bb4bb78d537a67a245a7bec64"),
  } as const;
  const WETH_BASE = "0x4200000000000000000000000000000000000006";
  const WETH_ARB = getAddress("0x82af49447d8a07e3bd95bd0d56f35241523fbab1");
  const USDT_BNB = getAddress("0x55d398326f99059ff775485246999027b3197955");
  const USDT_ETH = getAddress("0xdac17f958d2ee523a2206206994597c13d831ec7");
  const USDC_BNB = getAddress("0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d");
  type Deposit = { from: Hex; inputToken: Hex; outputToken: Hex; input: bigint; output: bigint; destination: bigint };
  const v3 = (d: Deposit) => encodeFunctionData({ abi, functionName: "depositV3", args: [d.from, d.from, d.inputToken, d.outputToken, d.input, d.output, d.destination, ZERO, 1_700_000_000, 1_700_003_600, 0, "0x"] });
  const v3Now = (d: Deposit) => encodeFunctionData({ abi, functionName: "depositV3Now", args: [d.from, d.from, d.inputToken, d.outputToken, d.input, d.output, d.destination, ZERO, 3600, 0, "0x"] });
  const bytes32 = (d: Deposit) => encodeFunctionData({ abi, functionName: "deposit", args: [pad(d.from), pad(d.from), pad(d.inputToken), pad(d.outputToken), d.input, d.output, d.destination, pad(ZERO), 1_700_000_000, 1_700_003_600, 0, "0x"] });
  const bytes32Now = (d: Deposit) => encodeFunctionData({ abi, functionName: "depositNow", args: [pad(d.from), pad(d.from), pad(d.inputToken), pad(d.outputToken), d.input, d.output, d.destination, pad(ZERO), 3600, 0, "0x"] });
  // ETH from Base to Arbitrum: WETH on both chains, msg.value = inputAmount.
  const eth = (from: Hex, output: bigint): Deposit => ({ from, inputToken: WETH_BASE, outputToken: WETH_ARB, input: value, output, destination: 42161n });

  test("a deposit that pays 0 or 1 wei on the other chain is refused before any check (local_danger), in each of the four functions", async () => {
    const { key, spy, signed } = signer();
    for (const encode of [v3, v3Now, bytes32, bytes32Now]) {
      for (const output of [0n, 1n]) {
        const api = boundProvider(flagDrainer);
        const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: 8453, ...FEES, to: SPOKE[8453], value, data: encode(eth(key.address, output)) } as never));
        assert.deepEqual([v.action, v.code], ["block", "local_danger"], `outputAmount ${output}`);
        assert.match(v.reasons.join(" "), output === 0n ? /pays nothing on the other chain/u : /less than half/u);
        assert.equal(api.seen.length, 0, "nothing is sent for checking");
      }
    }
    assert.equal(signed.length, 0);
  });
  test("a deposit paying 99% of its input signs, and its summary names both amounts", async () => {
    const api = boundProvider(flagDrainer);
    const { key, spy, signed } = signer();
    const data = v3(eth(key.address, (value * 99n) / 100n));
    await signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: 8453, ...FEES, to: SPOKE[8453], value, data } as never);
    assert.equal(signed.length, 1);
    const v = await createGuard({ pinnedKeys: false, fetch: api.fetch }).check({ kind: "transaction", from: key.address, transaction: { chainId: 8453, ...FEES, to: SPOKE[8453], value, data } as never });
    assert.equal(v.action, "allow");
    assert.match(v.summary, /taking 0\.1 WETH .* to pay 0\.099 WETH .* on eip155:42161/u);
  });
  test("decimals differ across chains (USDT and USDC have 18 on BNB Chain): legitimate deposits sign both ways; below half is refused", async () => {
    const { key, spy, signed } = signer();
    const legit: Array<[chainId: 1 | 56, Deposit, RegExp]> = [
      [56, { from: key.address, inputToken: USDT_BNB, outputToken: USDT_ETH, input: 100n * 10n ** 18n, output: 99_500_000n, destination: 1n }, /taking 100 USDT .* to pay 99\.5 USDT .* on eip155:1\b/u],
      [1, { from: key.address, inputToken: USDC_ETH, outputToken: USDC_BNB, input: 100_000_000n, output: 995n * 10n ** 17n, destination: 56n }, /taking 100 USDC .* to pay 99\.5 USDC .* on eip155:56/u],
    ];
    for (const [chainId, deposit, summary] of legit) {
      const api = boundProvider(flagDrainer);
      await signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId, ...FEES, to: SPOKE[chainId], value: 0n, data: v3(deposit) } as never);
      const v = await createGuard({ pinnedKeys: false, fetch: api.fetch }).check({ kind: "transaction", from: key.address, transaction: { chainId, ...FEES, to: SPOKE[chainId], value: 0n, data: v3(deposit) } as never });
      assert.equal(v.action, "allow");
      assert.match(v.summary, summary);
    }
    assert.equal(signed.length, 2);
    const half = v3({ from: key.address, inputToken: USDT_BNB, outputToken: USDT_ETH, input: 100n * 10n ** 18n, output: 40_000_000n, destination: 1n });
    const v = await refused(signTx(spy, { pinnedKeys: false, fetch: boundProvider(flagDrainer).fetch })({ chainId: 56, ...FEES, to: SPOKE[56], value: 0n, data: half } as never));
    assert.deepEqual([v.action, v.code, signed.length], ["block", "local_danger", 2]);
  });
  test("tokens the registry does not both know: no danger, a warning that names both amounts", async () => {
    const { key, spy, signed } = signer();
    const OTHER = "0x3333333333333333333333333333333333333333";
    const USDC_ARB = "0xaf88d065e77c8cc2239327c5edb3a432268e5831";
    for (const [outputToken, paid] of [
      [OTHER, `pays 1 base units of token ${OTHER} on eip155:42161`], // a token the registry does not know
      [USDC_ARB, `pays 0.000001 USDC (1 base units of ${USDC_ARB}) on eip155:42161`], // USDC for WETH: another symbol
      [ZERO, `pays 1 base units of token ${ZERO} on eip155:42161`], // no output token named
    ] as const) {
      const data = v3({ from: key.address, inputToken: WETH_BASE, outputToken, input: value, output: 1n, destination: 42161n });
      const decoded = decodeTransaction({ from: key.address, to: SPOKE[8453], value, data }, "eip155:8453");
      assert.deepEqual(decoded.danger, []);
      assert.ok(
        decoded.warnings.some((w) => w.includes(`takes 0.1 WETH (${value} base units of ${WETH_BASE})`) && w.includes(paid)),
        decoded.warnings.join(" | "),
      );
      await signTx(spy, { pinnedKeys: false, fetch: boundProvider(flagDrainer).fetch })({ chainId: 8453, ...FEES, to: SPOKE[8453], value, data } as never);
    }
    assert.equal(signed.length, 3);
  });
});
