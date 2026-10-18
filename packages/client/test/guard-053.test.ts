// Client 0.5.3, the follow-ups of the independent review of 0.5.2. Stubs only.
// - Across deposits whose tokens the decoders' registry did not both know passed with a warning: one that
//   paid out 1 unit on the other chain was signed with a stub provider, and the relayer that fills it keeps
//   the input. The registry now holds the tokens Across routes on every chain it serves (each read on-chain:
//   snap/src/util.ts), and US-dollar stablecoins compare at $1 each, WETH and bridged ETH 1:1.
// - Across's speedUpV3Deposit is authorized off-chain by EIP-712 UpdateDepositDetails, which rewrites what a
//   pending deposit pays and to whom without naming its input: it was read as a plain message and signed.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { concat, encodeAbiParameters, encodeFunctionData, formatUnits, getAddress, hashTypedData, keccak256, pad, parseAbi, parseAbiParameters, toHex, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { decodeTransaction } from "../src/decode/tx.js";
import { decodeTypedData } from "../src/decode/typed.js";
import { guardAccount, X402CheckBlockedError, type GuardVerdict } from "../src/guard.js";
import { boundProvider } from "./helpers.js";

const BOB = "0x1111111111111111111111111111111111111111";
const DRAINER = "0x2222222222222222222222222222222222222222";
const ZERO = "0x0000000000000000000000000000000000000000";
const LOW = { tier: "low" as const, score: 90, categories: [] };
const BLOCK = { tier: "critical" as const, score: 1, categories: ["known_scam_address"] };
const flagDrainer = (r: { wallet: string }) => (r.wallet.toLowerCase() === DRAINER ? BLOCK : LOW);
// What production signs for any Across deposit: its simulation sees the deposit event (cross_chain), a review.
const REVIEW = { tier: "medium" as const, score: 55, categories: ["simulation_incomplete"] };
const review = (r: { wallet: string }) => (r.wallet.toLowerCase() === DRAINER ? BLOCK : REVIEW);
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
    signTypedData: async (p: Parameters<typeof key.signTypedData>[0]) => {
      const signature = await key.signTypedData(p);
      signed.push(signature);
      return signature;
    },
  };
  return { key, spy, signed };
}
type Spy = ReturnType<typeof signer>["spy"];
const signTx = (account: Spy, options: Parameters<typeof guardAccount>[1]) => guardAccount(account, options).signTransaction as NonNullable<Spy["signTransaction"]>;
const seen = (api: ReturnType<typeof boundProvider>, address: string) => api.seen.some((r) => r.wallet.toLowerCase() === address.toLowerCase());

// Across's SpokePools on the chains the provider simulates (each answers wrappedNativeToken() and chainId()).
const SPOKE: Record<number, Hex> = {
  1: getAddress("0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5"),
  10: getAddress("0x6f26bf09b1c792e3228e5467807a900a503c0281"),
  56: getAddress("0x4e8e101924ede233c13e2d8622dc8aed2872d505"),
  137: getAddress("0x9295ee1d8c5b022be115a2ad3c30c72e34e7f096"),
  8453: getAddress("0x09aea4b2242abc8bb4bb78d537a67a245a7bec64"),
  42161: getAddress("0xe35e9842fceaca96570b734083f4a58e8f7c5f2a"),
};

/** A token as it is on-chain (symbol() and decimals()); `symbol` is the registry's ("USDT0" for USD₮0). */
type Token = { chain: number; address: Hex; symbol: string; decimals: number };
const token = (chain: number, address: string, symbol: string, decimals: number): Token => ({ chain, address: getAddress(address), symbol, decimals });

// Origins.
const WETH_BASE = token(8453, "0x4200000000000000000000000000000000000006", "WETH", 18);
const USDC_BASE = token(8453, "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "USDC", 6);
const USDBC_BASE = token(8453, "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca", "USDbC", 6);
const USDT_BASE = token(8453, "0xfde4c96c8593536e31f229ea8f37b2ada2699bb2", "USDT", 6);
const USDC_ETH = token(1, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "USDC", 6);
const USDT_ETH = token(1, "0xdac17f958d2ee523a2206206994597c13d831ec7", "USDT", 6);
const DAI_ETH = token(1, "0x6b175474e89094c44da98b954eedeac495271d0f", "DAI", 18);
const USDT_BNB = token(56, "0x55d398326f99059ff775485246999027b3197955", "USDT", 18);
const ETH_BNB = token(56, "0x2170ed0880ac9a755fd29b2688956bd959f933f8", "ETH", 18);
const USDCE_OP = token(10, "0x7f5c764cbc14f9669b88837ca1490cca17c31607", "USDC", 6);
const DAI_OP = token(10, "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1", "DAI", 18);
const USDC_POLYGON = token(137, "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", "USDC", 6);
const USDC_ARB = token(42161, "0xaf88d065e77c8cc2239327c5edb3a432268e5831", "USDC", 6);
const USDT_ARB = token(42161, "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", "USDT", 6);
const WETH_ARB = token(42161, "0x82af49447d8a07e3bd95bd0d56f35241523fbab1", "WETH", 18);

// Destinations new to the registry, by chain.
const OP_WETH = "0x4200000000000000000000000000000000000006";
const ETH_OUT = [
  token(130, OP_WETH, "WETH", 18), // Unichain
  token(143, "0xee8c0e9f1bffb4eb878d8f15f368a02a35481242", "WETH", 18), // Monad
  token(232, "0xe5ecd226b3032910ceaa43ba92ee8232f8237553", "ETH", 18), // Lens
  token(324, "0x5aea5775959fbc2557cc8789bc1bf90a239d9a91", "WETH", 18), // zkSync Era
  token(480, OP_WETH, "WETH", 18), // World Chain
  token(1135, OP_WETH, "WETH", 18), // Lisk
  token(1868, OP_WETH, "WETH", 18), // Soneium
  token(4326, OP_WETH, "WETH", 18), // MegaETH
  token(4663, "0x0bd7d308f8e1639fab988df18a8011f41eacad73", "WETH", 18), // Robinhood Chain
  token(9745, "0x9895d81bb462a195b4922ed7de0e3acd007c32cb", "WETH", 18), // Plasma
  token(34443, OP_WETH, "WETH", 18), // Mode
  token(57073, OP_WETH, "WETH", 18), // Ink
  token(59144, "0xe5d7c2a44ffddf6b295a15c148167daaaf5cf34f", "WETH", 18), // Linea
  token(81457, "0x4300000000000000000000000000000000000004", "WETH", 18), // Blast
  token(534352, "0x5300000000000000000000000000000000000004", "WETH", 18), // Scroll
  token(7777777, OP_WETH, "WETH", 18), // Zora
  ETH_BNB,
];
const USDC_OUT = [
  token(130, "0x078d782b760474a361dda0af3839290b0ef57ad6", "USDC", 6),
  token(143, "0x754704bc059f8c67012fed69bc8a327a5aafb603", "USDC", 6),
  token(232, "0x88f08e304ec4f90d644cec3fb69b8ad414acf884", "USDC", 6),
  token(324, "0x3355df6d4c9c3035724fd0e3914de96a5a83aaf4", "USDC.e", 6),
  token(480, "0x79a02482a880bce3f13e09da970dc34db4cd24d1", "USDC", 6),
  token(999, "0xb88339cb7199b77e23db6e890353e22632ba630f", "USDC", 6), // HyperEVM
  token(1135, "0xf242275d3a6527d877f2c927a82d9b057609cc71", "USDC.e", 6),
  token(1868, "0xba9986d2381edf1da03b0b9c1f8b00dc4aacc369", "USDC.e", 6),
  token(4217, "0x20c000000000000000000000b9537d11c60e8b50", "USDC.e", 6), // Tempo
  token(5042, "0x3600000000000000000000000000000000000000", "USDC", 6), // Arc
  token(9745, "0x2d661c89d812261039af9764eceaaee884f5f67f", "USDC", 6),
  token(34443, "0xd988097fb8612cc24eec14542bc03424c656005f", "USDC", 6),
  token(57073, "0x2d270e6886d130d724215a266106e6832161eaed", "USDC", 6),
  token(59144, "0x176211869ca2b568f2a7d4ee941e073a821ee1ff", "USDC", 6),
  token(81457, "0x4300000000000000000000000000000000000003", "USDB", 18),
  token(534352, "0x06efdbff2a14a7c8e15944d1f4a48f9f95f663a4", "USDC", 6),
  token(7777777, "0xcccccccc7021b32ebb4e8c08314bd62f7c653ec4", "USDzC", 6),
];
const USDT_OUT = [
  token(130, "0x9151434b16b9763660705744891fa906f660ecc5", "USDT0", 6),
  token(143, "0xe7cd86e13ac4309349f30b3435a9d337750fc82d", "USDT0", 6),
  token(324, "0x493257fd37edb34451f62edf8d2a0c418852ba4c", "USDT", 6),
  token(999, "0xb8ce59fc3717ada4c02eadf9682a9e934f625ebb", "USDT0", 6),
  token(1135, "0x05d032ac25d322df992303dca074ee7392c117b9", "USDT", 6),
  token(1868, "0x3a337a6ada9d885b6ad95ec48f9b75f197b5ae35", "USDT", 6),
  token(4217, "0x20c00000000000000000000014f22ca97301eb73", "USDT0", 6),
  token(4326, "0xb8ce59fc3717ada4c02eadf9682a9e934f625ebb", "USDT0", 6),
  token(9745, "0xb8ce59fc3717ada4c02eadf9682a9e934f625ebb", "USDT0", 6),
  token(34443, "0xf0f161fda2712db8b566946122a5af183995e2ed", "USDT", 6),
  token(57073, "0x0200c29006150606b650577bbe7b6248f58470c1", "USDT0", 6),
  token(59144, "0xa219439258ca9da29e9cc4ce5596924745e12b93", "USDT", 6),
  token(534352, "0xf55bec9cafdbe8730f096aa55dad6d22d44099df", "USDT", 6),
];
const DAI_OUT = [
  token(59144, "0x4af15ec2a0bd43db75dd04e62faa3b8ef36b00d5", "DAI", 18),
  token(324, "0x4b9eb6c0b6ea15176bbf62841c6b2a8a398cb656", "DAI", 18),
  token(81457, "0x4300000000000000000000000000000000000003", "USDB", 18),
];

const PAIRS: Array<[from: Token, to: Token]> = [
  ...ETH_OUT.map((to): [Token, Token] => [WETH_BASE, to]),
  ...USDC_OUT.map((to): [Token, Token] => [USDC_BASE, to]),
  ...USDT_OUT.map((to): [Token, Token] => [USDT_ETH, to]),
  ...DAI_OUT.map((to): [Token, Token] => [DAI_ETH, to]),
  // US-dollar stablecoins of different symbols ($1 each), mixed decimals included (BNB Chain's are 18).
  [USDC_BASE, USDT_ARB],
  [USDT_BNB, USDC_ETH],
  [USDC_ETH, USDT_BNB],
  [DAI_OP, USDC_POLYGON],
  [USDC_POLYGON, DAI_ETH],
  [USDBC_BASE, USDC_ARB],
  [USDCE_OP, USDC_BASE],
  [USDT_BASE, USDT_ARB],
  // ETH on BNB Chain (Binance-Peg, symbol "ETH") is Across's WETH there: 1:1.
  [ETH_BNB, WETH_ARB],
];

const across = parseAbi([
  "function depositV3(address depositor, address recipient, address inputToken, address outputToken, uint256 inputAmount, uint256 outputAmount, uint256 destinationChainId, address exclusiveRelayer, uint32 quoteTimestamp, uint32 fillDeadline, uint32 exclusivityDeadline, bytes message) payable",
  "function deposit(bytes32 depositor, bytes32 recipient, bytes32 inputToken, bytes32 outputToken, uint256 inputAmount, uint256 outputAmount, uint256 destinationChainId, bytes32 exclusiveRelayer, uint32 quoteTimestamp, uint32 fillDeadline, uint32 exclusivityParameter, bytes message) payable",
]);
const depositV3 = (me: Hex, from: Token, to: Token, input: bigint, output: bigint) =>
  encodeFunctionData({ abi: across, functionName: "depositV3", args: [me, me, from.address, to.address, input, output, BigInt(to.chain), ZERO, 1_700_000_000, 1_700_003_600, 0, "0x"] });
const depositBytes32 = (me: Hex, from: Token, to: Token, input: bigint, output: bigint) =>
  encodeFunctionData({ abi: across, functionName: "deposit", args: [pad(me), pad(me), pad(from.address), pad(to.address), input, output, BigInt(to.chain), pad(ZERO), 1_700_000_000, 1_700_003_600, 0, "0x"] });
/** 0.1 of an ETH-like token, 100 of a stablecoin. */
const inputOf = (t: Token) => (t.symbol === "WETH" || t.symbol === "ETH" ? 10n ** 17n : 100n * 10n ** BigInt(t.decimals));
/** `amount` in `from` decimals, written in `to` decimals. */
const scale = (amount: bigint, from: number, to: number) => (from >= to ? amount / 10n ** BigInt(from - to) : amount * 10n ** BigInt(to - from));
const name = (t: Token) => `${t.symbol} on eip155:${t.chain}`;
const escape = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");

describe("Across: deposits to every chain Across serves are compared in the same unit", () => {
  for (const [from, to] of PAIRS) {
    test(`${name(from)} to ${name(to)}: 1 unit paid out is refused before any check; 99% signs`, async () => {
      const { key, spy, signed } = signer();
      const input = inputOf(from);
      for (const encode of [depositV3, depositBytes32]) {
        const api = boundProvider(flagDrainer);
        const data = encode(key.address, from, to, input, 1n);
        const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: from.chain, ...FEES, to: SPOKE[from.chain], value: 0n, data } as never));
        assert.deepEqual([v.action, v.code], ["block", "local_danger"]);
        assert.match(v.reasons.join(" "), /less than half/u);
        if (from.symbol !== to.symbol) assert.match(v.reasons.join(" "), from.symbol === "ETH" || to.symbol === "ETH" ? /counted in ETH, 1:1/u : /counted in US dollars, \$1 each/u);
        assert.equal(api.seen.length, 0, "nothing is sent for checking");
      }
      assert.equal(signed.length, 0);
      const output = scale((input * 99n) / 100n, from.decimals, to.decimals);
      const data = depositV3(key.address, from, to, input, output);
      const api = boundProvider(flagDrainer);
      await signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: from.chain, ...FEES, to: SPOKE[from.chain], value: 0n, data } as never);
      assert.equal(signed.length, 1);
      assert.ok(seen(api, SPOKE[from.chain] as string), "the SpokePool is checked");
      // The summary names both amounts in their tokens, as the registry knows them on each chain.
      const decoded = decodeTransaction({ from: key.address, to: SPOKE[from.chain], value: 0n, data }, `eip155:${from.chain}`);
      assert.deepEqual(decoded.danger, []);
      assert.match(
        decoded.summary,
        new RegExp(`taking ${escape(formatUnits(input, from.decimals))} ${escape(from.symbol)} \\(.*to pay ${escape(formatUnits(output, to.decimals))} ${escape(to.symbol)} \\(${output} base units of ${to.address.toLowerCase()}\\) on eip155:${to.chain}\\b`, "u"),
      );
    });
  }
});

describe("Across: two known tokens of different assets are not compared", () => {
  const cases: Array<[from: Token, to: Token]> = [
    [WETH_BASE, USDC_OUT.find((t) => t.chain === 59144) as Token], // WETH to USDC on Linea
    [ETH_BNB, DAI_OUT.find((t) => t.chain === 81457) as Token], // ETH to USDB on Blast
    [USDC_BASE, ETH_OUT.find((t) => t.chain === 534352) as Token], // USDC to WETH on Scroll
  ];
  for (const [from, to] of cases) {
    test(`${name(from)} to ${name(to)} paying 1 unit: no local danger, a warning naming both, signed only with onWarn`, async () => {
      const { key, spy, signed } = signer();
      const input = inputOf(from);
      const data = depositV3(key.address, from, to, input, 1n);
      const decoded = decodeTransaction({ from: key.address, to: SPOKE[from.chain], value: 0n, data }, `eip155:${from.chain}`);
      assert.deepEqual(decoded.danger, []);
      assert.ok(
        decoded.warnings.some(
          (w) =>
            w.includes(`${from.symbol} and ${to.symbol} are different assets whose relative price x402check does not know`) &&
            w.includes(`pays ${formatUnits(1n, to.decimals)} ${to.symbol} (1 base units of ${to.address.toLowerCase()}) on eip155:${to.chain}`),
        ),
        decoded.warnings.join(" | "),
      );
      // Production reviews every Across deposit (cross_chain): without onWarn it is refused, with it signed.
      const tx = { chainId: from.chain, ...FEES, to: SPOKE[from.chain], value: 0n, data } as never;
      const v = await refused(signTx(spy, { pinnedKeys: false, fetch: boundProvider(review).fetch })(tx));
      assert.deepEqual([v.action, v.code, signed.length], ["warn", "warn_declined", 0]);
      const asked: GuardVerdict[] = [];
      await signTx(spy, { pinnedKeys: false, fetch: boundProvider(review).fetch, onWarn: (verdict) => (asked.push(verdict), true) })(tx);
      assert.deepEqual([asked.length, signed.length], [1, 1]);
    });
  }
});

describe("Across speed-ups (UpdateDepositDetails) are never signed", () => {
  const domain = { name: "ACROSS-V2", version: "1.0.0", chainId: 8453 } as const;
  const fields = (depositId: "uint32" | "uint256", recipient: "address" | "bytes32") => [
    { name: "depositId", type: depositId },
    { name: "originChainId", type: "uint256" },
    { name: "updatedOutputAmount", type: "uint256" },
    { name: "updatedRecipient", type: recipient },
    { name: "updatedMessage", type: "bytes" },
  ];
  // Across's SpokePool: UPDATE_V3_DEPOSIT_DETAILS_HASH (v3.0.0) and UPDATE_BYTES32_DEPOSIT_DETAILS_HASH (v4.1.5,
  // master; the deployed SpokePools on Ethereum, Base and Arbitrum return 0x8d1994e2… for it).
  const forms = [
    {
      form: "address recipient (v3.0.0)",
      typeString: "UpdateDepositDetails(uint32 depositId,uint256 originChainId,uint256 updatedOutputAmount,address updatedRecipient,bytes updatedMessage)",
      types: { UpdateDepositDetails: fields("uint32", "address") },
      message: { depositId: 4242, originChainId: 8453n, updatedOutputAmount: 1n, updatedRecipient: BOB, updatedMessage: "0x" },
    },
    {
      form: "bytes32 recipient (v4 and later)",
      typeString: "UpdateDepositDetails(uint256 depositId,uint256 originChainId,uint256 updatedOutputAmount,bytes32 updatedRecipient,bytes updatedMessage)",
      types: { UpdateDepositDetails: fields("uint256", "bytes32") },
      message: { depositId: 4242n, originChainId: 8453n, updatedOutputAmount: 1n, updatedRecipient: pad(BOB), updatedMessage: "0x" },
    },
  ];
  /** The digest the SpokePool recovers the depositor from (_verifyUpdateV3DepositMessage, EIP712CrossChainUpgradeable). */
  const spokePoolDigest = (typeString: string) => {
    const words = parseAbiParameters("bytes32, uint256, uint256, uint256, bytes32, bytes32");
    const struct = keccak256(encodeAbiParameters(words, [keccak256(toHex(typeString)), 4242n, 8453n, 1n, pad(BOB), keccak256("0x")]));
    const separator = keccak256(
      encodeAbiParameters(parseAbiParameters("bytes32, bytes32, bytes32, uint256"), [
        keccak256(toHex("EIP712Domain(string name,string version,uint256 chainId)")),
        keccak256(toHex("ACROSS-V2")),
        keccak256(toHex("1.0.0")),
        8453n,
      ]),
    );
    return keccak256(concat(["0x1901", separator, struct]));
  };
  for (const { form, typeString, types, message } of forms) {
    test(`${form}: a new amount of 1 wei to a clean recipient is refused as unreadable, nothing is checked or signed`, async () => {
      const typedData = { domain, types, primaryType: "UpdateDepositDetails", message } as const;
      // Exactly what a SpokePool verifies.
      assert.equal(hashTypedData(typedData as never), spokePoolDigest(typeString));
      const decoded = decodeTypedData(typedData as never);
      assert.match(decoded.opaque ?? "", /an Across deposit speed-up \(UpdateDepositDetails\) rewrites what pending deposit #4242 pays on the other chain \(1 base units of its output token\) and to whom \(0x1111111111111111111111111111111111111111\)/u);
      assert.equal(decoded.counterparty, BOB);
      const api = boundProvider(flagDrainer);
      const { spy, signed } = signer();
      const v = await refused(guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signTypedData(typedData as never));
      assert.deepEqual([v.action, v.code], ["not_verified", "opaque_signature"]);
      assert.match(v.reasons.join(" "), /Across deposit speed-up/u);
      assert.deepEqual([api.seen.length, signed.length], [0, 0]);
    });
  }
  test("a recipient outside EVM form (a Solana account), or the signer itself, is refused the same way", async () => {
    const { key, spy, signed } = signer();
    const [, bytes32] = forms as [unknown, (typeof forms)[1]];
    const solana = `0x${"8f".repeat(32)}` as Hex;
    for (const [recipient, named] of [
      [solana, `${solana} (not an EVM address)`],
      [pad(key.address), key.address.toLowerCase()],
    ] as const) {
      const typedData = { domain, types: bytes32.types, primaryType: "UpdateDepositDetails", message: { ...bytes32.message, updatedRecipient: recipient } } as const;
      assert.match(decodeTypedData(typedData as never, key.address).opaque ?? "", new RegExp(`and to whom \\(${escape(named)}\\)`, "u"));
      const api = boundProvider(flagDrainer);
      const v = await refused(guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }).signTypedData(typedData as never));
      assert.deepEqual([v.action, v.code, api.seen.length], ["not_verified", "opaque_signature", 0]);
    }
    assert.equal(signed.length, 0);
  });
});
