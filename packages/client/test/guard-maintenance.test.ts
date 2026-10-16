// The SDK review of the daily maintenance run (2026-10-16): A1-A4, M1, M2, L1, L2. Each case was
// reproduced against the code before its fix; C1 is in guard-review.test.ts and C2 in
// solana-stake-v5.test.ts. Stubs only: throwaway keys, no network.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { createWalletClient, custom, encodeFunctionData, erc20Abi, parseAbi, type Hex } from "viem";
import { base } from "viem/chains";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { guardAccount, X402CheckBlockedError, type GuardVerdict } from "../src/guard.js";
import { boundProvider } from "./helpers.js";

const BOB = "0x1111111111111111111111111111111111111111";
const DRAINER = "0x2222222222222222222222222222222222222222";
const WETH_BASE = "0x4200000000000000000000000000000000000006";
const LOW = { tier: "low" as const, score: 88, categories: [] };
const BLOCK = { tier: "critical" as const, score: 2, categories: ["known_scam_address"] };

function evmSigner() {
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

/** The guarded account's signTransaction, which the spy always has. */
const signTx = (account: ReturnType<typeof evmSigner>["spy"], options: Parameters<typeof guardAccount>[1]) =>
  (guardAccount(account, options).signTransaction as NonNullable<ReturnType<typeof guardAccount<typeof account>>["signTransaction"]>);

async function refused(p: Promise<unknown>): Promise<GuardVerdict> {
  try {
    await p;
  } catch (err) {
    assert.ok(err instanceof X402CheckBlockedError, String(err));
    return err.verdict;
  }
  assert.fail("it was signed");
}

describe("A1: only the fields the standard serializer reads are signed", () => {
  test("a field a chain's own serializer would read (Tempo `calls`, Celo `feeCurrency`) is refused unchecked", async () => {
    for (const extra of [{ calls: [{ to: DRAINER, value: 0n, data: "0x" }] }, { feeCurrency: DRAINER }]) {
      const api = boundProvider(() => LOW);
      const { spy, signed } = evmSigner();
      const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ chainId: 8453, nonce: 0, gas: 300_000n, maxFeePerGas: 10n ** 10n, maxPriorityFeePerGas: 1n, ...extra } as never));
      assert.deepEqual([v.action, v.code, signed.length, api.seen.length], ["not_verified", "invalid_transaction", 0, 0]);
    }
  });
});

describe("M1: viem's wallet actions work through the guard", () => {
  test("walletClient.sendTransaction on Base (account and chain attached, the OP Stack serializer passed) is checked and sent", async () => {
    const api = boundProvider(() => LOW);
    const { spy, signed } = evmSigner();
    const sent: string[] = [];
    const transport = custom({
      async request({ method, params }: { method: string; params?: unknown[] }) {
        switch (method) {
          case "eth_chainId":
            return "0x2105";
          case "eth_getTransactionCount":
            return "0x0";
          case "eth_estimateGas":
            return "0x5208";
          case "eth_gasPrice":
            return "0x3b9aca00";
          case "eth_maxPriorityFeePerGas":
            return "0x1";
          case "eth_getBlockByNumber":
            return { baseFeePerGas: "0x1", number: "0x1", hash: `0x${"11".repeat(32)}`, timestamp: "0x1", transactions: [] };
          case "eth_sendRawTransaction":
            sent.push(String(params?.[0]));
            return `0x${"22".repeat(32)}`;
          case "eth_fillTransaction":
            throw Object.assign(new Error("method not found"), { code: -32601 });
          default:
            throw new Error(`unexpected ${method}`);
        }
      },
    });
    const wallet = createWalletClient({ account: guardAccount(spy, { pinnedKeys: false, fetch: api.fetch }) as never, chain: base, transport });
    await wallet.sendTransaction({ to: BOB, value: 1n } as never);
    assert.deepEqual([signed.length, sent.length], [1, 1]);
    assert.ok(api.seen.some((r) => r.wallet.toLowerCase() === BOB.toLowerCase()), "the recipient was checked");
  });
});

describe("M2: the fee cap reads the fee the transaction pays", () => {
  for (const type of ["legacy", "eip2930"] as const) {
    test(`${type} with maxFeePerGas 0 and a huge gasPrice is over the cap`, async () => {
      const api = boundProvider(() => LOW);
      const { spy, signed } = evmSigner();
      const tx = { type, chainId: 8453, to: BOB, value: 1n, nonce: 0, gas: 21_000n, gasPrice: 10n ** 14n, maxFeePerGas: 0n, ...(type === "eip2930" ? { accessList: [] } : {}) };
      const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch, maxFeeWei: 10n ** 15n })(tx as never));
      assert.deepEqual([v.code, signed.length], ["fee_cap", 0]);
    });
  }
});

describe("A2: typed data read only in part is not signed", () => {
  test("a recipient past the reading budget (4,000 values) is never checked, so the request is refused", async () => {
    const api = boundProvider((r) => (r.wallet.toLowerCase() === DRAINER ? BLOCK : LOW));
    const key = privateKeyToAccount(generatePrivateKey());
    const pad = Array.from({ length: 256 }, (_, i) => BigInt(i));
    const fields = Array.from({ length: 16 }, (_, i) => ({ name: `pad${i}`, type: "uint256[]" }));
    const typed = {
      domain: { name: "Batch", version: "1", chainId: 8453 },
      types: { Batch: [...fields, { name: "recipient", type: "address" }] },
      primaryType: "Batch" as const,
      message: { ...Object.fromEntries(fields.map((f) => [f.name, pad])), recipient: DRAINER },
    };
    const v = await refused(guardAccount(key, { pinnedKeys: false, fetch: api.fetch }).signTypedData(typed as never));
    assert.equal(v.action, "not_verified");
  });
});

describe("A3: a call to a precompile or system contract is not signed unread", () => {
  test("Safe.execTransaction to Arbitrum's ArbSys withdrawing 100 ETH to an L1 address is refused", async () => {
    const api = boundProvider(() => LOW);
    const { key, spy, signed } = evmSigner();
    const inner = encodeFunctionData({ abi: parseAbi(["function withdrawEth(address destination) payable returns (uint256)"]), functionName: "withdrawEth", args: [DRAINER] });
    const sig = `0x${key.address.slice(2).toLowerCase().padStart(64, "0")}${"0".repeat(64)}01` as Hex;
    const data = encodeFunctionData({
      abi: parseAbi(["function execTransaction(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,bytes signatures) payable returns (bool)"]),
      functionName: "execTransaction",
      args: ["0x0000000000000000000000000000000000000064", 10n ** 20n, inner, 0, 0n, 0n, 0n, "0x0000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000", sig],
    });
    const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ type: "eip1559", chainId: 42161, nonce: 0, gas: 200_000n, maxFeePerGas: 10n ** 8n, maxPriorityFeePerGas: 1n, to: "0x5555555555555555555555555555555555555555", value: 0n, data } as never));
    assert.deepEqual([v.action, signed.length], ["not_verified", 0]);
  });
  test("a transaction with calldata to a precompile, naming nobody, is not signed on nothing", async () => {
    const api = boundProvider(() => LOW);
    const { spy, signed } = evmSigner();
    const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ type: "eip1559", chainId: 8453, nonce: 0, gas: 50_000n, maxFeePerGas: 10n ** 8n, maxPriorityFeePerGas: 1n, to: "0x0000000000000000000000000000000000000004", value: 0n, data: "0xdeadbeef" } as never));
    assert.deepEqual([v.action, signed.length], ["not_verified", 0]);
  });
});

describe("A4: every address typed data names is checked", () => {
  test("Withdrawal(token, dst): a known drainer as `dst` is checked and blocked", async () => {
    const api = boundProvider((r) => (r.wallet.toLowerCase() === DRAINER ? BLOCK : LOW));
    const key = privateKeyToAccount(generatePrivateKey());
    const typed = {
      domain: { name: "Vault", version: "1", chainId: 8453, verifyingContract: "0x4444444444444444444444444444444444444444" as Hex },
      types: { Withdrawal: [{ name: "token", type: "address" }, { name: "dst", type: "address" }, { name: "wad", type: "uint256" }, { name: "nonce", type: "uint256" }] },
      primaryType: "Withdrawal" as const,
      message: { token: WETH_BASE as Hex, dst: DRAINER as Hex, wad: 10n ** 21n, nonce: 0n },
    };
    const v = await refused(guardAccount(key, { pinnedKeys: false, fetch: api.fetch }).signTypedData(typed as never));
    assert.equal(v.action, "block");
    assert.ok(api.seen.some((r) => r.wallet.toLowerCase() === DRAINER));
  });
  test("a zkSync-style transaction signed as typed data (its recipient a uint256) is not verified", async () => {
    const api = boundProvider(() => LOW);
    const key = privateKeyToAccount(generatePrivateKey());
    const typed = {
      domain: { name: "zkSync", version: "2", chainId: 324 },
      types: {
        Transaction: [
          { name: "txType", type: "uint256" }, { name: "from", type: "uint256" }, { name: "to", type: "uint256" }, { name: "gasLimit", type: "uint256" },
          { name: "gasPerPubdataByteLimit", type: "uint256" }, { name: "maxFeePerGas", type: "uint256" }, { name: "maxPriorityFeePerGas", type: "uint256" },
          { name: "paymaster", type: "uint256" }, { name: "nonce", type: "uint256" }, { name: "value", type: "uint256" }, { name: "data", type: "bytes" },
          { name: "factoryDeps", type: "bytes32[]" }, { name: "paymasterInput", type: "bytes" },
        ],
      },
      primaryType: "Transaction" as const,
      message: { txType: 113n, from: BigInt(key.address), to: BigInt(DRAINER), gasLimit: 1n, gasPerPubdataByteLimit: 1n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n, paymaster: 0n, nonce: 0n, value: 5n * 10n ** 18n, data: "0x", factoryDeps: [], paymasterInput: "0x" },
    };
    const v = await refused(guardAccount(key, { pinnedKeys: false, fetch: api.fetch }).signTypedData(typed as never));
    assert.equal(v.action, "not_verified");
  });
});

describe("L2: delegations the simulation does not apply", () => {
  test("a type-4 transaction carrying an authorization list is not verified", async () => {
    const api = boundProvider(() => LOW);
    const { key, spy, signed } = evmSigner();
    const authorization = await key.signAuthorization({ contractAddress: BOB, chainId: 8453, nonce: 1 });
    const v = await refused(signTx(spy, { pinnedKeys: false, fetch: api.fetch })({ type: "eip7702", chainId: 8453, nonce: 0, gas: 100_000n, maxFeePerGas: 10n ** 8n, maxPriorityFeePerGas: 1n, to: key.address, value: 0n, data: encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [DRAINER, 1n] }), authorizationList: [authorization] } as never));
    assert.deepEqual([v.action, v.code, signed.length], ["not_verified", "not_simulated", 0]);
  });
});
