import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { AgentKit, EvmWalletProvider, x402ActionProvider, type Network } from "@coinbase/agentkit";
import { privateKeyToAccount } from "viem/accounts";
import { verifyTypedData, type Hex, type TransactionRequest } from "viem";
import type { RiskCheckRequest } from "@x402check/client";
import { X402CHECK_PAY_TO } from "@x402check/client/guard";
import { boundProvider } from "../../client/test/helpers.ts";
import { X402CheckBlockedError, X402checkActionProvider, caip2Of, guardWalletProvider, x402checkActionProvider, type GuardVerdict } from "../src/index.ts";

const USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PAYEE = "0x1111111111111111111111111111111111111111";
const DRAINER = "0x3333333333333333333333333333333333333333";
const KEY = `0x${"59".repeat(32)}` as Hex;

type Verdict = { tier: "low" | "medium" | "high" | "critical"; score: number; categories: string[] };
const LOW: Verdict = { tier: "low", score: 90, categories: [] };
const CRITICAL: Verdict = { tier: "critical", score: 4, categories: ["known_scam_address"] };
const decide = (r: RiskCheckRequest) => (r.wallet.toLowerCase() === DRAINER ? CRITICAL : LOW);

// Nothing in these tests may reach the network: AgentKit's own telemetry included.
const realFetch = globalThis.fetch;
const stray: string[] = [];
before(() => {
  globalThis.fetch = (async (input: unknown) => {
    stray.push(String(input instanceof Request ? input.url : input));
    return new Response(null, { status: 204 });
  }) as typeof fetch;
});
after(() => {
  globalThis.fetch = realFetch;
  assert.deepEqual(stray.filter((u) => !u.includes("cca-lite.coinbase.com")), []);
});

/** A wallet like AgentKit's own: private state, signing with a local key, sending recorded. */
class TestWallet extends EvmWalletProvider {
  readonly #account = privateKeyToAccount(KEY);
  readonly sent: unknown[] = [];
  readonly calls: string[] = [];
  /** A signing account kept on the wallet, as CDP's smart wallet keeps its owner. */
  readonly ownerAccount = privateKeyToAccount(KEY);
  getAddress(): string {
    return this.#account.address;
  }
  getNetwork(): Network {
    return { protocolFamily: "evm", networkId: "base-mainnet", chainId: "8453" };
  }
  getName(): string {
    return "test_wallet";
  }
  async getBalance(): Promise<bigint> {
    return 10n ** 18n;
  }
  async nativeTransfer(to: string, value: string): Promise<string> {
    this.calls.push(`nativeTransfer:${to}:${value}`);
    return `0x${"ab".repeat(32)}`;
  }
  async sign(hash: Hex): Promise<Hex> {
    this.calls.push("sign");
    return this.#account.sign({ hash });
  }
  /** As AgentKit's ViemWalletProvider: a hex string is signed as raw bytes. */
  async signMessage(message: string | Uint8Array): Promise<Hex> {
    this.calls.push("signMessage");
    return this.#account.signMessage({ message: typeof message === "string" && !/^0x[0-9a-fA-F]*$/.test(message) ? message : { raw: message as Hex | Uint8Array } });
  }
  async signTypedData(typedData: any): Promise<Hex> {
    this.calls.push("signTypedData");
    return this.#account.signTypedData(typedData);
  }
  async signTransaction(transaction: TransactionRequest): Promise<Hex> {
    this.calls.push("signTransaction");
    return this.#account.signTransaction({ ...transaction, chainId: 8453, type: "eip1559", gas: 21000n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n, nonce: 0 } as never);
  }
  async sendTransaction(transaction: TransactionRequest): Promise<Hex> {
    this.calls.push("sendTransaction");
    this.sent.push(transaction);
    return `0x${"cd".repeat(32)}`;
  }
  async waitForTransactionReceipt(): Promise<any> {
    return { status: "success" };
  }
  async readContract(): Promise<any> {
    return 0n;
  }
  getPublicClient(): any {
    return {};
  }
  /** A backend shortcut that signs on its own: the guard must refuse it. */
  async swapTokens(): Promise<string> {
    this.calls.push("swapTokens");
    return "swapped";
  }
  /** Like LegacyCdpWalletProvider.gaslessERC20Transfer: it signs, and its name says nothing of it. */
  async gaslessERC20Transfer(): Promise<string> {
    this.calls.push("gaslessERC20Transfer");
    return "sent";
  }
}

const payment = (from: string, to: string) => ({
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
  message: { from: from as Hex, to: to as Hex, value: 3500n, validAfter: 0n, validBefore: 2_000_000_000n, nonce: `0x${"01".repeat(32)}` as Hex },
});

async function refused(p: Promise<unknown>): Promise<GuardVerdict> {
  const err = await p.then(
    () => assert.fail("expected a refusal"),
    (e: unknown) => e,
  );
  assert.ok(err instanceof X402CheckBlockedError, String(err));
  return err.verdict;
}

function setup() {
  const api = boundProvider(decide);
  const wallet = new TestWallet();
  const verdicts: GuardVerdict[] = [];
  const guarded = guardWalletProvider(wallet, { fetch: api.fetch, pinnedKeys: false, creditToken: "x402c_" + "c".repeat(43), onVerdict: (v) => void verdicts.push(v) });
  return { api, wallet, guarded, verdicts };
}

test("the guarded wallet is still the wallet: AgentKit types, address and network", () => {
  const { wallet, guarded } = setup();
  assert.ok(guarded instanceof EvmWalletProvider);
  assert.equal(guarded.getAddress(), wallet.getAddress());
  assert.deepEqual(guarded.getNetwork(), wallet.getNetwork());
  assert.equal(guarded.getName(), "test_wallet");
});

test("an x402 payment (EIP-3009) to a clean payee is checked as a payment, then signed", async () => {
  const { api, wallet, guarded } = setup();
  const typed = payment(wallet.getAddress(), PAYEE);
  const signature = await guarded.signTypedData(typed);
  assert.ok(await verifyTypedData({ ...typed, address: wallet.getAddress() as Hex, signature }));
  const req = api.seen[0] as RiskCheckRequest;
  assert.equal(req.wallet, PAYEE);
  assert.deepEqual(req.payment, { network: "eip155:8453", pay_to: PAYEE, amount: "3500", asset: USDC_BASE });
});

test("AgentKit's x402 path (toSigner) signs through the guard: a drainer payee is refused and the key never signs", async () => {
  const { wallet, guarded } = setup();
  const signer = guarded.toSigner();
  const verdict = await refused(signer.signTypedData(payment(wallet.getAddress(), DRAINER)));
  assert.equal(verdict.action, "block");
  assert.deepEqual(wallet.calls, []);
  // Paying x402check itself is not checked (no recursion, no cost).
  await signer.signTypedData(payment(wallet.getAddress(), X402CHECK_PAY_TO[0] as string));
  assert.deepEqual(wallet.calls, ["signTypedData"]);
});

test("sendTransaction: the transaction is simulated and checked, and the checked copy is what gets sent", async () => {
  const { api, wallet, guarded } = setup();
  const tx = { to: PAYEE as Hex, value: 1000n, data: "0x" as Hex };
  await guarded.sendTransaction(tx);
  assert.equal(wallet.sent.length, 1);
  const sent = wallet.sent[0] as { to: string; value: bigint; chainId?: number };
  assert.equal(sent.to.toLowerCase(), PAYEE);
  assert.equal(sent.value, 1000n);
  assert.notEqual(sent, tx);
  const req = api.seen[0] as RiskCheckRequest;
  assert.ok(req.transaction, "the transaction went to the simulation");
  assert.equal(req.chain, "eip155:8453");

  await refused(guarded.sendTransaction({ to: DRAINER as Hex, value: 1n }));
  assert.equal(wallet.sent.length, 1);
});

test("nativeTransfer is checked before the wallet builds and sends it", async () => {
  const { wallet, guarded } = setup();
  await guarded.nativeTransfer(PAYEE, "5000");
  assert.deepEqual(wallet.calls, [`nativeTransfer:${PAYEE}:5000`]);
  await refused(guarded.nativeTransfer(DRAINER, "5000"));
  assert.equal(wallet.calls.length, 1);
});

test("raw hash signing and unguarded signing members refuse; plain members pass through", async () => {
  const { wallet, guarded, verdicts } = setup();
  const raw = await refused(guarded.sign(`0x${"11".repeat(32)}`));
  assert.equal(raw.code, "raw_hash_signing");
  const swap = await refused((guarded as unknown as TestWallet).swapTokens());
  assert.equal(swap.code, "unguarded_method");
  assert.deepEqual(wallet.calls, []);
  assert.equal(await guarded.getBalance(), 10n ** 18n);
  assert.equal(verdicts.filter((v) => !v.signed).length, 2);
});

test("a failed check refuses: the key signs only on a verified allow", async () => {
  const wallet = new TestWallet();
  const guarded = guardWalletProvider(wallet, { fetch: async () => new Response("{}", { status: 503 }), pinnedKeys: false });
  const verdict = await refused(guarded.signTypedData(payment(wallet.getAddress(), PAYEE)));
  assert.equal(verdict.action, "not_verified");
  // Default pinning: an attestation from any key other than x402check's is not trusted.
  const api = boundProvider(decide);
  const pinned = guardWalletProvider(wallet, { fetch: api.fetch });
  assert.equal((await refused(pinned.signTypedData(payment(wallet.getAddress(), PAYEE)))).action, "not_verified");
  assert.deepEqual(wallet.calls, []);
});

test("the action provider: one action, through AgentKit, with the wallet's network as the default chain", async () => {
  const api = boundProvider(decide);
  const wallet = new TestWallet();
  const agentkit = await AgentKit.from({ walletProvider: guardWalletProvider(wallet, { fetch: api.fetch, pinnedKeys: false }), actionProviders: [x402checkActionProvider({ fetch: api.fetch, pinnedKeys: false, creditToken: "x402c_" + "d".repeat(43) })] });
  const actions = agentkit.getActions();
  assert.deepEqual(
    actions.map((a) => a.name),
    ["X402checkActionProvider_check_counterparty"],
  );
  const action = actions[0]!;
  const out = JSON.parse(await action.invoke(action.schema.parse({ address: DRAINER, domain: "claim-usdc.example", interaction: "token_transfer" })));
  assert.equal(out.action, "block");
  assert.match(out.instruction, /Do not proceed/);
  assert.match(out.attestation, /^ey/);
  const req = api.seen[0] as RiskCheckRequest;
  assert.equal(req.chain, "eip155:8453");
  assert.equal(req.domain, "claim-usdc.example");

  // Invalid input is refused before anything is paid.
  const before = api.calls.length;
  assert.equal(action.schema.safeParse({ address: PAYEE, extra: 1 }).success, false);
  const bad = JSON.parse(await action.invoke({ address: "" } as never));
  assert.equal(bad.action, "not_verified");
  assert.equal(api.calls.length, before);
  assert.ok(new X402checkActionProvider().supportsNetwork());
});

test("caip2Of maps AgentKit networks", () => {
  assert.equal(caip2Of({ protocolFamily: "evm", networkId: "base-mainnet", chainId: "8453" }), "eip155:8453");
  assert.equal(caip2Of({ protocolFamily: "svm", networkId: "solana-mainnet" }), "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp");
  assert.equal(caip2Of({ protocolFamily: "evm" }), undefined);
});

test("only reading members pass: a gasless transfer, a backend shortcut or a signing account on the wallet is not reachable", async () => {
  const { wallet, guarded } = setup();
  const gasless = await refused((guarded as unknown as TestWallet).gaslessERC20Transfer());
  assert.equal(gasless.code, "unguarded_method");
  assert.throws(() => (guarded as unknown as TestWallet).ownerAccount, (e: unknown) => e instanceof X402CheckBlockedError && e.verdict.code === "unguarded_method");
  assert.deepEqual(wallet.calls, []);
  // Named in passthrough: reachable, unchecked, by the caller's choice.
  const open = guardWalletProvider(wallet, { pinnedKeys: false, passthrough: ["gaslessERC20Transfer", "ownerAccount"] }) as unknown as TestWallet;
  assert.equal(await open.gaslessERC20Transfer(), "sent");
  assert.equal(open.ownerAccount.address, wallet.getAddress());
});

test("signMessage reads a hex string as the bytes the wallet signs: a 32-byte hash is refused, text is checked and signed", async () => {
  const { api, wallet, guarded } = setup();
  const hash = await refused(guarded.signMessage(`0x${"11".repeat(32)}`));
  assert.equal(hash.code, "raw_hash_signing");
  assert.deepEqual(wallet.calls, []);
  assert.equal(api.calls.length, 0, "refused locally, before any paid check");
  // Hex that is readable text is read as that text; the wallet signs the same bytes.
  const hello = await guarded.signMessage("0x68656c6c6f");
  assert.equal(hello, await privateKeyToAccount(KEY).signMessage({ message: "hello" }));
  assert.equal(await guarded.signMessage("hello"), hello);
});

test("malformed amounts and transactions for another chain refuse with the guard's error", async () => {
  const { wallet, guarded, verdicts } = setup();
  const decimal = await refused(guarded.nativeTransfer(PAYEE, "0.1"));
  assert.equal(decimal.code, "invalid_transaction");
  const otherChain = await refused(guarded.sendTransaction({ to: PAYEE as Hex, value: 1n, chainId: 1 } as TransactionRequest));
  assert.equal(otherChain.code, "invalid_transaction");
  assert.deepEqual(wallet.calls, []);
  assert.equal(verdicts.length, 2);
});

const SELLER = "https://seller.example/data";

/** A seller that charges in x402 v2: a 402 with `PAYMENT-REQUIRED`, then 200 for a request that carries `PAYMENT-SIGNATURE`. */
async function withSeller<T>(payTo: string, run: (paid: string[]) => Promise<T>): Promise<T> {
  const accepts = [{ scheme: "exact", network: "eip155:8453", asset: USDC_BASE, amount: "3500", payTo, maxTimeoutSeconds: 60, extra: { name: "USD Coin", version: "2" } }];
  const required = { x402Version: 2, resource: { url: SELLER, description: "data", mimeType: "application/json" }, accepts };
  const paid: string[] = [];
  const previous = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    if (request.url !== SELLER) return previous(input, init);
    const signature = request.headers.get("payment-signature");
    if (!signature) return new Response("{}", { status: 402, headers: { "content-type": "application/json", "payment-required": btoa(JSON.stringify(required)) } });
    paid.push(signature);
    return Response.json({ ok: true });
  }) as typeof fetch;
  try {
    return await run(paid);
  } finally {
    globalThis.fetch = previous;
  }
}

/** The one-shot action answers `success: true`, the retry `status: "success"`. */
const succeeded = (result: { success?: unknown; status?: unknown }) => result.success === true || result.status === "success";

for (const name of ["make_http_request_with_x402", "retry_http_request_with_x402"]) {
  test(`AgentKit's own x402 action ${name} pays through the guard: a clean payee is paid, a drainer is refused before the key signs`, async () => {
    for (const payTo of [PAYEE, DRAINER]) {
      const { wallet, guarded, verdicts } = setup();
      const agentkit = await AgentKit.from({ walletProvider: guarded, actionProviders: [x402ActionProvider()] });
      const action = agentkit.getActions().find((a) => a.name.endsWith(`_${name}`));
      assert.ok(action, name);
      const args = { url: SELLER, method: "GET", selectedPaymentOption: { scheme: "exact", network: "eip155:8453", asset: USDC_BASE, amount: "3500", payTo } };
      const { result, paid } = await withSeller(payTo, async (paid) => ({ result: JSON.parse(await action.invoke(args)), paid }));
      assert.equal(verdicts.length, 1, "one check, before signing");
      if (payTo === PAYEE) {
        assert.equal(verdicts[0]!.action, "allow");
        assert.ok(succeeded(result), JSON.stringify(result));
        assert.deepEqual(wallet.calls, ["signTypedData"]);
        assert.equal(paid.length, 1);
        // The authorization the seller received pays the payee that was checked.
        const sent = JSON.parse(atob(paid[0]!)) as { payload: { authorization: { to: string; value: string } } };
        assert.equal(sent.payload.authorization.to.toLowerCase(), PAYEE);
        assert.equal(sent.payload.authorization.value, "3500");
      } else {
        assert.equal(verdicts[0]!.action, "block");
        assert.ok(!succeeded(result), JSON.stringify(result));
        assert.deepEqual(wallet.calls, [], "the key never signed");
        assert.deepEqual(paid, [], "the seller received no payment");
      }
    }
  });
}
