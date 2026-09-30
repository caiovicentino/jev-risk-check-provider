// End to end: the signing guard of @x402check/client against the REAL provider (in process):
// real evaluation, real ES256 attestations, real claim binding, DID document served by the
// handler. Only the model and the simulator are deterministic stand-ins, so this proves that
// what the provider signs is exactly what the guard verifies.
import { test } from "node:test";
import assert from "node:assert/strict";
import { encodeFunctionData, erc20Abi, maxUint256, parseUnits, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createGuard, guardAccount, X402CheckBlockedError } from "../packages/client/src/guard.js";
import { createHandler } from "../src/handler.js";
import { Provider } from "../src/provider.js";
import { generateKeyPair } from "../src/jws.js";
import type { SimulationEvidence, Simulator } from "../src/simulation.js";
import type { Answer } from "../src/types.js";

const USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const BOB = "0x1111111111111111111111111111111111111111";
const DRAINER = "0x2222222222222222222222222222222222222222";
const HIDDEN = "0x4444444444444444444444444444444444444444";
const ANSWERS: Record<string, Answer> = {
  known_threat: { type: "noul", noul: 0.02 },
  sanctions_concern: { type: "noul", noul: 0.02 },
  laundering_pattern: { type: "noul", noul: 0.02 },
  risky_domain: { type: "noul", noul: 0.02 },
  guard_bypass_attempt: { type: "noul", noul: 0.02 },
  risk_class: { type: "choice", choice: "benign", probabilities: { benign: 0.95 }, confidence: 0.9 },
  trust: { type: "score", score: 3.8, legend: {}, probabilities: { "4": 0.8 }, confidence: 0.85 },
};

/** The real handler behind a fetch, with a simulator scripted per call. */
function realProvider(simulate: (tx: { from: string; to?: string | undefined; data?: string | undefined }, network: string | undefined) => SimulationEvidence) {
  const simulator: Simulator = async (tx, network) => simulate(tx, network);
  const provider = new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("jev-attest-v1"), jev: { systemOne: async () => ({ answers: ANSWERS, usage: { inputTokens: 1, outputTokens: 0 } }) }, simulator });
  const handler = createHandler({ provider });
  const fetch = async (url: string, init: { method?: string; headers?: Record<string, string>; body?: string }) =>
    handler(new Request(url, { method: init?.method ?? "GET", headers: init?.headers ?? {}, ...(init?.body !== undefined ? { body: init.body } : {}) }));
  return fetch as never;
}

const base = (tx: { data: Hex; to?: string; value?: bigint }) => ({ to: (tx.to ?? USDC) as Hex, data: tx.data, value: tx.value ?? 0n, chainId: 8453, type: "eip1559" as const, nonce: 0, gas: 90_000n, maxFeePerGas: 1_000_000_000n, maxPriorityFeePerGas: 1_000_000n });

test("benign transfer: the real provider's attestation verifies and binds; the key signs", async () => {
  const fetch = realProvider((tx, network) => ({ status: "ok", ...(network ? { network } : {}), outflows: [{ standard: "erc20", asset: USDC, amount: "25000000", counterparty: BOB, counterparty_is_contract: false }], inflows: [], approvals: [], findings: [] }));
  const account = privateKeyToAccount(generatePrivateKey());
  const data = encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [BOB, parseUnits("25", 6)] });
  const verdict = await createGuard({ pinnedKeys: false, fetch }).check({ kind: "transaction", from: account.address, transaction: base({ data }) });
  assert.notEqual(verdict.action, "not_verified", `attestation must verify and bind: ${verdict.reasons.join("; ")}`);
  assert.ok(["allow", "warn"].includes(verdict.action));
  const signed = await guardAccount(account, { pinnedKeys: false, fetch, onWarn: () => true }).signTransaction(base({ data }));
  assert.match(String(signed), /^0x02/);
});

test("unlimited approval to a plain wallet: the real provider blocks it and the key never signs", async () => {
  const fetch = realProvider((_tx, network) => ({ status: "ok", ...(network ? { network } : {}), outflows: [], inflows: [], approvals: [{ standard: "erc20", asset: USDC, spender: DRAINER, unlimited: true, spender_is_contract: false }], findings: ["approval_to_eoa", "unlimited_approval"] }));
  const account = privateKeyToAccount(generatePrivateKey());
  let raw = 0;
  const spy = { ...account, signTransaction: async (...args: Parameters<typeof account.signTransaction>) => (raw++, account.signTransaction(...args)) };
  const data = encodeFunctionData({ abi: erc20Abi, functionName: "approve", args: [DRAINER, maxUint256] });
  await assert.rejects(guardAccount(spy, { pinnedKeys: false, fetch, onWarn: () => true }).signTransaction(base({ data })), (err: unknown) => {
    assert.ok(err instanceof X402CheckBlockedError);
    assert.equal(err.verdict.action, "block", err.verdict.reasons.join("; "));
    return true;
  });
  assert.equal(raw, 0);
});

test("drainer contract that forwards the assets to a hidden wallet: blocked by the simulation", async () => {
  const fetch = realProvider((_tx, network) => ({ status: "ok", ...(network ? { network } : {}), outflows: [{ standard: "native", asset: "native", amount: "1000000000000000000", counterparty: HIDDEN, counterparty_is_contract: false }], inflows: [], approvals: [], findings: ["outflow_to_undisclosed_eoa"] }));
  const account = privateKeyToAccount(generatePrivateKey());
  const verdict = await createGuard({ pinnedKeys: false, fetch }).check({ kind: "transaction", from: account.address, transaction: base({ to: DRAINER, data: "0x3ccfd60b", value: 10n ** 18n }) });
  assert.equal(verdict.action, "block", verdict.reasons.join("; "));
});

test("x402 payment (EIP-3009): the real provider signs the payment binding the guard requires", async () => {
  const fetch = realProvider(() => ({ status: "ok" }));
  const account = privateKeyToAccount(generatePrivateKey());
  const verdict = await createGuard({ pinnedKeys: false, fetch }).check({
    kind: "typed_data",
    from: account.address,
    typedData: {
      domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: USDC },
      types: { TransferWithAuthorization: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] },
      primaryType: "TransferWithAuthorization",
      message: { from: account.address, to: BOB, value: 3500n, validAfter: 0n, validBefore: 2_000_000_000n, nonce: `0x${"01".repeat(32)}` },
    },
  });
  assert.notEqual(verdict.action, "not_verified", verdict.reasons.join("; "));
  assert.deepEqual(verdict.checks[0]?.request.payment, { network: "eip155:8453", pay_to: BOB, amount: "3500", asset: USDC });
});
