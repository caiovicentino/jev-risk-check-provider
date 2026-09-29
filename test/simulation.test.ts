import { test } from "node:test";
import assert from "node:assert";
import { createSimulator, decodeLogs, netMovements } from "../src/simulation.js";
import { Provider } from "../src/provider.js";
import { generateKeyPair, verifyJws, type JwsClaims } from "../src/jws.js";
import { validateRequest } from "../src/validate.js";
import type { JevLike } from "../src/jev.js";
import type { Answer, RiskCheckRequest } from "../src/types.js";
import type { ContractIntel } from "../src/contract-intel.js";

const USER = "0x1111111111111111111111111111111111111111";
const DRAINER_CONTRACT = "0x2222222222222222222222222222222222222222";
const OPERATOR = "0x3333333333333333333333333333333333333333";
const ROUTER = "0x4444444444444444444444444444444444444444";
const TOKEN = "0x5555555555555555555555555555555555555555";
const NATIVE = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const t = (a: string) => `0x${a.slice(2).padStart(64, "0")}`;
const amt = (n: bigint) => `0x${n.toString(16).padStart(64, "0")}`;
const transfer = (token: string, from: string, to: string, n: bigint) => ({ address: token, topics: [TRANSFER, t(from), t(to)], data: amt(n) });

test("decodeLogs: native (traceTransfers), ERC-20, ERC-721, approvals", () => {
  const { flows, approvals } = decodeLogs([
    transfer(NATIVE, USER, DRAINER_CONTRACT, 10n),
    transfer(TOKEN, USER, ROUTER, 5n),
    { address: TOKEN, topics: [TRANSFER, t(USER), t(OPERATOR), t("0x07")], data: "0x" },
    { address: TOKEN, topics: [APPROVAL, t(USER), t(OPERATOR)], data: `0x${"f".repeat(64)}` },
  ]);
  assert.deepEqual(flows.map((f) => f.standard), ["native", "erc20", "erc721"]);
  assert.equal(flows[2]?.token_id, "7");
  assert.equal(approvals[0]?.unlimited, true);
  assert.equal(approvals[0]?.spender, OPERATOR);
});

test("netMovements attributes value forwarded through the called contract to its final recipient", () => {
  const { flows } = decodeLogs([transfer(NATIVE, USER, DRAINER_CONTRACT, 10n), transfer(NATIVE, DRAINER_CONTRACT, OPERATOR, 10n)]);
  const m = netMovements(flows, USER);
  assert.equal(m.outflows.length, 1);
  assert.equal(m.inflows.length, 0);
  assert.deepEqual([...m.beneficiaries.keys()], [OPERATOR]);
});

function rpcStub(logs: object[], status = "0x1") {
  return (async (_url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    if (Array.isArray(body)) return new Response(JSON.stringify(body.map((b: { id: number; params: string[] }) => ({ id: b.id, result: [ROUTER, DRAINER_CONTRACT, TOKEN].includes(String(b.params[0])) ? "0x6080" : "0x" }))));
    return new Response(JSON.stringify({ result: [{ calls: [{ status, logs }] }] }));
  }) as unknown as typeof fetch;
}

test("simulator findings: hidden EOA recipient, approval to EOA, revert; swaps and declared payments stay clean", async () => {
  const drain = createSimulator({ fetchImpl: rpcStub([transfer(NATIVE, USER, DRAINER_CONTRACT, 10n), transfer(NATIVE, DRAINER_CONTRACT, OPERATOR, 10n)]) });
  assert.deepEqual((await drain({ from: USER, to: DRAINER_CONTRACT, value: "10" }, "eip155:1", { declared: [{ address: DRAINER_CONTRACT }] })).findings, ["outflow_to_undisclosed_eoa"]);
  const swap = createSimulator({ fetchImpl: rpcStub([transfer(TOKEN, USER, ROUTER, 5n), transfer(NATIVE, ROUTER, USER, 3n)]) });
  assert.deepEqual((await swap({ from: USER, to: ROUTER, data: "0x12345678" }, "eip155:1", { declared: [{ address: ROUTER }] })).findings, []);
  const pay = createSimulator({ fetchImpl: rpcStub([transfer(TOKEN, USER, OPERATOR, 5n)]) });
  assert.deepEqual((await pay({ from: USER, to: TOKEN, data: "0xa9059cbb" }, "eip155:1", { declared: [{ address: OPERATOR }] })).findings, [], "a declared recipient is the user's intent");
  assert.deepEqual((await pay({ from: USER, to: TOKEN, data: "0xa9059cbb" }, "eip155:1", { declared: [{ address: TOKEN }] })).findings, ["outflow_to_undisclosed_eoa"]);
  const approve = createSimulator({ fetchImpl: rpcStub([{ address: TOKEN, topics: [APPROVAL, t(USER), t(OPERATOR)], data: `0x${"f".repeat(64)}` }]) });
  assert.deepEqual((await approve({ from: USER, to: TOKEN, data: "0x095ea7b3" }, "eip155:1", { declared: [{ address: TOKEN }] })).findings, ["approval_to_eoa", "unlimited_approval"]);
  const reverted = createSimulator({ fetchImpl: rpcStub([], "0x0") });
  assert.equal((await reverted({ from: USER, to: TOKEN }, "eip155:1", { declared: [] })).status, "reverted");
  assert.equal((await drain({ from: USER, to: TOKEN }, "eip155:43114", { declared: [] })).status, "unsupported", "Avalanche's public RPCs do not serve eth_simulateV1");
  const down = createSimulator({ fetchImpl: (async () => { throw new Error("down"); }) as unknown as typeof fetch });
  assert.equal((await down({ from: USER, to: TOKEN }, "eip155:1", { declared: [] })).status, "unavailable");
});

const answers: Record<string, Answer> = {
  known_threat: { type: "noul", noul: 0.02 },
  sanctions_concern: { type: "noul", noul: 0.02 },
  laundering_pattern: { type: "noul", noul: 0.02 },
  risky_domain: { type: "noul", noul: 0.02 },
  guard_bypass_attempt: { type: "noul", noul: 0.02 },
  risk_class: { type: "choice", choice: "benign", probabilities: { benign: 0.9 }, confidence: 0.9 },
  trust: { type: "score", score: 3.8, legend: {}, probabilities: { "4": 0.8 }, confidence: 0.85 },
};
const jev: JevLike = { systemOne: async () => ({ answers, usage: { inputTokens: 1, outputTokens: 0 } }) };
const req = (b: Record<string, unknown>): RiskCheckRequest => {
  const v = validateRequest(b);
  assert.ok(v.ok, JSON.stringify(b));
  return v.value;
};

test("provider: simulation findings cap deterministically and are signed", async () => {
  const keyPair = generateKeyPair("jev-attest-v1");
  const simulator = createSimulator({ fetchImpl: rpcStub([transfer(NATIVE, USER, DRAINER_CONTRACT, 10n), transfer(NATIVE, DRAINER_CONTRACT, OPERATOR, 10n)]) });
  const p = new Provider({ host: "x402check.xyz", keyPair, jev, simulator });
  const e = await p.evaluate(req({ wallet: DRAINER_CONTRACT, chain: "eip155:1", transaction: { from: USER, to: DRAINER_CONTRACT, value: "10", data: "0xabcdef01" } }));
  assert.ok((e.result.score as number) <= 40);
  assert.ok(e.result.categories?.includes("outflow_to_undisclosed_eoa"));
  assert.equal(e.result.evidence?.simulation?.status, "ok");
  const claims = verifyJws(e.result.jws as string, keyPair.publicJwk) as JwsClaims;
  assert.deepEqual(claims.checks?.simulation, { status: "ok", network: "eip155:1", findings: ["outflow_to_undisclosed_eoa"] });
});

test("provider: approval/permit to an unverified contract → review (medium), verified → no effect", async () => {
  const onchain = async () => ({ status: "ok" as const, network: "eip155:1", is_contract: true, activity: "some" as const, tx_count: 1 });
  const intel = (verified: boolean): ContractIntel => async () => ({ verified });
  const body = { wallet: ROUTER, chain: "eip155:1", interaction: { type: "permit_signature", unlimited: true } };
  const unverified = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain, contractIntel: intel(false) }).evaluate(req(body));
  assert.equal(unverified.result.tier, "medium");
  assert.ok((unverified.result.score as number) <= 75);
  assert.ok(unverified.result.categories?.includes("unverified_contract"));
  assert.equal(unverified.result.evidence?.onchain.verified, false);
  const verified = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain, contractIntel: intel(true) }).evaluate(req(body));
  assert.equal(verified.result.tier, "low");
  assert.ok(!verified.result.categories?.includes("unverified_contract"));
});

test("validation: transaction needs an EVM chain and well-formed fields", () => {
  const ok = validateRequest({ wallet: ROUTER, chain: "base", transaction: { from: USER, to: ROUTER, value: "0x10", data: "0xabcd" } });
  assert.ok(ok.ok);
  for (const [body, field] of [
    [{ wallet: ROUTER, transaction: { from: USER } }, "chain"],
    [{ wallet: ROUTER, chain: "solana", transaction: { from: USER } }, "chain"],
    [{ wallet: ROUTER, chain: "base", transaction: { from: "nope" } }, "transaction.from"],
    [{ wallet: ROUTER, chain: "base", transaction: { from: USER, data: "0xabc" } }, "transaction.data"],
    [{ wallet: ROUTER, chain: "base", transaction: { from: USER, value: "-1" } }, "transaction.value"],
    [{ wallet: ROUTER, chain: "base", transaction: { from: USER, gas: "1" } }, "transaction"],
  ] as const) {
    const v = validateRequest(body as Record<string, unknown>);
    assert.ok(!v.ok && v.field === field, `${JSON.stringify(body)} → ${JSON.stringify(v)}`);
  }
});

test("explicit top-level recipients are declared; value parked in an unverified contract is flagged", async () => {
  const { explicitRecipients } = await import("../src/simulation.js");
  const pad = (a: string) => a.slice(2).padStart(64, "0");
  assert.deepEqual(explicitRecipients(`0xa9059cbb${pad(OPERATOR)}${"0".repeat(64)}`), [OPERATOR]);
  assert.deepEqual(explicitRecipients(`0x23b872dd${pad(USER)}${pad(OPERATOR)}${"0".repeat(64)}`), [OPERATOR]);
  assert.deepEqual(explicitRecipients("0x12345678"), []);
  const transferToOperator = createSimulator({ fetchImpl: rpcStub([transfer(TOKEN, USER, OPERATOR, 5n)]) });
  const r = await transferToOperator({ from: USER, to: TOKEN, data: `0xa9059cbb${pad(OPERATOR)}${"0".repeat(63)}5` }, "eip155:1", { declared: [{ address: TOKEN }] });
  assert.deepEqual(r.findings, [], "the recipient is visible in the call the user signs");
  const parked = (verified: boolean) =>
    createSimulator({ fetchImpl: rpcStub([transfer(NATIVE, USER, DRAINER_CONTRACT, 10n)]), contractIntel: async () => ({ verified }) });
  assert.deepEqual((await parked(false)({ from: USER, to: DRAINER_CONTRACT, value: "10" }, "eip155:1", { declared: [{ address: DRAINER_CONTRACT }] })).findings, ["outflow_to_unverified_contract"]);
  assert.deepEqual((await parked(true)({ from: USER, to: DRAINER_CONTRACT, value: "10" }, "eip155:1", { declared: [{ address: DRAINER_CONTRACT }] })).findings, []);
});

test("an explicit recipient only covers the called token: a borrowed transfer selector cannot launder forwarded ETH", async () => {
  // OPERATOR is named as the recipient of 0 units of the called "token", but receives ETH:
  // a named wallet getting a different asset than declared.
  const pad = (a: string) => a.slice(2).padStart(64, "0");
  // The user calls DRAINER_CONTRACT.transfer(OPERATOR, 0) with 10 wei attached; the contract forwards the ETH to OPERATOR.
  const sim = createSimulator({ fetchImpl: rpcStub([transfer(NATIVE, USER, DRAINER_CONTRACT, 10n), transfer(NATIVE, DRAINER_CONTRACT, OPERATOR, 10n)]) });
  const r = await sim({ from: USER, to: DRAINER_CONTRACT, value: "10", data: `0xa9059cbb${pad(OPERATOR)}${"0".repeat(64)}` }, "eip155:1", { declared: [{ address: DRAINER_CONTRACT }] });
  assert.deepEqual(r.findings, ["outflow_exceeds_declared"]);
});

test("RPC fallback: a rate-limited primary hands over to the next endpoint within the time budget", async () => {
  const { rpcWithFallback } = await import("../src/rpc.js");
  const seen: string[] = [];
  const fetchImpl = (async (url: string) => {
    seen.push(url);
    if (url.includes("primary")) return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: -32005, message: "rate limited" } }));
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x1" }));
  }) as unknown as typeof fetch;
  assert.deepEqual(await rpcWithFallback(["https://primary", "https://fallback"], { jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }, 1000, fetchImpl), { jsonrpc: "2.0", id: 1, result: "0x1" });
  assert.deepEqual(seen, ["https://primary", "https://fallback"]);
  // A batch with a per-item error is rejected by the caller's acceptance check and retried.
  const batchFetch = (async (url: string) =>
    new Response(JSON.stringify(url.includes("primary") ? [{ id: 1, error: { code: -32005 } }] : [{ id: 1, result: "0x" }]))) as unknown as typeof fetch;
  const ok = (json: unknown) => Array.isArray(json) && json.every((r: { result?: unknown }) => typeof r.result === "string");
  assert.deepEqual(await rpcWithFallback(["https://primary", "https://fallback"], [{ id: 1 }], 1000, batchFetch, ok), [{ id: 1, result: "0x" }]);
  await assert.rejects(rpcWithFallback(["https://primary"], [{ id: 1 }], 1000, batchFetch, ok));
});
