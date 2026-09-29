// Regressions for the independent adversarial review of v0.3 (2026-09-29): every
// finding it reproduced is pinned here.
import { test } from "node:test";
import assert from "node:assert";
import { createSimulator, decodeLogs, netMovements, MAX_PROBE } from "../src/simulation.js";
import { codeFacts } from "../src/code-fingerprint.js";
import { Provider, declaredScope } from "../src/provider.js";
import { createContractIntel } from "../src/contract-intel.js";
import { generateKeyPair } from "../src/jws.js";
import { validateRequest } from "../src/validate.js";
import { parseSubject } from "../src/address.js";
import type { JevLike } from "../src/jev.js";
import type { Answer, RiskCheckRequest } from "../src/types.js";

const USER = "0x1111111111111111111111111111111111111111";
const KIT = "0x2222222222222222222222222222222222222222";
const X = "0x3333333333333333333333333333333333333333";
const ROUTER = "0x4444444444444444444444444444444444444444";
const TOKEN = "0x5555555555555555555555555555555555555555";
const OTHER = "0x6666666666666666666666666666666666666666";
const NATIVE = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const TRANSFER_BATCH = "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb";
const t = (a: string) => `0x${a.slice(2).padStart(64, "0")}`;
const w = (n: bigint | number) => BigInt(n).toString(16).padStart(64, "0");
const transfer = (token: string, from: string, to: string, n: bigint) => ({ address: token, topics: [TRANSFER, t(from), t(to)], data: `0x${w(n)}` });
const LOGIC = `0x6080604052${"63aabbccdd14".repeat(20)}00`;

/** eth_simulateV1 answers `logs`; batches answer eth_getCode / eth_getStorageAt from the maps. */
function rpcStub(opts: { logs: object[]; status?: string; code?: Record<string, string>; storage?: Record<string, string>; failCode?: boolean }) {
  return (async (_url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    if (Array.isArray(body)) {
      return new Response(
        JSON.stringify(
          body.map((b: { id: number; method: string; params: string[] }) => {
            if (b.method === "eth_getCode") return opts.failCode ? { id: b.id, error: { code: -32005, message: "rate limited" } } : { id: b.id, result: opts.code?.[b.params[0] as string] ?? "0x" };
            if (b.method === "eth_getStorageAt") return { id: b.id, result: opts.storage?.[b.params[0] as string] ?? `0x${"0".repeat(64)}` };
            return { id: b.id, result: "0x0" };
          }),
        ),
      );
    }
    return new Response(JSON.stringify({ result: [{ calls: [{ status: opts.status ?? "0x1", logs: opts.logs }] }] }));
  }) as unknown as typeof fetch;
}

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
const valid = (b: Record<string, unknown>): RiskCheckRequest => {
  const v = validateRequest(b);
  assert.ok(v.ok, JSON.stringify(b));
  return v.value;
};
const onchainContract = async () => ({ status: "ok" as const, network: "eip155:1", is_contract: true, activity: "some" as const, tx_count: 1 });

test("R1: a named payee covers the declared asset and amount only; anything else is outflow_exceeds_declared", async () => {
  // transfer(X, 1) on TOKEN, but the simulated transaction moves 1e24 of OTHER to X.
  const logs = [transfer(OTHER, USER, X, 10n ** 24n)];
  const data = `0xa9059cbb${t(X).slice(2)}${w(1)}`;
  const req = valid({ wallet: X, chain: "eip155:1", payment: { pay_to: X, asset: TOKEN, amount: "1" }, interaction: { type: "token_transfer" }, transaction: { from: USER, to: TOKEN, data } });
  const p = new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain: onchainContract, simulator: createSimulator({ fetchImpl: rpcStub({ logs, code: { [TOKEN]: LOGIC } }) }) });
  const e = await p.evaluate(req);
  assert.ok(e.result.categories?.includes("outflow_exceeds_declared"), JSON.stringify(e.result.categories));
  assert.ok((e.result.score as number) <= 40);
  // The declared asset within the declared amount stays clean.
  const ok = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain: onchainContract, simulator: createSimulator({ fetchImpl: rpcStub({ logs: [transfer(TOKEN, USER, X, 1n)], code: { [TOKEN]: LOGIC } }) }) }).evaluate(req);
  assert.equal(ok.result.tier, "low");
});

test("R2: code lookups that fail, or recipients beyond the probe cap, make the simulation incomplete (review), never clear", async () => {
  const drain = [transfer(NATIVE, USER, KIT, 10n), transfer(NATIVE, KIT, X, 10n)];
  const failing = await createSimulator({ fetchImpl: rpcStub({ logs: drain, failCode: true }) })({ from: USER, to: KIT, value: "10" }, "eip155:1", { declared: [{ address: KIT }] });
  assert.ok(failing.findings?.includes("simulation_incomplete"));
  assert.deepEqual(failing.limits, ["unclassified"]);
  const p = new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain: onchainContract, simulator: createSimulator({ fetchImpl: rpcStub({ logs: drain, failCode: true }) }) });
  const e = await p.evaluate(valid({ wallet: KIT, chain: "eip155:1", transaction: { from: USER, to: KIT, value: "10" } }));
  assert.equal(e.result.tier, "medium");
  assert.ok((e.result.score as number) <= 75);
  // More recipients than the probe cap: the tail is unclassified, not assumed safe.
  const many = Array.from({ length: MAX_PROBE + 5 }, (_, i) => transfer(NATIVE, USER, `0x${(i + 1).toString(16).padStart(40, "a")}`, BigInt(100 - (i % 50))));
  const tail = await createSimulator({ fetchImpl: rpcStub({ logs: many }) })({ from: USER, to: ROUTER, value: "1" }, "eip155:1", { declared: [] });
  assert.ok(tail.findings?.includes("simulation_incomplete"));
});

test("R3: an undisclosed recipient reached through a source-verified forwarder (bridge, batch sender) is review, not a drain cap", async () => {
  const logs = [transfer(NATIVE, USER, ROUTER, 10n), transfer(NATIVE, ROUTER, X, 10n)];
  const sim = (verified: boolean) => createSimulator({ fetchImpl: rpcStub({ logs, code: { [ROUTER]: LOGIC } }), contractIntel: async () => ({ verified }) });
  const req = valid({ wallet: ROUTER, chain: "eip155:1", transaction: { from: USER, to: ROUTER, value: "10" } });
  const verified = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain: onchainContract, simulator: sim(true) }).evaluate(req);
  assert.equal(verified.result.evidence?.simulation?.forwarder_verified, true);
  assert.ok(verified.result.categories?.includes("outflow_to_undisclosed_eoa"));
  assert.equal(verified.result.tier, "medium");
  assert.ok((verified.result.score as number) > 40 && (verified.result.score as number) <= 75);
  const unverified = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain: onchainContract, simulator: sim(false) }).evaluate(req);
  assert.ok((unverified.result.score as number) <= 40);
});

test("R4: paying a contract payee (a Safe) is not an 'unverified sink'; a fresh Safe is judged by its singleton", async () => {
  const SAFE = OTHER;
  const SINGLETON = "0x29fcb43b46531bca003ddc8fcb67ffe91900c762";
  const safeCode = `0x608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa619486e${"0".repeat(56)}6000351415605057${"5b".repeat(60)}`;
  assert.equal(codeFacts(safeCode).proxy, "safe");
  const logs = [transfer(TOKEN, USER, SAFE, 1_000_000n)];
  const intel = async (a: string) => ({ verified: a.toLowerCase() === SINGLETON });
  const data = `0xa9059cbb${t(SAFE).slice(2)}${w(1_000_000)}`;
  const sim = createSimulator({ fetchImpl: rpcStub({ logs, code: { [SAFE]: safeCode, [TOKEN]: LOGIC }, storage: { [SAFE]: t(SINGLETON) } }), contractIntel: intel });
  const asPayee = await sim({ from: USER, to: TOKEN, data }, "eip155:8453", { declared: [{ address: SAFE, payee: true, asset: TOKEN, max: "1000000" }] });
  assert.deepEqual(asPayee.findings, []);
  // Not declared as payee, reached by a plain call: judged by the singleton (verified).
  const bare = await createSimulator({ fetchImpl: rpcStub({ logs: [transfer(NATIVE, USER, SAFE, 5n)], code: { [SAFE]: safeCode }, storage: { [SAFE]: t(SINGLETON) } }), contractIntel: intel })({ from: USER, to: SAFE, value: "5" }, "eip155:8453", { declared: [] });
  assert.ok(!bare.findings?.includes("outflow_to_unverified_contract"), JSON.stringify(bare));
});

test("R5: log decoding and net movements stay linear (no CPU amplification)", () => {
  const ids = Array.from({ length: 200 }, (_, i) => w(i)).join("");
  const vals = Array.from({ length: 200 }, () => w(1)).join("");
  const batchData = `0x${w(64)}${w(64 + 32 * 201)}${w(200)}${ids}${w(200)}${vals}`;
  const logs = Array.from({ length: 300 }, (_, i) => ({ address: `0x${(i + 1).toString(16).padStart(40, "0")}`, topics: [TRANSFER_BATCH, t(USER), t(USER), t(X)], data: batchData }));
  const started = Date.now();
  const { flows, truncated } = decodeLogs(logs);
  const m = netMovements(flows, USER);
  assert.ok(Date.now() - started < 1500, `took ${Date.now() - started} ms`);
  assert.equal(truncated, true, "the global flow cap applies");
  assert.ok(m.outflows.length > 0);
});

test("R6: CAIP-10 and checksummed payees name the same wallet as the lowercase form", () => {
  const subject = parseSubject(`eip155:8453:${X}`);
  assert.ok(subject);
  const req = valid({ wallet: `eip155:8453:${X}`, payment: { pay_to: `eip155:8453:${X}` } });
  assert.deepEqual(declaredScope(req, subject), [{ address: X, payee: true }]);
});

test("R8: drainer code behind a 7702 delegation or an EIP-1167 proxy is still recognized", async () => {
  const fp = codeFacts(LOGIC).fingerprint as string;
  const codeMatch = (f: string) => (f === fp ? ["scamsniffer-code"] : []);
  const minimal = `0x363d3d373d3d3d363d73${KIT.slice(2)}5af43d82803e903d91602b57fd5bf3`;
  const delegated = `0xef0100${KIT.slice(2)}`;
  for (const code of [minimal, delegated]) {
    const r = await createSimulator({ fetchImpl: rpcStub({ logs: [transfer(NATIVE, USER, X, 1n)], code: { [X]: code, [KIT]: LOGIC } }) })({ from: USER, to: X, value: "1" }, "eip155:1", { declared: [{ address: X }], codeMatch });
    assert.ok(r.findings?.includes("known_drainer_code"), `${code.slice(0, 12)} → ${JSON.stringify(r.findings)}`);
  }
});

test("R9: TransferBatch entries past the 64th are decoded", () => {
  const n = 65;
  const ids = Array.from({ length: n }, (_, i) => w(i)).join("");
  const vals = Array.from({ length: n }, (_, i) => w(i === n - 1 ? 7 : 0)).join("");
  const data = `0x${w(64)}${w(64 + 32 * (n + 1))}${w(n)}${ids}${w(n)}${vals}`;
  const { flows, truncated } = decodeLogs([{ address: TOKEN, topics: [TRANSFER_BATCH, t(USER), t(USER), t(X)], data }]);
  assert.equal(truncated, false);
  assert.equal(flows.at(-1)?.amount, 7n);
});

test("R10: 'not verified' is cached briefly; 'verified' for a day", async () => {
  let verified = false;
  let calls = 0;
  const fetchImpl = (async () => {
    calls++;
    return new Response(JSON.stringify({ is_contract: true, is_verified: verified }));
  }) as unknown as typeof fetch;
  const intel = createContractIntel({ fetchImpl });
  const realNow = Date.now;
  try {
    assert.equal((await intel(KIT, "eip155:1")).verified, false);
    verified = true;
    Date.now = () => realNow() + 11 * 60 * 1000;
    assert.equal((await intel(KIT, "eip155:1")).verified, true, "re-checked after 10 minutes");
    Date.now = () => realNow() + 60 * 60 * 1000;
    assert.equal((await intel(KIT, "eip155:1")).verified, true);
    assert.equal(calls, 2, "a verified answer is served from cache");
  } finally {
    Date.now = realNow;
  }
});

test("a swap through a router is not 'exceeds declared' when the subject is someone else", async () => {
  // User swaps 5 TOKEN for 3 wei ETH via ROUTER; the Snap's subject would be the router or a decoded recipient.
  const logs = [transfer(TOKEN, USER, ROUTER, 5n), transfer(NATIVE, ROUTER, USER, 3n)];
  const r = await createSimulator({ fetchImpl: rpcStub({ logs, code: { [ROUTER]: LOGIC } }) })({ from: USER, to: ROUTER, data: "0x12345678" }, "eip155:1", { declared: [{ address: X }] });
  assert.deepEqual(r.findings, []);
  // A payee paid more than declared, even through a router, is.
  const over = await createSimulator({ fetchImpl: rpcStub({ logs: [transfer(TOKEN, USER, ROUTER, 5n), transfer(TOKEN, ROUTER, X, 5n)], code: { [ROUTER]: LOGIC } }) })({ from: USER, to: ROUTER, data: "0x12345678" }, "eip155:1", { declared: [{ address: X, payee: true, asset: TOKEN, max: "1" }] });
  assert.deepEqual(over.findings, ["outflow_exceeds_declared"]);
});
