// Freshness anchors (provider 0.6.1): each signed evidence item carries the anchor of its kind.
// The OFAC screen states the SDN.XML digest it ran against, the kit watch its coverage clock
// (the last block each chain's scan completed), and a simulation the block whose state it ran on.
import { test } from "node:test";
import assert from "node:assert";
import { Provider } from "../src/provider.js";
import { generateKeyPair } from "../src/jws.js";
import { validateRequest } from "../src/validate.js";
import { parseSubject } from "../src/address.js";
import { screenSubject, sanctionsListMeta } from "../src/sanctions.js";
import { OFAC_SDN_META } from "../src/data/ofac-sdn.js";
import { createSimulator } from "../src/simulation.js";
import { coverageOf } from "../deploy/kit-watch.js";
import type { JevLike } from "../src/jev.js";
import type { KitWatchLookup } from "../src/kit-watch.js";
import type { Answer, RiskCheckRequest } from "../src/types.js";

const answers: Record<string, Answer> = {
  known_threat: { type: "noul", noul: 0.02 },
  sanctions_concern: { type: "noul", noul: 0.02 },
  laundering_pattern: { type: "noul", noul: 0.02 },
  risky_domain: { type: "noul", noul: 0.02 },
  guard_bypass_attempt: { type: "noul", noul: 0.02 },
  risk_class: { type: "choice", choice: "benign", probabilities: { benign: 0.95 }, confidence: 0.9 },
  trust: { type: "score", score: 3.8, legend: {}, probabilities: { "4": 0.8 }, confidence: 0.85 },
};
const jev: JevLike = { systemOne: async () => ({ answers, usage: { inputTokens: 1, outputTokens: 0 } }) };
const USER = "0x1111111111111111111111111111111111111111";
const ROUTER = "0x4444444444444444444444444444444444444444";
const valid = (b: Record<string, unknown>): RiskCheckRequest => {
  const v = validateRequest(b);
  if (!v.ok) throw new Error(`invalid: ${v.field}`);
  return v.value;
};
type Checks = { sanctions: Record<string, unknown>; simulation?: Record<string, unknown>; kit_watch?: Record<string, unknown> };
const signedChecks = (jws: string | undefined): Checks => (JSON.parse(Buffer.from((jws as string).split(".")[1] as string, "base64url").toString()) as { checks: Checks }).checks;

test("the OFAC screen states the SDN.XML digest it ran against, in the evidence and in the signature", async () => {
  const digest = `sha256:${OFAC_SDN_META.sha256}`;
  assert.match(digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(sanctionsListMeta().digest, digest);
  assert.equal(screenSubject(parseSubject(USER)!).digest, digest);
  const { result } = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev }).evaluate(valid({ wallet: USER, chain: "base" }));
  assert.ok(result.checked);
  assert.equal(result.evidence?.sanctions.digest, digest);
  assert.equal(signedChecks(result.jws).sanctions.digest, digest);
});

function kitWatch(coverage?: KitWatchLookup["coverage"]): KitWatchLookup {
  return {
    families: async () => ({ exact: new Map(), skeleton: new Map() }) as never,
    addresses: async () => new Map(),
    asOf: async () => "2026-10-01T12:00:00.000Z",
    ...(coverage ? { coverage } : {}),
  };
}
const onchain = async () => ({ status: "ok" as const, network: "eip155:8453", is_contract: false, activity: "some" as const, tx_count: 3 });

test("the kit watch signs its coverage clock for the chain it consulted, only when it ran and only when known", async () => {
  const covered = kitWatch(async () => ({ complete_through: { "eip155:1": 23500000, "eip155:8453": 36000005 }, gaps: { "eip155:1": 1 } }));
  const base = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain, kitWatch: covered }).evaluate(valid({ wallet: USER, chain: "base" }));
  assert.ok(base.result.checked);
  assert.deepEqual(base.result.evidence?.kit_watch?.complete_through, { "eip155:8453": 36000005 }, "the chain consulted, not every chain");
  assert.equal(base.result.evidence?.kit_watch?.gaps, undefined, "no gap on Base");
  assert.deepEqual(signedChecks(base.result.jws).kit_watch, { as_of: "2026-10-01T12:00:00.000Z", status: "clear", complete_through: { "eip155:8453": 36000005 } });

  // An EOA with no chain: the watch is consulted on every chain, and states each chain's clock and gaps.
  const anyChain = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, kitWatch: covered }).evaluate(valid({ wallet: USER }));
  assert.deepEqual(signedChecks(anyChain.result.jws).kit_watch?.complete_through, { "eip155:1": 23500000, "eip155:8453": 36000005 });
  assert.deepEqual(signedChecks(anyChain.result.jws).kit_watch?.gaps, { "eip155:1": 1 });

  const unknown = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain, kitWatch: kitWatch() }).evaluate(valid({ wallet: USER, chain: "base" }));
  assert.deepEqual(signedChecks(unknown.result.jws).kit_watch, { as_of: "2026-10-01T12:00:00.000Z", status: "clear" }, "no coverage clock when the lookup has none");
  const failing = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain, kitWatch: kitWatch(async () => Promise.reject(new Error("kv down"))) }).evaluate(valid({ wallet: USER, chain: "base" }));
  assert.equal(signedChecks(failing.result.jws).kit_watch?.complete_through, undefined, "a failed read is omitted, never guessed");

  const none = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain }).evaluate(valid({ wallet: USER, chain: "base" }));
  assert.equal(signedChecks(none.result.jws).kit_watch, undefined, "no kit watch, no kit_watch claim");
});

test("coverageOf reads the cron's cursor per chain, with the recorded gaps", () => {
  const chain = (cursor: number, gaps = 0) => ({ cursor, head: cursor + 2, last_run: "", scanned_blocks: 1, flagged: {}, delegates: 0, gaps: Array.from({ length: gaps }, (_, i) => ({ from: i, to: i + 1, at: "" })) });
  assert.deepEqual(coverageOf({ updated_at: "", chains: { "eip155:1": chain(23500000, 2), "eip155:8453": chain(36000005) } }), { complete_through: { "eip155:1": 23500000, "eip155:8453": 36000005 }, gaps: { "eip155:1": 2 } });
  assert.deepEqual(coverageOf({ updated_at: "", chains: { "eip155:1": chain(0) } }), { complete_through: {} }, "a chain that never completed a run has no clock");
});

test("the coverage clock states the reads still queued and every hole, uncapped (provider 0.6.2)", async () => {
  const queued = kitWatch(async () => ({ complete_through: { "eip155:1": 23500000, "eip155:8453": 36000005 }, gaps: { "eip155:1": 37 }, pending: { "eip155:8453": 4 } }));
  const base = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain, kitWatch: queued }).evaluate(valid({ wallet: USER, chain: "base" }));
  assert.deepEqual(signedChecks(base.result.jws).kit_watch, { as_of: "2026-10-01T12:00:00.000Z", status: "clear", complete_through: { "eip155:8453": 36000005 }, pending: { "eip155:8453": 4 } }, "coverage through the clock is not claimed whole while reads wait");
  assert.deepEqual(base.result.evidence?.kit_watch?.pending, { "eip155:8453": 4 });
  const anyChain = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, kitWatch: queued }).evaluate(valid({ wallet: USER }));
  assert.deepEqual([signedChecks(anyChain.result.jws).kit_watch?.gaps, signedChecks(anyChain.result.jws).kit_watch?.pending], [{ "eip155:1": 37 }, { "eip155:8453": 4 }]);
  // The stats keep the last 10 skipped ranges; the signed count is every hole recorded.
  const ranges = Array.from({ length: 10 }, (_, i) => ({ from: i, to: i + 1, at: "" }));
  const eth = { cursor: 23500000, head: 23500002, last_run: "", scanned_blocks: 1, flagged: {}, delegates: 0, gaps: ranges, gaps_total: 37, pending: 3 };
  assert.deepEqual(coverageOf({ updated_at: "", chains: { "eip155:1": eth } }), { complete_through: { "eip155:1": 23500000 }, gaps: { "eip155:1": 37 }, pending: { "eip155:1": 3 } });
});

/** eth_simulateV1 stub: the simulated block carries `number` (or not), and moves nothing. */
function rpc(number?: string): typeof fetch {
  return (async (_url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body)) as { id: number; params: string[] } | Array<{ id: number; params: string[] }>;
    if (Array.isArray(body)) return new Response(JSON.stringify(body.map((b) => ({ id: b.id, result: b.params[0] === ROUTER ? "0x6080" : "0x" }))));
    return new Response(JSON.stringify({ result: [{ ...(number ? { number } : {}), calls: [{ status: "0x1", logs: [] }] }] }));
  }) as unknown as typeof fetch;
}

test("a simulation states the block whose state it ran on; nothing when the RPC does not say", async () => {
  const tx = { from: USER, to: ROUTER, value: "0x0", data: "0x" };
  const at = await createSimulator({ fetchImpl: rpc("0x2255a40") })(tx, "eip155:8453", { declared: [{ address: ROUTER }] });
  assert.equal(at.status, "ok");
  assert.equal(at.at_block, 0x2255a40 - 1);
  const unknown = await createSimulator({ fetchImpl: rpc() })(tx, "eip155:8453", { declared: [{ address: ROUTER }] });
  assert.equal(unknown.at_block, undefined);

  const { result } = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, simulator: createSimulator({ fetchImpl: rpc("0x2255a40") }) }).evaluate(valid({ wallet: ROUTER, chain: "base", transaction: tx }));
  assert.ok(result.checked);
  assert.equal(signedChecks(result.jws).simulation?.at_block, 0x2255a40 - 1);
});
