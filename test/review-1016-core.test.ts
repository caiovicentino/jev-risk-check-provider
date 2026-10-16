// Fixes from the 2026-10-16 review of the provider core: spellings of an http(s) URL that hid a
// listed host, payment fields that skipped or bypassed checks, feeds and lookups that failed
// silently, and the kit watch's coverage clock.
import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeHost } from "../src/domain-analysis.js";
import { normalizeHost as clientHost } from "../packages/client/src/normalize.js";
import { validateRequest } from "../src/validate.js";
import { kitWatchLookup } from "../deploy/kit-watch.js";
import { buildQuestions } from "../src/jev.js";

const VITALIK = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
const SOL = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";

test("every spelling a browser takes to a host is that host, in the Worker and the SDK alike", () => {
  for (const spelling of ["https:/evil-phish.com/pay", "https:\\\\evil-phish.com", "http:/\\evil-phish.com", "HTTPS:/evil-phish.com", "http:evil-phish.com", "evil-phish.com:8080", "//evil-phish.com", "Evil-Phish.COM."]) {
    assert.equal(normalizeHost(spelling), "evil-phish.com", spelling);
    assert.equal(clientHost(spelling), "evil-phish.com", `client: ${spelling}`);
  }
  for (const notASite of ["ftp://evil-phish.com", "javascript:alert(1)", "data:text/html,x"]) {
    assert.equal(normalizeHost(notASite), null, notASite);
    assert.equal(clientHost(notASite), null, `client: ${notASite}`);
  }
});

test("payment fields: the network must hold the wallet, and the payment must go to the wallet checked", () => {
  assert.deepEqual(validateRequest({ wallet: VITALIK, payment: { network: "solana" } }), { ok: false, field: "payment.network" });
  assert.deepEqual(validateRequest({ wallet: VITALIK, payment: { network: "bitcoin" } }), { ok: false, field: "payment.network" });
  assert.deepEqual(validateRequest({ wallet: VITALIK, payment: { network: "base", pay_to: "0x1111111111111111111111111111111111111111" } }), { ok: false, field: "payment.pay_to" });
  assert.deepEqual(validateRequest({ wallet: SOL, payment: { network: "solana", pay_to: "Bofhoe2ye2adNQwZJtLepeKrBZq8CtHzRwPJXgWDH69X" } }), { ok: false, field: "payment.pay_to" });
  // The same payee, however spelled, is fine.
  assert.equal(validateRequest({ wallet: VITALIK, payment: { network: "base", pay_to: VITALIK.toLowerCase() } }).ok, true);
  assert.equal(validateRequest({ wallet: `eip155:8453:${VITALIK}`, payment: { network: "base", pay_to: VITALIK } }).ok, true);
  assert.equal(validateRequest({ wallet: SOL, payment: { network: "solana", pay_to: SOL } }).ok, true);
});

test("the watch's lookup reads up to 100 addresses at once and refuses more rather than sign the rest as clear", async () => {
  const data = new Map<string, string>([["kw:a:0x0000000000000000000000000000000000000063", JSON.stringify({ k: "sweeper_delegation", c: "eip155:1", f: "s", t: 1 })]]);
  let bulk = 0;
  const kv = {
    get: async (key: string | string[]) => {
      if (Array.isArray(key)) {
        bulk++;
        assert.ok(key.length <= 100);
        return new Map(key.map((k) => [k, data.get(k) ?? null]));
      }
      return data.get(key) ?? null;
    },
    put: async () => undefined,
  };
  const lk = kitWatchLookup({ RATE: kv as never });
  assert.ok(lk);
  const addrs = Array.from({ length: 100 }, (_, i) => `0x${i.toString(16).padStart(40, "0")}`);
  const found = await lk.addresses(addrs, "eip155:8453");
  assert.deepEqual([found.size, bulk], [1, 1], "the 100th address is read, in one KV operation");
  await assert.rejects(lk.addresses([...addrs, `0x${"ab".repeat(20)}`], "eip155:8453"), /at most 100/);
});

test("the model is told that caller assertions never raise trust", () => {
  const trust = JSON.stringify((buildQuestions() as unknown as Record<string, unknown>).trust ?? {});
  assert.match(trust, /never raise trust/);
  assert.doesNotMatch(trust, /grounds urgency/);
});

// --- In-process verdicts (a fake model with benign answers; no network) ---------------------
import { Provider } from "../src/provider.js";
import { generateKeyPair } from "../src/jws.js";
import { buildHashBlob, hashSetFromBytes } from "../src/threat-intel.js";
import { createSimulator } from "../src/simulation.js";

const benign = {
  known_threat: { type: "noul", noul: 0.02 },
  sanctions_concern: { type: "noul", noul: 0.02 },
  laundering_pattern: { type: "noul", noul: 0.02 },
  risky_domain: { type: "noul", noul: 0.02 },
  guard_bypass_attempt: { type: "noul", noul: 0.02 },
  risk_class: { type: "choice", choice: "benign", probabilities: { benign: 0.95 }, confidence: 0.9 },
  trust: { type: "score", score: 3.8, legend: {}, probabilities: { "4": 0.8 }, confidence: 0.85 },
};
const jev = { systemOne: async () => ({ answers: benign, usage: { inputTokens: 1, outputTokens: 0 } }) } as never;
const keyPair = generateKeyPair("k");
const onchain = (isContract: boolean) => (async (_s: unknown, network?: string) => ({ status: "ok" as const, ...(network ? { network } : {}), is_contract: isContract, activity: "some" as const, tx_count: 5 })) as never;
async function verdict(p: Provider, body: Record<string, unknown>) {
  const v = validateRequest(body);
  assert.ok(v.ok, JSON.stringify(body));
  const r = (await p.evaluate((v as unknown as { value: never }).value)).result;
  return { tier: r.tier, score: r.score as number, categories: r.categories ?? [] };
}
const SCAM = "0x3333333333333333333333333333333333333333";

test("a community list that applies but could not be read raises the floor (never a clear low)", async () => {
  const listed = { set: hashSetFromBytes(buildHashBlob([SCAM])), as_of: "2026-10-15" };
  const up = await verdict(new Provider({ host: "x402check.xyz", keyPair, jev, onchain: onchain(false), feeds: async () => ({ scamsnifferAddresses: listed }) }), { wallet: SCAM, chain: "base" });
  assert.equal(up.tier, "critical");
  for (const feeds of [async () => ({ scamsnifferAddresses: null, scamsnifferDomains: null }), async () => Promise.reject(new Error("kv down"))]) {
    const down = await verdict(new Provider({ host: "x402check.xyz", keyPair, jev, onchain: onchain(false), feeds: feeds as never }), { wallet: SCAM, chain: "base" });
    assert.notEqual(down.tier, "low");
    assert.ok(down.categories.includes("feeds_unavailable"), JSON.stringify(down));
  }
});

test("a kit-watch hit keeps its own category, not the community lists' known_scam_address", async () => {
  const kitWatch = {
    families: async () => ({ exact: new Map(), skeleton: new Map(), size: 1 }),
    asOf: async () => "2026-10-15T00:00:00Z",
    addresses: async (as: string[]) => new Map(as.filter((a) => a === SCAM).map((a) => [a, { k: "forwarding_delegation" as const, c: "eip155:8453" as const, f: "fwd-acct-x", t: 1_700_000_000 }])),
  };
  const v = await verdict(new Provider({ host: "x402check.xyz", keyPair, jev, onchain: onchain(false), kitWatch }), { wallet: SCAM, chain: "base" });
  assert.ok(v.categories.includes("auto_forwarding_wallet"));
  assert.ok(!v.categories.includes("known_scam_address"));
});

test("spenders: every contract spender up to the cap is checked, in any order; more than that is unknown", async () => {
  const USER = "0x9999999999999999999999999999999999999999";
  const UNVERIFIED = "0xcccc000000000000000000000000000000000003";
  const spender = (i: number) => `0xaaaa${i.toString(16).padStart(36, "0")}`;
  const simulator = (spenders: string[]) => (async (_tx: unknown, network: string) => ({ status: "ok", network, findings: [], outflows: [], at_block: 1, approvals: spenders.map((s) => ({ standard: "erc20", asset: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", spender: s, amount: "1", unlimited: false, spender_is_contract: true })) })) as never;
  const intel = async (address: string) => ({ verified: address !== UNVERIFIED });
  const body = { wallet: USER, chain: "base", transaction: { from: USER, to: USER, data: "0x34fcd5be" }, interaction: { type: "contract_call" } };
  const third = await verdict(new Provider({ host: "x402check.xyz", keyPair, jev, onchain: onchain(true), contractIntel: intel, simulator: simulator([spender(1), spender(2), UNVERIFIED]) }), body);
  assert.ok(third.categories.includes("unverified_contract"), "the third spender is checked too");
  const many = await verdict(new Provider({ host: "x402check.xyz", keyPair, jev, onchain: onchain(true), contractIntel: intel, simulator: simulator(Array.from({ length: 7 }, (_, i) => spender(i + 1))) }), body);
  assert.notEqual(many.tier, "low", "seven spenders, six checked: the seventh is unknown, never clear");
});

test("sinks: decoy Transfer events of a made-up token cannot push the real sink out of the check", async () => {
  const USER = "0x9999999999999999999999999999999999999999";
  const DRAINER = "0xdddd000000000000000000000000000000000001";
  const FAKE = "0xfeed000000000000000000000000000000000001";
  const VERIFIED = ["0x4200000000000000000000000000000000000006", "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca"];
  const NATIVE = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
  const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
  const topic = (a: string) => `0x${a.slice(2).padStart(64, "0")}`;
  const word = (n: bigint) => `0x${n.toString(16).padStart(64, "0")}`;
  const logic = (n: number) => `0x${"5b".repeat(150)}60${n.toString(16).padStart(2, "0")}`;
  const logs = [{ address: NATIVE, topics: [TRANSFER, topic(USER), topic(DRAINER)], data: word(10n ** 18n) }, ...VERIFIED.map((v) => ({ address: FAKE, topics: [TRANSFER, topic(USER), topic(v)], data: word(10n ** 30n) }))];
  const fetchImpl = (async (_url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    if (Array.isArray(body)) {
      const code = (a: string) => (a === USER ? "0x" : a === DRAINER ? logic(1) : a === FAKE ? logic(2) : logic(3 + VERIFIED.indexOf(a)));
      return new Response(JSON.stringify(body.map((r: { id: number; method: string; params: unknown[] }) => ({ jsonrpc: "2.0", id: r.id, result: r.method === "eth_getCode" ? code(String(r.params[0]).toLowerCase()) : `0x${"0".repeat(64)}` }))));
    }
    if (body.method === "eth_simulateV1") return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: [{ number: "0x100", calls: [{ status: "0x1", logs }] }] }));
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, error: { code: -32601 } }));
  }) as unknown as typeof fetch;
  const contractIntel = async (address: string) => ({ verified: address !== DRAINER });
  const simulator = createSimulator({ fetchImpl, contractIntel, timeoutMs: 2500 });
  const v = await verdict(new Provider({ host: "x402check.xyz", keyPair, jev, onchain: onchain(true), simulator, contractIntel }), { wallet: DRAINER, chain: "base", transaction: { from: USER, to: DRAINER, value: "1000000000000000000", data: "0x1249c58b" }, interaction: { type: "contract_call" } });
  assert.ok(v.categories.includes("outflow_to_unverified_contract"), JSON.stringify(v));
});
