// Kit watch (src/kit-watch.ts, deploy/kit-watch.ts): block activity, forwarding probes,
// family matching by exact and template fingerprint, the cron's KV bookkeeping, and
// how the provider turns what the watch knows into caps, categories and evidence.
import { test } from "node:test";
import assert from "node:assert";
import { privateKeyToAccount } from "viem/accounts";
import { codeFacts } from "../src/code-fingerprint.js";
import { blockActivity, indexFamilies, kindForCode, mergeEntries, probeForwarding, runningFamily, scanBlocks, type DelegateVerdict, type Family, type KitWatchLookup, type RawAuthorization, type RawBlock, type SimulateCall, type WatchEntry } from "../src/kit-watch.js";
import { Provider } from "../src/provider.js";
import { generateKeyPair, verifyJws, type JwsClaims } from "../src/jws.js";
import { validateRequest } from "../src/validate.js";
import type { JevLike } from "../src/jev.js";
import type { Answer, RiskCheckRequest } from "../src/types.js";
import { KW, kitWatchLookup, runKitWatch } from "../deploy/kit-watch.js";
import type { KVNamespace, WorkerEnv } from "../deploy/runtime.js";

const hex20 = (n: number) => n.toString(16).padStart(40, "0");
const body = "63aabbccdd14".repeat(20);
/** Logic code with one PUSH20 (a hard-coded address) and one PUSH32 (an immutable). */
const kitCode = (addr: number, immutable: number, tail = "00") => `0x6080604052` + `73${hex20(addr)}50` + `7f${immutable.toString(16).padStart(64, "0")}50` + body + tail;
const NATIVE = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const topic = (a: string) => `0x${a.slice(2).padStart(64, "0")}`;

test("template fingerprints ignore immutables and hard-coded addresses, not the logic", () => {
  const a = codeFacts(kitCode(1, 7));
  const b = codeFacts(kitCode(2, 9));
  const c = codeFacts(kitCode(1, 7, "0000"));
  assert.equal(a.kind, "logic");
  assert.notEqual(a.fingerprint, b.fingerprint);
  assert.equal(a.skeleton, b.skeleton);
  assert.notEqual(a.skeleton, c.skeleton);
});

const signer = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const signer2 = privateKeyToAccount("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");
const signer3 = privateKeyToAccount("0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6");
async function auth(account: typeof signer, delegate: string, chainId: number, nonce = 0): Promise<RawAuthorization> {
  const a = await account.signAuthorization({ address: delegate as `0x${string}`, chainId, nonce });
  return { chainId: `0x${chainId.toString(16)}`, address: delegate, nonce: `0x${nonce.toString(16)}`, yParity: `0x${(a.yParity ?? 0).toString(16)}`, r: a.r, s: a.s };
}

test("block activity: CREATE addresses from sender and nonce; authorizations valid for this chain only", async () => {
  const P = `0x${hex20(0xaa)}`;
  const block: RawBlock = {
    number: "0x10",
    timestamp: "0x64",
    transactions: [
      // The classic example: 0x6ac7…dbf0 at nonce 0 creates 0xcd23…cd8d.
      { hash: "0x01", from: "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", to: null, nonce: "0x0" },
      { hash: "0x02", from: "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", to: P, nonce: "0x1", type: "0x4", authorizationList: [await auth(signer, P, 1), await auth(signer, P, 0), await auth(signer, P, 8453)] },
    ],
  };
  const act = blockActivity(block, "eip155:1");
  assert.deepEqual(act.creations.map((c) => c.address), ["0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d"]);
  assert.equal(act.authorizations.length, 2); // chain 1 and chain 0 (any), not Base's
  assert.equal(blockActivity(block, "eip155:8453").authorizations.length, 2);
});

function simulating(onward: Record<string, Array<{ to: string; value: bigint }>>, status = "0x1"): SimulateCall {
  return async (c) => ({
    status,
    logs: [
      { address: NATIVE, topics: [TRANSFER, topic(c.from), topic(c.to)], data: `0x${BigInt(c.value).toString(16)}` },
      ...(onward[c.to] ?? []).map((m) => ({ address: NATIVE, topics: [TRANSFER, topic(c.to), topic(m.to)], data: `0x${m.value.toString(16)}` })),
    ],
  });
}

test("forwarding probe: most of the value passed on is a forwarder; a revert or a keeper is not", async () => {
  const A = `0x${hex20(0xa1)}`;
  const D = `0x${hex20(0xd1)}`;
  assert.deepEqual(await probeForwarding(simulating({ [A]: [{ to: D, value: 10n ** 16n }] }), A), { forwards: true, destinations: [D] });
  assert.equal((await probeForwarding(simulating({ [A]: [{ to: D, value: 10n ** 15n }] }), A))?.forwards, false);
  assert.equal((await probeForwarding(simulating({}, "0x0"), A))?.forwards, false);
  assert.equal(await probeForwarding(async () => null, A), null);
});

const POISONER = kitCode(0x50, 1);
const DRAINER = kitCode(0x60, 2, "0000");
const SWEEPER_CODE = kitCode(0x70, 3, "000000");
const WALLET = kitCode(0x80, 4, "00000000");
const fam = (id: string, cls: Family["class"], code: string, template: boolean): Family => {
  const f = codeFacts(code);
  return { id, class: cls, exact: [f.fingerprint as string], skeleton: template ? [f.skeleton as string] : [], sources: ["test"] };
};

test("scan: poisoner and sweeper delegations, a learned forwarder, a kit deployment by template, never a guarded implementation", async () => {
  const dPoison = `0x${hex20(0xd0)}`; // an existing poisoner deployment
  const dForward = `0x${hex20(0xd2)}`; // unknown code that forwards
  const dWallet = `0x${hex20(0xd3)}`; // a wallet: keeps what it receives
  const dTiny = `0x${hex20(0xd4)}`; // a forwarder too small to fingerprint
  const dest = `0x${hex20(0xde)}`;
  const deployer = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0";
  const kitAddress = "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d";
  const newPoisoner = "0x343c43a37d37dff08ae8c4a11544c718abb4fcf8"; // CREATE by deployer at nonce 1
  const families = indexFamilies({ updated_at: "", families: [fam("poisoner-x", "poisoner", kitCode(0x51, 99), true), fam("kit-y", "drainer_kit", kitCode(0x61, 98, "0000"), true), fam("guarded-z", "drainer_kit", WALLET, false)] });
  const code: Record<string, string> = {
    [dPoison]: POISONER,
    [dForward]: `0x6080604052${"63aabbccdd15".repeat(20)}00`,
    [dWallet]: WALLET,
    [kitAddress]: DRAINER,
    [newPoisoner]: kitCode(0x52, 5),
    [signer.address.toLowerCase()]: `0xef0100${dForward.slice(2)}`,
    [signer2.address.toLowerCase()]: `0xef0100${dWallet.slice(2)}`,
    [dTiny]: "0x3615600b57005b",
    [signer3.address.toLowerCase()]: `0xef0100${dTiny.slice(2)}`,
  };
  const call = async (reqs: Array<{ method: string; params: unknown[] }>) => reqs.map((r) => (r.method === "eth_getCode" ? (code[r.params[0] as string] ?? "0x") : undefined));
  const block: RawBlock = {
    number: "0x20",
    timestamp: "0x6400",
    transactions: [
      { hash: "0xc1", from: deployer, to: null, nonce: "0x0" },
      { hash: "0xc2", from: deployer, to: null, nonce: "0x1" },
      { hash: "0xa1", from: deployer, to: dPoison, nonce: "0x2", type: "0x4", authorizationList: [await auth(signer, dPoison, 1)] },
      { hash: "0xa2", from: deployer, to: dForward, nonce: "0x3", type: "0x4", authorizationList: [await auth(signer, dForward, 1, 1)] },
      { hash: "0xa3", from: deployer, to: dWallet, nonce: "0x4", type: "0x4", authorizationList: [await auth(signer2, dWallet, 1)] },
      { hash: "0xa4", from: deployer, to: dTiny, nonce: "0x5", type: "0x4", authorizationList: [await auth(signer3, dTiny, 1)] },
    ],
  };
  const delegates = new Map<string, DelegateVerdict>();
  const guarded = new Set([codeFacts(WALLET).fingerprint as string]);
  const res = await scanBlocks([block], { chain: "eip155:1", call, simulate: simulating({ [signer.address.toLowerCase()]: [{ to: dest, value: 10n ** 16n }], [signer3.address.toLowerCase()]: [{ to: dest, value: 10n ** 16n }] }), families, delegates, guarded, now: () => 1_000_000 });
  const merged = mergeEntries(res.entries);
  const me = signer.address.toLowerCase();
  // The same key authorized a poisoner, then a forwarder: only the delegation in effect (the forwarder) counts.
  assert.equal(merged.get(me)?.k, "forwarding_delegation");
  assert.equal(merged.has(dest), false, "a forwarder's destinations are chosen by its author: never recorded");
  assert.equal(merged.has(dPoison), false);
  assert.equal(merged.get(kitAddress)?.k, "drainer_kit_contract"); // by template
  assert.equal(merged.get(deployer)?.k, "drainer_kit_deployer");
  assert.equal(merged.has(signer2.address.toLowerCase()), false); // a wallet that keeps its ETH
  assert.equal(res.learned.length, 1); // the tiny forwarder has no code to learn: its address is the family
  assert.equal(res.learned[0]?.class, "forwarder");
  assert.equal(delegates.get(dForward)?.class, "forwarder");
  assert.equal(delegates.get(dTiny)?.family, `fwd-at-${dTiny.slice(2, 14)}`);
  assert.equal(merged.get(signer3.address.toLowerCase())?.k, "forwarding_delegation");
  assert.equal(delegates.get(dWallet)?.class, "not_forwarding");
  // A new poisoner deployment is classified before anyone delegates to it.
  assert.equal(delegates.get(newPoisoner)?.class, "poisoner");
  assert.equal(merged.get(me)?.t, 0x6400); // block time, not scan time
  assert.equal(delegates.get(dForward)?.code_kind, "logic");
});

test("code families: what running them makes an address", () => {
  const index = indexFamilies({ updated_at: "", families: [fam("p", "poisoner", POISONER, true), fam("f", "forwarder", SWEEPER_CODE, false), fam("k", "drainer_kit", DRAINER, true)] });
  const delegated = (code: string) => {
    const f = codeFacts(code);
    return { kind: "delegated" as const, bytes: 23, delegate: "0x01", implementation_fingerprint: f.fingerprint as string, implementation_skeleton: f.skeleton as string };
  };
  assert.equal(kindForCode(runningFamily(index, delegated(kitCode(0x51, 77))) as Family, { kind: "delegated" }), "poisoner_delegation");
  assert.equal(kindForCode(runningFamily(index, delegated(SWEEPER_CODE)) as Family, { kind: "delegated" }), "forwarding_delegation");
  assert.equal(kindForCode(runningFamily(index, codeFacts(kitCode(0x61, 55, "0000"))) as Family, { kind: "logic" }), "drainer_kit_contract");
  assert.equal(kindForCode(runningFamily(index, codeFacts(SWEEPER_CODE)) as Family, { kind: "logic" }), null);
});

// --- provider ---------------------------------------------------------------------

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
const PAYEE = "0x7777777777777777777777777777777777777777";
const eoa = async () => ({ status: "ok" as const, network: "eip155:8453", is_contract: false, activity: "some" as const, tx_count: 4 });

function lookup(entries: Record<string, WatchEntry>, families: Family[] = [], fail = false): KitWatchLookup {
  return {
    families: async () => indexFamilies({ updated_at: "", families }),
    asOf: async () => "2026-09-29T20:00:00.000Z",
    addresses: async (addresses) => {
      if (fail) throw new Error("kv down");
      return new Map(addresses.filter((a) => entries[a]).map((a) => [a, entries[a] as WatchEntry]));
    },
  };
}

test("provider: a watched look-alike caps at 20 (address_poisoning), signed in checks.feeds with the scan time", async () => {
  const keyPair = generateKeyPair("k");
  const kitWatch = lookup({ [PAYEE]: { k: "poisoner_delegation", c: "eip155:1", f: "poisoner-x", t: 1_790_000_000, b: 1, x: "0xab", d: "0x01" } });
  // Observed on Ethereum, evaluated on Base: the same key controls the address.
  const e = await new Provider({ host: "x402check.xyz", keyPair, jev, onchain: eoa, kitWatch }).evaluate(valid({ wallet: PAYEE, chain: "eip155:8453" }));
  assert.ok((e.result.score as number) <= 20, String(e.result.score));
  assert.ok(e.result.categories?.includes("address_poisoning"));
  assert.equal(e.result.evidence?.kit_watch?.status, "hit");
  assert.equal(e.result.evidence?.kit_watch?.hits?.[0]?.via, "watchlist");
  const claims = verifyJws(e.result.jws as string, keyPair.publicJwk) as JwsClaims;
  assert.ok(claims.checks?.feeds?.includes("x402check-kit-watch@2026-09-29T20:00:00.000Z:hit"), JSON.stringify(claims.checks?.feeds));
});

test("provider: a wallet delegated to a sweeper family is caught by its code even if the scan never saw it", async () => {
  const sweeper = fam("sweeper-s", "sweeper", SWEEPER_CODE, false);
  const f = codeFacts(SWEEPER_CODE);
  const onchain = async () => ({ ...(await eoa()), code: { kind: "delegated" as const, bytes: 23, delegate: "0x02", implementation_fingerprint: f.fingerprint as string, implementation_skeleton: f.skeleton as string } });
  const e = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain, kitWatch: lookup({}, [sweeper]) }).evaluate(valid({ wallet: PAYEE, chain: "eip155:8453" }));
  assert.ok((e.result.score as number) <= 20);
  assert.ok(e.result.categories?.includes("compromised_wallet"));
  assert.deepEqual(e.result.evidence?.kit_watch?.hits?.map((h) => [h.kind, h.via]), [["sweeper_delegation", "code"]]);
  // A behaviour-learned forwarder reads like an undisclosed recipient (40), not a listed scam.
  const fwd = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain, kitWatch: lookup({}, [{ ...sweeper, class: "forwarder", id: "fwd-s" }]) }).evaluate(valid({ wallet: PAYEE, chain: "eip155:8453" }));
  assert.ok((fwd.result.score as number) <= 40 && (fwd.result.score as number) > 20, String(fwd.result.score));
  assert.ok(fwd.result.categories?.includes("auto_forwarding_wallet"));
  assert.ok(!fwd.result.categories?.includes("compromised_wallet"));
});

test("provider: a delegate the scan classified without a code family (tiny forwarder) still flags its wallets", async () => {
  const onchain = async () => ({ ...(await eoa()), code: { kind: "delegated" as const, bytes: 23, delegate: "0x00000000000000000000000000000000000000d9" } });
  const kitWatch: KitWatchLookup = { ...lookup({}), delegate: async (_n, d) => (d === "0x00000000000000000000000000000000000000d9" ? { class: "forwarder", family: "fwd-at-0000000000d9", at: 1, bytes: 7, code_kind: "tiny" } : undefined) };
  const e = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain, kitWatch }).evaluate(valid({ wallet: PAYEE, chain: "eip155:8453" }));
  assert.deepEqual(e.result.evidence?.kit_watch?.hits?.map((h) => [h.kind, h.family]), [["forwarding_delegation", "fwd-at-0000000000d9"]]);
  assert.ok((e.result.score as number) <= 40);
  // A proxy or larger implementation forwarding for one account does not flag every account delegated to it.
  for (const verdict of [{ class: "forwarder" as const, family: "fwd-at-x", at: 1, bytes: 45, code_kind: "delegating" }, { class: "forwarder" as const, family: "fwd-at-x", at: 1, bytes: 9000, code_kind: "logic" }, { class: "forwarder" as const, family: "fwd-at-x", at: 1 }]) {
    const shared: KitWatchLookup = { ...lookup({}), delegate: async () => verdict };
    const s = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain, kitWatch: shared }).evaluate(valid({ wallet: PAYEE, chain: "eip155:8453" }));
    assert.equal(s.result.evidence?.kit_watch?.hits, undefined, JSON.stringify(verdict));
  }
});

test("provider: clear when nothing is known; unavailable (not clear) when the lookup fails", async () => {
  const clean = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain: eoa, kitWatch: lookup({}) }).evaluate(valid({ wallet: PAYEE, chain: "eip155:8453" }));
  assert.equal(clean.result.tier, "low");
  assert.equal(clean.result.evidence?.kit_watch?.status, "clear");
  const down = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, onchain: eoa, kitWatch: lookup({}, [], true) }).evaluate(valid({ wallet: PAYEE, chain: "eip155:8453" }));
  assert.equal(down.result.evidence?.kit_watch?.status, "unavailable");
  assert.equal(down.result.evidence?.feeds?.find((f) => f.source === "x402check-kit-watch")?.status, "unavailable");
  // Solana subjects are out of scope: no kit-watch entry at all.
  const sol = await new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("k"), jev, kitWatch: lookup({}) }).evaluate(valid({ wallet: "Bofhoe2ye2adNQwZJtLepeKrBZq8CtHzRwPJXgWDH69X", chain: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" }));
  assert.equal(sol.result.evidence?.kit_watch, undefined);
});

// --- Worker cron and lookup ---------------------------------------------------------

function memoryKv(): KVNamespace & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    data,
    get: (async (key: string) => data.get(key) ?? null) as KVNamespace["get"],
    put: async (key: string, value: string) => void data.set(key, value),
  };
}

test("cron: scans from the cursor, writes watch entries, cursor and stats; a lease keeps a second run out", async () => {
  const kv = memoryKv();
  const dPoison = `0x${hex20(0xd0)}`;
  kv.data.set(KW.registry, JSON.stringify({ updated_at: "2026-09-29", families: [fam("poisoner-x", "poisoner", POISONER, true)] }));
  kv.data.set(KW.cursor("eip155:1"), "99");
  kv.data.set(KW.cursor("eip155:8453"), "499");
  const a = await auth(signer, dPoison, 0);
  const block = (n: number): RawBlock => ({ number: `0x${n.toString(16)}`, timestamp: "0x10", transactions: n === 100 ? [{ hash: "0xa1", from: signer.address, to: dPoison, nonce: "0x0", type: "0x4", authorizationList: [a] }] : [] });
  const fetchImpl = (async (_url: string, init: RequestInit) => {
    const req = JSON.parse(String(init.body));
    const answer = (r: { id: number; method: string; params: unknown[] }) => {
      if (r.method === "eth_blockNumber") return { id: r.id, result: "0x200" };
      if (r.method === "eth_getBlockByNumber") return { id: r.id, result: block(Number.parseInt(r.params[0] as string, 16)) };
      if (r.method === "eth_getCode") return { id: r.id, result: r.params[0] === dPoison ? POISONER : String(r.params[0]).toLowerCase() === signer.address.toLowerCase() ? `0xef0100${dPoison.slice(2)}` : "0x" };
      return { id: r.id, result: null };
    };
    return new Response(JSON.stringify(Array.isArray(req) ? req.map(answer) : answer(req)));
  }) as unknown as typeof fetch;
  const env: WorkerEnv = { RATE: kv };
  const stats = await runKitWatch(env, { fetchImpl, now: 1_000_000 });
  assert.ok(stats);
  const entry = JSON.parse(kv.data.get(KW.address(signer.address.toLowerCase())) as string) as WatchEntry;
  assert.equal(entry.k, "poisoner_delegation");
  assert.equal(stats.chains["eip155:1"]?.cursor, 99 + 15); // seeded by kw:cursor, then kept in the stats
  assert.equal(stats.chains["eip155:1"]?.flagged.poisoner_delegation, 1);
  assert.equal(await runKitWatch(env, { fetchImpl, now: 1_010_000 }), null); // lease held
  // Lookups: EOA kinds on any chain, contract kinds only where they were seen.
  kv.data.set(KW.address(PAYEE), JSON.stringify({ k: "drainer_kit_contract", c: "eip155:1", f: "kit", t: 1 }));
  const lk = kitWatchLookup(env) as KitWatchLookup;
  assert.equal((await lk.addresses([signer.address], "eip155:8453")).size, 1);
  assert.equal((await lk.addresses([PAYEE], "eip155:8453")).size, 0);
  assert.equal((await lk.addresses([PAYEE], "eip155:1")).size, 1);
  assert.equal(kitWatchLookup({ RATE: kv, KIT_WATCH: "off" }), null);
});

test("scan: a forwarder's destinations are never recorded, whether contracts or plain wallets", async () => {
  const dFwd = `0x${hex20(0xe1)}`;
  const weth = `0x${hex20(0xe2)}`; // a contract receiving forwarded ETH (say, WETH)
  const code: Record<string, string> = { [dFwd]: `0x6080604052${"63aabbccdd16".repeat(20)}00`, [weth]: WALLET, [signer.address.toLowerCase()]: `0xef0100${dFwd.slice(2)}` };
  const call = async (reqs: Array<{ method: string; params: unknown[] }>) => reqs.map((r) => (r.method === "eth_getCode" ? (code[r.params[0] as string] ?? "0x") : undefined));
  const block: RawBlock = { number: "0x30", timestamp: "0x10", transactions: [{ hash: "0xb1", from: signer.address, to: dFwd, nonce: "0x0", type: "0x4", authorizationList: [await auth(signer, dFwd, 1)] }] };
  const victim = `0x${hex20(0xe3)}`; // a merchant's wallet the forwarder's author picked
  const res = await scanBlocks([block], { chain: "eip155:1", call, simulate: simulating({ [signer.address.toLowerCase()]: [{ to: weth, value: 10n ** 16n }, { to: victim, value: 1n }] }), families: indexFamilies(null), delegates: new Map() });
  const merged = mergeEntries(res.entries);
  assert.equal(merged.get(signer.address.toLowerCase())?.k, "forwarding_delegation");
  assert.equal(merged.has(weth), false);
  assert.equal(merged.has(victim), false);
});

test("scan: forwarding by a proxy flags only the probed account; stale authorizations and unreadable code flag no one", async () => {
  const dProxy = `0x${hex20(0xf1)}`;
  // An EIP-1167 minimal proxy: its behaviour depends on the account's own configuration.
  const proxyCode = `0x363d3d373d3d3d363d73${hex20(0xf9)}5af43d82803e903d91602b57fd5bf3`;
  const code: Record<string, string> = { [dProxy]: proxyCode, [signer.address.toLowerCase()]: `0xef0100${dProxy.slice(2)}`, [signer2.address.toLowerCase()]: `0xef0100${dProxy.slice(2)}` };
  const call = async (reqs: Array<{ method: string; params: unknown[] }>) => reqs.map((r) => (r.method === "eth_getCode" ? (code[r.params[0] as string] ?? "0x") : undefined));
  const block: RawBlock = {
    number: "0x40",
    timestamp: "0x10",
    transactions: [
      { hash: "0xd1", from: signer.address, to: dProxy, nonce: "0x0", type: "0x4", authorizationList: [await auth(signer, dProxy, 1)] },
      { hash: "0xd2", from: signer2.address, to: dProxy, nonce: "0x0", type: "0x4", authorizationList: [await auth(signer2, dProxy, 1)] },
    ],
  };
  const delegates = new Map<string, DelegateVerdict>();
  const res = await scanBlocks([block], { chain: "eip155:1", call, simulate: simulating({ [signer.address.toLowerCase()]: [{ to: `0x${hex20(0xee)}`, value: 10n ** 16n }] }), families: indexFamilies(null), delegates });
  const merged = mergeEntries(res.entries);
  assert.equal(merged.get(signer.address.toLowerCase())?.k, "forwarding_delegation", "the probed account forwards");
  assert.equal(merged.has(signer2.address.toLowerCase()), false, "another account on the same proxy is not flagged");
  assert.equal(delegates.get(dProxy)?.class, "not_forwarding");

  // A delegate whose code cannot be read gets no cached verdict (retried when seen again).
  const failing = async (reqs: Array<{ method: string; params: unknown[] }>) => reqs.map(() => undefined);
  const again = new Map<string, DelegateVerdict>();
  const r2 = await scanBlocks([block], { chain: "eip155:1", call: failing, simulate: simulating({}), families: indexFamilies(null), delegates: again });
  assert.equal(again.size, 0);
  assert.ok(r2.stats.degraded > 0);
});
