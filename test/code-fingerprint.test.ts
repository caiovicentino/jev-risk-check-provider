import { test } from "node:test";
import assert from "node:assert";
import { codeFacts, stripMetadata } from "../src/code-fingerprint.js";
import { buildHashBlob, codeFeedResults, hashSetFromBytes, matchCode, type ThreatIntelFeeds } from "../src/threat-intel.js";
import { createSimulator } from "../src/simulation.js";
import { Provider } from "../src/provider.js";
import { generateKeyPair, verifyJws, type JwsClaims } from "../src/jws.js";
import { validateRequest } from "../src/validate.js";
import type { JevLike } from "../src/jev.js";
import type { Answer, RiskCheckRequest } from "../src/types.js";

// solc-style CBOR trailer: a2 64 "ipfs" 58 22 <34-byte multihash> 64 "solc" 43 <version>, then its length (0x0033).
const trailer = (hashByte: string) => `a264697066735822${"1220"}${hashByte.repeat(32)}64736f6c6343000813${"0033"}`;
// Logic code: a dispatcher over made-up selectors (PUSH4 sel; EQ), > 100 bytes, no DELEGATECALL.
const logic = (sel: string) => `0x6080604052${`63${sel}14`.repeat(20)}00`;
const DRAINER_KIT = logic("aabbccdd");

test("codeFacts: classifies EOAs, 7702 delegation, tiny, delegating, token, NFT and logic code", () => {
  assert.equal(codeFacts("0x").kind, "none");
  const delegated = codeFacts("0xef010063c0c19a282a1b52b07dd5a65b58948a07dae32b");
  assert.equal(delegated.kind, "delegated");
  assert.equal(delegated.delegate, "0x63c0c19a282a1b52b07dd5a65b58948a07dae32b");
  assert.equal(codeFacts("0x6080604052").kind, "tiny");
  assert.equal(codeFacts(`0x${"5b".repeat(120)}f4`).kind, "delegating", "DELEGATECALL = proxy-like, shared by many contracts");
  assert.equal(codeFacts(`0x6080604052${"63a9059cbb14" + "6370a0823114" + "6318160ddd14"}${"5b".repeat(100)}`).kind, "token");
  assert.equal(codeFacts(`0x6080604052${"636352211e14" + "6342842e0e14"}${"5b".repeat(100)}`).kind, "nft");
  const f = codeFacts(DRAINER_KIT);
  assert.equal(f.kind, "logic");
  assert.match(f.fingerprint as string, /^[0-9a-f]{64}$/);
});

test("codeFacts: PUSH data is skipped, so an 0xf4 byte inside a constant is not a DELEGATECALL", () => {
  assert.equal(codeFacts(`0x${"63f4f4f4f414".repeat(20)}00`).kind, "logic");
});

test("fingerprint ignores the compiler metadata trailer but not the logic", () => {
  const a = codeFacts(`${DRAINER_KIT}${trailer("11")}`);
  const b = codeFacts(`${DRAINER_KIT}${trailer("22")}`);
  assert.equal(a.fingerprint, b.fingerprint, "same kit recompiled from a different source file");
  assert.equal(a.fingerprint, codeFacts(DRAINER_KIT).fingerprint);
  assert.notEqual(codeFacts(logic("aabbccde")).fingerprint, a.fingerprint);
  // A trailer-length that does not point at a CBOR map is not metadata: nothing stripped.
  const raw = Buffer.from(`${"5b".repeat(10)}0005`, "hex");
  assert.equal(stripMetadata(raw).length, raw.length);
});

const feedsWith = (fingerprints: string[]): ThreatIntelFeeds => ({ fortaCode: { set: hashSetFromBytes(buildHashBlob(fingerprints)), as_of: "2023-01-26" } });

test("matchCode / codeFeedResults report per-source hits and scope", () => {
  const fp = codeFacts(DRAINER_KIT).fingerprint as string;
  const feeds = feedsWith([fp]);
  assert.deepEqual(matchCode(feeds, fp), ["forta-phishing-code"]);
  assert.deepEqual(matchCode(feeds, "00".repeat(32)), []);
  assert.equal(codeFeedResults(feeds, "checked", new Set(["forta-phishing-code"]))[0]?.status, "hit");
  assert.equal(codeFeedResults(feeds, "checked", new Set())[0]?.status, "clear");
  assert.equal(codeFeedResults(feeds, "not_applicable", new Set())[0]?.status, "not_applicable");
  assert.equal(codeFeedResults({ ...feeds, scamsnifferCode: null }, "checked", new Set()).find((r) => r.source === "scamsniffer-code")?.status, "unavailable");
});

const USER = "0x1111111111111111111111111111111111111111";
const KIT = "0x2222222222222222222222222222222222222222";
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

test("provider: a subject running a listed drainer kit's code is capped and signed, without being on any address list", async () => {
  const keyPair = generateKeyPair("jev-attest-v1");
  const code = codeFacts(`${DRAINER_KIT}${trailer("33")}`);
  const onchain = async () => ({ status: "ok" as const, network: "eip155:1", is_contract: true, activity: "some" as const, tx_count: 0, code });
  const feeds = feedsWith([codeFacts(DRAINER_KIT).fingerprint as string]);
  const e = await new Provider({ host: "x402check.xyz", keyPair, jev, onchain, feeds: () => feeds }).evaluate(req({ wallet: KIT, chain: "eip155:1" }));
  assert.ok((e.result.score as number) <= 30);
  assert.ok(e.result.categories?.includes("known_drainer_code"));
  assert.deepEqual(e.result.evidence?.feeds?.find((f) => f.source === "forta-phishing-code"), { source: "forta-phishing-code", kind: "code", as_of: "2023-01-26", status: "hit" });
  const claims = verifyJws(e.result.jws as string, keyPair.publicJwk) as JwsClaims;
  assert.ok(claims.checks?.feeds?.includes("forta-phishing-code@2023-01-26:hit"));

  const clean = await new Provider({ host: "x402check.xyz", keyPair, jev, onchain: async () => ({ ...(await onchain()), code: codeFacts(logic("01020304")) }), feeds: () => feeds }).evaluate(req({ wallet: KIT, chain: "eip155:1" }));
  assert.equal(clean.result.tier, "low");
  assert.equal(clean.result.evidence?.feeds?.find((f) => f.source === "forta-phishing-code")?.status, "clear");
  const eoa = await new Provider({ host: "x402check.xyz", keyPair, jev, onchain: async () => ({ status: "ok" as const, network: "eip155:1", is_contract: false, activity: "some" as const, tx_count: 3 }), feeds: () => feeds }).evaluate(req({ wallet: USER, chain: "eip155:1" }));
  assert.equal(eoa.result.evidence?.feeds?.find((f) => f.source === "forta-phishing-code")?.status, "not_applicable");
});

test("simulation: the called contract's code is matched even when the replay reverts", async () => {
  const stub = (status: string) =>
    (async (_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body));
      if (Array.isArray(body)) return new Response(JSON.stringify(body.map((b: { id: number; params: string[] }) => ({ id: b.id, result: b.params[0] === KIT ? DRAINER_KIT : "0x" }))));
      return new Response(JSON.stringify({ result: [{ calls: [{ status, logs: [] }] }] }));
    }) as unknown as typeof fetch;
  const fp = codeFacts(DRAINER_KIT).fingerprint as string;
  const codeMatch = (f: string) => (f === fp ? ["scamsniffer-code"] : []);
  const reverted = await createSimulator({ fetchImpl: stub("0x0") })({ from: USER, to: KIT, value: "1" }, "eip155:1", { declared: [{ address: KIT }], codeMatch });
  assert.deepEqual(reverted.findings, ["simulation_reverted", "known_drainer_code"]);
  assert.deepEqual(reverted.code_matches, [{ address: KIT, role: "called", sources: ["scamsniffer-code"] }]);
  const ok = await createSimulator({ fetchImpl: stub("0x1") })({ from: USER, to: KIT, value: "1" }, "eip155:1", { declared: [{ address: KIT }], codeMatch });
  assert.ok(ok.findings?.includes("known_drainer_code"));
  assert.equal(ok.code_checked, true);
  const noMatch = await createSimulator({ fetchImpl: stub("0x1") })({ from: USER, to: KIT, value: "1" }, "eip155:1", { declared: [{ address: KIT }], codeMatch: () => [] });
  assert.ok(!noMatch.findings?.includes("known_drainer_code"));
});
