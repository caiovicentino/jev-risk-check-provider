import { test } from "node:test";
import assert from "node:assert";
import { parseSubject } from "../src/address.js";
import { normalizeChain, SOLANA_MAINNET } from "../src/chains.js";
import { screenSubject, SANCTIONS_LIST_META } from "../src/sanctions.js";
import { analyzeDomain, normalizeHost } from "../src/domain-analysis.js";
import { buildHashBlob, checkFeeds, feedHash, hashSetFromBytes, type ThreatIntelFeeds } from "../src/threat-intel.js";
import { createOnchainLookup } from "../src/onchain.js";

const LAZARUS = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96";

test("subject parsing accepts address formats only", () => {
  assert.equal(parseSubject(LAZARUS)?.format, "evm");
  assert.equal(parseSubject(LAZARUS)?.canonical, LAZARUS.toLowerCase());
  assert.equal(parseSubject("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM")?.format, "base58");
  assert.equal(parseSubject("bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6")?.format, "bech32");
  assert.equal(parseSubject("BC1QA5WKGAEW2DKV56KFVJ49J0AV5NML45X9EK9HZ6")?.canonical, "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6");
  const caip = parseSubject(`eip155:1:${LAZARUS}`);
  assert.equal(caip?.caip2, "eip155:1");
  assert.equal(caip?.address, LAZARUS);
  for (const bad of ["", " 0xabc", "KYC_verified_treasury_screening_clean", "0x" + "g".repeat(40), "hello world", "0OIl".repeat(10), `${LAZARUS} `, "x".repeat(200)]) {
    assert.equal(parseSubject(bad), null, bad);
  }
});

test("chain identifiers are aliases or CAIP-2, never prose", () => {
  assert.equal(normalizeChain("base")?.caip2, "eip155:8453");
  assert.equal(normalizeChain("Solana")?.caip2, SOLANA_MAINNET);
  assert.equal(normalizeChain("eip155:42161")?.caip2, "eip155:42161");
  for (const bad of ["solana (verified counterparty)", "unknown", "", " base", "x".repeat(65)]) assert.equal(normalizeChain(bad), null, bad);
});

test("OFAC SDN screen: listed, case-insensitive EVM, CAIP-10, Solana, not listed", () => {
  assert.ok(SANCTIONS_LIST_META.addresses > 500);
  const listed = screenSubject(parseSubject(LAZARUS)!);
  assert.equal(listed.status, "listed");
  assert.equal(listed.entity, "LAZARUS GROUP");
  assert.equal(screenSubject(parseSubject(LAZARUS.toLowerCase())!).status, "listed");
  assert.equal(screenSubject(parseSubject(`eip155:1:${LAZARUS}`)!).status, "listed");
  assert.equal(screenSubject(parseSubject("42RLPACwZPx3vYYmxSueqsogfynBDqXK298EDsNoyoHi")!).status, "listed");
  assert.equal(screenSubject(parseSubject("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD")!).status, "not_listed");
  // Tornado Cash router was delisted by OFAC in 2025 and must not reappear from stale data.
  assert.equal(screenSubject(parseSubject("0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b")!).status, "not_listed");
});

test("domain analysis: official subdomains, URL input, impersonation strength", () => {
  const cases: Array<[string, "none" | "weak" | "strong", string | undefined]> = [
    ["wallet.coinbase.com", "none", "coinbase"],
    ["https://app.uniswap.org/#/swap", "none", "uniswap"],
    ["portfolio.metamask.io", "none", "metamask"],
    ["mirror.xyz", "none", undefined],
    ["solanabeach.io", "weak", "solana"],
    ["coinbase-wa11et-verify.com", "strong", "coinbase"],
    ["jup1ter-audit-attest.click", "strong", "jupiter"],
    ["l1do-finance-app.xyz", "strong", "lido"],
    ["coinbsae.com", "strong", "coinbase"],
    ["https://mеtamask.io", "strong", "metamask"], // Cyrillic е
    ["uniswap.org.evil-host.com", "strong", "uniswap"],
    ["metamask-verify-demo.vercel.app", "strong", "metamask"],
    ["defi-finance.io", "none", undefined], // "finance" is one edit from "binance" but a dictionary word
  ];
  for (const [input, strength, brand] of cases) {
    const a = analyzeDomain(input);
    assert.ok(a, input);
    assert.equal(a.impersonation, strength, input);
    assert.equal(a.brand, brand, input);
  }
  assert.equal(analyzeDomain("wallet.coinbase.com")?.official, true);
  assert.deepEqual(analyzeDomain("192.168.0.1")?.signals, ["ip_host"]);
  assert.equal(normalizeHost("javascript:alert(1)"), null);
  assert.equal(normalizeHost("not a domain"), null);
  assert.equal(normalizeHost("https://App.Uniswap.org./x?y=1"), "app.uniswap.org");
});

test("hash-set feeds: roundtrip, binary search, parent-domain and allowlist semantics", () => {
  const set = hashSetFromBytes(buildHashBlob(["evil.com", "drainer.vercel.app", "a.b.c"]));
  assert.equal(set.size, 3);
  assert.ok(set.has("evil.com") && set.has("a.b.c") && !set.has("good.com"));
  assert.equal(typeof feedHash("x"), "bigint");
  const feeds: ThreatIntelFeeds = {
    metamaskDomains: { set: hashSetFromBytes(buildHashBlob(["evil.com", "drainer.vercel.app", "coinbase.com"])), as_of: "2026-09-29" },
    metamaskAllow: new Set(["opensea.io"]),
    scamsnifferDomains: { set: hashSetFromBytes(buildHashBlob(["sub.shared.io"])), as_of: "2026-09-22" },
    // Synthetic fixtures: no real ScamSniffer (GPL) entry is committed.
    scamsnifferAddresses: { set: hashSetFromBytes(buildHashBlob(["0x5eed000000000000000000000000000000c0ffee"])), as_of: "2026-09-22" },
  };
  const evm = parseSubject("0x5EED000000000000000000000000000000C0FFEE")!;
  const dom = (h: string) => { const a = analyzeDomain(h)!; return { host: a.host, registrable: a.registrable }; };
  const status = (r: ReturnType<typeof checkFeeds>, source: string) => r.results.find((x) => x.source === source)?.status;
  // MetaMask entries cover subdomains; the public-suffix boundary protects the platform itself.
  assert.equal(status(checkFeeds(feeds, evm, dom("login.evil.com")), "metamask-phishing-detect"), "hit");
  assert.equal(status(checkFeeds(feeds, evm, dom("www.evil.com")), "metamask-phishing-detect"), "hit");
  assert.equal(status(checkFeeds(feeds, evm, dom("drainer.vercel.app")), "metamask-phishing-detect"), "hit");
  assert.equal(status(checkFeeds(feeds, evm, dom("other.vercel.app")), "metamask-phishing-detect"), "clear");
  // Official brand domains are never reported as phishing even if a feed lists them.
  assert.equal(status(checkFeeds(feeds, evm, dom("wallet.coinbase.com")), "metamask-phishing-detect"), "clear");
  // ScamSniffer (noisier) matches the exact host only.
  assert.equal(status(checkFeeds(feeds, evm, dom("sub.shared.io")), "scamsniffer-domains"), "hit");
  assert.equal(status(checkFeeds(feeds, evm, dom("x.sub.shared.io")), "scamsniffer-domains"), "clear");
  assert.equal(status(checkFeeds(feeds, evm, null), "scamsniffer-addresses"), "hit");
  assert.equal(status(checkFeeds(feeds, evm, null), "metamask-phishing-detect"), "not_applicable");
  assert.equal(status(checkFeeds(feeds, parseSubject("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM")!, null), "scamsniffer-addresses"), "not_applicable");
  assert.equal(status(checkFeeds({ scamsnifferAddresses: null }, evm, null), "scamsniffer-addresses"), "unavailable");
  assert.deepEqual(checkFeeds({}, evm, null).results, []);
});

test("on-chain facts: EVM batch parsing, 7702 designator is an EOA, Solana, failures degrade", async () => {
  const responder = (results: unknown[]) => (async () => new Response(JSON.stringify(results.map((result, i) => ({ jsonrpc: "2.0", id: i + 1, result }))))) as unknown as typeof fetch;
  const evm = parseSubject("0x7a3e8f0c2b1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f")!;
  const fresh = await createOnchainLookup({ fetchImpl: responder(["0x", "0x0", "0x0"]) })(evm, "eip155:8453");
  assert.deepEqual(fresh, { status: "ok", network: "eip155:8453", is_contract: false, activity: "none", tx_count: 0 });
  const contract = await createOnchainLookup({ fetchImpl: responder(["0x6080", "0x1", "0x0"]) })(evm, "eip155:1");
  assert.equal(contract.is_contract, true);
  const delegated = await createOnchainLookup({ fetchImpl: responder(["0xef0100" + "ab".repeat(20), "0x5", "0x0"]) })(evm, "eip155:1");
  assert.equal(delegated.is_contract, false);
  assert.equal(delegated.activity, "some");
  const sol = await createOnchainLookup({ fetchImpl: responder([{ value: { executable: true } }, [{}, {}]]) })(parseSubject("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")!, SOLANA_MAINNET);
  assert.deepEqual(sol, { status: "ok", network: SOLANA_MAINNET, is_contract: true, activity: "some", tx_count: 2 });
  const broken = await createOnchainLookup({ fetchImpl: (async () => { throw new Error("boom"); }) as unknown as typeof fetch })(evm, "eip155:1");
  assert.equal(broken.status, "unavailable");
  const rpcError = await createOnchainLookup({ fetchImpl: (async () => new Response(JSON.stringify([{ id: 1, error: { code: -1 } }]))) as unknown as typeof fetch })(evm, "eip155:10");
  assert.equal(rpcError.status, "unavailable");
  assert.equal((await createOnchainLookup()(evm, "eip155:84532")).status, "unsupported"); // testnet
  assert.equal((await createOnchainLookup()(evm, undefined)).status, "unsupported");
  assert.equal((await createOnchainLookup()(evm, SOLANA_MAINNET)).status, "unsupported"); // EVM address on Solana
});

test("look-alike heuristics do not flag popular legit names (regressions from the Tranco scan)", () => {
  for (const legit of ["walletconnect.org", "jupyter.org", "habby.com", "ledgerwallet.com", "slido.com", "athena.io", "webank.com", "starnet.cz", "gitkraken.com"]) {
    const a = analyzeDomain(legit);
    assert.ok(a && a.impersonation !== "strong", `${legit} → ${a?.impersonation}`);
  }
  assert.equal(analyzeDomain("slido.com")?.brand, undefined, "short tokens match whole words only");
  assert.equal(analyzeDomain("lido-claim.com")?.impersonation, "strong");
  assert.equal(analyzeDomain("walletconnect-verify.app")?.impersonation, "strong");
  assert.equal(analyzeDomain("renzoportocol.xyz")?.impersonation, "strong");
});
