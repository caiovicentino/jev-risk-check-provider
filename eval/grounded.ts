// Externally grounded evaluation: every label here comes from a source this project
// did not author — the OFAC SDN list, MetaMask's and ScamSniffer's public phishing /
// drainer lists, well-known production contracts and dApps, and the Tranco top list.
//
// Layers
//   A  OFAC SDN addresses (deterministic screen, end to end)
//   B  feed coverage: MetaMask-listed domains, ScamSniffer drainer addresses (feeds on)
//   C  generalization, feed held out: ScamSniffer-only phishing domains with ScamSniffer
//      OFF (look-alike analysis + model), ScamSniffer drainer addresses with ScamSniffer
//      OFF (on-chain facts + approval-to-EOA rule + model)
//   D  false positives: well-known legit contracts/wallets, top dApp domains (model in
//      the loop), and a deterministic scan of the Tranco top-N (no model calls)
//
//   npx tsx eval/grounded.ts [--tranco path/to/top-domains.txt] [--tranco-n 20000]
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { EVAL_EVIDENCE_DIR } from "./harness.js";
import { sample, wilson } from "./stats.js";
import { Provider } from "../src/provider.js";
import { generateKeyPair } from "../src/jws.js";
import { GatewayJevClient } from "../src/backends/gateway.js";
import { JevClient, type JevLike } from "../src/jev.js";
import { createOnchainLookup } from "../src/onchain.js";
import { loadFeedsFromDisk } from "../src/feeds-node.js";
import { analyzeDomain } from "../src/domain-analysis.js";
import { checkFeeds, feedHost, type ThreatIntelFeeds } from "../src/threat-intel.js";
import { parseSubject } from "../src/address.js";
import { OFAC_SDN_ADDRESSES } from "../src/data/ofac-sdn.js";
import { validateRequest } from "../src/validate.js";
import type { RiskCheckRequest } from "../src/types.js";

const CACHE = new URL("../.cache/eval-sources/", import.meta.url);
const SOURCES = {
  metamask: "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json",
  ssDomains: "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json",
  ssAddresses: "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json",
};

// Well-known production contracts and wallets (public, verifiable on any explorer).
const LEGIT_ADDRESSES: Array<{ label: string; wallet: string; chain: string; interaction: "permit_signature" | "token_approval" | "native_transfer" | "token_transfer" | "contract_call" }> = [
  { label: "Uniswap Universal Router", wallet: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", chain: "eip155:1", interaction: "permit_signature" },
  { label: "Permit2", wallet: "0x000000000022D473030F116dDEE9F6B43aC78BA3", chain: "eip155:1", interaction: "token_approval" },
  { label: "Uniswap V2 Router", wallet: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", chain: "eip155:1", interaction: "token_approval" },
  { label: "Uniswap V3 SwapRouter", wallet: "0xE592427A0AEce92De3Edee1F18E0157C05861564", chain: "eip155:1", interaction: "token_approval" },
  { label: "1inch Aggregation Router v5", wallet: "0x1111111254EEB25477B68fb85Ed929f73A960582", chain: "eip155:1", interaction: "token_approval" },
  { label: "0x Exchange Proxy", wallet: "0xDef1C0ded9bec7F1a1670819833240f027b25EfF", chain: "eip155:1", interaction: "token_approval" },
  { label: "OpenSea Seaport 1.5", wallet: "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC", chain: "eip155:1", interaction: "contract_call" },
  { label: "Aave V3 Pool", wallet: "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", chain: "eip155:1", interaction: "token_approval" },
  { label: "Lido stETH", wallet: "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84", chain: "eip155:1", interaction: "contract_call" },
  { label: "USDC (Ethereum)", wallet: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", chain: "eip155:1", interaction: "contract_call" },
  { label: "USDT (Ethereum)", wallet: "0xdAC17F958D2ee523a2206206994597C13D831ec7", chain: "eip155:1", interaction: "contract_call" },
  { label: "WETH (Ethereum)", wallet: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", chain: "eip155:1", interaction: "contract_call" },
  { label: "DAI", wallet: "0x6B175474E89094C44Da98b954EedeAC495271d0F", chain: "eip155:1", interaction: "contract_call" },
  { label: "Binance 14 hot wallet", wallet: "0x28C6c06298d514Db089934071355E5743bf21d60", chain: "eip155:1", interaction: "native_transfer" },
  { label: "vitalik.eth", wallet: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", chain: "eip155:1", interaction: "native_transfer" },
  { label: "USDC (Base)", wallet: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", chain: "eip155:8453", interaction: "contract_call" },
  { label: "WETH (Base)", wallet: "0x4200000000000000000000000000000000000006", chain: "eip155:8453", interaction: "contract_call" },
  { label: "Uniswap Universal Router (Base)", wallet: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", chain: "eip155:8453", interaction: "permit_signature" },
  { label: "SPL Token program", wallet: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", chain: "solana", interaction: "contract_call" },
  { label: "Jupiter v6 aggregator", wallet: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", chain: "solana", interaction: "contract_call" },
  { label: "USDC mint (Solana)", wallet: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", chain: "solana", interaction: "contract_call" },
  { label: "Raydium AMM v4", wallet: "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", chain: "solana", interaction: "contract_call" },
];

const LEGIT_DOMAINS = [
  "app.uniswap.org", "app.aave.com", "curve.fi", "lido.fi", "stake.lido.fi", "opensea.io", "blur.io", "jup.ag", "raydium.io", "magiceden.io",
  "pancakeswap.finance", "app.compound.finance", "1inch.io", "etherscan.io", "basescan.org", "solscan.io", "coinbase.com", "wallet.coinbase.com",
  "portfolio.metamask.io", "phantom.com", "rabby.io", "zapper.xyz", "mirror.xyz", "zora.co", "warpcast.com", "x402.org", "app.hyperliquid.xyz",
  "app.morpho.org", "app.ens.domains", "app.safe.global", "debank.com", "defillama.com", "dexscreener.com", "pump.fun", "app.kamino.finance",
  "drift.trade", "app.eigenlayer.xyz", "app.pendle.finance", "revoke.cash", "docs.cdp.coinbase.com",
];

async function cached(name: string, url: string): Promise<string> {
  mkdirSync(CACHE, { recursive: true });
  const day = new Date().toISOString().slice(0, 10);
  const file = new URL(`${name}-${day}.json`, CACHE);
  if (existsSync(file)) return readFileSync(file, "utf8");
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  const text = await res.text();
  writeFileSync(file, text);
  return text;
}

type Row = { layer: string; id: string; expected: "risky" | "safe"; score: number | null; tier: string | null; categories: string[]; checked: boolean };

async function pool<T>(items: T[], n: number, fn: (x: T) => Promise<void>): Promise<void> {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) await fn(items[i++] as T);
  }));
}

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 ? process.argv[i + 1] : undefined;
}

// Default seed 100: samples drawn with seeds 0–99 were inspected while tuning the
// domain heuristics, so only fresh seeds give an honest held-out measurement.
export async function runGrounded(jev: JevLike, seed = Number(arg("seed") ?? 100)): Promise<Record<string, unknown>> {
  const onchain = createOnchainLookup({ timeoutMs: 2500 });
  const all = loadFeedsFromDisk();
  const mmOnly: ThreatIntelFeeds = { metamaskDomains: all.metamaskDomains ?? null, ...(all.metamaskAllow ? { metamaskAllow: all.metamaskAllow } : {}) };
  const noFeeds: ThreatIntelFeeds = {};
  const make = (feeds: ThreatIntelFeeds) => new Provider({ host: "x402check.xyz", keyPair: generateKeyPair("jev-attest-v1"), jev, onchain, feeds: () => feeds });
  const pFull = make(all);
  const pMmOnly = make(mmOnly);
  const pNone = make(noFeeds);

  const mm = JSON.parse(await cached("metamask-config", SOURCES.metamask)) as { blacklist: string[] };
  const ssDomains = JSON.parse(await cached("scamsniffer-domains", SOURCES.ssDomains)) as string[];
  const ssAddresses = (JSON.parse(await cached("scamsniffer-addresses", SOURCES.ssAddresses)) as string[]).filter((a) => /^0x[0-9a-fA-F]{40}$/.test(a));
  const mmSet = new Set(mm.blacklist.map((d) => feedHost(d)));
  const mmDomains = mm.blacklist.filter((d) => !d.includes("/") && analyzeDomain(d));
  const ssOnlyDomains = ssDomains.filter((d) => !d.includes("/") && !mmSet.has(feedHost(d)) && analyzeDomain(d));

  const jobs: Array<{ layer: string; id: string; expected: "risky" | "safe"; provider: Provider; body: Record<string, unknown> }> = [];
  const ofac = [
    ...sample(OFAC_SDN_ADDRESSES.filter((r) => r[1] === "ETH"), 12, 1 + seed),
    ...OFAC_SDN_ADDRESSES.filter((r) => r[1] === "SOL"),
    ...sample(OFAC_SDN_ADDRESSES.filter((r) => r[1] === "TRX"), 4, 2 + seed),
    ...sample(OFAC_SDN_ADDRESSES.filter((r) => r[1] === "XBT" && parseSubject(r[0])), 4, 3 + seed),
  ];
  for (const [address, ticker] of ofac) {
    const chain = ticker === "ETH" ? "ethereum" : ticker === "SOL" ? "solana" : ticker === "TRX" ? "tron" : "bitcoin";
    jobs.push({ layer: "A_ofac_sdn", id: `${ticker}:${address}`, expected: "risky", provider: pFull, body: { wallet: address, chain, context: "user sends a payment to this address" } });
  }
  for (const d of sample(mmDomains, 40, 4 + seed)) jobs.push({ layer: "B_metamask_listed_domain", id: d, expected: "risky", provider: pFull, body: { wallet: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", chain: "eip155:1", domain: d, context: "user connects wallet on this site to sign a transaction", interaction: { type: "contract_call" } } });
  const ssAddrSample = sample(ssAddresses, 30, 5 + seed);
  for (const a of ssAddrSample) jobs.push({ layer: "B_scamsniffer_address", id: a, expected: "risky", provider: pFull, body: { wallet: a, chain: "eip155:1", context: "permit signature granting this spender an allowance on USDC", interaction: { type: "permit_signature", unlimited: true } } });
  const ssOnlySample = sample(ssOnlyDomains, 60, 6 + seed);
  const domainBody = (d: string) => ({ wallet: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", chain: "eip155:1", domain: d, context: "user connects wallet on this site to sign a transaction", interaction: { type: "contract_call" } });
  for (const d of ssOnlySample) jobs.push({ layer: "C_heldout_phishing_domain", id: d, expected: "risky", provider: pMmOnly, body: domainBody(d) });
  for (const d of ssOnlySample) jobs.push({ layer: "B_scamsniffer_only_domain_feed_on", id: d, expected: "risky", provider: pFull, body: domainBody(d) });
  for (const a of ssAddrSample) {
    jobs.push({ layer: "C_heldout_drainer_transfer", id: a, expected: "risky", provider: pNone, body: { wallet: a, chain: "eip155:1", context: "native transfer of 0.4 ETH", interaction: { type: "native_transfer" } } });
    jobs.push({ layer: "C_heldout_drainer_permit", id: a, expected: "risky", provider: pNone, body: { wallet: a, chain: "eip155:1", context: "permit signature granting this spender an allowance on USDC", interaction: { type: "permit_signature", unlimited: true } } });
  }
  for (const a of LEGIT_ADDRESSES) {
    jobs.push({ layer: "D_legit_address", id: a.label, expected: "safe", provider: pFull, body: { wallet: a.wallet, chain: a.chain, context: a.interaction === "native_transfer" ? "user sends 0.2 ETH to this address" : `user interacts with ${a.label}`, interaction: { type: a.interaction, ...(a.interaction === "permit_signature" || a.interaction === "token_approval" ? { unlimited: true } : {}) } } });
  }
  for (const d of LEGIT_DOMAINS) jobs.push({ layer: "D_legit_domain", id: d, expected: "safe", provider: pFull, body: { wallet: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD", chain: "eip155:1", domain: `https://${d}`, context: "user connects wallet on this site to sign a transaction", interaction: { type: "contract_call" } } });

  const rows: Row[] = [];
  let invalid = 0;
  await pool(jobs, 6, async (j) => {
    const v = validateRequest(j.body);
    if (!v.ok) {
      invalid++;
      return;
    }
    const ev = await j.provider.evaluate(v.value as RiskCheckRequest);
    rows.push({ layer: j.layer, id: j.id, expected: j.expected, score: ev.result.score ?? null, tier: ev.result.tier ?? null, categories: ev.result.categories ?? [], checked: ev.result.checked });
  });

  const layers: Record<string, unknown> = {};
  for (const layer of [...new Set(rows.map((r) => r.layer))].sort()) {
    const g = rows.filter((r) => r.layer === layer && r.checked);
    const expected = g[0]?.expected;
    const flagged = g.filter((r) => (r.score as number) < 60);
    const warned = g.filter((r) => r.tier === "high" || r.tier === "critical");
    const ciBlock = wilson(expected === "risky" ? flagged.length : g.length - flagged.length, g.length);
    layers[layer] = {
      expected,
      n: g.length,
      unchecked: rows.filter((r) => r.layer === layer && !r.checked).length,
      [expected === "risky" ? "detected_below_60" : "passed_60_or_above"]: `${expected === "risky" ? flagged.length : g.length - flagged.length}/${g.length}`,
      rate: `${(ciBlock.p * 100).toFixed(1)}% (95% CI ${(ciBlock.lo * 100).toFixed(1)}–${(ciBlock.hi * 100).toFixed(1)}%)`,
      tier_high_or_critical: `${warned.length}/${g.length}`,
      misses: g.filter((r) => (expected === "risky" ? (r.score as number) >= 60 : (r.score as number) < 60)).slice(0, 8).map((r) => `${r.id} → ${r.score}/${r.tier}`),
      categories: Object.fromEntries(
        Object.entries(g.flatMap((r) => r.categories).reduce<Record<string, number>>((m, c) => ((m[c] = (m[c] ?? 0) + 1), m), {})).filter(([c]) => c !== "intent_risk" && c !== "behavioral"),
      ),
    };
  }

  // D3: deterministic false-positive scan over popular domains (no model calls).
  const trancoPath = arg("tranco") ?? process.env.TRANCO_LIST;
  if (trancoPath && existsSync(trancoPath)) {
    const n = Number(arg("tranco-n") ?? 20000);
    const top = readFileSync(trancoPath, "utf8").split("\n").map((l) => l.trim().split(",").pop() ?? "").filter(Boolean).slice(0, n);
    const subject = parseSubject("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD")!;
    let strong = 0, weak = 0, feedHits = 0, capped = 0, analyzed = 0;
    const examples: string[] = [];
    for (const d of top) {
      const a = analyzeDomain(d);
      if (!a) continue;
      analyzed++;
      const hits = checkFeeds(all, subject, a).hits;
      // Mirrors the provider: MetaMask hits cap; ScamSniffer domain hits cap only when corroborated.
      const corroborated = a.impersonation !== "none" || a.signals.some((s) => s === "suspicious_tld" || s === "lure_keyword" || s === "punycode");
      const caps = a.impersonation === "strong" || hits.some((h) => h.source === "metamask-phishing-detect" || (h.source === "scamsniffer-domains" && corroborated));
      if (a.impersonation === "strong") strong++;
      if (a.impersonation === "weak") weak++;
      if (hits.length) feedHits++;
      if (caps) capped++;
      if (caps && examples.length < 25) examples.push(`${d}: ${a.impersonation}${a.brand ? `(${a.brand})` : ""}${hits.length ? ` feed:${hits.map((h) => h.source).join("+")}` : ""}`);
    }
    const fp = wilson(capped, analyzed);
    layers["D_tranco_deterministic_scan"] = {
      expected: "safe",
      n: analyzed,
      strong_impersonation: strong,
      weak_brand_token_uncapped: weak,
      any_feed_hit: feedHits,
      capped_by_deterministic_rules: capped,
      capped_rate: `${(fp.p * 100).toFixed(3)}% (95% CI ${(fp.lo * 100).toFixed(3)}–${(fp.hi * 100).toFixed(3)}%) — upper bound on FP: popular ≠ benign (some listed hosts are genuine abuse)`,
      capped_examples: examples,
    };
  }
  return { timestamp: new Date().toISOString(), invalid_requests: invalid, sources: SOURCES, layers };
}

async function main(): Promise<void> {
  const key = process.env.TYPESAFE_API_KEY;
  if (!key && !process.env.AI_GATEWAY_API_KEY) throw new Error("requires TYPESAFE_API_KEY or AI_GATEWAY_API_KEY");
  const report = await runGrounded(key ? new JevClient({ apiKey: key }) : new GatewayJevClient());
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  writeFileSync(`${EVAL_EVIDENCE_DIR}/grounded-report.json`, JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report, null, 2));
}

if (process.argv[1]?.endsWith("grounded.ts")) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
