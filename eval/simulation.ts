// Simulation layer, externally grounded (no model calls).
//
// Positives: REAL transactions that victims sent TO ScamSniffer-listed drainer
// CONTRACTS on Ethereum, replayed with eth_simulateV1 at the latest block.
// Negatives: recent REAL user transactions to well-known contracts (routers,
// lending pool, WETH, Lido). In both cases the declared counterparty is the called
// contract — what a wallet sends for a contract call it cannot decode.
// A transaction counts as flagged when the simulation finds assets ending with an
// undisclosed plain wallet, an approval granted to a plain wallet, or assets parked
// with nothing in return in an unverified contract. Replays that revert at the latest
// block (deadlines, spent nonces, paused drainers) are reported separately, never
// counted as detections. Replays that move no assets at the latest block (the
// victim's approvals were already spent, balances already drained) still count as
// misses; the rate among replays that do move assets is reported alongside.
// Code-fingerprint matching is deliberately NOT applied here: the drainer contracts
// come from the same ScamSniffer list the runtime fingerprints are built from
// (measured separately, held out, in eval/code-fingerprint.ts).
//
//   npx tsx eval/simulation.ts [--drainers 300] [--per-contract 3] [--legit-per-contract 10] [--seed 7]
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { createSimulator, type SimulationEvidence } from "../src/simulation.js";
import { createContractIntel } from "../src/contract-intel.js";
import { EVAL_EVIDENCE_DIR } from "./harness.js";
import { sample, wilson } from "./stats.js";

const BS = "https://eth.blockscout.com/api/v2";
const LEGIT: Record<string, string> = {
  "Uniswap Universal Router v2": "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af",
  "Uniswap Universal Router v1.2": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
  "Uniswap V2 Router": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
  "1inch Aggregation Router v6": "0x111111125421cA6dc452d289314280a0f8842A65",
  "Aave V3 Pool": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
  "WETH": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
  "Lido stETH": "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84",
  "Balancer Vault": "0xBA12222222228d8Ba445958a75a0704d566BF2C8",
  "Uniswap SwapRouter02": "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
  "Uniswap V3 Positions NFT": "0xC36442b4a4522E871399CD717aBDD847Ab11FE88",
  "Seaport 1.6": "0x0000000000000068F116a894984e2DB1123eB395",
  "Seaport 1.5": "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC",
  "Blur Exchange": "0x000000000000Ad05Ccc4F10045630fb830B95127",
  "Curve 3pool": "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7",
  "Across SpokePool": "0x5c7BCd6E7De5423a257D81B442095A1a6ced35C5",
  "Lido Withdrawal Queue": "0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1",
  "ENS ETHRegistrarController": "0x59E16fcCd424Cc24e280Be16E11Bcd56fb0CE547",
  "Pendle Router V4": "0x888888888889758F76e7103c6CbF23ABbF58F946",
  "MetaMask Swap Router": "0x881D40237659C251811CEC9c364ef91dC08D300C",
  "USDC (transfers)": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "USDT (transfers)": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
};

const arg = (name: string, fallback: number): number => {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 ? Number(process.argv[i + 1]) : fallback;
};

async function bs<T>(path: string): Promise<T | null> {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(`${BS}${path}`, { headers: { accept: "application/json", "user-agent": "x402check-eval/0.3" }, signal: AbortSignal.timeout(20000) });
      if (res.status === 429) {
        await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
        continue;
      }
      return res.ok ? ((await res.json()) as T) : null;
    } catch {
      await new Promise((r) => setTimeout(r, 800));
    }
  }
  return null;
}

type Tx = { hash: string; from: string; to: string; value: string; input: string };
type TxList = { items?: Array<{ hash: string; from?: { hash: string; is_contract?: boolean }; to?: { hash: string }; value: string; raw_input?: string; status?: string | null }> };

async function incoming(contract: string, limit: number): Promise<Tx[]> {
  const list = await bs<TxList>(`/addresses/${contract}/transactions?filter=to`);
  return (list?.items ?? [])
    .filter((t) => t.status === "ok" && t.from && t.from.is_contract === false && t.to && (BigInt(t.value || "0") > 0n || (t.raw_input ?? "0x").length > 10))
    .slice(0, limit)
    .map((t) => ({ hash: t.hash, from: (t.from as { hash: string }).hash, to: (t.to as { hash: string }).hash, value: t.value, input: t.raw_input ?? "0x" }));
}

async function pool<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) {
      const k = i++;
      out[k] = await fn(items[k] as T);
    }
  }));
  return out;
}

type Row = { label: "drainer" | "legit"; contract: string; tx: string; status: SimulationEvidence["status"]; findings: string[]; flows: string; forwarderVerified?: boolean };

export async function runSimulationEval(opts: { drainers?: number; perContract?: number; legitPerContract?: number; seed?: number } = {}): Promise<Record<string, unknown>> {
  const cacheDir = new URL("../.cache/eval-sources/", import.meta.url);
  const file = readdirSync(cacheDir).find((f) => f.startsWith("scamsniffer-addresses"));
  if (!file) throw new Error("run eval/grounded.ts once to cache the ScamSniffer address list");
  const all = (JSON.parse(readFileSync(new URL(file, cacheDir), "utf8")) as string[]).filter((a) => /^0x[0-9a-fA-F]{40}$/.test(a));
  const candidates = sample(all, opts.drainers ?? 300, opts.seed ?? 7);

  const infos = await pool(candidates, 4, async (a) => ({ a, info: await bs<{ is_contract?: boolean }>(`/addresses/${a}`) }));
  const drainerContracts = infos.filter((x) => x.info?.is_contract === true).map((x) => x.a);
  const drainerTxs = (await pool(drainerContracts, 3, (c) => incoming(c, opts.perContract ?? 3))).flat();
  const legitTxs = (await pool(Object.values(LEGIT), 3, (c) => incoming(c, opts.legitPerContract ?? 10))).flat();

  const simulate = createSimulator({ timeoutMs: 8000, contractIntel: createContractIntel({ timeoutMs: 8000 }) });
  const run = async (label: Row["label"], t: Tx): Promise<Row> => {
    const r = await simulate({ from: t.from, to: t.to, value: t.value, data: t.input }, "eip155:1", { declared: [{ address: t.to }] });
    const flows = [
      ...(r.outflows ?? []).map((o) => `out ${o.standard}:${o.asset === "native" ? "ETH" : o.asset.slice(0, 10)}→${o.counterparty}${o.counterparty_is_contract === undefined ? "" : o.counterparty_is_contract ? "(contract)" : "(eoa)"}`),
      ...(r.inflows ?? []).map((i) => `in ${i.standard}:${i.asset === "native" ? "ETH" : i.asset.slice(0, 10)}`),
      ...(r.approvals ?? []).map((a) => `approve ${a.standard}→${a.spender}`),
    ].join("; ");
    return { label, contract: t.to.toLowerCase(), tx: t.hash, status: r.status, findings: r.findings ?? [], flows, ...(r.forwarder_verified !== undefined ? { forwarderVerified: r.forwarder_verified } : {}) };
  };
  const rows = [...(await pool(drainerTxs, 4, (t) => run("drainer", t))), ...(await pool(legitTxs, 4, (t) => run("legit", t)))];

  // "Flagged" = the provider would cap the score at 55 or below (high/critical). A hidden
  // recipient behind a source-verified forwarder and an incomplete simulation are review
  // (75, medium): counted separately as "review", never as detections.
  const flagged = (r: Row) =>
    ["outflow_exceeds_declared", "approval_to_eoa", "outflow_to_unverified_contract"].some((f) => r.findings.includes(f)) ||
    (r.findings.includes("outflow_to_undisclosed_eoa") && r.forwarderVerified !== true);
  const review = (r: Row) => !flagged(r) && (r.findings.includes("outflow_to_undisclosed_eoa") || r.findings.includes("simulation_incomplete"));
  const summarize = (label: Row["label"]) => {
    const g = rows.filter((r) => r.label === label);
    const ok = g.filter((r) => r.status === "ok");
    const hits = ok.filter(flagged).length;
    const w = wilson(hits, ok.length);
    const moving = ok.filter((r) => r.flows !== "");
    const wm = wilson(moving.filter(flagged).length, moving.length);
    return {
      transactions: g.length,
      contracts: new Set(g.map((r) => r.contract)).size,
      simulated_ok: ok.length,
      reverted_at_latest: g.filter((r) => r.status === "reverted").length,
      unavailable: g.filter((r) => r.status === "unavailable").length,
      flagged: `${hits}/${ok.length}`,
      review_only: ok.filter(review).length,
      rate: `${(w.p * 100).toFixed(1)}% (95% CI ${(w.lo * 100).toFixed(1)}–${(w.hi * 100).toFixed(1)}%)`,
      no_asset_movement_at_latest: ok.length - moving.length,
      flagged_when_assets_move: `${moving.filter(flagged).length}/${moving.length}`,
      rate_when_assets_move: `${(wm.p * 100).toFixed(1)}% (95% CI ${(wm.lo * 100).toFixed(1)}–${(wm.hi * 100).toFixed(1)}%)`,
      findings: ok.flatMap((r) => r.findings).reduce<Record<string, number>>((m, f) => ((m[f] = (m[f] ?? 0) + 1), m), {}),
      // Every miss (drainer) or false positive (legit) with its full hash and simulated flows, for audit.
      [label === "legit" ? "false_positives" : "misses"]: g
        .filter((r) => r.status === "ok" && (label === "legit" ? flagged(r) : !flagged(r)))
        .map((r) => ({ tx: r.tx, contract: r.contract, findings: r.findings, flows: r.flows || "(no asset movement)" })),
    };
  };
  return {
    timestamp: new Date().toISOString(),
    network: "eip155:1",
    candidates_sampled: candidates.length,
    drainer_contracts_found: drainerContracts.length,
    drainer: summarize("drainer"),
    legit: summarize("legit"),
    legit_contracts: LEGIT,
    // Every replayed transaction, for audit (replays run against the state at the time of the run).
    sample: rows.map((r) => ({ label: r.label, tx: r.tx, status: r.status, flagged: r.status === "ok" && flagged(r) })),
  };
}

async function main(): Promise<void> {
  const report = await runSimulationEval({ drainers: arg("drainers", 300), perContract: arg("per-contract", 3), legitPerContract: arg("legit-per-contract", 10), seed: arg("seed", 7) });
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  writeFileSync(`${EVAL_EVIDENCE_DIR}/simulation-report.json`, JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report, null, 2));
}

if (process.argv[1]?.endsWith("simulation.ts")) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
