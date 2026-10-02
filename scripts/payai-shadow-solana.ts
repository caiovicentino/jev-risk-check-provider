// Shadow evaluation of a facilitator's Solana traffic, from public on-chain data only (the Solana
// half of scripts/payai-shadow.ts).
//
// PayAI publishes its Solana fee payers (x402 v2 /supported → signers["solana:*"]): every payment
// it settles is a transaction one of them pays the fee for. Every signature of the window is
// counted; a seeded random sample of the successful ones is read in full (a public RPC serves a
// few transactions a second, not the week's tens of thousands), and each USDC transferChecked in
// it is a payment: the transfer's authority is the payer, the destination account's owner the payee.
// Every payer and payee in the sample is screened against the OFAC SDN list, the deterministic
// layer x402check has for Solana addresses (the community address lists and the kit watch are EVM).
//
//   npx tsx scripts/payai-shadow-solana.ts [--days 7] [--sample 3000] [--seed 402] [--out payai-shadow-solana-report.json]
//
// Outputs: eval/evidence/<out> (aggregates only: no addresses) and
// .cache/intel/payai-shadow-solana-details.json (per-address results; private).
import { mkdirSync, writeFileSync } from "node:fs";
import { parseSubject } from "../src/address.js";
import { screenSubject } from "../src/sanctions.js";

const RPC = process.env.SOL_RPC ?? "https://api.mainnet-beta.solana.com";
const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const INTEL = new URL("../.cache/intel/", import.meta.url);
const arg = (name: string, fallback: string): string => {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : (process.argv[i + 1] as string);
};

async function rpc<T>(method: string, params: unknown[]): Promise<T> {
  for (let attempt = 0; attempt < 8; attempt++) {
    try {
      const res = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json", "user-agent": "x402check-shadow/0.6" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(45000) });
      if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
      const body = (await res.json()) as { result?: T; error?: { message?: string } };
      if (body.error) throw new Error(body.error.message ?? "rpc error");
      return body.result as T;
    } catch {
      await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
    }
  }
  throw new Error(`${method}: no answer after retries`);
}

type Sig = { signature: string; blockTime?: number | null; err?: unknown };

/** Every signature of `address` since `since` (unix seconds), newest first. A page that cannot be read aborts. */
async function signatures(address: string, since: number): Promise<Sig[]> {
  const out: Sig[] = [];
  let before: string | undefined;
  for (;;) {
    const page = await rpc<Sig[]>("getSignaturesForAddress", [address, { limit: 1000, ...(before ? { before } : {}) }]);
    for (const s of page) if ((s.blockTime ?? 0) >= since) out.push(s);
    const last = page[page.length - 1];
    if (page.length < 1000 || !last || (last.blockTime ?? 0) < since) break;
    before = last.signature;
  }
  return out;
}

/** A seeded shuffle (mulberry32): the same seed draws the same sample. */
function sample<T>(items: T[], n: number, seed: number): T[] {
  let a = seed >>> 0;
  const rand = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const copy = [...items];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [copy[i], copy[j]] = [copy[j] as T, copy[i] as T];
  }
  return copy.slice(0, n);
}

type Ix = { program?: string; parsed?: { type?: string; info?: Record<string, unknown> } };
type ParsedTx = {
  meta?: { err?: unknown; postTokenBalances?: Array<{ accountIndex: number; mint: string; owner?: string }>; innerInstructions?: Array<{ instructions: Ix[] }> } | null;
  transaction?: { message?: { accountKeys?: Array<{ pubkey: string } | string>; instructions?: Ix[] } };
};
type Payment = { sig: string; payer: string; payTo: string; amount: number };

/** The USDC transferChecked payments in a transaction: authority → owner of the destination account. */
function paymentsOf(sig: string, tx: ParsedTx): Payment[] {
  const keys = (tx.transaction?.message?.accountKeys ?? []).map((k) => (typeof k === "string" ? k : k.pubkey));
  const ownerOf = new Map<string, string>();
  for (const b of tx.meta?.postTokenBalances ?? []) if (b.owner) ownerOf.set(keys[b.accountIndex] ?? "", b.owner);
  const all = [...(tx.transaction?.message?.instructions ?? []), ...(tx.meta?.innerInstructions ?? []).flatMap((i) => i.instructions)];
  const out: Payment[] = [];
  for (const ix of all) {
    const info = ix.parsed?.info;
    if (ix.program !== "spl-token" || ix.parsed?.type !== "transferChecked" || !info || info.mint !== USDC) continue;
    const payer = String(info.authority ?? info.multisigAuthority ?? "");
    const payTo = ownerOf.get(String(info.destination)) ?? "";
    const amount = Number((info.tokenAmount as { amount?: string } | undefined)?.amount ?? 0) / 1e6;
    if (payer && payTo && payer !== payTo) out.push({ sig, payer, payTo, amount });
  }
  return out;
}

async function pool<T, R>(items: T[], size: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: size }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i] as T);
      }
    }),
  );
  return out;
}

async function main(): Promise<void> {
  const days = Number(arg("days", "7"));
  const n = Number(arg("sample", "3000"));
  const seed = Number(arg("seed", "402"));
  const facilitator = arg("facilitator", "https://facilitator.payai.network");
  const since = Math.floor(Date.now() / 1000) - days * 86400;
  const supported = (await (await fetch(`${facilitator}/supported`)).json()) as { signers?: Record<string, string[]> };
  const signers = supported.signers?.["solana:*"] ?? [];
  if (!signers.length) throw new Error("facilitator publishes no Solana signers");
  console.log(`${facilitator}: ${signers.length} Solana fee payers; window ${days} days`);

  const perSigner = await Promise.all(signers.map((s) => signatures(s, since)));
  const all = perSigner.flat();
  const ok = [...new Map(all.filter((s) => !s.err).map((s) => [s.signature, s])).values()];
  console.log(`  ${all.length} signatures, ${ok.length} successful; reading a sample of ${Math.min(n, ok.length)}`);

  const drawn = sample(ok, n, seed);
  let unreadable = 0;
  const txs = await pool(drawn, 3, async (s) => {
    try {
      return { sig: s.signature, tx: await rpc<ParsedTx | null>("getTransaction", [s.signature, { encoding: "jsonParsed", maxSupportedTransactionVersion: 0 }]) };
    } catch {
      unreadable++;
      return { sig: s.signature, tx: null };
    }
  });
  const pays = txs.flatMap(({ sig, tx }) => (tx ? paymentsOf(sig, tx) : []));
  const withPayment = new Set(pays.map((p) => p.sig)).size;
  const read = drawn.length - unreadable;

  // --- screening: every payer and payee in the sample ---
  const payTos = [...new Set(pays.map((p) => p.payTo))];
  const payers = [...new Set(pays.map((p) => p.payer))];
  const listed = new Set([...payTos, ...payers].filter((a) => {
    const subject = parseSubject(a);
    return !!subject && screenSubject(subject).status === "listed";
  }));

  const amounts = pays.map((p) => p.amount).sort((x, y) => x - y);
  const q = (p: number) => (amounts.length ? (amounts[Math.min(amounts.length - 1, Math.floor(p * amounts.length))] as number) : 0);
  const byPayTo = new Map<string, number>();
  for (const p of pays) byPayTo.set(p.payTo, (byPayTo.get(p.payTo) ?? 0) + 1);
  const top = [...byPayTo.values()].sort((x, y) => y - x);
  const share = read ? withPayment / read : 0;
  const meanPerTx = withPayment ? pays.length / withPayment : 0;
  const volume = pays.reduce((s, p) => s + p.amount, 0);
  const report = {
    timestamp: new Date().toISOString(),
    facilitator,
    network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    window_days: days,
    method: "every signature of the facilitator's published Solana fee payers (x402 v2 /supported) in the window, counted; a seeded random sample of the successful ones read in full; payments are their USDC transferChecked instructions (authority → destination owner); every sampled payer and payee screened against the OFAC SDN list (no model calls)",
    signers: { published: signers.length, active: perSigner.filter((l) => l.length > 0).length },
    signatures: { total: all.length, successful: ok.length },
    sample: { seed, drawn: drawn.length, read, unreadable, with_usdc_payment: withPayment, usdc_payments: pays.length },
    sample_usdc_volume: Math.round(volume * 100) / 100,
    usdc_amount_quantiles: { p10: q(0.1), p50: q(0.5), p90: q(0.9), p99: q(0.99) },
    estimate_for_window: {
      usdc_payments: Math.round(ok.length * share * meanPerTx),
      usdc_volume: read ? Math.round((volume / read) * ok.length) : 0,
      note: "the sample's payment share and mean amount applied to every successful signature of the window",
    },
    payees_in_sample: { distinct: payTos.length, top10_share_of_payments: pays.length ? Math.round((top.slice(0, 10).reduce((s, k) => s + k, 0) / pays.length) * 1000) / 1000 : 0 },
    payers_in_sample: { distinct: payers.length },
    flags: {
      ofac_listed_payees: payTos.filter((a) => listed.has(a)).length,
      ofac_listed_payers: payers.filter((a) => listed.has(a)).length,
      payments_involving_listed: pays.filter((p) => listed.has(p.payer) || listed.has(p.payTo)).length,
    },
    cost_if_every_payment_were_checked_usd: Math.round(ok.length * share * meanPerTx * 0.001 * 100) / 100,
  };
  mkdirSync("eval/evidence", { recursive: true });
  writeFileSync(`eval/evidence/${arg("out", "payai-shadow-solana-report.json")}`, JSON.stringify(report, null, 2));
  mkdirSync(INTEL, { recursive: true });
  writeFileSync(new URL("payai-shadow-solana-details.json", INTEL), JSON.stringify({ report, top_payees: [...byPayTo].sort((a, b) => b[1] - a[1]).slice(0, 25), listed: [...listed] }, null, 1));
  console.log(JSON.stringify(report, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
