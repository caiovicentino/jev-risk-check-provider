// Is x402check listed in Coinbase CDP's x402 Bazaar? Pays one per-call check and a one-item
// batch on Base (routed to CDP), proves each payment carried the `bazaar` discovery
// extension, then scans the public discovery catalog until both resources appear. The API
// ignores a payTo filter, so the whole catalog (~19k resources) is read.
//
//   X402CHECK_BASE=https://x402check.xyz PAY_NETWORK=eip155:8453 npx tsx eval/bazaar.ts
//   PAY=none npx tsx eval/bazaar.ts     # only report the listing
//
// Budget: $0.007 (two $0.0035 items). Report: eval/evidence/bazaar-report.json.
import { mkdirSync, writeFileSync } from "node:fs";
import { EVAL_EVIDENCE_DIR } from "./harness.js";
import { buildPayFetch, settlementReceipt } from "./paid-fetch.js";

const BASE = process.env.X402CHECK_BASE ?? "https://x402check.xyz";
const PAY_TO = "0xbF88b1F49B5e8Ec386289341c4a5ee00bB0E0178";
const DISCOVERY = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources";
const POLL_MINUTES = Number(process.env.POLL_MINUTES ?? 10);

type Listed = {
  resource: string;
  lastUpdated?: string;
  serviceName?: string;
  tags?: string[];
  iconUrl?: string;
  quality?: unknown;
  description?: string;
  accepts?: Array<{ network?: string; amount?: string; maxAmountRequired?: string; payTo?: string }>;
  extensions?: { bazaar?: { info?: { input?: { method?: string } } } };
};

/** Our entries in the catalog (paged; the API has no working filter by pay_to). */
async function listed(): Promise<{ ours: Listed[]; total: number }> {
  const ours: Listed[] = [];
  let total = 0;
  for (let offset = 0; ; offset += 1000) {
    const res = await fetch(`${DISCOVERY}?limit=1000&offset=${offset}`, { signal: AbortSignal.timeout(30_000) });
    if (!res.ok) throw new Error(`discovery HTTP ${res.status}`);
    const body = (await res.json()) as { items?: Listed[]; pagination?: { total?: number } };
    const items = body.items ?? [];
    total = body.pagination?.total ?? total;
    ours.push(...items.filter((i) => i.resource.startsWith(`${BASE}/`) && (i.accepts ?? []).some((a) => a.payTo === PAY_TO)));
    if (items.length < 1000) break;
  }
  return { ours, total };
}

const WANT = [`${BASE}/v1/risk-check`, `${BASE}/v1/risk-check/batch`];

async function main(): Promise<void> {
  const before = (await listed()).ours;
  console.log(`listed before: ${before.length} ${before.map((i) => i.resource).join(", ")}`);

  const sent: Array<Record<string, unknown>> = [];
  const observe: typeof fetch = (input, init) => {
    // The x402 fetch wrapper passes a Request (headers inside it), not an init object.
    const sig = (input instanceof Request ? input.headers : new Headers(init?.headers)).get("payment-signature");
    if (sig) sent.push(JSON.parse(Buffer.from(sig, "base64").toString("utf8")) as Record<string, unknown>);
    return fetch(input, init);
  };
  const paid: Array<{ path: string; status: number; transaction: string | null; payment_carried_bazaar: boolean }> = [];
  if (process.env.PAY !== "none") {
    const pay = await buildPayFetch(observe);
    const subject = { wallet: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", chain: "base" };
    for (const [path, body] of [["/v1/risk-check", subject], ["/v1/risk-check/batch", { requests: [subject] }]] as const) {
      const before = sent.length;
      const res = await pay(`${BASE}${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(60_000) });
      const payload = sent[before] ?? {};
      const bazaar = (payload.extensions as Listed["extensions"])?.bazaar;
      const receipt = settlementReceipt(res.headers);
      paid.push({ path, status: res.status, transaction: receipt?.transaction ?? null, payment_carried_bazaar: Boolean(bazaar) });
      console.log(`paid ${path}: HTTP ${res.status}, tx ${receipt?.transaction ?? "none"}; payment carried bazaar: ${Boolean(bazaar)} (method ${bazaar?.info?.input?.method ?? "-"})`);
    }
  }

  let after = before;
  let total = 0;
  const deadline = Date.now() + POLL_MINUTES * 60_000;
  for (;;) {
    ({ ours: after, total } = await listed());
    if (WANT.every((w) => after.some((i) => i.resource === w)) || Date.now() > deadline) break;
    await new Promise((r) => setTimeout(r, 30_000));
  }
  for (const w of WANT) {
    const e = after.find((i) => i.resource === w);
    console.log(e ? `LISTED ${w} · updated ${e.lastUpdated} · ${e.serviceName} · tags ${JSON.stringify(e.tags)} · icon ${e.iconUrl ? "yes" : "no"} · ${e.accepts?.length} networks · method ${e.extensions?.bazaar?.info?.input?.method ?? "-"}` : `NOT LISTED ${w}`);
  }
  const report = {
    timestamp: new Date().toISOString(),
    base: BASE,
    catalog_total: total,
    paid,
    listed: after.map((i) => ({
      resource: i.resource,
      lastUpdated: i.lastUpdated ?? null,
      serviceName: i.serviceName ?? null,
      tags: i.tags ?? [],
      iconUrl: i.iconUrl ?? null,
      quality: i.quality ?? null,
      method: i.extensions?.bazaar?.info?.input?.method ?? null,
      accepts: (i.accepts ?? []).map((a) => ({ network: a.network, amount: a.amount ?? a.maxAmountRequired })),
    })),
    all_listed: WANT.every((w) => after.some((i) => i.resource === w)),
  };
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  writeFileSync(`${EVAL_EVIDENCE_DIR}/bazaar-report.json`, JSON.stringify(report, null, 2));
  if (!report.all_listed) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
