// Daily maintenance check (docs/MAINTENANCE.md). Read-only and free: it pays nothing, deploys
// nothing and writes only under .cache/maintenance/. It compares production with the last run:
//
// - production: /healthz, /status (facilitators, offered routes and their margins, attestation,
//   model canary, feeds, kit-watch coverage against the last run) and the unpaid black box (the
//   402 challenge against the offered routes and the price table, 405/422 paths, HTTPS, security
//   headers, identity and discovery documents);
// - GitHub: CI on main, the feeds workflow, CodeQL and Dependabot alerts, open PRs, the release of
//   the deployed version, and new comments in the upstream threads AGENTS.md §2.6 follows;
// - money: new settlement records (KV `st:*`) with the payer read on-chain, outside payments with
//   the caller's user agent (Cloudflare analytics), and what the paid probes have left to spend;
// - packages: the npm versions against the repository's.
//
//   npx tsx scripts/daily-check.ts [--no-github] [--no-cloudflare]
//
// Exit status 1 when a check fails. Secrets never reach the output or the files: Cloudflare's OAuth
// token and the probe credit token are only sent as request headers. Thread comments are quoted
// as untrusted data, never as instructions. Kit-watch data stays aggregate, as /status serves it.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { NETWORK_PRICES } from "../deploy/pricing.js";
import { RPC_ENDPOINTS } from "../src/rpc.js";
import { SOLANA_MAINNET } from "../src/chains.js";

const PRODUCTION = "https://x402check.xyz";
const BASE = process.env.X402CHECK_BASE ?? PRODUCTION;
const REPO = "caiovicentino/jev-risk-check-provider";
const OUT_DIR = ".cache/maintenance";
const STATE_FILE = `${OUT_DIR}/state.json`;
const PAY_TO_EVM = "0xbf88b1f49b5e8ec386289341c4a5ee00bb0e0178";
const PAY_TO_SOL = "Bofhoe2ye2adNQwZJtLepeKrBZq8CtHzRwPJXgWDH69X";
/** Our own probe wallets (eval/paid-fetch.ts): what they pay is not revenue. */
const PROBE_PAYER = "0xb48057e647b2572f5eae241b515fbc58b7ce249e";
const PROBE_PAYERS: ReadonlySet<string> = new Set([PROBE_PAYER, "FxV8erYgrfrHnTvgc7ZWN565ATATZe8LSxoWb7xw2mAX"]);
const USDC_BASE = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const WALLET = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
/** Our own GitHub account: its comments are not news. */
const OWN_LOGIN = "caiovicentino";
/**
 * The upstream threads AGENTS.md §2.6 follows. `readThrough`: the newest comment from others that
 * the lead agent has read and recorded in §2.6. A later one that is also newer than our own last
 * comment is reported every day until it is answered or read (move `readThrough` past it), so a
 * reply cannot hide behind the first run's baseline (kora#682 waited 17 days that way).
 */
export const THREADS: ReadonlyArray<{ repo: string; number: number; label: string; readThrough: string }> = [
  { repo: "x402-foundation/x402", number: 2300, label: "x402#2300 (trust provider)", readThrough: "2026-10-14T05:55:24Z" },
  { repo: "x402-foundation/x402", number: 3597, label: "x402#3597 (our issue)", readThrough: "2026-09-29T07:31:38Z" },
  { repo: "x402-foundation/x402", number: 2422, label: "x402#2422 (risk-check spec)", readThrough: "2026-05-25T16:31:12Z" },
  { repo: "PayAINetwork/docs", number: 98, label: "PayAI docs#98 (shadow proposal)", readThrough: "2026-09-29T00:00:00Z" },
  { repo: "solana-foundation/kora", number: 682, label: "kora#682 (fee-payer gate)", readThrough: "2026-10-06T14:48:40Z" },
  { repo: "romudille-bit/agentpay", number: 9, label: "agentpay#9 (pay_to screen)", readThrough: "2026-10-02T16:04:36Z" },
  { repo: "romudille-bit/awesome-x402", number: 1, label: "awesome-x402#1 (our listing PR)", readThrough: "2026-10-01T00:00:00Z" },
];
/** EVM RPCs for networks the evaluation tables do not cover (settlement payers only). */
const EXTRA_RPC: Record<string, readonly string[]> = {
  "eip155:143": ["https://rpc.monad.xyz"],
  "eip155:1329": ["https://evm-rpc.sei-apis.com"],
};

export type Level = "ok" | "info" | "warn" | "fail";
export type Check = { id: string; level: Level; detail: string };

type Route = { network: string; facilitator: string | null; transfer_method: string | null; margin_usd: number | null; margin_pct: number | null; offered?: boolean; reason?: string };
type ChainView = { status: string; lag_blocks: number; gaps: number; unbroken_since?: number; pending_reads: number; error?: string };
export type Status = {
  version: string;
  data: {
    ofac_sdn: { as_of: string; age_days: number; origin: string };
    metamask_phishing: { as_of: string; age_days: number; origin: string };
    scamsniffer: { status?: string; stale?: boolean; refreshed_at?: string };
    kit_watch: { status: string; age_s?: number | null; chains: Record<string, ChainView> };
  };
  refresh: { checked_at: string | null; published_at: string | null; error: string | null };
  payments: Route[] | { status: string };
  facilitators: Array<{ name: string; ok: boolean; error?: string }> | { status: string };
  attestation: { ok: boolean; kid: string; thumbprint: string | null; reason?: string };
  model: { canary: { ok: boolean; stale: boolean; at: string } | null };
};
export type OutsidePayment = { key: string; at: string; network: string; path: string; payer: string; micro: number; ua?: string; country?: string; worker?: boolean; undelivered?: boolean };
export type State = {
  at: string;
  kit_watch?: Record<string, { gaps: number; unbroken_since?: number }>;
  settlements_seen?: string[];
  outside?: OutsidePayment[];
  threads?: Record<string, { comments: number; updated_at: string }>;
  /** Kept for the agent (the session cron's renewal); the check never changes it. */
  cron?: Record<string, unknown>;
};

/** How far behind each chain may be, in blocks: a warning past 5 minutes, a failure past an hour. */
const LAG: Record<string, { warn: number; fail: number }> = { "eip155:1": { warn: 25, fail: 300 }, "eip155:8453": { warn: 150, fail: 1800 } };

/** The checks on /status alone, against the last run's state (pure: tested in test/daily-check.test.ts). */
export function statusChecks(status: Status, prev: State | null, published?: { metamask?: string; ofac?: string }): Check[] {
  const out: Check[] = [];
  const add = (id: string, level: Level, detail: string) => out.push({ id, level, detail });

  // Facilitators and routes: every offered route must clear its cost.
  if (Array.isArray(status.facilitators)) {
    const down = status.facilitators.filter((f) => !f.ok);
    add("facilitators", down.length ? "fail" : "ok", down.length ? `down: ${down.map((f) => `${f.name} (${f.error ?? "?"})`).join(", ")}` : status.facilitators.map((f) => f.name).join(", "));
  } else add("facilitators", "fail", `unavailable (${status.facilitators.status})`);
  if (Array.isArray(status.payments)) {
    const offered = status.payments.filter((r) => r.offered !== false);
    const losing = offered.filter((r) => r.margin_usd !== null && r.margin_usd <= 0);
    const unknown = offered.filter((r) => r.margin_usd === null);
    const base = offered.find((r) => r.network === "eip155:8453");
    const level: Level = losing.length || !base ? "fail" : unknown.length ? "warn" : "ok";
    add("payments", level, `${offered.length} networks offered${base ? "" : ", Base NOT offered"}; margins ${offered.map((r) => `${short(r.network)} ${r.margin_pct ?? "?"}%`).join(", ")}${losing.length ? `; LOSING: ${losing.map((r) => short(r.network)).join(", ")}` : ""}`);
    const notOffered = status.payments.filter((r) => r.offered === false);
    if (notOffered.length) add("payments.not_offered", "info", notOffered.map((r) => `${short(r.network)} (${r.reason}: ${r.facilitator ?? "none"} ${r.margin_pct ?? "?"}%)`).join(", "));
  } else add("payments", "fail", `unavailable (${status.payments.status})`);

  add("attestation", status.attestation.ok ? "ok" : "fail", status.attestation.ok ? `${status.attestation.kid} ${status.attestation.thumbprint}` : `misconfigured: ${status.attestation.reason ?? "?"}`);
  const canary = status.model.canary;
  add("model_canary", !canary ? "warn" : !canary.ok ? "fail" : canary.stale ? "warn" : "ok", canary ? `ok=${canary.ok} stale=${canary.stale} at ${canary.at}` : "no canary yet");

  // Feeds. /status describes the isolate that answered: a new one serves its embedded lists until
  // its first refresh, so the comparison is with what the feeds branch publishes.
  const d = status.data;
  add("feeds.scamsniffer", d.scamsniffer.stale || d.scamsniffer.status === "unavailable" ? "warn" : "ok", `refreshed ${d.scamsniffer.refreshed_at ?? "?"}${d.scamsniffer.stale ? " (STALE)" : ""}`);
  const behind = (served: string, pub: string | undefined) => !!pub && served < pub;
  add("feeds.ofac", behind(d.ofac_sdn.as_of, published?.ofac) ? "warn" : "ok", `served ${d.ofac_sdn.as_of} (${d.ofac_sdn.origin}), published ${published?.ofac ?? "?"}`);
  const mmBehindDays = published?.metamask ? Math.round((Date.parse(published.metamask) - Date.parse(d.metamask_phishing.as_of)) / 86_400_000) : 0;
  add("feeds.metamask", mmBehindDays > 2 ? "warn" : "ok", `served ${d.metamask_phishing.as_of} (${d.metamask_phishing.origin}), published ${published?.metamask ?? "?"}${mmBehindDays > 2 ? `: this isolate is ${mmBehindDays} days behind` : ""}`);
  if (status.refresh.error) add("feeds.refresh", "warn", status.refresh.error);

  // Kit watch: lag, errors, queued work, and whether coverage gained a hole since the last run.
  const kw = d.kit_watch;
  add("kit_watch", kw.status === "stale" ? "fail" : kw.status === "ok" ? "ok" : "warn", `status ${kw.status}, stats ${kw.age_s ?? "?"} s old`);
  for (const [chain, c] of Object.entries(kw.chains ?? {})) {
    const lag = LAG[chain] ?? { warn: 100, fail: 1000 };
    const was = prev?.kit_watch?.[chain];
    const newGaps = was ? c.gaps - was.gaps : 0;
    const moved = !!was && was.unbroken_since !== undefined && c.unbroken_since !== was.unbroken_since;
    let level: Level = "ok";
    if (c.lag_blocks > lag.warn || c.error || c.pending_reads >= 50 || newGaps > 0 || moved) level = "warn";
    if (c.lag_blocks > lag.fail || newGaps > 1000) level = "fail";
    const parts = [`lag ${c.lag_blocks}`, `gaps ${c.gaps}${was ? ` (${newGaps >= 0 ? "+" : ""}${newGaps} since last run)` : ""}`, `unbroken_since ${c.unbroken_since ?? "?"}${moved ? ` (moved from ${was?.unbroken_since})` : ""}`, `pending ${c.pending_reads}`];
    if (c.error) parts.push(`error: ${clean(c.error, 160)}`);
    add(`kit_watch.${short(chain)}`, level, parts.join(", "));
  }
  return out;
}

type Accept = { network: string; amount: string; extra?: Record<string, unknown> };

/** The unpaid 402 challenge must list exactly the offered networks, at the table's prices (pure). */
export function challengeCheck(accepts: Accept[], routes: Route[]): Check {
  const offered = routes.filter((r) => r.offered !== false);
  const want = new Set(offered.map((r) => r.network));
  const got = new Set(accepts.map((a) => a.network));
  const problems: string[] = [];
  for (const n of want) if (!got.has(n)) problems.push(`${short(n)} missing`);
  for (const n of got) if (!want.has(n)) problems.push(`${short(n)} offered but not routed`);
  for (const a of accepts) {
    const price = NETWORK_PRICES[a.network];
    if (price !== undefined && a.amount !== String(Math.round(price * 1e6))) problems.push(`${short(a.network)} amount ${a.amount} ≠ ${Math.round(price * 1e6)}`);
    const permit2 = a.extra?.assetTransferMethod === "permit2";
    const route = offered.find((r) => r.network === a.network);
    if (route && permit2 !== (route.transfer_method === "permit2")) problems.push(`${short(a.network)} transfer method ≠ route`);
  }
  return { id: "blackbox.challenge", level: problems.length ? "fail" : "ok", detail: problems.length ? problems.join("; ") : `${accepts.length} options, prices and transfer methods match` };
}

/** Text from others (comments, titles, errors) for a terminal and a file: control and bidi characters are blanked. */
export function clean(text: string, max = 240): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
}

function short(network: string): string {
  return ({ "eip155:1": "ethereum", "eip155:8453": "base", "eip155:137": "polygon", "eip155:42161": "arbitrum", "eip155:43114": "avalanche", "eip155:143": "monad", "eip155:1329": "sei", [SOLANA_MAINNET]: "solana" } as Record<string, string>)[network] ?? network;
}

// --- I/O ----------------------------------------------------------------------------------

async function http(path: string, init: RequestInit = {}): Promise<{ status: number; headers: Headers; text: string }> {
  const res = await fetch(path.startsWith("http") ? path : `${BASE}${path}`, { redirect: "manual", ...init, signal: AbortSignal.timeout(30_000) });
  return { status: res.status, headers: res.headers, text: init.method === "HEAD" ? "" : await res.text() };
}
const parse = <T>(text: string): T | null => {
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
};

function run(cmd: string, args: string[], timeoutMs = 120_000): string {
  return execFileSync(cmd, args, { encoding: "utf8", timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 * 1024 * 1024 });
}
function gh<T>(args: string[]): T {
  return JSON.parse(run("gh", args)) as T;
}

async function rpc(urls: readonly string[], method: string, params: unknown[]): Promise<unknown> {
  for (const url of urls) {
    try {
      const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(15_000) });
      const body = (await res.json()) as { result?: unknown };
      if (body.result !== undefined && body.result !== null) return body.result;
    } catch {
      // next endpoint
    }
  }
  return null;
}

/** Cloudflare: wrangler's OAuth token (refreshed by `wrangler whoami` when it is about to lapse). */
function cloudflareToken(): string | null {
  const paths = [`${homedir()}/Library/Preferences/.wrangler/config/default.toml`, `${homedir()}/.config/.wrangler/config/default.toml`, `${homedir()}/.wrangler/config/default.toml`];
  const read = () => {
    const file = paths.find((p) => existsSync(p));
    if (!file) return null;
    const toml = readFileSync(file, "utf8");
    const token = /oauth_token\s*=\s*"([^"]+)"/.exec(toml)?.[1] ?? null;
    const expires = Date.parse(/expiration_time\s*=\s*"([^"]+)"/.exec(toml)?.[1] ?? "");
    return { token, expires };
  };
  let cfg = read();
  if (!cfg?.token || !Number.isFinite(cfg.expires) || cfg.expires - Date.now() < 5 * 60_000) {
    try {
      run("npx", ["wrangler", "whoami"], 60_000);
    } catch {
      return null;
    }
    cfg = read();
  }
  return cfg?.token ?? null;
}
async function cf<T>(token: string, path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`https://api.cloudflare.com/client/v4${path}`, { ...init, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", ...(init.headers ?? {}) }, signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`cloudflare ${path.split("?")[0]}: HTTP ${res.status}`);
  return (await res.json()) as T;
}

/** The payer of a settlement, read on-chain: the sender of the transfer to our pay_to. */
async function payerOf(network: string, tx: string): Promise<{ payer: string; micro: number } | null> {
  if (network === SOLANA_MAINNET) {
    type Ix = { program?: string; parsed?: { type?: string; info?: Record<string, unknown> } };
    const t = (await rpc(RPC_ENDPOINTS[SOLANA_MAINNET] ?? [], "getTransaction", [tx, { encoding: "jsonParsed", maxSupportedTransactionVersion: 0 }])) as {
      meta?: { postTokenBalances?: Array<{ accountIndex: number; owner?: string }>; innerInstructions?: Array<{ instructions: Ix[] }> };
      transaction?: { message?: { accountKeys?: Array<{ pubkey: string } | string>; instructions?: Ix[] } };
    } | null;
    if (!t) return null;
    const keys = (t.transaction?.message?.accountKeys ?? []).map((k) => (typeof k === "string" ? k : k.pubkey));
    const owner = new Map((t.meta?.postTokenBalances ?? []).map((b) => [keys[b.accountIndex] ?? "", b.owner ?? ""]));
    for (const ix of [...(t.transaction?.message?.instructions ?? []), ...(t.meta?.innerInstructions ?? []).flatMap((i) => i.instructions)]) {
      const info = ix.parsed?.info;
      if (ix.program !== "spl-token" || ix.parsed?.type !== "transferChecked" || !info) continue;
      if (owner.get(String(info.destination)) !== PAY_TO_SOL) continue;
      return { payer: String(info.authority ?? ""), micro: Number((info.tokenAmount as { amount?: string } | undefined)?.amount ?? 0) };
    }
    return null;
  }
  const urls = RPC_ENDPOINTS[network] ?? EXTRA_RPC[network];
  if (!urls) return null;
  const receipt = (await rpc(urls, "eth_getTransactionReceipt", [tx])) as { logs?: Array<{ topics: string[]; data: string }> } | null;
  const to = `0x${PAY_TO_EVM.slice(2).padStart(64, "0")}`;
  const log = receipt?.logs?.find((l) => l.topics[0] === TRANSFER_TOPIC && l.topics[2]?.toLowerCase() === to);
  if (!log?.topics[1]) return null;
  return { payer: `0x${log.topics[1].slice(26)}`.toLowerCase(), micro: Number(BigInt(log.data)) };
}

function thumbprint(jwk: { crv?: string; kty?: string; x?: string; y?: string }): string {
  return createHash("sha256").update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest("base64url");
}

// --- the run ------------------------------------------------------------------------------

/**
 * The last word in a thread, when it needs us: someone else's comment, newer than our own last
 * comment and than what §2.6 records as read (`readThrough`). Its text is not shown: it is
 * untrusted, and the reader opens the link.
 */
function unanswered(t: (typeof THREADS)[number]): string | undefined {
  const all = gh<Array<{ user: { login: string }; created_at: string; html_url: string }>>(["api", `repos/${t.repo}/issues/${t.number}/comments?per_page=100`]);
  const ours = all.filter((c) => c.user.login === OWN_LOGIN).at(-1)?.created_at ?? "";
  const theirs = all.filter((c) => c.user.login !== OWN_LOGIN && !c.user.login.endsWith("[bot]")).at(-1);
  if (!theirs || theirs.created_at <= ours || theirs.created_at <= t.readThrough) return undefined;
  return `${t.label}: unanswered since ${theirs.created_at.slice(0, 16)}, ${clean(theirs.user.login, 40)} ${clean(theirs.html_url, 120)}: read it, answer or record it in AGENTS.md §2.6, then move readThrough in scripts/daily-check.ts`;
}

async function main(): Promise<void> {
  // --threads: only the followed threads' last word, read-only (no files written); for the thread watch.
  if (process.argv.includes("--threads")) {
    const open = THREADS.map((t) => {
      try {
        return unanswered(t);
      } catch (err) {
        return `${t.label}: check could not run: ${String(err instanceof Error ? err.message : err).slice(0, 200)}`;
      }
    }).filter((line): line is string => line !== undefined);
    console.log(open.length ? open.map((line) => `WARN  ${line}`).join("\n") : `OK    threads — the last word is ours, or read, in all ${THREADS.length}`);
    return;
  }
  const noGithub = process.argv.includes("--no-github");
  const noCloudflare = process.argv.includes("--no-cloudflare");
  mkdirSync(OUT_DIR, { recursive: true });
  const prev = existsSync(STATE_FILE) ? (JSON.parse(readFileSync(STATE_FILE, "utf8")) as State) : null;
  const checks: Check[] = [];
  const add = (id: string, level: Level, detail: string): void => {
    checks.push({ id, level, detail });
  };
  const guard = async (id: string, fn: () => Promise<void>) => {
    try {
      await fn();
    } catch (err) {
      add(id, "warn", `check could not run: ${String(err instanceof Error ? err.message : err).slice(0, 200)}`);
    }
  };
  const now = new Date();
  const next: State = { ...(prev ?? {}), at: now.toISOString() };

  // --- production ---
  const health = await http("/healthz");
  const hz = parse<{ ok?: boolean; version?: string; commit?: string; attestation_key?: string }>(health.text) ?? {};
  add("healthz", health.status === 200 && hz.ok && hz.attestation_key === "ok" ? "ok" : "fail", `HTTP ${health.status} v${hz.version} ${hz.commit} key ${hz.attestation_key}`);
  const statusRes = await http("/status");
  const status = parse<Status>(statusRes.text);
  let published: { metamask?: string; ofac?: string } = {};
  await guard("feeds.published", async () => {
    const m = parse<{ metamask?: { as_of?: string }; ofac?: { publish_date?: string } }>((await http(`https://raw.githubusercontent.com/${REPO}/feeds/manifest.json`)).text);
    published = { ...(m?.metamask?.as_of ? { metamask: m.metamask.as_of } : {}), ...(m?.ofac?.publish_date ? { ofac: m.ofac.publish_date } : {}) };
  });
  // /status describes the isolate that answered. A new isolate waits up to 2.5 s for its feeds
  // before answering (as a paid request does), and can still answer behind when they take longer.
  // A list behind the published one is looked at again on up to two more isolates before it counts.
  const behind = (s: Status) => (!!published.metamask && s.data.metamask_phishing.as_of < published.metamask) || (!!published.ofac && s.data.ofac_sdn.as_of < published.ofac);
  if (status && behind(status)) {
    for (let i = 0; i < 2 && behind(status); i++) {
      await new Promise((r) => setTimeout(r, 3000));
      const again = parse<Status>((await http("/status")).text);
      if (again && again.data.metamask_phishing.as_of > status.data.metamask_phishing.as_of) status.data.metamask_phishing = again.data.metamask_phishing;
      if (again && again.data.ofac_sdn.as_of > status.data.ofac_sdn.as_of) status.data.ofac_sdn = again.data.ofac_sdn;
    }
  }
  if (!status) add("status", "fail", `HTTP ${statusRes.status}: not JSON`);
  else {
    checks.push(...statusChecks(status, prev, published));
    next.kit_watch = Object.fromEntries(Object.entries(status.data.kit_watch.chains ?? {}).map(([c, v]) => [c, { gaps: v.gaps, ...(v.unbroken_since !== undefined ? { unbroken_since: v.unbroken_since } : {}) }]));
  }

  // --- the unpaid black box ---
  await guard("blackbox", async () => {
    const unpaid = await http("/v1/risk-check", { method: "POST" });
    const header = unpaid.headers.get("payment-required");
    const accepts = header ? (JSON.parse(Buffer.from(header, "base64").toString("utf8")) as { accepts: Accept[] }).accepts : [];
    if (unpaid.status !== 402 || !header) add("blackbox.challenge", "fail", `unpaid POST without a body: HTTP ${unpaid.status}${header ? "" : ", no PAYMENT-REQUIRED"}`);
    else if (status && Array.isArray(status.payments)) checks.push(challengeCheck(accepts, status.payments));
    const expect = async (id: string, path: string, init: RequestInit, want: number, extra?: (r: { status: number; headers: Headers; text: string }) => string | null) => {
      const r = await http(path, init);
      const problem = r.status !== want ? `HTTP ${r.status}, expected ${want}` : (extra?.(r) ?? null);
      add(`blackbox.${id}`, problem ? "fail" : "ok", problem ?? `${init.method ?? "GET"} ${path} → ${r.status}`);
    };
    await expect("batch", "/v1/risk-check/batch", { method: "POST" }, 402);
    await expect("get_405", "/v1/risk-check", {}, 405);
    await expect("credits_422", "/v1/credits", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }, 422);
    await expect("request_error", "/v1/risk-check", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ wallet: WALLET, bogus: 1 }) }, 402, (r) =>
      (parse<{ request_error?: { field?: string } }>(r.text)?.request_error?.field === "bogus" ? null : "the 402 does not name the refused field"),
    );
    await expect("http_page", `${BASE.replace("https://", "http://")}/`, { headers: { accept: "text/html" } }, 301);
    await expect("http_api", `${BASE.replace("https://", "http://")}/v1/risk-check`, { method: "POST" }, 403);
    await expect("site", "/", { headers: { accept: "text/html" } }, 200, (r) => {
      const missing = ["content-security-policy", "strict-transport-security", "x-content-type-options", "referrer-policy"].filter((h) => !r.headers.get(h));
      return missing.length ? `missing ${missing.join(", ")}` : null;
    });
    for (const path of ["/openapi.json", "/llms.txt", "/.well-known/x402", "/sitemap.xml", "/.well-known/security.txt", "/.well-known/risk-check.json", "/.well-known/did.json"]) await expect(`doc${path.replace(/[^a-z0-9]+/gi, "_")}`, path, {}, 200);
    await expect("favicon_head", "/favicon.ico", { method: "HEAD" }, 200);
    const jwks = parse<{ keys?: Array<{ kid?: string; crv?: string; kty?: string; x?: string; y?: string }> }>((await http("/.well-known/jwks.json")).text);
    const key = jwks?.keys?.find((k) => k.kid === status?.attestation.kid);
    add("blackbox.jwks", key && thumbprint(key) === status?.attestation.thumbprint ? "ok" : "fail", key ? `kid ${key.kid}, thumbprint ${thumbprint(key) === status?.attestation.thumbprint ? "matches" : "DIFFERS from /status"}` : "the attestation key is not published");
  });

  // --- the repository and GitHub ---
  await guard("deploy", async () => {
    run("git", ["fetch", "-q", "origin", "main"], 60_000);
    const main = run("git", ["rev-parse", "origin/main"]).trim();
    const deployed = hz.commit ?? "";
    if (!deployed || main.startsWith(deployed)) return add("deploy", "ok", `production runs origin/main (${deployed})`);
    const known = (() => {
      try {
        run("git", ["cat-file", "-e", `${deployed}^{commit}`]);
        return true;
      } catch {
        return false;
      }
    })();
    if (!known) return add("deploy", "warn", `production runs ${deployed}, unknown to the repository`);
    // The Worker also bundles parts of the SDK (packages/client/src: the Solana decoder, interpret, redaction).
    const code = run("git", ["log", "--format=%h %s", `${deployed}..origin/main`, "--", "src", "deploy", "packages/client/src", "package.json", "package-lock.json"]).trim();
    const all = Number(run("git", ["rev-list", "--count", `${deployed}..origin/main`]).trim());
    add("deploy", code ? "warn" : "info", code ? `main has code production does not run: ${code.split("\n").length} commit(s): ${code.split("\n").slice(0, 3).join(" | ")}` : `main is ${all} docs/test commit(s) ahead of production`);
  });
  if (!noGithub) {
    await guard("github.ci", async () => {
      const [r] = gh<Array<{ conclusion: string; status: string; headSha: string; url: string }>>(["run", "list", "--repo", REPO, "--branch", "main", "--workflow", "ci.yml", "--limit", "1", "--json", "conclusion,status,headSha,url"]);
      add("github.ci", !r ? "warn" : r.status !== "completed" ? "info" : r.conclusion === "success" ? "ok" : "fail", r ? `${r.headSha.slice(0, 7)} ${r.status}/${r.conclusion || "-"}` : "no run");
    });
    await guard("github.feeds", async () => {
      const [r] = gh<Array<{ conclusion: string; status: string; createdAt: string }>>(["run", "list", "--repo", REPO, "--workflow", "feeds.yml", "--limit", "1", "--json", "conclusion,status,createdAt"]);
      const age = r ? (Date.now() - Date.parse(r.createdAt)) / 3_600_000 : Infinity;
      add("github.feeds", !r || r.conclusion === "failure" ? "fail" : age > 36 ? "warn" : "ok", r ? `${r.createdAt} ${r.status}/${r.conclusion || "-"} (${age.toFixed(0)} h ago)` : "no run");
    });
    await guard("github.codeql", async () => {
      const alerts = gh<Array<{ rule?: { severity?: string; description?: string } }>>(["api", `repos/${REPO}/code-scanning/alerts?state=open&per_page=100`]);
      add("github.codeql", alerts.length ? "warn" : "ok", alerts.length ? `${alerts.length} open: ${alerts.slice(0, 3).map((a) => clean(a.rule?.description ?? "", 120)).join("; ")}` : "0 open");
    });
    await guard("github.dependabot", async () => {
      const alerts = gh<Array<{ number: number; security_advisory: { severity: string; summary: string }; dependency: { package: { name: string }; scope?: string; manifest_path: string } }>>(["api", `repos/${REPO}/dependabot/alerts?state=open&per_page=100`]);
      const runtime = alerts.filter((a) => a.dependency.scope === "runtime" && ["high", "critical"].includes(a.security_advisory.severity));
      add("github.dependabot", runtime.length ? "fail" : alerts.length ? "warn" : "ok", alerts.length ? alerts.map((a) => `#${a.number} ${a.security_advisory.severity} ${clean(a.dependency.package.name, 80)} (${a.dependency.scope ?? "?"}, ${clean(a.dependency.manifest_path, 80)})`).join("; ") : "0 open");
    });
    await guard("github.prs", async () => {
      const prs = gh<Array<{ number: number; title: string; author: { login: string } }>>(["pr", "list", "--repo", REPO, "--state", "open", "--json", "number,title,author"]);
      add("github.prs", prs.length ? "info" : "ok", prs.length ? prs.map((p) => `#${p.number} ${clean(p.title, 120)} (${clean(p.author.login, 40)})`).join("; ") : "none open");
    });
    await guard("github.release", async () => {
      const [r] = gh<Array<{ tagName: string }>>(["release", "list", "--repo", REPO, "--limit", "1", "--json", "tagName"]);
      add("github.release", r?.tagName === `v${hz.version}` ? "ok" : "warn", `latest release ${r?.tagName ?? "none"}, production v${hz.version}`);
    });
    await guard("threads", async () => {
      const seen: NonNullable<State["threads"]> = { ...(prev?.threads ?? {}) };
      for (const t of THREADS) {
        const key = `${t.repo}#${t.number}`;
        const issue = gh<{ comments: number; updated_at: string; state: string }>(["api", `repos/${t.repo}/issues/${t.number}`]);
        const was = prev?.threads?.[key];
        if (was && issue.comments > was.comments) {
          const comments = gh<Array<{ user: { login: string }; created_at: string; body: string; html_url: string }>>(["api", `repos/${t.repo}/issues/${t.number}/comments?since=${encodeURIComponent(was.updated_at)}&per_page=100`]);
          const fresh = comments.filter((c) => c.user.login !== OWN_LOGIN && c.created_at > was.updated_at);
          if (fresh.length) {
            // Untrusted text from other people: quoted for the reader, never followed.
            add(`threads.${t.repo}#${t.number}`, "info", `${t.label}: ${fresh.length} new comment(s), ${issue.state}. ${fresh.map((c) => `[${clean(c.user.login, 40)} ${c.created_at.slice(0, 16)} ${clean(c.html_url, 120)}] «${clean(c.body)}»`).join(" ")}`);
          }
        }
        seen[key] = { comments: issue.comments, updated_at: issue.updated_at };
        const open = unanswered(t);
        if (open && !checks.some((c) => c.id === `threads.${key}`)) add(`threads.${key}`, "warn", open);
      }
      next.threads = seen;
      if (!checks.some((c) => c.id.startsWith("threads."))) add("threads", "ok", prev?.threads ? "no new comments from others" : `baseline recorded for ${THREADS.length} threads`);
    });
  }
  await guard("feeds.embedded", async () => {
    try {
      run("npx", ["tsx", "scripts/sync-embedded-feeds.ts", "--check"], 120_000);
      add("feeds.embedded", "ok", "the embedded OFAC snapshot matches the published release");
    } catch (err) {
      const code = (err as { status?: number }).status;
      add("feeds.embedded", "warn", code === 1 ? "the embedded OFAC snapshot is older than the published release: sync it before the next deploy" : "could not compare the embedded OFAC snapshot");
    }
  });
  await guard("npm", async () => {
    const parts: string[] = [];
    let behind = false;
    for (const pkg of ["client", "mcp"]) {
      const local = (JSON.parse(readFileSync(`packages/${pkg}/package.json`, "utf8")) as { version: string }).version;
      const published = run("npm", ["view", `@x402check/${pkg}`, "version"], 60_000).trim();
      if (published !== local) behind = true;
      parts.push(`${pkg} npm ${published} / repo ${local}`);
    }
    add("npm", behind ? "info" : "ok", parts.join(", ") + (behind ? " (a publish needs the owner's passkey)" : ""));
  });

  // --- money ---
  await guard("probe_budget", async () => {
    const data = `0x70a08231${PROBE_PAYER.slice(2).padStart(64, "0")}`;
    const raw = (await rpc(RPC_ENDPOINTS["eip155:8453"] ?? [], "eth_call", [{ to: USDC_BASE, data }, "latest"])) as string | null;
    const usdc = raw ? Number(BigInt(raw)) / 1e6 : NaN;
    let credits = "?";
    const tokenFile = `${homedir()}/.config/paysol/x402check-credit-token`;
    // The token is a bearer secret: it goes to production only, never to another X402CHECK_BASE.
    if (existsSync(tokenFile) && new URL(BASE).origin !== PRODUCTION) credits = "not read (X402CHECK_BASE is not production)";
    else if (existsSync(tokenFile)) {
      const r = await http(`${PRODUCTION}/v1/credits`, { headers: { Authorization: `Bearer ${readFileSync(tokenFile, "utf8").trim()}` } });
      credits = parse<{ balance_usd?: string }>(r.text)?.balance_usd ?? `HTTP ${r.status}`;
    }
    add("probe_budget", "info", `probe payer ${Number.isFinite(usdc) ? `$${usdc.toFixed(4)}` : "?"} USDC on Base, credits ${credits} (the paid suite takes ~$0.10)`);
  });
  if (!noCloudflare) {
    await guard("revenue", async () => {
      const token = cloudflareToken();
      if (!token) return add("revenue", "warn", "no Cloudflare token (run `npx wrangler login`)");
      const account = (await cf<{ result: Array<{ id: string }> }>(token, "/accounts")).result[0]?.id;
      const ns = /binding\s*=\s*"RATE"\s*\n\s*id\s*=\s*"([0-9a-f]+)"/.exec(readFileSync("deploy/wrangler.toml", "utf8"))?.[1];
      if (!account || !ns) return add("revenue", "warn", "no account or KV namespace");
      const keys: string[] = [];
      for (let cursor = ""; ; ) {
        const page = await cf<{ result: Array<{ name: string }>; result_info?: { cursor?: string } }>(token, `/accounts/${account}/storage/kv/namespaces/${ns}/keys?prefix=st:&limit=1000${cursor ? `&cursor=${cursor}` : ""}`);
        keys.push(...page.result.map((k) => k.name));
        cursor = page.result_info?.cursor ?? "";
        if (!cursor) break;
      }
      const seen = new Set(prev?.settlements_seen ?? []);
      const baseline = !prev?.settlements_seen;
      const fresh = keys.filter((k) => !seen.has(k));
      const zone = (await cf<{ result: Array<{ id: string }> }>(token, `/zones?name=${new URL(BASE).hostname}`)).result[0]?.id;
      const outside: OutsidePayment[] = [...(prev?.outside ?? [])];
      let ours = 0;
      const unresolvedKeys = new Set<string>();
      const found: OutsidePayment[] = [];
      for (const key of fresh) {
        const [, network, tx] = /^st:(.+):([^:]+)$/.exec(key) ?? [];
        if (!network || !tx) continue;
        const rec = parse<{ at?: string; path?: string; micro?: number; undelivered?: boolean }>(await (await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/storage/kv/namespaces/${ns}/values/${encodeURIComponent(key)}`, { headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(30_000) })).text()) ?? {};
        const who = await payerOf(network, tx);
        if (!who) {
          // Read again next run (an RPC that failed today must not hide a payment for good).
          unresolvedKeys.add(key);
          continue;
        }
        if (PROBE_PAYERS.has(who.payer)) {
          ours++;
          continue;
        }
        const pay: OutsidePayment = { key, at: rec.at ?? "", network, path: rec.path ?? "", payer: who.payer, micro: rec.micro ?? who.micro, ...(rec.undelivered ? { undelivered: true } : {}) };
        // Who called: the analytics rows of that path, around the settlement record's time. Any request
        // source: a payer can call from another zone's Worker (requestSource "edgeWorkerFetch").
        if (zone && pay.at) {
          const t = Date.parse(pay.at);
          const q = `query($z:String!,$a:Time!,$b:Time!,$p:String!){viewer{zones(filter:{zoneTag:$z}){httpRequestsAdaptiveGroups(limit:5,filter:{datetime_geq:$a,datetime_lt:$b,clientRequestPath:$p,edgeResponseStatus:200}){count dimensions{userAgent clientCountryName requestSource}}}}}`;
          const g = await cf<{ data?: { viewer?: { zones?: Array<{ httpRequestsAdaptiveGroups?: Array<{ dimensions: { userAgent: string; clientCountryName: string; requestSource: string } }> }> } } }>(token, "/graphql", { method: "POST", body: JSON.stringify({ query: q, variables: { z: zone, a: new Date(t - 120_000).toISOString(), b: new Date(t + 30_000).toISOString(), p: pay.path } }) }).catch(() => null);
          const row = g?.data?.viewer?.zones?.[0]?.httpRequestsAdaptiveGroups?.[0]?.dimensions;
          if (row) Object.assign(pay, { ua: row.userAgent.slice(0, 80), country: row.clientCountryName, ...(row.requestSource === "edgeWorkerFetch" ? { worker: true } : {}) });
        }
        found.push(pay);
      }
      outside.push(...found);
      next.outside = outside.sort((a, b) => a.at.localeCompare(b.at));
      next.settlements_seen = keys.filter((k) => !unresolvedKeys.has(k));
      const unresolved = unresolvedKeys.size;
      const total = outside.reduce((s, p) => s + p.micro, 0) / 1e6;
      const fmt = (p: OutsidePayment) => `$${(p.micro / 1e6).toFixed(4)} ${short(p.network)} ${p.path} ${p.at.slice(0, 16)} from ${p.payer.slice(0, 10)}… ${p.ua ?? "(no user agent found)"}${p.country ? ` [${p.country}]` : ""}${p.worker ? " (from a Cloudflare Worker)" : ""}${p.undelivered ? " UNDELIVERED" : ""}`;
      // A payment that settled for a client who had left: a verdict, or a new credit token, reached nobody.
      const undelivered = found.filter((p) => p.undelivered);
      if (undelivered.length) add("revenue.undelivered", "warn", `${undelivered.length} payment(s) settled for a client who left, so what it paid for reached nobody: ${undelivered.map(fmt).join("; ")} (a verdict reaches its payer if the same payment is resent for the same request within a day; a new credit token on /v1/credits is the owner's to make right)`);
      if (baseline) add("revenue", "info", `baseline: ${keys.length} settlements, ${outside.length} from outside payers ($${total.toFixed(4)}), ${ours} probes, ${unresolved} unresolved`);
      else add("revenue", found.length ? "info" : "ok", `${found.length} new outside payment(s)${found.length ? `: ${found.map(fmt).join("; ")}` : ""}; ${ours} probe settlement(s); ${unresolved} unresolved; outside total $${total.toFixed(4)}`);
    });
  }

  // --- output ---
  const order: Level[] = ["fail", "warn", "info", "ok"];
  checks.sort((a, b) => order.indexOf(a.level) - order.indexOf(b.level));
  const day = now.toISOString().slice(0, 10);
  const header = `x402check daily check ${now.toISOString().slice(0, 16)}Z — production v${hz.version} (${hz.commit})`;
  const lines = [header, ...checks.map((c) => `${c.level.toUpperCase().padEnd(4)}  ${c.id} — ${c.detail}`)];
  console.log(lines.join("\n"));
  writeFileSync(`${OUT_DIR}/${day}.json`, JSON.stringify({ at: now.toISOString(), production: hz, checks }, null, 1));
  writeFileSync(`${OUT_DIR}/${day}.txt`, `${lines.join("\n")}\n`);
  writeFileSync(STATE_FILE, JSON.stringify(next, null, 1));
  process.exitCode = checks.some((c) => c.level === "fail") ? 1 : 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((err) => {
    console.error(err);
    process.exit(2);
  });
}
