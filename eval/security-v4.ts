// Live probes for v0.4.0: the kit watch (watchlist and code families at evaluation time),
// the collision gate on the code sets, and the /status coverage report.
//
//   X402CHECK_BASE=https://x402check.xyz PAY_NETWORK=eip155:8453 npx tsx eval/security-v4.ts
//
// Budget: 5 paid evaluations (≈ $0.005) through eval/paid-fetch.ts. Without a funded payer
// the evaluation probes are SKIP (not verified), never PASS. The kit-watch probes pick their
// subjects from the private watchlist (.cache/intel/, scripts/hunt-kits.ts); the report
// names them only by a SHA-256 prefix.
import { createHash, createPublicKey, createVerify, type JsonWebKey } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { EVAL_EVIDENCE_DIR } from "./harness.js";
import { buildPayFetch, settlementReceipt, type PayFetch, type SettlementReceipt } from "./paid-fetch.js";
import type { WatchEntry } from "../src/kit-watch.js";

const receipts: Array<SettlementReceipt & { probe: string }> = [];
const BASE = process.env.X402CHECK_BASE ?? "https://x402check.xyz";
const ISSUER = `did:web:${process.env.EXPECTED_HOST ?? "x402check.xyz"}`;
// Exchange deposit contracts that the v0.3 Forta set flagged as drainer code (their code is
// the exchange's standard deposit contract; single deposit addresses were labelled phishing).
const LUNO_DEPOSIT = "0xea21d5ac9cbd3b84e00da63e610025577b87cea1";
const BITGO_FORWARDER = "0x95115419b09e8cea70a9bdbca3fee8c5e118b228";
const INTEL = new URL("../.cache/intel/", import.meta.url);
const hashed = (a: string) => `sha256:${createHash("sha256").update(a.toLowerCase()).digest("hex").slice(0, 16)}`;

type Res = { status: number; headers: Headers; json: Record<string, unknown> | null };
type Outcome = { id: string; status: "PASS" | "FAIL" | "SKIP"; detail: string };

let payFetch: PayFetch | null | undefined;
async function call(method: string, path: string, body?: unknown, opts: { paid?: boolean } = {}): Promise<Res> {
  if (opts.paid && payFetch === undefined) payFetch = await buildPayFetch().catch(() => null);
  if (opts.paid && !payFetch) return { status: 0, headers: new Headers(), json: { error: "no payer configured (~/.config/paysol)" } };
  const res = await ((opts.paid ? payFetch : null) ?? fetch)(`${BASE}${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(60_000),
  });
  const receipt = opts.paid ? settlementReceipt(res.headers) : null;
  if (receipt) receipts.push({ probe: `${method} ${path}`, ...receipt });
  const text = await res.text();
  let json: Record<string, unknown> | null = null;
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    json = null;
  }
  return { status: res.status, headers: res.headers, json };
}

let keys: Array<JsonWebKey & { kid?: string }> | null = null;
async function verify(jws: string): Promise<Record<string, unknown> | null> {
  if (!keys) {
    const did = (await (await fetch(`${BASE}/.well-known/did.json`)).json()) as { verificationMethod: Array<{ publicKeyJwk: JsonWebKey & { kid?: string } }> };
    keys = did.verificationMethod.map((v) => v.publicKeyJwk);
  }
  const [h, p, s] = jws.split(".");
  const header = JSON.parse(Buffer.from(h ?? "", "base64url").toString("utf8")) as { kid?: string; alg?: string; typ?: string };
  const key = keys.find((k) => k.kid === header.kid);
  if (!key || header.alg !== "ES256" || header.typ !== "risk-check+jwt") return null;
  const ok = createVerify("SHA256").update(`${h}.${p}`).verify({ key: createPublicKey({ key, format: "jwk" }), dsaEncoding: "ieee-p1363" }, Buffer.from(s ?? "", "base64url"));
  if (!ok) return null;
  const claims = JSON.parse(Buffer.from(p ?? "", "base64url").toString("utf8")) as Record<string, unknown>;
  return claims.iss === ISSUER ? claims : null;
}

/** An address of the given kind from the private watchlist (Ethereum), still delegated if a delegation. */
async function watched(kind: WatchEntry["k"]): Promise<string | null> {
  const file = new URL("watch-eip155-1.json", INTEL);
  if (!existsSync(file)) return null;
  const store = JSON.parse(readFileSync(file, "utf8")) as Record<string, WatchEntry>;
  const candidates = Object.entries(store).filter(([, e]) => e.k === kind).sort((a, b) => a[1].t - b[1].t);
  for (const [address, e] of candidates.slice(0, 20)) {
    if (!e.d) return address;
    const res = await fetch("https://ethereum-rpc.publicnode.com", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getCode", params: [address, "latest"] }) });
    const code = ((await res.json()) as { result?: string }).result?.toLowerCase() ?? "";
    if (code === `0xef0100${e.d.slice(2)}`) return address;
  }
  return candidates[0]?.[0] ?? null;
}

async function main(): Promise<void> {
  const out: Outcome[] = [];
  const settled = (r: Res) => r.status !== 402 && r.status !== 0;
  const add = (id: string, pass: boolean | null, detail: string) => {
    out.push({ id, status: pass === null ? "SKIP" : pass ? "PASS" : "FAIL", detail });
    console.log(`${pass === null ? "SKIP" : pass ? "PASS" : "FAIL"}  ${id} — ${detail}`);
  };
  const categories = (r: Res) => (r.json?.categories as string[] | undefined) ?? [];
  const kitWatch = (r: Res) => (r.json?.evidence as { kit_watch?: { status?: string; as_of?: string; hits?: Array<{ kind: string; via: string; role: string }> } } | undefined)?.kit_watch;
  const signedFeeds = async (r: Res) => {
    const claims = typeof r.json?.jws === "string" ? await verify(r.json.jws) : null;
    return { claims, feeds: ((claims?.checks as { feeds?: string[] } | undefined)?.feeds ?? []).filter((f) => f.startsWith("x402check-kit-watch@")) };
  };

  const disc = await call("GET", "/.well-known/risk-check.json");
  const signals = (disc.json?.signals as string[] | undefined) ?? [];
  add("discovery_v04", String(disc.json?.version ?? "").startsWith("0.4.") && signals.includes("kit_watch"), `version=${String(disc.json?.version)} kit_watch=${signals.includes("kit_watch")}`);

  const st = await call("GET", "/status");
  const kw = ((st.json?.data ?? {}) as { kit_watch?: { updated_at?: string; chains?: Record<string, { lag_blocks?: number; scanned_blocks?: number }> } }).kit_watch;
  const text = JSON.stringify(st.json ?? {});
  // The watchlist is private: no address may appear in the coverage report; nor may a key.
  const leaks = /0x[0-9a-fA-F]{40}/.test(JSON.stringify(kw ?? {})) || /-----BEGIN|PRIVATE KEY|API_KEY/.test(text);
  const fresh = !!kw?.updated_at && Date.now() - Date.parse(kw.updated_at) < 10 * 60_000;
  add("status_kit_watch", st.status === 200 && fresh && !!kw?.chains?.["eip155:1"] && !!kw?.chains?.["eip155:8453"] && !leaks, `updated=${kw?.updated_at} lag=${JSON.stringify(Object.fromEntries(Object.entries(kw?.chains ?? {}).map(([c, v]) => [c, v.lag_blocks])))} addresses_in_status=${leaks}`);

  const poisoner = await watched("poisoner_delegation");
  if (!poisoner) add("kit_watch_poisoner", null, "no watchlist on this machine (run scripts/hunt-kits.ts)");
  else {
    // Observed on Ethereum, evaluated on Base: the same key controls the address on every chain.
    const r = await call("POST", "/v1/risk-check", { wallet: poisoner, chain: "eip155:8453" }, { paid: true });
    const { claims, feeds } = await signedFeeds(r);
    if (!settled(r)) add("kit_watch_poisoner", null, `not paid (status ${r.status})`);
    else add("kit_watch_poisoner", r.status === 200 && (r.json?.score as number) <= 20 && categories(r).includes("address_poisoning") && kitWatch(r)?.status === "hit" && !!claims && feeds.some((f) => f.endsWith(":hit")), `${hashed(poisoner)} → HTTP ${r.status} score=${String(r.json?.score)} tier=${String(r.json?.tier)} hits=${JSON.stringify(kitWatch(r)?.hits?.map((h) => `${h.kind}/${h.via}`))} signed=${feeds.join(",")}`);
  }

  const sweeper = await watched("sweeper_delegation");
  if (!sweeper) add("kit_watch_compromised_wallet", null, "no sweeper delegation in the watchlist");
  else {
    const r = await call("POST", "/v1/risk-check", { wallet: sweeper, chain: "eip155:1" }, { paid: true });
    if (!settled(r)) add("kit_watch_compromised_wallet", null, `not paid (status ${r.status})`);
    else add("kit_watch_compromised_wallet", r.status === 200 && (r.json?.score as number) <= 20 && categories(r).includes("compromised_wallet"), `${hashed(sweeper)} → HTTP ${r.status} score=${String(r.json?.score)} hits=${JSON.stringify(kitWatch(r)?.hits?.map((h) => `${h.kind}/${h.via}`))}`);
  }

  // The collision gate: exchange deposit contracts are no longer drainer code.
  for (const [id, wallet] of [
    ["gate_luno_deposit_not_drainer", LUNO_DEPOSIT],
    ["gate_bitgo_forwarder_not_drainer", BITGO_FORWARDER],
  ] as const) {
    const r = await call("POST", "/v1/risk-check", { wallet, chain: "eip155:1" }, { paid: true });
    const code = ((r.json?.evidence as { feeds?: Array<{ source: string; status: string }> } | undefined)?.feeds ?? []).filter((f) => f.source.endsWith("-code"));
    if (!settled(r)) add(id, null, `not paid (status ${r.status})`);
    else add(id, r.status === 200 && !categories(r).includes("known_drainer_code") && code.every((f) => f.status !== "hit"), `HTTP ${r.status} score=${String(r.json?.score)} tier=${String(r.json?.tier)} code_feeds=${code.map((f) => `${f.source}:${f.status}`).join(",")}`);
  }

  const clean = await call("POST", "/v1/risk-check", { wallet: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", chain: "eip155:1" }, { paid: true });
  if (!settled(clean)) add("kit_watch_clear", null, `not paid (status ${clean.status})`);
  else add("kit_watch_clear", clean.status === 200 && kitWatch(clean)?.status === "clear" && !categories(clean).some((c) => ["address_poisoning", "compromised_wallet", "drainer_operator", "auto_forwarding_wallet"].includes(c)), `HTTP ${clean.status} score=${String(clean.json?.score)} kit_watch=${kitWatch(clean)?.status}@${kitWatch(clean)?.as_of}`);

  const report = {
    timestamp: new Date().toISOString(),
    base: BASE,
    paid_via: process.env.PAY_NETWORK ?? "solana:*",
    summary: { pass: out.filter((o) => o.status === "PASS").length, fail: out.filter((o) => o.status === "FAIL").length, skip: out.filter((o) => o.status === "SKIP").length },
    outcomes: out,
    settlements: receipts,
  };
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  writeFileSync(`${EVAL_EVIDENCE_DIR}/security-v4-report.json`, JSON.stringify(report, null, 2));
  console.log(JSON.stringify(report.summary));
  if (report.summary.fail > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
