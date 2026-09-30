// Live probes for the v0.3.0 features: transaction simulation, drainer-kit code
// fingerprints, the /status freshness report, and the new validation rules.
//
//   X402CHECK_BASE=https://x402check.xyz npx tsx eval/security-v3.ts
//
// Budget: 3 paid evaluations (≈ $0.003) through eval/paid-fetch.ts (payer keys in
// ~/.config/paysol; PAY_NETWORK=eip155:8453 for Base USDC). Without a funded payer the
// evaluation probes are SKIP (not verified), never PASS. The 422 probes are unpriced.
import { mkdirSync, writeFileSync } from "node:fs";
import { createPublicKey, createVerify, type JsonWebKey } from "node:crypto";
import { EVAL_EVIDENCE_DIR } from "./harness.js";
import { buildPayFetch, settlementReceipt, type PayFetch, type SettlementReceipt } from "./paid-fetch.js";

/** Every settlement this run paid for (tx hashes on-chain), for the report. */
const receipts: Array<SettlementReceipt & { probe: string }> = [];

const BASE = process.env.X402CHECK_BASE ?? "https://x402check.xyz";
const ISSUER = `did:web:${process.env.EXPECTED_HOST ?? "x402check.xyz"}`;
// A Forta-labelled phishing contract (2023) that is on no address feed x402check uses:
// only its code fingerprint can flag it.
const FORTA_DRAINER = "0x02745ad75e786f0b2efbd99504e22c3cace354c1";
const USER = "0x1111111111111111111111111111111111111111";
const WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
// The hidden-recipient probe replays a REAL drainer transaction that the simulation
// evaluation flagged (eval/evidence/simulation-report.json).

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

/** A drainer transaction the simulation evaluation flagged (replayed live again here). */
async function flaggedDrainerTx(): Promise<{ from: string; to: string; value: string; data: string; hash: string } | null> {
  let report: { sample?: Array<{ label: string; tx: string; flagged: boolean }> } = {};
  try {
    report = JSON.parse((await import("node:fs")).readFileSync(`${EVAL_EVIDENCE_DIR}/simulation-report.json`, "utf8")) as typeof report;
  } catch {
    return null;
  }
  for (const s of (report.sample ?? []).filter((x) => x.label === "drainer" && x.flagged).slice(0, 5)) {
    const tx = (await (await fetch(`https://eth.blockscout.com/api/v2/transactions/${s.tx}`, { headers: { accept: "application/json" } })).json()) as { from?: { hash: string }; to?: { hash: string }; value?: string; raw_input?: string };
    if (tx.from && tx.to) return { from: tx.from.hash, to: tx.to.hash, value: tx.value ?? "0", data: tx.raw_input ?? "0x", hash: s.tx };
  }
  return null;
}

async function main(): Promise<void> {
  const out: Outcome[] = [];
  const settled = (r: Res) => r.status !== 402 && r.status !== 0;
  const add = (id: string, pass: boolean | null, detail: string) => {
    out.push({ id, status: pass === null ? "SKIP" : pass ? "PASS" : "FAIL", detail });
    console.log(`${pass === null ? "SKIP" : pass ? "PASS" : "FAIL"}  ${id} — ${detail}`);
  };

  const disc = await call("GET", "/.well-known/risk-check.json");
  const signals = (disc.json?.signals as string[] | undefined) ?? [];
  // A historical suite: against another version it would pay for probes, fail on version-specific
  // expectations and overwrite the committed report. It stops before paying anything.
  if (!String(disc.json?.version ?? "").startsWith("0.3.")) {
    console.log(`historical suite for v0.3: the endpoint runs ${String(disc.json?.version)}; nothing was paid and the committed report is unchanged (run the current suite instead)`);
    return;
  }
  add("discovery_v03", String(disc.json?.version ?? "").startsWith("0.3.") && signals.includes("transaction_simulation") && signals.includes("drainer_code_fingerprint"), `version=${String(disc.json?.version)} signals=${signals.join(",")}`);

  const st = await call("GET", "/status");
  const data = (st.json?.data ?? {}) as Record<string, { as_of?: string; age_days?: number; origin?: string } | undefined>;
  const text = JSON.stringify(st.json ?? {});
  const leaks = /PRIVATE|API_KEY|BEGIN|secret/i.test(text);
  add("status_freshness", st.status === 200 && !!data.ofac_sdn?.as_of && !!data.metamask_phishing?.as_of && !leaks, `ofac=${data.ofac_sdn?.as_of}(${data.ofac_sdn?.origin}) metamask=${data.metamask_phishing?.as_of}(${data.metamask_phishing?.origin}) scamsniffer=${JSON.stringify(data.scamsniffer).slice(0, 80)} leaks=${leaks}`);

  for (const [id, body, field] of [
    ["tx_non_evm_chain", { wallet: USER, chain: "solana", transaction: { from: USER } }, "chain"],
    ["tx_odd_hex_data", { wallet: USER, chain: "eip155:1", transaction: { from: USER, to: WETH, data: "0xabc" } }, "transaction.data"],
    ["tx_unknown_key", { wallet: USER, chain: "eip155:1", transaction: { from: USER, gas: "1" } }, "transaction"],
  ] as const) {
    const r = await call("POST", "/v1/risk-check", body);
    add(id, r.status === 422 && r.json?.field === field, `HTTP ${r.status} field=${String(r.json?.field)}`);
  }

  const code = await call("POST", "/v1/risk-check", { wallet: FORTA_DRAINER, chain: "eip155:1" }, { paid: true });
  const codeClaims = typeof code.json?.jws === "string" ? await verify(code.json.jws) : null;
  const codeFeeds = ((code.json?.evidence as { feeds?: Array<{ source: string; status: string }> } | undefined)?.feeds ?? []).map((f) => `${f.source}:${f.status}`);
  if (!settled(code)) add("drainer_code_fingerprint", null, `not paid (status ${code.status}): fund the payer`);
  else add(
    "drainer_code_fingerprint",
    code.status === 200 && (code.json?.categories as string[] | undefined)?.includes("known_drainer_code") === true && (code.json?.score as number) <= 30 && !!codeClaims && (codeClaims.checks as { feeds?: string[] }).feeds?.some((f) => f.startsWith("forta-phishing-code@") && f.endsWith(":hit")) === true,
    `HTTP ${code.status} score=${String(code.json?.score)} tier=${String(code.json?.tier)} feeds=${codeFeeds.join(",")} jws=${codeClaims ? "verified" : "INVALID"}`,
  );

  const drain = await flaggedDrainerTx();
  if (!drain) add("simulation_hidden_recipient", null, "no flagged drainer transaction in eval/evidence/simulation-report.json");
  else {
    const r = await call("POST", "/v1/risk-check", { wallet: drain.to, chain: "eip155:1", transaction: { from: drain.from, to: drain.to, value: drain.value, data: drain.data } }, { paid: true });
    if (!settled(r)) {
      add("simulation_hidden_recipient", null, `not paid (status ${r.status}): fund the payer`);
    } else {
    const sim = (r.json?.evidence as { simulation?: { status: string; findings?: string[] } } | undefined)?.simulation;
    const claims = typeof r.json?.jws === "string" ? await verify(r.json.jws) : null;
    const signed = (claims?.checks as { simulation?: { findings?: string[] } } | undefined)?.simulation;
    add(
      "simulation_hidden_recipient",
      r.status === 200 && sim?.findings?.includes("outflow_to_undisclosed_eoa") === true && (r.json?.score as number) <= 40 && signed?.findings?.includes("outflow_to_undisclosed_eoa") === true,
      `replay of ${drain.hash.slice(0, 18)}… HTTP ${r.status} score=${String(r.json?.score)} simulation=${sim?.status}:${(sim?.findings ?? []).join("+")} signed=${JSON.stringify(signed)}`,
    );
    }
  }

  const wrap = await call("POST", "/v1/risk-check", { wallet: WETH, chain: "eip155:1", transaction: { from: USER, to: WETH, value: "10000000000000000", data: "0xd0e30db0" } }, { paid: true });
  const wsim = (wrap.json?.evidence as { simulation?: { status: string; findings?: string[]; inflows?: unknown[] } } | undefined)?.simulation;
  if (!settled(wrap)) add("simulation_legit_wrap", null, `not paid (status ${wrap.status}): fund the payer`);
  else add("simulation_legit_wrap", wrap.status === 200 && wsim?.status === "ok" && (wsim.findings ?? []).length === 0 && (wsim.inflows ?? []).length === 1 && wrap.json?.tier === "low", `HTTP ${wrap.status} score=${String(wrap.json?.score)} tier=${String(wrap.json?.tier)} simulation=${wsim?.status} findings=${(wsim?.findings ?? []).join("+") || "none"}`);

  for (const r of receipts) console.log(`paid: ${r.network} tx ${r.transaction} (payer ${r.payer})`);
  const report = { timestamp: new Date().toISOString(), base: BASE, receipts, pass: out.filter((o) => o.status === "PASS").length, fail: out.filter((o) => o.status === "FAIL").length, skip: out.filter((o) => o.status === "SKIP").length, outcomes: out };
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  writeFileSync(`${EVAL_EVIDENCE_DIR}/security-v3-report.json`, JSON.stringify(report, null, 2));
  console.log(`\n${report.pass} PASS · ${report.fail} FAIL · ${report.skip} SKIP`);
  if (report.fail) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
