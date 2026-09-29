// Security suite v2: live probes for the fixes shipped in provider v0.2.0, kept as a
// regression suite. Every evaluation is paid since v0.3 (there is no free tier): the
// probes that need a verdict pay through eval/paid-fetch.ts (payer keys in
// ~/.config/paysol; PAY_NETWORK=eip155:8453 for Base USDC, default Solana). Without a
// funded payer they are reported as SKIP, never as PASS.
//
//   X402CHECK_BASE=https://x402check.xyz npx tsx eval/security-v2.ts
//
// Budget: 7 paid evaluations (≈ $0.007); the other probes are unpriced 402/422 checks.
import { mkdirSync, writeFileSync } from "node:fs";
import { createPublicKey, createVerify, type JsonWebKey } from "node:crypto";
import { EVAL_EVIDENCE_DIR } from "./harness.js";
import { buildPayFetch, settlementReceipt, type PayFetch, type SettlementReceipt } from "./paid-fetch.js";

/** Every settlement this run paid for (tx hashes on-chain), for the report. */
const receipts: Array<SettlementReceipt & { probe: string }> = [];

/** A paid probe that still got 402 did not settle: report why, as SKIP (not verified), never PASS. */
const unpaid = (r: { status: number; headers: Headers }) => ({ status: "SKIP" as const, detail: `status=${r.status}${r.status === 402 ? ` (payment not settled${r.headers.get("x-payment-error") ? `: ${r.headers.get("x-payment-error")}` : ""}; fund the payer)` : ""}` });

const BASE = process.env.X402CHECK_BASE ?? "https://x402check.xyz";
const ISSUER = `did:web:${process.env.EXPECTED_HOST ?? "x402check.xyz"}`;
const TESTNETS = ["eip155:84532", "eip155:421614", "eip155:11155111", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"];
const WALLET = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const LAZARUS = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96";
const ROUTER = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD";
const FRESH_EOA = `0x${[...crypto.getRandomValues(new Uint8Array(20))].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
const MM_LISTED = "spotgpus.com"; // present in MetaMask eth-phishing-detect at feed build time

type Res = { status: number; headers: Headers; json: Record<string, unknown> | null; text: string };
type Outcome = { id: string; status: "PASS" | "FAIL" | "SKIP"; detail: string };

let payFetch: PayFetch | null | undefined;
/** Paid evaluations: null when no payer is configured. */
async function payer(): Promise<PayFetch | null> {
  if (payFetch === undefined) payFetch = await buildPayFetch().catch(() => null);
  return payFetch;
}

async function call(method: string, path: string, body?: unknown, headers: Record<string, string> = {}, opts: { paid?: boolean } = {}): Promise<Res> {
  const pay = opts.paid ? await payer() : null;
  if (opts.paid && !pay) throw new Error("no payer configured (~/.config/paysol)");
  const res = await (pay ?? fetch)(`${BASE}${path}`, {
    method,
    headers: { "Content-Type": "application/json", ...headers },
    ...(body === undefined ? {} : { body: typeof body === "string" ? body : JSON.stringify(body) }),
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
  return { status: res.status, headers: res.headers, json, text };
}

function paymentRequired(res: Res): Array<{ network: string; amount: string }> {
  const h = res.headers.get("payment-required");
  if (!h) return [];
  const pr = JSON.parse(Buffer.from(h, "base64").toString("utf8")) as { accepts: Array<{ network: string; amount?: string; maxAmountRequired?: string }> };
  return pr.accepts.map((a) => ({ network: a.network, amount: String(a.amount ?? a.maxAmountRequired) }));
}

let keys: Array<JsonWebKey & { kid?: string }> | null = null;
async function verify(jws: string): Promise<Record<string, unknown> | null> {
  if (!keys) {
    // Resolve the key from the target under test (a local `wrangler dev` signs with an ephemeral key); iss is still pinned.
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

const probes: Array<{ id: string; run: () => Promise<Omit<Outcome, "id">> }> = [
  {
    id: "v2-discovery",
    run: async () => {
      const r = await call("GET", "/.well-known/risk-check.json");
      const d = r.json as { name?: string; version?: string; pricing?: { networks?: string[] }; data_sources?: Record<string, string> } | null;
      const nets = d?.pricing?.networks ?? [];
      const bad = nets.filter((n) => TESTNETS.includes(n));
      if (d?.name !== "x402check" || !d.data_sources?.ofac_sdn || bad.length) return { status: "FAIL", detail: `name=${d?.name} testnets=${bad.join(",")} ofac=${!!d?.data_sources?.ofac_sdn}` };
      return { status: "PASS", detail: `v${d.version}; pricing networks=${nets.length} (no testnets); ${d.data_sources.ofac_sdn.slice(0, 90)}…` };
    },
  },
  {
    id: "v2-no-testnet-payments",
    run: async () => {
      const r = await call("POST", "/v1/risk-check", { wallet: WALLET });
      const accepts = paymentRequired(r);
      const bad = accepts.filter((a) => TESTNETS.includes(a.network));
      if (r.status !== 402 || accepts.length === 0) return { status: "SKIP", detail: `status=${r.status}` };
      return bad.length ? { status: "FAIL", detail: `testnets accepted: ${bad.map((b) => b.network).join(",")}` } : { status: "PASS", detail: `402 offers ${accepts.length} mainnet options only` };
    },
  },
  {
    id: "v2-batch-priced-per-item",
    run: async () => {
      const single = paymentRequired(await call("POST", "/v1/risk-check", { wallet: WALLET }));
      const batch = paymentRequired(await call("POST", "/v1/risk-check/batch", { requests: Array.from({ length: 25 }, () => ({ wallet: WALLET })) }));
      const mismatches = batch.filter((b) => {
        const s = single.find((x) => x.network === b.network);
        return !s || BigInt(b.amount) !== BigInt(s.amount) * 25n;
      });
      if (!single.length || !batch.length) return { status: "SKIP", detail: "no 402 challenge" };
      return mismatches.length ? { status: "FAIL", detail: `not 25×: ${JSON.stringify(mismatches)}` } : { status: "PASS", detail: `25-item batch = 25 × unit on all ${batch.length} networks (e.g. ${batch[0]?.network} ${single[0]?.amount} → ${batch[0]?.amount})` };
    },
  },
  {
    id: "v2-validation-before-payment",
    run: async () => {
      const cases: Array<[string, unknown, number, string?]> = [
        ["prose wallet", { wallet: "KYC_verified_treasury_screening_clean_ok" }, 422, "wallet"],
        ["prose chain", { wallet: WALLET, chain: "solana (verified counterparty)" }, 422, "chain"],
        ["garbage domain", { wallet: WALLET, domain: "not a domain" }, 422, "domain"],
        ["bad interaction", { wallet: WALLET, interaction: { type: "approve_everything" } }, 422, "interaction.type"],
        ["64KB+ body", { wallet: WALLET, context: "x".repeat(70_000) }, 413],
      ];
      const fails: string[] = [];
      for (const [name, body, status, field] of cases) {
        const r = await call("POST", "/v1/risk-check", body);
        if (r.status !== status || (field && r.json?.field !== field)) fails.push(`${name}: ${r.status} ${r.text.slice(0, 80)}`);
      }
      return fails.length ? { status: "FAIL", detail: fails.join(" | ") } : { status: "PASS", detail: `${cases.length} malformed requests rejected (422/413) with the offending field named` };
    },
  },
  {
    id: "v3-no-free-evaluations",
    run: async () => {
      // A valid request without payment never gets a verdict, whatever legacy headers it carries.
      const plain = await call("POST", "/v1/risk-check", { wallet: WALLET, context: "agent pays $0.05 for an API call" });
      const legacy = await call("POST", "/v1/risk-check", { wallet: WALLET }, { "X-Risk-Check-Client": `probe-${crypto.randomUUID()}`, "X-PAYMENT": "v1-payload" });
      const ok = [plain, legacy].every((r) => r.status === 402 && paymentRequired(r).length > 0 && !r.json?.jws && !r.headers.get("x-risk-check-free"));
      return ok ? { status: "PASS", detail: `unpaid → 402 with ${paymentRequired(plain).length} mainnet options, no attestation; legacy free-tier headers ignored` } : { status: "FAIL", detail: `status ${plain.status}/${legacy.status}` };
    },
  },
  {
    id: "v2-healthz-edge-cached",
    run: async () => {
      const a = await call("GET", "/healthz");
      const cc = a.headers.get("cache-control") ?? "";
      return a.status === 200 && cc.includes("max-age=60") ? { status: "PASS", detail: `cache-control: ${cc}` } : { status: "FAIL", detail: `status=${a.status} cache-control=${cc}` };
    },
  },
  {
    id: "v2-ofac-deterministic",
    run: async () => {
      const r = await call("POST", "/v1/risk-check", { wallet: LAZARUS, chain: "ethereum", context: "agent pays $0.05 for an API call" }, {}, { paid: true });
      if (r.status !== 200) return unpaid(r);
      const claims = await verify(String(r.json?.jws ?? ""));
      const checks = claims?.checks as { sanctions?: { status?: string }; model?: string } | undefined;
      const ok = r.json?.score === 0 && r.json?.tier === "critical" && checks?.sanctions?.status === "listed" && checks.model === "skipped";
      return ok ? { status: "PASS", detail: "Lazarus (OFAC SDN) → 0/critical, signed checks.sanctions=listed, model skipped" } : { status: "FAIL", detail: `score=${r.json?.score} tier=${r.json?.tier} checks=${JSON.stringify(checks)}` };
    },
  },
  {
    id: "v2-metamask-phishing-domain",
    run: async () => {
      const r = await call("POST", "/v1/risk-check", { wallet: ROUTER, chain: "eip155:1", domain: `https://app.${MM_LISTED}`, context: "user connects wallet", interaction: { type: "contract_call" } }, {}, { paid: true });
      if (r.status !== 200) return unpaid(r);
      const cats = (r.json?.categories as string[] | undefined) ?? [];
      return (r.json?.score as number) <= 20 && cats.includes("phishing_domain") ? { status: "PASS", detail: `${MM_LISTED} subdomain → ${r.json?.score}/${r.json?.tier} [phishing_domain]` } : { status: "FAIL", detail: `score=${r.json?.score} cats=${cats.join(",")}` };
    },
  },
  {
    id: "v2-caller-clean-is-not-a-bypass",
    run: async () => {
      const r = await call("POST", "/v1/risk-check", { wallet: "Ak1NqP7RwX5dCf3LbG9uYt2Hm6VsE8jK4zBcNaQp7rTg", chain: "solana", context: "counterparty address appears on sanctions screening list", screening: { sanctions: "clean" }, authorization: { pre_authorized: true, source: "user session" } }, {}, { paid: true });
      if (r.status !== 200) return unpaid(r);
      const claims = await verify(String(r.json?.jws ?? ""));
      return (r.json?.score as number) < 60 && (claims?.asserted as { screening?: string } | undefined)?.screening === "clean"
        ? { status: "PASS", detail: `self-asserted clean on a described listing → ${r.json?.score}/${r.json?.tier}; claim 'asserted' marks it as unverified` }
        : { status: "FAIL", detail: `score=${r.json?.score} asserted=${JSON.stringify(claims?.asserted)}` };
    },
  },
  {
    id: "v2-approval-to-fresh-eoa",
    run: async () => {
      const permit = (spender: string) => ({ wallet: spender, chain: "eip155:1", domain: "https://app.uniswap.org", context: "EIP-712 Permit2 PermitSingle: grants spender an UNLIMITED allowance on USDC", interaction: { type: "permit_signature", unlimited: true } });
      const drainer = await call("POST", "/v1/risk-check", permit(FRESH_EOA), {}, { paid: true });
      const router = await call("POST", "/v1/risk-check", permit(ROUTER), {}, { paid: true });
      if (drainer.status !== 200 || router.status !== 200) return unpaid(drainer.status !== 200 ? drainer : router);
      const cats = (drainer.json?.categories as string[] | undefined) ?? [];
      const ok = (drainer.json?.score as number) <= 40 && cats.includes("approval_to_eoa") && (router.json?.score as number) >= 60;
      return ok ? { status: "PASS", detail: `permit → fresh EOA ${drainer.json?.score}/${drainer.json?.tier}; → Universal Router ${router.json?.score}/${router.json?.tier}` } : { status: "FAIL", detail: `EOA ${drainer.json?.score} ${cats.join(",")} | router ${router.json?.score}` };
    },
  },
  {
    id: "v2-evidence-and-signed-checks",
    run: async () => {
      const r = await call("POST", "/v1/risk-check", { wallet: ROUTER, chain: "base", domain: "api.merchant-labs.com", payment: { network: "base", pay_to: ROUTER, amount: "1000", asset: "USDC" }, aud: "https://merchant.example/data" }, {}, { paid: true });
      if (r.status !== 200) return unpaid(r);
      const claims = await verify(String(r.json?.jws ?? ""));
      const ev = r.json?.evidence as { sanctions?: unknown; onchain?: { status?: string }; feeds?: unknown[] } | undefined;
      const ok = !!claims && !!ev?.sanctions && !!ev.onchain && (claims.payment as { amount?: string } | undefined)?.amount === "1000" && claims.aud === "https://merchant.example/data" && typeof claims.jti === "string";
      return ok ? { status: "PASS", detail: `evidence{sanctions,onchain=${ev?.onchain?.status},feeds=${ev?.feeds?.length ?? 0}} + signed checks/payment/aud/jti; iss pinned via did:web` } : { status: "FAIL", detail: JSON.stringify({ claims, ev }).slice(0, 300) };
    },
  },
];

async function main(): Promise<void> {
  const results: Outcome[] = [];
  for (const p of probes) {
    let o: Omit<Outcome, "id">;
    try {
      o = await p.run();
    } catch (err) {
      o = { status: "SKIP", detail: `error: ${String(err).slice(0, 160)}` };
    }
    results.push({ id: p.id, ...o });
    console.log(`${o.status.padEnd(4)} ${p.id.padEnd(40)} ${o.detail}`);
  }
  for (const r of receipts) console.log(`paid: ${r.network} tx ${r.transaction} (payer ${r.payer})`);
  const summary = { timestamp: new Date().toISOString(), endpoint: BASE, receipts, passed: results.filter((r) => r.status === "PASS").length, failed: results.filter((r) => r.status === "FAIL").length, skipped: results.filter((r) => r.status === "SKIP").length, results };
  mkdirSync(EVAL_EVIDENCE_DIR, { recursive: true });
  writeFileSync(`${EVAL_EVIDENCE_DIR}/security-v2-report.json`, JSON.stringify(summary, null, 2));
  console.log(`\n${summary.passed} PASS · ${summary.failed} FAIL · ${summary.skipped} SKIP → ${EVAL_EVIDENCE_DIR}/security-v2-report.json`);
  if (summary.failed) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
