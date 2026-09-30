import { INTERACTION_TYPES, isSafeId, normalizeEvidence, parseSubject, RISK_TIERS, sanitizeText, X402CheckError } from "@x402check/client";
import type { PaymentRefused } from "./payer.js";
import type {
  Action,
  ApprovalGrant,
  AssetMovement,
  Interpretation,
  PaymentRequired,
  RiskCheckRequest,
  RiskCheckResult,
  SafeEvidence,
  VerificationResult,
} from "@x402check/client";

// Everything rendered here is read by a model. Two layers keep response data from steering it:
// (1) values from the response are shown only when they match their expected format
//     (normalizeEvidence, identifier and id patterns), so free text never reaches the transcript;
// (2) every interpolated string is stripped of control, format (bidi, zero-width, tag) and
//     line-separator characters and capped, so nothing can forge a line or hide text.
export function clean(value: unknown, max = 120): string {
  return sanitizeText(String(value), max);
}

const UNSAFE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

/** The same characters removed from every string (and key) of a JSON value, without truncation. */
export function sanitizeDeep(value: unknown, depth = 0): unknown {
  if (typeof value === "string") return value.replace(UNSAFE, " ");
  if (depth > 32) return "[truncated]";
  if (Array.isArray(value)) return value.map((item) => sanitizeDeep(item, depth + 1));
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k.replace(UNSAFE, " "), sanitizeDeep(v, depth + 1)]));
  }
  return value;
}

const JTI = /^[A-Za-z0-9-]{1,64}$/;
const DID_WEB = /^did:web:[A-Za-z0-9.%-]{1,253}(?::[A-Za-z0-9._~-]+)*$/;
/** Any DID (W3C DID syntax), for an audience. */
const DID = /^did:[a-z0-9]{1,32}:[A-Za-z0-9._%-]+(?::[A-Za-z0-9._%-]+)*$/;
const JWS = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const HTTPS_URL = /^https?:\/\/[A-Za-z0-9.-]+(?::\d{1,5})?(?:\/[A-Za-z0-9._~/-]*)?$/;
/** A host name with at least one dot. */
const HOST = /^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const FEED_CHECK = /^[a-z0-9][a-z0-9_-]{0,47}@[0-9A-Za-z.:+/-]{0,40}:[a-z_]{1,20}$/;
const HEX64 = /^[0-9a-fA-F]{64}$/;
/** An identifier, date, network or version ("not_listed", "2026-09-23", "eip155:8453", "jev-wallet-risk/v6"). */
const WORD = /^[A-Za-z0-9_.:/-]{1,64}$/;
const CLAIM_KEY = /^[a-z][a-z0-9_]{0,31}$/;
const ASSET_SYMBOL = /^[A-Za-z0-9._-]{1,32}$/;
/** Shown instead of a value that is not in its expected format (it may be free text). */
export const NOT_SHOWN = "(not shown: unexpected format)";

export interface PaymentView {
  settled?: boolean;
  network?: string;
  transaction?: string;
  payer?: string;
  spent_usd?: number;
  budget_usd?: number;
  /** Paid from prepaid credits: this check's charge and the balance left ("$0.001"). */
  credits_charged_usd?: string;
  credits_balance_usd?: string;
}

const TX_HASH = /^(?:0x[0-9a-fA-F]{64}|[1-9A-HJ-NP-Za-km-z]{64,90})$/;
const CAIP2 = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/;

/** The decoded PAYMENT-RESPONSE receipt (format-checked), the payer's spend so far, or the prepaid-credit charge. */
export function paymentView(
  receipt: Record<string, unknown> | undefined,
  spend: { spent_usd: number; budget_usd: number } | undefined,
  credits?: { chargedUsd: string; balanceUsd: string } | undefined,
): PaymentView | undefined {
  const view: PaymentView = {};
  if (credits) {
    view.credits_charged_usd = credits.chargedUsd;
    view.credits_balance_usd = credits.balanceUsd;
  }
  if (receipt) {
    if (typeof receipt.success === "boolean") view.settled = receipt.success;
    if (typeof receipt.network === "string" && CAIP2.test(receipt.network)) view.network = receipt.network;
    if (typeof receipt.transaction === "string" && TX_HASH.test(receipt.transaction)) view.transaction = receipt.transaction;
    if (typeof receipt.payer === "string" && parseSubject(receipt.payer)) view.payer = receipt.payer;
  }
  if (spend) {
    view.spent_usd = spend.spent_usd;
    view.budget_usd = spend.budget_usd;
  }
  return Object.keys(view).length > 0 ? view : undefined;
}

function dollars(n: number): string {
  return `$${n.toFixed(n < 0.1 ? 3 : 2)}`;
}

/** The x402 payment challenge reduced to its format-checked payment options (no free text). */
export function safePaymentRequired(pr: PaymentRequired | undefined): Record<string, unknown> | undefined {
  if (!pr || !Array.isArray(pr.accepts)) return undefined;
  const accepts = pr.accepts
    .slice(0, 16)
    .map((a) => {
      if (typeof a !== "object" || a === null) return undefined;
      const scheme = typeof a.scheme === "string" && /^[a-z0-9_-]{1,32}$/.test(a.scheme) ? a.scheme : undefined;
      const network = typeof a.network === "string" && /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/.test(a.network) ? a.network : undefined;
      const amount = typeof a.amount === "string" && /^\d{1,78}$/.test(a.amount) ? a.amount : undefined;
      const asset = typeof a.asset === "string" && parseSubject(a.asset) ? a.asset : undefined;
      const payTo = typeof a.payTo === "string" && parseSubject(a.payTo) ? a.payTo : undefined;
      return scheme && network && amount && asset && payTo ? { scheme, network, amount, asset, payTo } : undefined;
    })
    .filter((a) => a !== undefined);
  return { x402Version: typeof pr.x402Version === "number" ? pr.x402Version : undefined, accepts };
}

/**
 * The API result with every field in its expected format (evidence through `normalizeEvidence`),
 * for the structured output an agent reads. The `jws` is untouched and still verifies.
 */
export function safeResult(result: RiskCheckResult): Record<string, unknown> {
  const str = (v: unknown, re: RegExp): string | undefined => (typeof v === "string" && re.test(v) ? v : undefined);
  const out: Record<string, unknown> = { checked: result.checked === true };
  if (result.checked !== true && isSafeId(result.reason)) out.reason = result.reason;
  if (typeof result.score === "number" && Number.isFinite(result.score)) out.score = result.score;
  if ((RISK_TIERS as readonly unknown[]).includes(result.tier)) out.tier = result.tier;
  const provider = str(result.provider, DID_WEB);
  if (provider) out.provider = provider;
  if (Array.isArray(result.categories)) out.categories = result.categories.filter(isSafeId);
  const jws = str(result.jws, JWS);
  if (jws) out.jws = jws;
  const jwks = str(result.jwks_url, HTTPS_URL);
  if (jwks) out.jwks_url = jwks;
  const checkedAt = str(result.checked_at, TIMESTAMP);
  if (checkedAt) out.checked_at = checkedAt;
  const expiresAt = str(result.expires_at, TIMESTAMP);
  if (expiresAt) out.expires_at = expiresAt;
  const evidence = normalizeEvidence(result.evidence);
  if (evidence) out.evidence = evidence;
  return out;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** An audience in one of its expected shapes (an http(s) URL, a DID, a host name), or NOT_SHOWN. */
function audience(value: unknown): string {
  return typeof value === "string" && value.length <= 256 && (HTTPS_URL.test(value) || DID.test(value) || HOST.test(value)) ? value : NOT_SHOWN;
}

function wordValue(value: unknown): unknown {
  if (typeof value === "string") return WORD.test(value) ? value : NOT_SHOWN;
  return typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value)) ? value : NOT_SHOWN;
}

/** The payment binding, each field in its expected format. */
function safePayment(value: unknown): unknown {
  if (!isRecord(value)) return NOT_SHOWN;
  const out: Record<string, unknown> = {};
  for (const [key, v] of Object.entries(value)) {
    if (!CLAIM_KEY.test(key)) continue;
    const s = typeof v === "string" ? v : undefined;
    const ok =
      s !== undefined &&
      (key === "network"
        ? /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/.test(s)
        : key === "pay_to"
          ? parseSubject(s) !== null
          : key === "amount"
            ? /^\d{1,78}$/.test(s)
            : key === "asset"
              ? s === "native" || parseSubject(s) !== null || ASSET_SYMBOL.test(s)
              : key === "resource"
                ? s.length <= 512 && HTTPS_URL.test(s)
                : false);
    out[key] = ok ? s : NOT_SHOWN;
  }
  return out;
}

/** The provider-verified checks, as identifiers, dates and networks. */
function safeChecks(value: unknown): unknown {
  if (!isRecord(value)) return NOT_SHOWN;
  const out: Record<string, unknown> = {};
  for (const [key, v] of Object.entries(value)) {
    if (!CLAIM_KEY.test(key)) continue;
    if (key === "feeds") out.feeds = Array.isArray(v) ? v.filter((f): f is string => typeof f === "string" && FEED_CHECK.test(f)) : NOT_SHOWN;
    else if (key === "model") out.model = wordValue(v);
    else if (isRecord(v)) {
      out[key] = Object.fromEntries(
        Object.entries(v)
          .filter(([k]) => CLAIM_KEY.test(k))
          .map(([k, x]) => [k, k === "findings" ? (Array.isArray(x) ? x.filter(isSafeId) : NOT_SHOWN) : wordValue(x)]),
      );
    } else out[key] = NOT_SHOWN;
  }
  return out;
}

/**
 * Attestation claims for an agent to read: every value in its expected format (a DID, an
 * address, a URL or host for the audience, numbers, enums, identifiers), anything else replaced
 * by NOT_SHOWN. A genuinely signed claim can still carry a caller's free text (e.g. `aud`): the
 * signature proves who signed it, not that it is safe to read as instructions.
 */
export function safeClaims(claims: unknown): Record<string, unknown> | null {
  if (!isRecord(claims)) return null;
  const out: Record<string, unknown> = {};
  const num = (v: unknown): unknown => (typeof v === "number" && Number.isFinite(v) ? v : NOT_SHOWN);
  for (const [key, value] of Object.entries(claims)) {
    if (!CLAIM_KEY.test(key)) continue;
    switch (key) {
      case "iss":
        out.iss = typeof value === "string" && value.length <= 256 && DID.test(value) ? value : NOT_SHOWN;
        break;
      case "sub":
        out.sub = typeof value === "string" && parseSubject(value) ? value : NOT_SHOWN;
        break;
      case "aud":
        out.aud = Array.isArray(value) ? value.slice(0, 16).map(audience) : audience(value);
        break;
      case "iat":
      case "exp":
      case "nbf":
        out[key] = num(value);
        break;
      case "score":
        out.score = typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 100 ? value : NOT_SHOWN;
        break;
      case "tier":
        out.tier = (RISK_TIERS as readonly unknown[]).includes(value) ? value : NOT_SHOWN;
        break;
      case "jti":
        out.jti = typeof value === "string" && JTI.test(value) ? value : NOT_SHOWN;
        break;
      case "categories":
        out.categories = Array.isArray(value) ? value.filter(isSafeId) : NOT_SHOWN;
        break;
      case "input_hash":
      case "request_hash":
        out[key] = typeof value === "string" && HEX64.test(value) ? value : NOT_SHOWN;
        break;
      case "interaction":
        out.interaction = (INTERACTION_TYPES as readonly unknown[]).includes(value) ? value : NOT_SHOWN;
        break;
      case "payment":
        out.payment = safePayment(value);
        break;
      case "checks":
        out.checks = safeChecks(value);
        break;
      case "asserted":
        out.asserted = isRecord(value)
          ? Object.fromEntries(
              Object.entries(value)
                .filter(([k]) => CLAIM_KEY.test(k))
                .map(([k, v]) => [k, k === "screening" ? (v === "clean" || v === "flagged" || v === "unknown" ? v : NOT_SHOWN) : k === "pre_authorized" && typeof v === "boolean" ? v : NOT_SHOWN]),
            )
          : NOT_SHOWN;
        break;
      default:
        out[key] = NOT_SHOWN;
    }
  }
  return out;
}

function isoTime(seconds: unknown): string {
  if (typeof seconds !== "number" || !Number.isFinite(seconds)) return NOT_SHOWN;
  const date = new Date(seconds * 1000);
  return Number.isNaN(date.getTime()) ? NOT_SHOWN : date.toISOString();
}

function short(address: string): string {
  const a = clean(address, 160);
  return a.length > 14 ? `${a.slice(0, 6)}…${a.slice(-4)}` : a;
}

function party(address: string, isContract: boolean | undefined): string {
  return `${short(address)}${isContract === false ? " (EOA)" : isContract === true ? " (contract)" : ""}`;
}

const HEADLINE: Record<Action, string> = {
  allow: "ALLOW. No check fired; you may proceed. This is not a guarantee of safety.",
  warn: "WARN. Risk signals present: get explicit confirmation from the user before proceeding.",
  block: "BLOCK. Do not proceed.",
  not_verified: "NOT VERIFIED. STOP: the check did not complete or could not be verified. This is never an all-clear.",
};

const POLICY = "Policy: allow → proceed · warn → ask the user first · block or not_verified → STOP.";

function evidenceLine(e: SafeEvidence): string {
  const parts: string[] = [];
  if (e.sanctions) parts.push(`OFAC SDN ${e.sanctions.status === "listed" ? "LISTED" : "not listed"} (list as of ${e.sanctions.as_of})`);
  const o = e.onchain;
  if (o?.status === "ok") {
    const kind = o.is_contract === true ? "contract" : o.is_contract === false ? "plain wallet (EOA)" : "account";
    const source = o.verified === true ? ", verified source" : o.verified === false ? ", UNVERIFIED source" : "";
    const activity = o.activity === "none" ? ", no history" : o.activity === "some" ? `, active${o.tx_count !== undefined ? ` (${o.tx_count} tx)` : ""}` : "";
    const delegated = o.code?.kind === "delegated" && o.code.delegate ? `, EIP-7702 delegated to ${short(o.code.delegate)}` : "";
    parts.push(`on-chain: ${kind}${source}${activity}${delegated}${o.network ? ` on ${o.network}` : ""}`);
  } else if (o) {
    parts.push(`on-chain: ${o.status === "unavailable" ? "unavailable" : "not supported for this chain"}`);
  }
  const d = e.domain;
  if (d) parts.push(`domain ${d.host}: ${d.official ? "official" : `impersonation ${d.impersonation}${d.brand ? ` of ${d.brand}` : ""}`}`);
  if (e.feeds && e.feeds.length > 0) parts.push(`feeds: ${e.feeds.slice(0, 6).map((f) => `${f.source} ${f.status === "hit" ? "HIT" : f.status}`).join(", ")}`);
  if (e.model) parts.push(`model ${e.model}`);
  return clean(`Evidence: ${parts.length > 0 ? parts.join(" · ") : "none reported"}`, 1200);
}

function listed<T>(items: T[] | undefined, fmt: (item: T) => string, max = 5): string {
  if (!items || items.length === 0) return "none";
  const shown = items.slice(0, max).map(fmt).join("; ");
  return items.length > max ? `${shown}; (+${items.length - max} more)` : shown;
}

function movement(m: AssetMovement): string {
  const asset = m.standard === "native" ? "native" : `${m.standard} ${short(m.asset)}`;
  return `${asset}${m.amount !== undefined ? ` ${m.amount}` : ""}${m.token_id !== undefined ? ` #${m.token_id}` : ""}`;
}

function approval(a: ApprovalGrant): string {
  const scope = a.unlimited ? " UNLIMITED" : a.standard === "erc721" && a.amount !== undefined ? ` token #${a.amount}` : a.amount !== undefined ? ` ${a.amount}` : "";
  return `${a.standard} ${short(a.asset)}${scope} to ${party(a.spender, a.spender_is_contract)}`;
}

function simulationLines(e: SafeEvidence): string[] {
  const sim = e.simulation;
  if (!sim) return [];
  const head = `Simulation${sim.network ? ` (${sim.network})` : ""}: ${sim.status}`;
  if (sim.status !== "ok" && sim.status !== "reverted") return [head];
  const lines = [
    `${head} · amounts in base units`,
    `- sends: ${listed(sim.outflows, (m) => `${movement(m)} → ${party(m.counterparty, m.counterparty_is_contract)}`)}`,
    `- receives: ${listed(sim.inflows, (m) => `${movement(m)} from ${party(m.counterparty, m.counterparty_is_contract)}`)}`,
    `- approves: ${listed(sim.approvals, approval)}`,
  ];
  if (sim.code_matches && sim.code_matches.length > 0) {
    lines.push(`- drainer code: ${listed(sim.code_matches, (m) => `${short(m.address)} (${m.role}) matches ${m.sources.join(", ")}`)}`);
  }
  if (sim.forwarder_verified === true) lines.push("- forwarded by a source-verified contract (e.g. a bridge or batch sender)");
  if (sim.limits && sim.limits.length > 0) lines.push(`- incomplete (not an all-clear): ${sim.limits.join(", ")}`);
  if (sim.findings && sim.findings.length > 0) lines.push(`- findings: ${sim.findings.slice(0, 8).join(", ")}`);
  return lines.map((line) => clean(line, 1200));
}

function attestationLine(result: RiskCheckResult | undefined, v: VerificationResult | undefined): string | undefined {
  if (!result?.checked) return undefined;
  if (!v) return "Attestation: missing (a verdict without a signed attestation cannot be trusted)";
  const jti = typeof v.claims?.jti === "string" && JTI.test(v.claims.jti) ? v.claims.jti : undefined;
  if (v.valid) {
    const exp = typeof v.claims.exp === "number" ? new Date(v.claims.exp * 1000).toISOString() : "unknown";
    return `Attestation: signature verified against ${clean(v.issuer, 100)} · jti ${jti ?? "none"} · expires ${exp}`;
  }
  return `Attestation: NOT VERIFIED (${v.failures.join(", ")})${jti ? ` · unverified jti ${jti}` : ""}`;
}

type PayerInfo = { address: string; maxPaymentUsd: number; budgetUsd: number; spentUsd: number };

const NO_PAYER =
  "Next: every check is paid. Set X402CHECK_CREDIT_TOKEN to a prepaid credit token ($0.001 a check; buy one with POST https://x402check.xyz/v1/credits), or X402CHECK_PAYER_KEY to the private key of a dedicated, low-balance wallet funded with a little USDC on Base (paid per call via x402: $0.0035 on Base, gasless for the payer), then restart this server. Do not proceed without a check.";

function paymentNextStep(refusal: PaymentRefused | undefined, error: unknown, payer: PayerInfo | undefined): string | undefined {
  if (refusal) {
    switch (refusal.kind) {
      case "budget_exhausted":
        return `Next: this server's payment budget is used up (${dollars(payer?.spentUsd ?? 0)} of ${dollars(payer?.budgetUsd ?? 0)}; X402CHECK_BUDGET_USD). Ask the operator to raise it or restart the server. Do not proceed without a check.`;
      case "over_max_payment":
        return `Next: the price exceeds this server's per-payment cap (${dollars(payer?.maxPaymentUsd ?? 0)}; X402CHECK_MAX_PAYMENT_USD). Do not proceed without a check.`;
      case "no_payable_option":
        return "Next: this server can only pay USDC on EVM networks (Base first), and none was offered. Do not proceed without a check.";
      default:
        return "Next: the payment could not be created; ask the operator to check X402CHECK_PAYER_KEY. Do not proceed without a check.";
    }
  }
  // Paid from prepaid credits: retrying cannot help, and there is no payer to check.
  if (error instanceof X402CheckError && error.code === "insufficient_credits") {
    return `Next: this server's prepaid credits cannot pay for this check (${error.message}). Ask the operator to top up the X402CHECK_CREDIT_TOKEN balance: POST https://x402check.xyz/v1/credits with that token. Do not proceed without a check.`;
  }
  if (error instanceof X402CheckError && error.code === "invalid_credit_token") {
    return "Next: the prepaid credit token was not accepted; ask the operator to check X402CHECK_CREDIT_TOKEN. Do not proceed without a check.";
  }
  if (error instanceof X402CheckError && error.code === "payment_required") {
    if (!payer) return NO_PAYER;
    return `Next: the payment was not accepted${error.paymentError ? ` (${error.paymentError})` : ""}. Check the USDC balance of the payer ${payer.address} on Base. Do not proceed without a check.`;
  }
  return undefined;
}

function nextStep(error: unknown, result: RiskCheckResult | undefined): string | undefined {
  if (error === undefined && result && result.checked !== true) {
    return result.reason === "invalid_subject"
      ? 'Next: check the address ("wallet") and call x402check_check again.'
      : "Next: retry the check; do not proceed until it succeeds.";
  }
  if (!(error instanceof X402CheckError)) return error ? "Next: retry the check; do not proceed until it succeeds." : undefined;
  switch (error.code) {
    case "invalid_request":
      return `Next: fix ${error.field ? `"${clean(error.field, 64)}"` : "the input"} and call x402check_check again.`;
    case "too_large":
      return "Next: shorten the request (context ≤ 4096 characters, body ≤ 64 KiB).";
    default:
      return "Next: retry the check; do not proceed until it succeeds.";
  }
}

export interface CheckRendering {
  request: RiskCheckRequest;
  verdict: Interpretation;
  result?: RiskCheckResult | undefined;
  error?: unknown;
  /** A payment this server refused or could not make. */
  refusal?: PaymentRefused | undefined;
  verification?: VerificationResult | undefined;
  /** The configured payer (public data only). */
  payer?: PayerInfo | undefined;
  payment?: PaymentView | undefined;
}

/** The concise, human-readable verdict an agent reads. */
export function renderCheck(r: CheckRendering): string {
  const lines = [`x402check: ${HEADLINE[r.verdict.action]}`];
  const subject = [`Checked ${clean(r.request.wallet, 160)}`];
  if (r.request.chain) subject.push(`on ${clean(r.request.chain, 64)}`);
  if (r.request.interaction) subject.push(`for ${clean(r.request.interaction.type, 32)}${r.request.interaction.unlimited ? " (unlimited)" : ""}`);
  if (r.request.domain) subject.push(`from ${clean(r.request.domain, 100)}`);
  lines.push(subject.join(" "));
  lines.push("Why:", ...r.verdict.reasons.map((reason) => `- ${clean(reason, 600)}`));
  const evidence = r.result?.checked ? normalizeEvidence(r.result.evidence) : undefined;
  if (evidence) {
    // Display only (the action is already decided): nothing here may break the verdict.
    try {
      lines.push(evidenceLine(evidence), ...simulationLines(evidence));
    } catch {
      lines.push("Evidence: present but malformed (see the structured result)");
    }
  }
  const attestation = attestationLine(r.result, r.verification);
  if (attestation) lines.push(attestation);
  const p = r.payment;
  if (p?.transaction || p?.settled !== undefined) {
    const where = p.network ? ` on ${p.network}` : "";
    lines.push(`Payment: ${p.settled === false ? "NOT settled" : "settled"}${where}${p.transaction ? ` · tx ${p.transaction}` : ""}`);
  }
  if (p?.spent_usd !== undefined && p.budget_usd !== undefined) lines.push(`Payer budget: ${dollars(p.spent_usd)} of ${dollars(p.budget_usd)} spent by this server`);
  if (p?.credits_charged_usd && p.credits_balance_usd) lines.push(`Paid from prepaid credits: ${p.credits_charged_usd} (balance ${p.credits_balance_usd})`);
  const next = paymentNextStep(r.refusal, r.error, r.payer) ?? nextStep(r.error, r.result);
  if (next) lines.push(next);
  lines.push(POLICY);
  return lines.join("\n");
}

/** Human-readable result of verifying an attestation. */
export function renderVerification(v: VerificationResult): string {
  try {
    return verificationText(v);
  } catch {
    return `x402check attestation: ${v.valid ? "VALID" : `INVALID (${v.failures.join(", ")}). Do not rely on it`}.`;
  }
}

function verificationText(v: VerificationResult): string {
  if (!v.valid) {
    // Unverified claims are attacker-controlled: show only values in their expected formats.
    const c = v.claims;
    const sub = typeof c?.sub === "string" && parseSubject(c.sub) ? c.sub : undefined;
    const tier = (RISK_TIERS as readonly unknown[]).includes(c?.tier) ? c?.tier : undefined;
    const score = typeof c?.score === "number" && Number.isFinite(c.score) ? c.score : undefined;
    const shown = [sub && `sub ${sub}`, tier && `tier ${tier}`, score !== undefined && `score ${score}`].filter(Boolean);
    return [
      `x402check attestation: INVALID (${v.failures.join(", ")}). Do not rely on it.`,
      `Expected issuer: ${clean(v.issuer, 100)}`,
      ...(shown.length > 0 ? [`Unverified claims: ${shown.join(", ")}`] : []),
    ].join("\n");
  }
  // Signed is not the same as safe to read: a caller chooses some signed values (e.g. `aud`), so
  // every value is shown only in its expected format, and NOT_SHOWN otherwise.
  const c = v.claims;
  const jti = typeof c.jti === "string" && JTI.test(c.jti) ? c.jti : "none";
  const subject = typeof c.sub === "string" && parseSubject(c.sub) ? c.sub : NOT_SHOWN;
  const tier = (RISK_TIERS as readonly unknown[]).includes(c.tier) ? c.tier : NOT_SHOWN;
  const score = typeof c.score === "number" && Number.isFinite(c.score) ? `${c.score}/100` : NOT_SHOWN;
  const lines = [
    `x402check attestation: VALID. Signed by ${clean(v.issuer, 100)}${v.verificationMethod ? ` (${clean(v.verificationMethod, 160)})` : ""}.`,
    `Subject ${subject} · tier ${tier} · score ${score} · jti ${jti}`,
    `Issued ${isoTime(c.iat)} · expires ${isoTime(c.exp)}`,
  ];
  const categories = (Array.isArray(c.categories) ? c.categories : []).filter((x) => isSafeId(x) && x !== "intent_risk" && x !== "behavioral");
  if (categories.length > 0) lines.push(`Findings: ${categories.join(", ")}`);
  const checks = c.checks;
  if (checks && typeof checks === "object") {
    const word = (x: unknown): string => (typeof x === "string" && /^[A-Za-z0-9_.:/-]{1,64}$/.test(x) ? x : "?");
    const parts = [`sanctions ${word(checks.sanctions?.status)} (${word(checks.sanctions?.as_of)})`, `on-chain ${word(checks.onchain?.status)}`];
    if (checks.domain) parts.push(`domain ${word(checks.domain.host)} impersonation ${word(checks.domain.impersonation)}`);
    if (checks.simulation) {
      const findings = (Array.isArray(checks.simulation.findings) ? checks.simulation.findings : []).filter(isSafeId);
      parts.push(`simulation ${word(checks.simulation.status)}${findings.length ? ` [${findings.join(", ")}]` : ""}`);
    }
    const feeds = (Array.isArray(checks.feeds) ? checks.feeds : []).filter((f): f is string => typeof f === "string" && FEED_CHECK.test(f));
    if (feeds.length > 0) parts.push(`feeds ${feeds.join(", ")}`);
    parts.push(`model ${word(checks.model)}`);
    lines.push(clean(`Provider-verified checks: ${parts.join(" · ")}`, 1200));
  }
  if (c.payment !== undefined) {
    const payment = safePayment(c.payment);
    const shown = isRecord(payment) ? Object.entries(payment).map(([k, val]) => `${k}=${String(val)}`) : [];
    lines.push(clean(`Bound to payment: ${shown.length > 0 ? shown.join(", ") : NOT_SHOWN}`, 1200));
  }
  if (c.interaction !== undefined) lines.push(`Bound to interaction: ${(INTERACTION_TYPES as readonly unknown[]).includes(c.interaction) ? String(c.interaction) : NOT_SHOWN}`);
  if (c.aud !== undefined) lines.push(`Audience: ${(Array.isArray(c.aud) ? c.aud.slice(0, 16).map(audience) : [audience(c.aud)]).join(", ") || NOT_SHOWN}`);
  if (c.asserted) lines.push("Note: `asserted` fields were self-reported by the caller and NOT verified by the provider.");
  return lines.join("\n");
}
