import { X402CheckError } from "./errors.js";
import { isRecord } from "./encoding.js";
import { isSafeId, normalizeEvidence, type SafeEvidence } from "./evidence.js";
import type { ApprovalGrant, AssetMovement, AttestationClaims, RiskCheckResult, RiskTier } from "./types.js";
import { RISK_TIERS } from "./types.js";
import type { VerificationResult } from "./verify.js";

export type Action = "allow" | "warn" | "block" | "not_verified";

export interface Interpretation {
  /**
   * allow: no check fired (still not a guarantee of safety) · warn: review / confirm with a human ·
   * block: do not proceed · not_verified: the check did not complete or cannot be trusted: STOP.
   */
  action: Action;
  /** Human-readable reasons, most important first. */
  reasons: string[];
  tier?: RiskTier;
  score?: number;
  /**
   * With `not_verified`: a stable code for why. An `X402CheckError` code ("payment_required",
   * "invalid_request", "network_error", "timeout", …), or "checked_false", "malformed_verdict",
   * "invalid_time", "attestation_invalid", "attestation_mismatch", "expired", "error".
   */
  code?: string;
  /** With `not_verified`: what to do next. */
  next?: string;
}

export interface InterpretOptions {
  /**
   * Result of `verifyAttestation` on `result.jws`. Anything but valid → not_verified; when valid,
   * the body's tier, score and categories must equal the signed claims (else not_verified).
   */
  verification?: VerificationResult | undefined;
  /** For the `expires_at` check: a Date or epoch milliseconds. Default now. */
  now?: Date | number | undefined;
}

const ACTION_BY_TIER: Record<RiskTier, Action> = { low: "allow", medium: "warn", high: "block", critical: "block" };

/** Deterministic findings (lists, code fingerprints, simulated overpayment): block whatever the tier. */
const HARD_BLOCK = new Set(["sanctioned_address", "known_scam_address", "phishing_domain", "known_drainer_code", "outflow_exceeds_declared"]);

/**
 * Checks that did not fully run, or evidence that needs a human: never an unremarked allow. The
 * provider raises these to at least "medium"; a "low" that still carries one is read as "warn".
 */
const REVIEW_FLOOR = new Set(["onchain_unavailable", "simulation_unavailable", "simulation_incomplete", "unverified_contract"]);

/** Most important first. `intent_risk` and `behavioral` are evaluated families, not findings. */
const CATEGORY_TEXT: ReadonlyArray<readonly [string, string]> = [
  ["sanctioned_address", "Sanctioned: the address is on the OFAC SDN list"],
  ["outflow_to_undisclosed_eoa", "Drainer pattern: assets leave the sender, nothing comes back, and a plain wallet (EOA) the sender did not name ends up with them"],
  ["outflow_exceeds_declared", "A named payee receives a different asset, or more, than the declared payment or transfer"],
  ["approval_to_eoa", "Drainer pattern: an approval or permit grants a plain wallet (EOA) control over the user's assets"],
  ["known_drainer_code", "Known drainer code: a contract involved runs the same logic code as a listed drainer"],
  ["known_scam_address", "Known scam or drainer address (threat feed)"],
  ["phishing_domain", "Known phishing domain (threat feed)"],
  ["impersonation", "Look-alike domain impersonating a known brand"],
  ["guard_bypass", "The content tries to disable or bypass payment safeguards (injected instruction)"],
  ["known_threat", "The content matches a known threat pattern"],
  ["unlimited_approval", "Unlimited allowance"],
  ["outflow_to_unverified_contract", "Assets leave the sender and end up in a contract whose source code is not verified"],
  ["simulation_reverted", "The simulated transaction reverts"],
  ["simulation_incomplete", "The simulation is incomplete (recipients or spenders could not be classified, or logs were truncated): not an all-clear"],
  ["simulation_unavailable", "The transaction could not be simulated (transient failure): its asset flows were not checked"],
  ["onchain_unavailable", "The spender could not be classified (on-chain lookups failed): the approval-to-EOA check did not run"],
  ["laundering_pattern", "The content describes a laundering pattern"],
  ["fraud_signal", "Fraud signals in the content"],
  ["automated_abuse", "Automated-abuse signals in the content"],
  ["compliance_risk", "Compliance risk (sanctions exposure described or flagged)"],
  ["community_flagged_domain", "Domain flagged by a community feed (not corroborated by domain analysis)"],
  ["unverified_contract", "Approval or permit to a contract whose source code is not verified: review"],
  ["new_address", "New address: no on-chain history"],
];
const CATEGORY_RANK = new Map(CATEGORY_TEXT.map(([c], i) => [c, i]));
const CATEGORY_LABEL = new Map(CATEGORY_TEXT);
const FAMILIES = new Set(["intent_risk", "behavioral"]);

/**
 * Human-readable text for a category. Unknown snake_case ids are humanized ("Finding: …");
 * anything else is never echoed.
 */
export function describeCategory(category: string): string {
  const known = CATEGORY_LABEL.get(category);
  if (known) return known;
  if (!isSafeId(category)) return "Finding: unrecognized category";
  return `Finding: ${category.replace(/_+/g, " ")}`;
}

// Reasons are read by people and models: strip control, format (bidi, zero-width, tag) and
// line-separator characters, collapse whitespace, and cap the length.
const UNSAFE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

export function sanitizeText(text: string, max = 600): string {
  const clean = String(text).replace(UNSAFE, " ").replace(/\s+/g, " ").trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

function shortAddress(address: string): string {
  return address.length > 14 ? `${address.slice(0, 6)}…${address.slice(-4)}` : address;
}

function party(address: string, isContract: boolean | undefined): string {
  return `${shortAddress(address)}${isContract === false ? " (EOA)" : isContract === true ? " (contract)" : ""}`;
}

function movementText(m: AssetMovement): string {
  const what = m.standard === "native" ? "native" : `${m.standard} ${shortAddress(m.asset)}`;
  const amount = m.amount !== undefined ? ` ${m.amount}` : "";
  const token = m.token_id !== undefined ? ` #${m.token_id}` : "";
  return `${what}${amount}${token}`;
}

function approvalText(a: ApprovalGrant): string {
  const scope = a.unlimited ? " UNLIMITED" : a.standard === "erc721" && a.amount !== undefined ? ` token #${a.amount}` : a.amount !== undefined ? ` ${a.amount}` : "";
  return `${a.standard} ${shortAddress(a.asset)}${scope} to ${party(a.spender, a.spender_is_contract)}`;
}

/** Extra evidence for a category. `evidence` is normalized: every value has its expected format. */
function detailFor(category: string, evidence: SafeEvidence | undefined): string | undefined {
  if (!evidence) return undefined;
  const sim = evidence.simulation;
  switch (category) {
    case "sanctioned_address": {
      const s = evidence.sanctions;
      if (!s) return undefined;
      const sameKey = s.match === "same_key" && s.listed_address ? `same key as listed ${shortAddress(s.listed_address)}` : undefined;
      return [s.entity, sameKey, `list as of ${s.as_of}`].filter(Boolean).join("; ");
    }
    case "outflow_to_undisclosed_eoa": {
      const flows = (sim?.outflows ?? []).filter((o) => o.counterparty_is_contract === false);
      const shown = flows.slice(0, 3).map((o) => `${movementText(o)} → ${party(o.counterparty, o.counterparty_is_contract)}`);
      // Bridges and batch senders legitimately pay wallets the sender did not name: review, not a drain.
      if (sim?.forwarder_verified === true) shown.push("through a source-verified forwarder (e.g. a bridge or batch sender): review");
      return shown.length > 0 ? shown.join("; ") : undefined;
    }
    case "outflow_exceeds_declared": {
      const flows = sim?.outflows ?? [];
      return flows.length > 0 ? flows.slice(0, 3).map((o) => `${movementText(o)} → ${party(o.counterparty, o.counterparty_is_contract)}`).join("; ") : undefined;
    }
    case "simulation_incomplete": {
      const labels: Record<string, string> = { unclassified: "unclassified recipients or spenders", logs_truncated: "logs truncated", flows_truncated: "flows truncated" };
      const limits = (sim?.limits ?? []).map((l) => labels[l] ?? l.replace(/_+/g, " "));
      return limits.length > 0 ? limits.join(", ") : undefined;
    }
    case "outflow_to_unverified_contract": {
      const flows = (sim?.outflows ?? []).filter((o) => o.counterparty_is_contract === true);
      return flows.length > 0 ? flows.slice(0, 3).map((o) => `${movementText(o)} → ${party(o.counterparty, o.counterparty_is_contract)}`).join("; ") : undefined;
    }
    case "approval_to_eoa": {
      const grants = (sim?.approvals ?? []).filter((a) => a.spender_is_contract === false);
      if (grants.length > 0) return grants.slice(0, 3).map(approvalText).join("; ");
      const o = evidence.onchain;
      return o?.status === "ok" && o.is_contract === false ? `spender is an EOA${o.activity === "none" ? " with no history" : ""}` : undefined;
    }
    case "unlimited_approval": {
      const grants = (sim?.approvals ?? []).filter((a) => a.unlimited);
      return grants.length > 0 ? grants.slice(0, 3).map(approvalText).join("; ") : undefined;
    }
    case "known_drainer_code": {
      const matches = sim?.code_matches ?? [];
      if (matches.length > 0) return matches.slice(0, 3).map((m) => `${shortAddress(m.address)} (${m.role}) matches ${m.sources.join(", ")}`).join("; ");
      const hits = (evidence.feeds ?? []).filter((f) => f.status === "hit" && f.kind === "code");
      return hits.length > 0 ? `listed by ${hits.map((f) => `${f.source}${f.as_of ? ` (as of ${f.as_of})` : ""}`).join(", ")}` : undefined;
    }
    case "known_scam_address":
    case "phishing_domain":
    case "community_flagged_domain": {
      const kind = category === "known_scam_address" ? "address" : "domain";
      const hits = (evidence.feeds ?? []).filter((f) => f.status === "hit" && f.kind === kind);
      return hits.length > 0 ? `listed by ${hits.map((f) => `${f.source}${f.as_of ? ` (as of ${f.as_of})` : ""}`).join(", ")}` : undefined;
    }
    case "impersonation": {
      const d = evidence.domain;
      return d ? `${d.host}${d.brand ? ` imitates ${d.brand}` : ""} (${d.impersonation})` : undefined;
    }
    default:
      return undefined;
  }
}

const RETRY = "Retry the check; do not proceed until it succeeds.";
const UNTRUSTED = "Do not proceed: this verdict cannot be trusted. Retry the check over a direct connection to the provider.";

type Failure = { reason: string; code: string; next: string };

function describeError(err: unknown): Failure {
  if (err instanceof X402CheckError) {
    const code = err.code;
    switch (err.code) {
      case "invalid_request":
        return {
          code,
          reason: `The request was rejected as invalid${err.field ? ` (field "${err.field}"${err.index !== undefined ? `, batch index ${err.index}` : ""})` : ""}`,
          next: `Fix ${err.field ? `"${err.field}"` : "the request"} and check again.`,
        };
      case "payment_required":
        return err.paymentError
          ? {
              code,
              reason: `The check did not run: the x402 payment failed (${err.paymentError})`,
              next: "Check the payer's USDC balance on the network it pays on, then check again.",
            }
          : {
              code,
              reason: "The check did not run: payment required (every evaluation is paid via x402)",
              next: "Configure an x402 payer: pass an x402-paying fetch (e.g. wrapFetchWithPayment from @x402/fetch) to createClient, then check again.",
            };
      case "too_large":
        return { code, reason: "The request was too large", next: "Shorten the request (context up to 4096 characters, body up to 64 KiB, at most 25 batch items)." };
      case "evaluation_unavailable":
        return { code, reason: `The provider could not complete the evaluation${err.retryAfter !== undefined ? ` (retry in ${err.retryAfter}s)` : ""}`, next: RETRY };
      case "timeout":
        return { code, reason: "No response from the provider in time", next: RETRY };
      case "aborted":
        return { code, reason: "The check was aborted", next: RETRY };
      case "network_error":
        return { code, reason: "The provider could not be reached (network error)", next: RETRY };
      case "invalid_response":
        return { code, reason: "The provider's response was malformed", next: RETRY };
      default:
        return { code, reason: `The check failed (HTTP ${err.status})`, next: RETRY };
    }
  }
  return { code: "error", reason: "The check failed (unexpected error)", next: RETRY };
}

const FAILURE_TEXT: Record<string, string> = {
  invalid_subject: "the address could not be screened",
  model_unconfigured: "the provider's evaluation model is not configured",
  model_malformed_answers: "the evaluation returned an incomplete answer",
  model_unavailable: "the evaluation model was unavailable",
};

/** Why a `checked: false` result was not completed, as text (only known or snake_case codes are echoed). */
export function describeFailureReason(reason: unknown): string | undefined {
  if (typeof reason !== "string") return undefined;
  return FAILURE_TEXT[reason] ?? (isSafeId(reason) ? `reason: ${reason}` : "reason unrecognized");
}

function notVerified(reason: string, code: string, next: string): Interpretation {
  return { action: "not_verified", reasons: [sanitizeText(reason), "Not verified is never an all-clear: do not proceed"], code, next };
}

function epochMs(now: Date | number | undefined): number {
  return now instanceof Date ? now.getTime() : typeof now === "number" ? now : Date.now();
}

/** With a verified attestation, the body must say what was signed. */
function matchesClaims(result: RiskCheckResult, claims: AttestationClaims): boolean {
  const body = new Set(Array.isArray(result.categories) ? result.categories : []);
  const signed = new Set(Array.isArray(claims.categories) ? claims.categories : []);
  return claims.tier === result.tier && claims.score === result.score && body.size === signed.size && [...signed].every((c) => body.has(c));
}

/**
 * The fail-closed policy wallets and agents should apply to a check:
 * low → allow · medium → warn · high/critical → block ·
 * `checked: false`, any error, a malformed or expired verdict, or a failed attestation → not_verified.
 * Never throws. Reasons only contain fixed text and values checked against their expected
 * formats (see `normalizeEvidence`).
 *
 * @param input The result of `check()`, or the error it threw.
 */
export function interpret(input: RiskCheckResult | unknown, options?: InterpretOptions | null): Interpretation {
  const opts: InterpretOptions = options ?? {};
  if (input instanceof Error) {
    const f = describeError(input);
    return notVerified(f.reason, f.code, f.next);
  }
  if (!isRecord(input) || input.checked !== true) {
    const why = isRecord(input) ? describeFailureReason(input.reason) : undefined;
    const next = isRecord(input) && input.reason === "invalid_subject" ? "Check the address and try again." : RETRY;
    return notVerified(`The provider could not complete the check (checked: false${why ? `: ${why}` : ""})`, "checked_false", next);
  }
  const result = input as unknown as RiskCheckResult;
  const { tier, score } = result;
  if (!tier || !(RISK_TIERS as readonly string[]).includes(tier) || typeof score !== "number" || !Number.isFinite(score) || score < 0 || score > 100) {
    return notVerified("The verdict is malformed (missing or out-of-range tier or score)", "malformed_verdict", RETRY);
  }
  const nowMs = epochMs(opts.now);
  if (!Number.isFinite(nowMs)) return notVerified("Invalid evaluation time", "invalid_time", "Pass a valid `now` (a Date or epoch milliseconds).");
  const v = opts.verification;
  if (v && !v.valid) return notVerified(`The attestation failed verification (${v.failures.join(", ") || "unknown"})`, "attestation_invalid", UNTRUSTED);
  // The response body is unsigned: with a verified attestation, the signed claims are the
  // verdict, and a body that disagrees with them (e.g. a downgraded tier) is not trusted.
  if (v?.valid && !matchesClaims(result, v.claims)) {
    return notVerified("The response does not match its signed attestation (tier, score or categories differ)", "attestation_mismatch", UNTRUSTED);
  }
  if (result.expires_at !== undefined) {
    const expires = typeof result.expires_at === "string" ? Date.parse(result.expires_at) : Number.NaN;
    if (!Number.isFinite(expires)) return notVerified("The verdict is malformed (unreadable expires_at)", "malformed_verdict", RETRY);
    if (expires <= nowMs) return notVerified(`The verdict expired at ${new Date(expires).toISOString()}`, "expired", "Run a fresh check.");
  }

  const evidence = normalizeEvidence(result.evidence);
  const categories = (Array.isArray(result.categories) ? result.categories : []).filter((c): c is string => typeof c === "string");
  const found = new Set<string>(categories.filter((c) => !FAMILIES.has(c)));
  for (const f of evidence?.simulation?.findings ?? []) found.add(f);
  if (evidence?.sanctions?.status === "listed") found.add("sanctioned_address");

  let action = ACTION_BY_TIER[tier];
  if ([...found].some((c) => HARD_BLOCK.has(c))) action = "block";
  // Defense in depth (only ever stricter): unsigned evidence of an incomplete check also floors.
  const simStatus = evidence?.simulation?.status;
  const incomplete = simStatus === "unavailable" || (evidence?.simulation?.limits?.length ?? 0) > 0;
  if (action === "allow" && ([...found].some((c) => REVIEW_FLOOR.has(c)) || incomplete)) action = "warn";

  // Known findings first, by importance; a flood of unknown categories is capped.
  const ordered = [...found].sort((a, b) => (CATEGORY_RANK.get(a) ?? 900) - (CATEGORY_RANK.get(b) ?? 900)).slice(0, 24);
  const reasons = ordered.map((c) => {
    let detail: string | undefined;
    try {
      detail = detailFor(c, evidence);
    } catch {
      detail = undefined;
    }
    return sanitizeText(detail ? `${describeCategory(c)}: ${detail}` : describeCategory(c));
  });
  const summary = `Risk tier ${tier}, score ${score}/100 (higher is safer)`;
  if (reasons.length === 0) {
    reasons.push(`No check fired: risk tier ${tier}, score ${score}/100 (higher is safer). A clean verdict means none of the checks fired, not that the counterparty is safe`);
  } else {
    reasons.push(summary);
  }
  // Caveats the categories do not already state.
  if (evidence?.onchain?.status === "unavailable" && !found.has("onchain_unavailable")) {
    reasons.push("On-chain facts were unavailable: the approval-to-EOA and new-address checks did not run");
  }
  if (simStatus === "unavailable" && !found.has("simulation_unavailable")) {
    reasons.push("The transaction could not be simulated: its asset flows and approvals were not checked");
  }
  if (simStatus === "unsupported") {
    reasons.push("Transaction simulation is not supported on this chain: asset flows and approvals were not checked");
  }
  return { action, reasons, tier, score };
}
