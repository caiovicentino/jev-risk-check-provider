/**
 * Request/response contract with the x402check API.
 *
 * Pure except for `postRiskChecks`, which takes the `fetch` implementation as
 * a parameter (the Snap passes its network endowment).
 */
import type { Candidate, Decoded, Interaction, Payment } from "./util";
import { capText, hostFromUrl, isPlausibleHost, redactSecrets } from "./util";

export const API_ORIGIN = "https://x402check.xyz";
export const ENDPOINT = `${API_ORIGIN}/v1/risk-check`;
export const BATCH_ENDPOINT = `${API_ORIGIN}/v1/risk-check/batch`;
export const JWKS_URL = `${API_ORIGIN}/.well-known/jwks.json`;
export const MAX_CONTEXT = 700;
/** Addresses checked per request (billed per item by the batch endpoint). */
export const MAX_CHECKS = 3;
/** Insight handlers get 10s (manifest maxRequestTime); keep headroom. */
export const REQUEST_TIMEOUT_MS = 8000;

/** Exactly the fields the backend accepts; unknown fields are rejected. */
export type RiskCheckBody = {
  wallet: string;
  chain?: string;
  domain?: string;
  context: string;
  payment?: Payment;
  interaction: Interaction;
};

export type Tier = "low" | "medium" | "high" | "critical";

export type SanctionsEvidence = {
  list: "ofac-sdn";
  as_of: string;
  status: "listed" | "not_listed";
  entity?: string;
};

export type DomainEvidence = {
  host: string;
  registrable: string;
  official: boolean;
  impersonation: "none" | "weak" | "strong";
  brand?: string;
  signals: string[];
};

export type OnchainEvidence = {
  status: "ok" | "unavailable" | "unsupported";
  network?: string;
  is_contract?: boolean;
  activity?: "none" | "some";
  tx_count?: number;
};

export type FeedEvidence = {
  source: string;
  kind?: string;
  as_of?: string;
  status: "hit" | "clear" | "unavailable" | "not_applicable";
};

export type Evidence = {
  sanctions?: SanctionsEvidence;
  domain?: DomainEvidence;
  onchain?: OnchainEvidence;
  feeds?: FeedEvidence[];
};

export type Verdict = {
  checked: true;
  score?: number;
  tier?: Tier;
  categories: string[];
  jws?: string;
  jwks_url?: string;
  provider?: string;
  evidence?: Evidence;
};

/** One item of a batch check. */
export type BatchItem = { status: "ok"; verdict: Verdict } | { status: "unverified" } | { status: "invalid" };

export type CheckOutcome =
  | { kind: "ok"; verdict: Verdict }
  | { kind: "batch"; items: BatchItem[] }
  | { kind: "unverified" }
  | { kind: "quota" }
  | { kind: "http_error"; status: number }
  | { kind: "invalid_response" }
  | { kind: "network_error"; timedOut: boolean };

/**
 * Hostname of a request origin ("https://app.example.com" or a bare host),
 * punycode-encoded. Undefined for non-web origins ("metamask", "npm:...").
 *
 * @param origin - The transaction or signature origin.
 * @returns The lowercase hostname, or undefined.
 */
export function originHost(origin: unknown): string | undefined {
  if (typeof origin !== "string") return undefined;
  const raw = origin.trim();
  if (!raw || raw.length > 2048 || /\s/u.test(raw)) return undefined;
  if (/^https?:\/\//iu.test(raw)) return hostFromUrl(raw);
  if (/^[\p{L}\p{N}.-]{1,253}(?::\d{1,5})?$/u.test(raw)) {
    const host = hostFromUrl(`https://${raw}`);
    return host && isPlausibleHost(host) ? host : undefined;
  }
  return undefined;
}

/**
 * Builds the human-readable `context` string (hard cap 700 chars): proven
 * dangers first, then the decoded summary, warnings and requesting site, and
 * (for batch checks) which address this item is about. Secret-looking strings
 * are redacted.
 *
 * @param decoded - The decoded request.
 * @param host - Hostname of the requesting site, if any.
 * @param candidate - The address this context accompanies (batch items).
 * @returns The context string.
 */
export function composeContext(decoded: Decoded, host?: string, candidate?: Candidate): string {
  const parts: string[] = [];
  if (decoded.danger.length > 0) parts.push(`Proven danger: ${decoded.danger.join("; ")}.`);
  parts.push(decoded.summary);
  if (decoded.warnings.length > 0) parts.push(`Local warnings: ${decoded.warnings.join("; ")}.`);
  if (host) parts.push(`Requested by ${host}.`);
  const checked = candidate
    ? ` Checked address: ${candidate.role} ${candidate.address}${candidate.reason ? ` (${capText(candidate.reason, 120)})` : ""}.`
    : "";
  const body = redactSecrets(capText(parts.join(" "), 4096));
  return `${capText(body, MAX_CONTEXT - checked.length)}${checked}`;
}

function cleanPayment(input?: Payment): Payment | undefined {
  if (!input) return undefined;
  const payment: Payment = {};
  if (input.network) payment.network = input.network;
  if (input.pay_to) payment.pay_to = input.pay_to;
  if (input.amount && /^\d{1,78}$/u.test(input.amount)) payment.amount = input.amount;
  if (input.asset) payment.asset = input.asset;
  return Object.keys(payment).length > 0 ? payment : undefined;
}

/**
 * Builds one POST body per checked address (primary first, at most 3). Empty
 * when there is nothing to check.
 *
 * @param decoded - The decoded request.
 * @param origin - The request origin, if any.
 * @returns The bodies to send.
 */
export function buildRiskCheckBodies(decoded: Decoded, origin?: unknown): RiskCheckBody[] {
  if (!decoded.counterparty) return [];
  const host = originHost(origin);
  // The requesting site is the primary domain; a signed message with no origin
  // falls back to the first host named inside the message.
  const domain = host ?? decoded.referencedHosts?.[0];
  const primary: Candidate = {
    address: decoded.counterparty,
    role: decoded.role ?? "counterparty",
    interaction: decoded.interaction,
    ...(decoded.payment ? { payment: decoded.payment } : {}),
    ...(decoded.reason ? { reason: decoded.reason } : {}),
    rank: 0,
  };
  const candidates = [primary, ...decoded.others].slice(0, MAX_CHECKS);
  return candidates.map((candidate) => {
    const payment = cleanPayment(candidate.payment);
    return {
      wallet: candidate.address,
      ...(decoded.chain ? { chain: decoded.chain } : {}),
      ...(domain ? { domain } : {}),
      context: composeContext(decoded, host, candidates.length > 1 ? candidate : undefined),
      ...(payment ? { payment } : {}),
      // Only `type` and `unlimited: true`; nothing else inside `interaction`.
      interaction:
        candidate.interaction.unlimited === true
          ? { type: candidate.interaction.type, unlimited: true }
          : { type: candidate.interaction.type },
    };
  });
}

/**
 * The body for the primary address (undefined when nothing is checked).
 *
 * @param decoded - The decoded request.
 * @param origin - The request origin, if any.
 * @returns The primary body.
 */
export function buildRiskCheckBody(decoded: Decoded, origin?: unknown): RiskCheckBody | undefined {
  return buildRiskCheckBodies(decoded, origin)[0];
}

// ---------------------------------------------------------------------------
// Response parsing (defensive: the UI only ever sees validated fields)
// ---------------------------------------------------------------------------

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeString(value: unknown, max: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const text = value
    .slice(0, max * 4)
    .replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069]/gu, " ")
    .trim();
  return text ? capText(text, max) : undefined;
}

function parseSanctions(value: unknown): SanctionsEvidence | undefined {
  if (!isObject(value)) return undefined;
  if (value.status !== "listed" && value.status !== "not_listed") return undefined;
  const entity = safeString(value.entity, 80);
  return {
    list: "ofac-sdn",
    as_of: safeString(value.as_of, 32) ?? "unknown date",
    status: value.status,
    ...(entity ? { entity } : {}),
  };
}

function parseDomain(value: unknown): DomainEvidence | undefined {
  if (!isObject(value)) return undefined;
  const host = safeString(value.host, 100);
  if (!host) return undefined;
  const impersonation =
    value.impersonation === "strong" || value.impersonation === "weak" || value.impersonation === "none"
      ? value.impersonation
      : "none";
  const brand = safeString(value.brand, 40);
  const signals = Array.isArray(value.signals)
    ? value.signals
        .slice(0, 16)
        .map((signal) => safeString(signal, 80))
        .filter((signal): signal is string => Boolean(signal))
        .slice(0, 4)
    : [];
  return {
    host,
    registrable: safeString(value.registrable, 100) ?? host,
    official: value.official === true,
    impersonation,
    ...(brand ? { brand } : {}),
    signals,
  };
}

function parseOnchain(value: unknown): OnchainEvidence | undefined {
  if (!isObject(value)) return undefined;
  if (value.status !== "ok" && value.status !== "unavailable" && value.status !== "unsupported") return undefined;
  const out: OnchainEvidence = { status: value.status };
  const network = safeString(value.network, 40);
  if (network) out.network = network;
  if (typeof value.is_contract === "boolean") out.is_contract = value.is_contract;
  if (value.activity === "none" || value.activity === "some") out.activity = value.activity;
  if (typeof value.tx_count === "number" && Number.isFinite(value.tx_count) && value.tx_count >= 0) {
    out.tx_count = Math.floor(value.tx_count);
  }
  return out;
}

function parseFeeds(value: unknown): FeedEvidence[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const feeds: FeedEvidence[] = [];
  for (const item of value.slice(0, 12)) {
    if (!isObject(item)) continue;
    const source = safeString(item.source, 48);
    const { status } = item;
    if (!source || (status !== "hit" && status !== "clear" && status !== "unavailable" && status !== "not_applicable")) {
      continue;
    }
    const kind = safeString(item.kind, 32);
    const asOf = safeString(item.as_of, 32);
    feeds.push({ source, status, ...(kind ? { kind } : {}), ...(asOf ? { as_of: asOf } : {}) });
  }
  return feeds.length > 0 ? feeds : undefined;
}

/**
 * Validates a 200 response body. Returns undefined when it is not a verdict.
 *
 * @param json - The parsed response body.
 * @returns The sanitized verdict, `{checked:false}` marker, or undefined.
 */
export function parseVerdict(json: unknown): Verdict | { checked: false } | undefined {
  if (!isObject(json) || typeof json.checked !== "boolean") return undefined;
  if (json.checked === false) return { checked: false };
  const verdict: Verdict = { checked: true, categories: [] };
  if (typeof json.score === "number" && Number.isFinite(json.score)) {
    verdict.score = Math.min(100, Math.max(0, Math.round(json.score)));
  }
  if (json.tier === "low" || json.tier === "medium" || json.tier === "high" || json.tier === "critical") {
    verdict.tier = json.tier;
  }
  if (Array.isArray(json.categories)) {
    verdict.categories = json.categories
      .slice(0, 32)
      .map((category) => safeString(category, 48))
      .filter((category): category is string => Boolean(category))
      .slice(0, 8);
  }
  if (typeof json.jws === "string" && json.jws.length <= 16384 && /^[\w-]+\.[\w-]*\.[\w-]+$/u.test(json.jws)) {
    verdict.jws = json.jws;
  }
  if (typeof json.jwks_url === "string" && json.jwks_url.length <= 308 && /^https:\/\/[^\s]{1,300}$/u.test(json.jwks_url)) {
    verdict.jwks_url = json.jwks_url;
  }
  const provider = safeString(json.provider, 64);
  if (provider) verdict.provider = provider;
  if (isObject(json.evidence)) {
    const evidence: Evidence = {};
    const sanctions = parseSanctions(json.evidence.sanctions);
    const domain = parseDomain(json.evidence.domain);
    const onchain = parseOnchain(json.evidence.onchain);
    const feeds = parseFeeds(json.evidence.feeds);
    if (sanctions) evidence.sanctions = sanctions;
    if (domain) evidence.domain = domain;
    if (onchain) evidence.onchain = onchain;
    if (feeds) evidence.feeds = feeds;
    if (Object.keys(evidence).length > 0) verdict.evidence = evidence;
  }
  return verdict;
}

/**
 * Maps an HTTP status and body to an outcome. Only a 200 with a well-formed
 * `checked: true` body is ever treated as a verdict.
 *
 * @param status - HTTP status code.
 * @param json - Parsed body (undefined when it was not JSON).
 * @returns The outcome.
 */
export function classifyResponse(status: number, json: unknown): CheckOutcome {
  if (status === 402) return { kind: "quota" };
  if (status !== 200) return { kind: "http_error", status };
  const verdict = parseVerdict(json);
  if (!verdict) return { kind: "invalid_response" };
  if (verdict.checked === false) return { kind: "unverified" };
  return { kind: "ok", verdict };
}

/**
 * Maps a batch response: `{ results: [...] }` in request order.
 *
 * @param status - HTTP status code.
 * @param json - Parsed body.
 * @param expected - Number of requests sent.
 * @returns The outcome.
 */
export function classifyBatchResponse(status: number, json: unknown, expected: number): CheckOutcome {
  if (status === 402) return { kind: "quota" };
  if (status !== 200) return { kind: "http_error", status };
  if (!isObject(json) || !Array.isArray(json.results) || json.results.length !== expected) return { kind: "invalid_response" };
  const items: BatchItem[] = json.results.map((result) => {
    const verdict = parseVerdict(result);
    if (!verdict) return { status: "invalid" };
    if (verdict.checked === false) return { status: "unverified" };
    return { status: "ok", verdict };
  });
  return { kind: "batch", items };
}

type FetchLike = (input: string, init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal }) => Promise<{
  status: number;
  json(): Promise<unknown>;
}>;

type Posted = { status: number; json: unknown } | { failed: true; timedOut: boolean };

async function postJson(url: string, payload: unknown, installId: string, fetchImpl: FetchLike, timeoutMs: number): Promise<Posted> {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  try {
    const response = await fetchImpl(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Risk-Check-Client": installId,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    let json: unknown;
    if (response.status === 200) {
      try {
        json = await response.json();
      } catch {
        json = undefined;
      }
    }
    return { status: response.status, json };
  } catch {
    return { failed: true, timedOut };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * POSTs one body to the risk-check endpoint with a timeout.
 *
 * @param body - The request body.
 * @param installId - Random per-install id (free-tier accounting only).
 * @param fetchImpl - The fetch implementation.
 * @param timeoutMs - Abort after this many milliseconds.
 * @returns The outcome; never throws.
 */
export async function postRiskCheck(
  body: RiskCheckBody,
  installId: string,
  fetchImpl: FetchLike,
  timeoutMs = REQUEST_TIMEOUT_MS,
): Promise<CheckOutcome> {
  const posted = await postJson(ENDPOINT, body, installId, fetchImpl, timeoutMs);
  if ("failed" in posted) return { kind: "network_error", timedOut: posted.timedOut };
  return classifyResponse(posted.status, posted.json);
}

/**
 * Checks one address (single endpoint) or several (batch endpoint).
 *
 * @param bodies - Request bodies, primary first.
 * @param installId - Random per-install id.
 * @param fetchImpl - The fetch implementation.
 * @param timeoutMs - Abort after this many milliseconds.
 * @returns The outcome; never throws.
 */
export async function postRiskChecks(
  bodies: RiskCheckBody[],
  installId: string,
  fetchImpl: FetchLike,
  timeoutMs = REQUEST_TIMEOUT_MS,
): Promise<CheckOutcome> {
  if (bodies.length <= 1) {
    const [body] = bodies;
    return body ? postRiskCheck(body, installId, fetchImpl, timeoutMs) : { kind: "invalid_response" };
  }
  const requests = bodies.slice(0, MAX_CHECKS);
  const posted = await postJson(BATCH_ENDPOINT, { requests }, installId, fetchImpl, timeoutMs);
  if ("failed" in posted) return { kind: "network_error", timedOut: posted.timedOut };
  return classifyBatchResponse(posted.status, posted.json, requests.length);
}
