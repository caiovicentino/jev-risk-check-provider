import { X402CheckError } from "./errors.js";
import { base64ToBytes, isRecord, parseJson, utf8 } from "./encoding.js";
import { defaultFetch, exchange, ExchangeError } from "./transport.js";
import type { FetchLike, FetchResponseLike, PaymentRequired, RiskCheckRequest, RiskCheckResult, RiskTier } from "./types.js";
import { RISK_TIERS } from "./types.js";

export const DEFAULT_BASE_URL = "https://x402check.xyz";
export const DEFAULT_TIMEOUT_MS = 10_000;
/** The API accepts at most 25 requests per batch. */
export const MAX_BATCH = 25;

export interface ClientOptions {
  /** Default "https://x402check.xyz". */
  baseUrl?: string | undefined;
  /**
   * Default `globalThis.fetch`. Every evaluation is paid via x402: pass an x402-paying fetch
   * (e.g. `wrapFetchWithPayment(fetch, x402Client)` from `@x402/fetch`). Without one, a check
   * rejects with a 402 `X402CheckError` whose `paymentRequired` lists the payment options.
   */
  fetch?: FetchLike | undefined;
  /**
   * Per request, including reading the body. Default 10000. A paid call is two round trips plus
   * on-chain settlement: allow more (e.g. 30000) with a paying fetch.
   */
  timeoutMs?: number | undefined;
}

export interface CallOptions {
  signal?: AbortSignal | undefined;
}

/** Response metadata. */
export interface ResponseInfo {
  status: number;
  /**
   * Decoded x402 `PAYMENT-RESPONSE` settlement receipt, when the call was paid:
   * `{ success, transaction, network, payer, … }`.
   */
  paymentResponse: Record<string, unknown> | undefined;
}

export interface X402CheckClient {
  readonly baseUrl: string;
  /** One risk check. Resolves with the result (possibly `checked: false`); rejects with `X402CheckError`. */
  check(request: RiskCheckRequest, options?: CallOptions): Promise<RiskCheckResult>;
  /** Up to 25 checks, all-or-nothing validation; results are in request order. */
  checkBatch(requests: RiskCheckRequest[], options?: CallOptions): Promise<RiskCheckResult[]>;
  /** `check` plus response metadata (the settlement receipt of a paid call). */
  checkWithInfo(request: RiskCheckRequest, options?: CallOptions): Promise<{ result: RiskCheckResult; info: ResponseInfo }>;
  /** `checkBatch` plus response metadata. */
  checkBatchWithInfo(requests: RiskCheckRequest[], options?: CallOptions): Promise<{ results: RiskCheckResult[]; info: ResponseInfo }>;
}

function normalizeBaseUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new TypeError(`invalid baseUrl: ${raw}`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new TypeError(`baseUrl must be http(s): ${raw}`);
  if (raw.includes("?") || raw.includes("#")) throw new TypeError(`baseUrl must not carry a query or fragment: ${raw}`);
  if (url.username || url.password) throw new TypeError("baseUrl must not carry credentials");
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

/** Validates the shape of one result. Anything off is a protocol error, never a verdict. */
export function isRiskCheckResult(value: unknown): value is RiskCheckResult {
  if (!isRecord(value) || typeof value.checked !== "boolean") return false;
  if (!value.checked) return value.reason === undefined || typeof value.reason === "string";
  const score = value.score;
  return (
    typeof score === "number" &&
    Number.isFinite(score) &&
    score >= 0 &&
    score <= 100 &&
    typeof value.tier === "string" &&
    (RISK_TIERS as readonly string[]).includes(value.tier as RiskTier) &&
    (value.categories === undefined || (Array.isArray(value.categories) && value.categories.every((c) => typeof c === "string"))) &&
    (value.jws === undefined || typeof value.jws === "string") &&
    (value.provider === undefined || typeof value.provider === "string") &&
    (value.checked_at === undefined || typeof value.checked_at === "string") &&
    (value.expires_at === undefined || typeof value.expires_at === "string") &&
    (value.evidence === undefined || isRecord(value.evidence))
  );
}

function decodeBase64Json(header: string | null): Record<string, unknown> | undefined {
  if (!header) return undefined;
  const bytes = base64ToBytes(header);
  const text = bytes ? utf8(bytes) : null;
  const value = text === null ? undefined : parseJson(text);
  return isRecord(value) ? value : undefined;
}

export function decodePaymentRequired(header: string | null): PaymentRequired | undefined {
  const value = decodeBase64Json(header);
  if (!value || !Array.isArray(value.accepts)) return undefined;
  return value as unknown as PaymentRequired;
}

function retryAfterSeconds(header: string | null): number | undefined {
  if (!header) return undefined;
  const n = Number(header.trim());
  if (Number.isFinite(n) && n >= 0) return n;
  const at = Date.parse(header);
  return Number.isFinite(at) ? Math.max(0, Math.ceil((at - Date.now()) / 1000)) : undefined;
}

function responseInfo(res: FetchResponseLike): ResponseInfo {
  return {
    status: res.status,
    paymentResponse: decodeBase64Json(res.headers.get("payment-response") ?? res.headers.get("x-payment-response")),
  };
}

// Error details are echoed into messages people and models read: accept only the identifier
// formats the API uses ("invalid_request", "payment.amount", "insufficient_funds").
const CODE = /^[a-z0-9_]{1,64}$/;
const FIELD = /^[a-z0-9_.]{1,64}$/;

function httpError(res: FetchResponseLike, body: unknown): X402CheckError {
  const b = isRecord(body) ? body : {};
  const error = typeof b.error === "string" && CODE.test(b.error) ? b.error : undefined;
  const field = typeof b.field === "string" && FIELD.test(b.field) ? b.field : undefined;
  const index = typeof b.index === "number" && Number.isInteger(b.index) && b.index >= 0 ? b.index : undefined;
  const common = { status: res.status, body };
  switch (res.status) {
    case 422:
      return new X402CheckError({
        ...common,
        code: "invalid_request",
        field,
        index,
        message: `invalid request${field ? `: field "${field}"` : ""}${index !== undefined ? ` (batch index ${index})` : ""}`,
      });
    case 402: {
      const paymentRequired = decodePaymentRequired(res.headers.get("payment-required"));
      const rawPaymentError = res.headers.get("x-payment-error");
      const paymentError = rawPaymentError !== null && CODE.test(rawPaymentError) ? rawPaymentError : undefined;
      const detail = paymentError ?? error;
      return new X402CheckError({
        ...common,
        code: "payment_required",
        paymentRequired,
        paymentError,
        message: `payment required: every evaluation is paid via x402${detail ? ` (${detail})` : ""}`,
      });
    }
    case 413:
      return new X402CheckError({ ...common, code: "too_large", message: `request too large${error ? ` (${error})` : ""}` });
    case 503:
      return new X402CheckError({
        ...common,
        code: "evaluation_unavailable",
        retryAfter: retryAfterSeconds(res.headers.get("retry-after")),
        message: `evaluation unavailable${error ? ` (${error})` : ""}`,
      });
    default:
      return new X402CheckError({
        ...common,
        code: "http_error",
        retryAfter: retryAfterSeconds(res.headers.get("retry-after")),
        message: `unexpected HTTP ${res.status}${error ? ` (${error})` : ""}`,
      });
  }
}

/**
 * Creates a client for the x402check API.
 *
 * @example
 * const x402check = createClient({ fetch: payingFetch }); // an x402-paying fetch, see the README
 * const result = await x402check.check({ wallet: spender, chain: "base", interaction: { type: "permit_signature" } });
 * const { action } = interpret(result); // "allow" | "warn" | "block" | "not_verified"
 */
export function createClient(options: ClientOptions = {}): X402CheckClient {
  const baseUrl = normalizeBaseUrl(options.baseUrl ?? DEFAULT_BASE_URL);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  // setTimeout clamps anything above 2^31−1 ms to 1 ms: reject instead of timing out every call.
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2_147_483_647) throw new TypeError("timeoutMs must be between 1 and 2147483647");
  const fetchImpl: FetchLike = options.fetch ?? defaultFetch;

  async function post(path: string, payload: unknown, call: CallOptions | undefined): Promise<{ body: unknown; info: ResponseInfo }> {
    const headers: Record<string, string> = { "Content-Type": "application/json", Accept: "application/json" };
    let res: FetchResponseLike;
    let text: string;
    try {
      ({ res, text } = await exchange(fetchImpl, `${baseUrl}${path}`, { method: "POST", headers, body: JSON.stringify(payload) }, timeoutMs, call?.signal));
    } catch (err) {
      const kind = err instanceof ExchangeError ? err.kind : "network";
      const cause = err instanceof ExchangeError ? err.cause : err;
      if (kind === "timeout") throw new X402CheckError({ code: "timeout", message: `no response within ${timeoutMs} ms`, cause });
      if (kind === "aborted") throw new X402CheckError({ code: "aborted", message: "request aborted by the caller", cause });
      const detail = cause instanceof Error ? cause.message : String(cause);
      throw new X402CheckError({ code: "network_error", message: `network error: ${detail}`, cause });
    }
    const body = parseJson(text);
    if (res.status !== 200) throw httpError(res, body);
    return { body, info: responseInfo(res) };
  }

  async function checkWithInfo(request: RiskCheckRequest, call?: CallOptions): Promise<{ result: RiskCheckResult; info: ResponseInfo }> {
    const { body, info } = await post("/v1/risk-check", request, call);
    if (!isRiskCheckResult(body)) {
      throw new X402CheckError({ code: "invalid_response", status: info.status, body, message: "the response is not a well-formed risk-check result" });
    }
    return { result: body, info };
  }

  async function checkBatchWithInfo(requests: RiskCheckRequest[], call?: CallOptions): Promise<{ results: RiskCheckResult[]; info: ResponseInfo }> {
    if (!Array.isArray(requests)) throw new TypeError("checkBatch expects an array of requests");
    const { body, info } = await post("/v1/risk-check/batch", { requests }, call);
    const results = isRecord(body) ? body.results : undefined;
    if (!Array.isArray(results) || results.length !== requests.length || !results.every(isRiskCheckResult)) {
      throw new X402CheckError({
        code: "invalid_response",
        status: info.status,
        body,
        message: "the batch response is not one well-formed result per request",
      });
    }
    return { results, info };
  }

  return {
    baseUrl,
    check: async (request, call) => (await checkWithInfo(request, call)).result,
    checkBatch: async (requests, call) => (await checkBatchWithInfo(requests, call)).results,
    checkWithInfo,
    checkBatchWithInfo,
  };
}
