import type { PaymentRequired } from "./types.js";

export type X402CheckErrorCode =
  /** 422: the request is malformed; `field` (and `index` for batches) names the offending input. */
  | "invalid_request"
  /** 402: the call was not paid (every evaluation is paid via x402), or the payment failed; see `paymentRequired` / `paymentError`. */
  | "payment_required"
  /** 413: body over 64 KiB, or more than 25 batch items. */
  | "too_large"
  /** 503: the evaluation could not be completed (paid path, no charge). Retry after `retryAfter`. */
  | "evaluation_unavailable"
  /** Any other non-200 status. */
  | "http_error"
  /** 200 with a body that is not a well-formed result. */
  | "invalid_response"
  /** The request never produced a response (DNS, TLS, connection reset, CORS…). */
  | "network_error"
  /** No complete response within `timeoutMs`. */
  | "timeout"
  /** The caller's AbortSignal fired. */
  | "aborted";

export interface X402CheckErrorInit {
  code: X402CheckErrorCode;
  message: string;
  status?: number | undefined;
  field?: string | undefined;
  index?: number | undefined;
  paymentRequired?: PaymentRequired | undefined;
  paymentError?: string | undefined;
  retryAfter?: number | undefined;
  body?: unknown;
  cause?: unknown;
}

/**
 * Every failure of `check` / `checkBatch`. A failed check is NOT a verdict: treat it as
 * "not verified" and do not proceed (see `interpret`).
 */
export class X402CheckError extends Error {
  override readonly name = "X402CheckError";
  readonly code: X402CheckErrorCode;
  /** HTTP status, or 0 when no response was received (network error, timeout, abort). */
  readonly status: number;
  /** 422: the offending request field (e.g. "wallet", "payment.amount"). */
  readonly field: string | undefined;
  /** 422 on a batch: index of the offending request. */
  readonly index: number | undefined;
  /** 402: the decoded x402 `PAYMENT-REQUIRED` challenge (`accepts` lists the payment options). */
  readonly paymentRequired: PaymentRequired | undefined;
  /** 402 after a payment attempt: the `X-Payment-Error` reason. */
  readonly paymentError: string | undefined;
  /** Seconds, from `Retry-After`. */
  readonly retryAfter: number | undefined;
  /** Parsed error body, when there was one. */
  readonly body: unknown;

  constructor(init: X402CheckErrorInit) {
    super(init.message, init.cause !== undefined ? { cause: init.cause } : undefined);
    this.code = init.code;
    this.status = init.status ?? 0;
    this.field = init.field;
    this.index = init.index;
    this.paymentRequired = init.paymentRequired;
    this.paymentError = init.paymentError;
    this.retryAfter = init.retryAfter;
    this.body = init.body;
  }
}

export function isX402CheckError(value: unknown): value is X402CheckError {
  return value instanceof X402CheckError;
}
