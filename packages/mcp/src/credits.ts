// Prepaid credits have no cap of their own, so X402CHECK_BUDGET_USD also bounds what this process
// spends from them. Each check reserves its price before it is sent (refused, unsent, once the
// budget cannot cover it) and is then counted at the X-Credits-Charged amount the API returns.
// A check that got no answer stays counted (it may have been charged); an HTTP error is not
// charged by the API, so it is not counted.
import { X402CheckError, type CallOptions, type ResponseInfo, type RiskCheckRequest, type X402CheckClient } from "@x402check/client";
import { PaymentRefused } from "./payer.js";

/** x402check's prices from prepaid credits: a check, and a check that simulates a transaction. */
export const CREDIT_CHECK_USD = 0.001;
export const CREDIT_SIMULATED_CHECK_USD = 0.005;
export const CREDIT_BUDGET_EXHAUSTED = "the prepaid-credit budget of this server is exhausted (X402CHECK_BUDGET_USD)";

const CHARGED = /^\$(\d{1,6})\.(\d{2,6})$/;

export interface CreditMeter {
  /** The most this process spends from prepaid credits (X402CHECK_BUDGET_USD). */
  readonly budgetUsd: number;
  /** Charged so far, plus the price of checks in flight. */
  spentUsd(): number;
  /** Reserves a check's price (micro-USD returned), or undefined when the budget cannot cover it. */
  reserve(usd: number): number | undefined;
  /** Replaces a reservation with what the call cost: the charge it reported, nothing after an HTTP error, else the reservation. */
  settle(reservedMicro: number, outcome: { info: ResponseInfo } | { error: unknown }): void;
}

export function createCreditMeter(budgetUsd: number): CreditMeter {
  const budget = Math.round(budgetUsd * 1e6);
  let spent = 0; // integer micro-USD
  return {
    budgetUsd,
    spentUsd: () => spent / 1e6,
    reserve: (usd) => {
      const cost = Math.round(usd * 1e6);
      if (spent + cost > budget) return undefined;
      spent += cost;
      return cost;
    },
    settle: (reserved, outcome) => {
      let cost = reserved;
      if ("info" in outcome) {
        const m = outcome.info.credits ? CHARGED.exec(outcome.info.credits.chargedUsd) : null;
        if (m) cost = Number(m[1]) * 1e6 + Number((m[2] as string).padEnd(6, "0"));
      } else if (outcome.error instanceof X402CheckError && outcome.error.status > 0) {
        cost = 0; // the API answered with an error: it does not charge for a verdict it did not produce
      }
      spent += cost - reserved;
    },
  };
}

/** The price of a check from prepaid credits. */
export function creditPrice(request: RiskCheckRequest): number {
  return request.transaction ? CREDIT_SIMULATED_CHECK_USD : CREDIT_CHECK_USD;
}

export interface ClientBounds {
  /** Aborts every call (the MCP request was cancelled). */
  signal?: AbortSignal | undefined;
  /** Checks paid from prepaid credits: reserved against this budget first, counted when charged. */
  credits?: CreditMeter | undefined;
  /** The credit budget refused a check (nothing was sent). */
  onRefused?: (() => void) | undefined;
}

function either(a: AbortSignal | undefined, b: AbortSignal | undefined): AbortSignal | undefined {
  if (!a || !b) return a ?? b;
  const both = new AbortController();
  const abort = (s: AbortSignal) => () => both.abort(s.reason);
  if (a.aborted) both.abort(a.reason);
  else if (b.aborted) both.abort(b.reason);
  else {
    a.addEventListener("abort", abort(a), { once: true });
    b.addEventListener("abort", abort(b), { once: true });
  }
  return both.signal;
}

/** `client` with its calls bounded: aborted with `signal`, and checks within the credit budget. */
export function boundClient(client: X402CheckClient, bounds: ClientBounds): X402CheckClient {
  const call = (options: CallOptions | undefined): CallOptions | undefined => {
    const signal = either(options?.signal, bounds.signal);
    return signal ? { ...options, signal } : options;
  };
  async function metered<T extends { info: ResponseInfo }>(usd: number, send: (options: CallOptions | undefined) => Promise<T>, options: CallOptions | undefined): Promise<T> {
    const meter = bounds.credits;
    if (!meter) return send(call(options));
    const reserved = meter.reserve(usd);
    if (reserved === undefined) {
      bounds.onRefused?.();
      const refusal = new PaymentRefused("budget_exhausted", CREDIT_BUDGET_EXHAUSTED);
      throw new X402CheckError({ code: "insufficient_credits", message: refusal.message, cause: refusal });
    }
    try {
      const out = await send(call(options));
      meter.settle(reserved, { info: out.info });
      return out;
    } catch (error) {
      meter.settle(reserved, { error });
      throw error;
    }
  }
  const checkWithInfo: X402CheckClient["checkWithInfo"] = (request, options) => metered(creditPrice(request), (o) => client.checkWithInfo(request, o), options);
  const checkBatchWithInfo: X402CheckClient["checkBatchWithInfo"] = (requests, options) =>
    metered(Array.isArray(requests) ? requests.reduce((sum, r) => sum + creditPrice(r), 0) : 0, (o) => client.checkBatchWithInfo(requests, o), options);
  return {
    baseUrl: client.baseUrl,
    check: async (request, options) => (await checkWithInfo(request, options)).result,
    checkBatch: async (requests, options) => (await checkBatchWithInfo(requests, options)).results,
    checkWithInfo,
    checkBatchWithInfo,
    buyCredits: (amountUsd, options) => client.buyCredits(amountUsd, call(options)),
    creditBalance: (options) => client.creditBalance(call(options)),
  };
}
