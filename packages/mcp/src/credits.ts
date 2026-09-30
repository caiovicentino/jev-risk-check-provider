// The x402check client as a tool call uses it: its calls are aborted when the MCP request is
// cancelled, so a check the client no longer waits for is not bought.
import type { CallOptions, X402CheckClient } from "@x402check/client";

export interface ClientBounds {
  /** Aborts every call (the MCP request was cancelled). */
  signal?: AbortSignal | undefined;
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

/** `client` with its calls aborted with `signal`. */
export function boundClient(client: X402CheckClient, bounds: ClientBounds): X402CheckClient {
  const call = (options: CallOptions | undefined): CallOptions | undefined => {
    const signal = either(options?.signal, bounds.signal);
    return signal ? { ...options, signal } : options;
  };
  const checkWithInfo: X402CheckClient["checkWithInfo"] = (request, options) => client.checkWithInfo(request, call(options));
  const checkBatchWithInfo: X402CheckClient["checkBatchWithInfo"] = (requests, options) => client.checkBatchWithInfo(requests, call(options));
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
