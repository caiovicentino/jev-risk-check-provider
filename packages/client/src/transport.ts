import type { FetchInitLike, FetchLike, FetchResponseLike } from "./types.js";

// A module-level default keeps one stable identity (the DID-document cache is keyed by fetch)
// and never calls fetch as a method of another object ("Illegal invocation" in browsers).
export const defaultFetch: FetchLike = (url, init) => {
  if (typeof globalThis.fetch !== "function") {
    return Promise.reject(new TypeError("globalThis.fetch is unavailable: pass `fetch` in the options"));
  }
  return globalThis.fetch(url, init);
};

/** Why an exchange produced no response. */
export class ExchangeError extends Error {
  constructor(
    readonly kind: "timeout" | "aborted" | "network",
    cause: unknown,
  ) {
    super(kind, { cause });
  }
}

/**
 * One request/response exchange, body included, bounded by `timeoutMs` and `signal`.
 * Racing (not only aborting) bounds the call even when a custom fetch ignores the signal.
 * Rejects with an `ExchangeError`.
 */
export async function exchange(
  fetchImpl: FetchLike,
  url: string,
  init: Omit<FetchInitLike, "signal">,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<{ res: FetchResponseLike; text: string }> {
  if (signal?.aborted) throw new ExchangeError("aborted", signal.reason);
  const controller = new AbortController();
  let interrupt: (error: ExchangeError) => void = () => {};
  const interrupted = new Promise<never>((_, reject) => {
    interrupt = reject;
  });
  // Interrupt before aborting, so the race settles with the reason rather than a fetch AbortError.
  const timer = setTimeout(() => {
    interrupt(new ExchangeError("timeout", new Error(`no response within ${timeoutMs} ms`)));
    controller.abort();
  }, timeoutMs);
  const onAbort = (): void => {
    interrupt(new ExchangeError("aborted", signal?.reason));
    controller.abort();
  };
  signal?.addEventListener("abort", onAbort, { once: true });

  const work = (async () => {
    const res = await fetchImpl(url, { ...init, signal: controller.signal });
    // The body is read inside the deadline too: a stalled body is a timeout, not a hang.
    return { res, text: await res.text() };
  })();
  work.catch(() => {}); // may settle after an interrupt, when nobody awaits it any more

  try {
    return await Promise.race([work, interrupted]);
  } catch (err) {
    throw err instanceof ExchangeError ? err : new ExchangeError("network", err);
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}
