// Batched eth_getCode over public RPCs, shared by the feed builder and the evals.

export async function fetchCodes(
  addresses: string[],
  rpcUrl: string,
  opts: { batch?: number; retries?: number; timeoutMs?: number; onError?: (err: unknown) => void } = {},
): Promise<{ codes: Map<string, string>; failedBatches: number }> {
  const size = opts.batch ?? 25;
  const codes = new Map<string, string>();
  let failedBatches = 0;
  for (let i = 0; i < addresses.length; i += size) {
    let ok = false;
    for (let attempt = 0; attempt <= (opts.retries ?? 3) && !ok; attempt++) {
      // Retry only the addresses a previous attempt left unanswered (per-item RPC errors).
      const chunk = addresses.slice(i, i + size).filter((a) => !codes.has(a));
      const body = chunk.map((a, k) => ({ jsonrpc: "2.0", id: k + 1, method: "eth_getCode", params: [a, "latest"] }));
      try {
        const res = await fetch(rpcUrl, {
          method: "POST",
          headers: { "content-type": "application/json", "user-agent": "x402check-feeds/0.3" },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(opts.timeoutMs ?? 20000),
        });
        const json = (await res.json()) as unknown;
        if (!Array.isArray(json)) throw new Error(`non-batch response: ${JSON.stringify(json).slice(0, 120)}`);
        let answered = 0;
        for (const r of json as Array<{ id: number; result?: unknown }>) {
          const a = chunk[r.id - 1];
          if (a && typeof r.result === "string") {
            codes.set(a, r.result);
            answered++;
          }
        }
        if (answered < chunk.length) throw new Error(`${chunk.length - answered} of ${chunk.length} unanswered`);
        ok = true;
      } catch (err) {
        opts.onError?.(err);
        await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
      }
    }
    if (!ok) failedBatches++;
  }
  return { codes, failedBatches };
}
