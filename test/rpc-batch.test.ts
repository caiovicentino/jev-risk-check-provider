// batchReads (src/rpc.ts): a keyless tier that refuses large batches is still a fallback, and an
// item no endpoint answers stays unknown (undefined), never empty.
import { test } from "node:test";
import assert from "node:assert";
import { batchReads } from "../src/rpc.js";

const PRIMARY = "https://primary.example";
const DRPC = "https://eth.drpc.org"; // BATCH_LIMITS: 3

test("the primary's holes go to a fallback in batches it accepts; what nobody answers stays undefined", async () => {
  const sizes: Array<[string, number]> = [];
  const doFetch = (async (url: string, init?: RequestInit) => {
    const batch = JSON.parse(String(init?.body)) as Array<{ id: number; params: [string] }>;
    sizes.push([url, batch.length]);
    if (url === DRPC && batch.length > 3) return new Response("batch too large", { status: 500 });
    return Response.json(
      batch.map((r) => {
        const n = Number.parseInt(r.params[0].slice(-2), 16);
        // The primary rate-limits every odd item; the fallback cannot read item 7 either.
        if (url === PRIMARY && n % 2 === 1) return { jsonrpc: "2.0", id: r.id, error: { code: 429, message: "rate limited" } };
        if (url === DRPC && n === 7) return { jsonrpc: "2.0", id: r.id, error: { code: -32000, message: "unavailable" } };
        return { jsonrpc: "2.0", id: r.id, result: `0x${n.toString(16).padStart(2, "0")}` };
      }),
    );
  }) as typeof fetch;
  const requests = Array.from({ length: 10 }, (_, i) => ({ method: "eth_getCode", params: [`0x${"00".repeat(19)}${i.toString(16).padStart(2, "0")}`, "latest"] }));
  const out = await batchReads([PRIMARY, DRPC], requests, 2000, doFetch, 10);
  assert.deepEqual(out, ["0x00", "0x01", "0x02", "0x03", "0x04", "0x05", "0x06", undefined, "0x08", "0x09"]);
  assert.ok(sizes.filter(([u]) => u === DRPC).every(([, n]) => n <= 3), "the fallback only ever got batches it accepts");
});
