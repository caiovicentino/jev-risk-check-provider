import { test } from "node:test";
import assert from "node:assert";
import { DatabaseSync } from "node:sqlite";

import { RateCounter } from "../deploy/counter.js";

type Counter = { fetch(req: Request): Promise<Response> };

function counter(): Counter {
  const db = new DatabaseSync(":memory:");
  // Cloudflare's sql.exec runs eagerly; toArray() just returns the rows.
  const sql = { exec: (q: string, ...p: unknown[]) => { const rows = db.prepare(q).all(...(p as never[])); return { toArray: () => rows }; } };
  return new RateCounter({ storage: { sql } }, {});
}

async function consume(c: Counter, key: string, daily: number, admit?: { key: string; daily: number }[]) {
  const res = await c.fetch(new Request("https://counter/consume", {
    method: "POST",
    body: JSON.stringify({ op: "consume", key, day: "2026-09-29", daily, ...(admit ? { admit } : {}) }),
  }));
  return (await res.json()) as { allowed: boolean; remaining: number };
}

test("per-key daily cap is enforced", async () => {
  const c = counter();
  for (let i = 0; i < 3; i++) assert.equal((await consume(c, "ip:1", 3)).allowed, true);
  assert.equal((await consume(c, "ip:1", 3)).allowed, false);
});

test("new client ids are admitted against global and per-ip budgets; known ids are not recharged", async () => {
  const c = counter();
  const admit = (ip: string) => [{ key: "client-new:global", daily: 3 }, { key: `client-new-ip:${ip}`, daily: 2 }];
  assert.equal((await consume(c, "client:a", 25, admit("1"))).allowed, true);
  assert.equal((await consume(c, "client:b", 25, admit("1"))).allowed, true);
  // third fresh id from the same ip exceeds the per-ip cap
  assert.equal((await consume(c, "client:c", 25, admit("1"))).allowed, false);
  // an already-admitted id keeps working without consuming admission budget
  for (let i = 0; i < 5; i++) assert.equal((await consume(c, "client:a", 25, admit("1"))).allowed, true);
  // another ip gets one more fresh id, then the global budget (3) is exhausted
  assert.equal((await consume(c, "client:d", 25, admit("2"))).allowed, true);
  assert.equal((await consume(c, "client:e", 25, admit("3"))).allowed, false);
});
