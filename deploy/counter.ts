import type { DurableObjectState, SqlStorage, WorkerEnv } from "./runtime.js";

type ConsumeBody = {
  op: "consume" | "total";
  key?: string;
  day: string;
  daily?: number;
  cost?: number;
  countTotal?: boolean;
  admit?: { key: string; daily: number }[];
};

export class RateCounter {
  private readonly sql: SqlStorage;
  private day: string | null = null;
  constructor(state: DurableObjectState, _env: WorkerEnv) {
    this.sql = (state.storage as { sql: SqlStorage }).sql;
  }
  /** Schema once per instance; stale-day rows dropped only when the day rolls over. */
  private roll(day: string): void {
    if (this.day === day) return;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS counters (k TEXT PRIMARY KEY, used INTEGER NOT NULL, day TEXT NOT NULL)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS totals (day TEXT PRIMARY KEY, total INTEGER NOT NULL)`);
    this.sql.exec(`DELETE FROM counters WHERE day != ?`, day);
    this.sql.exec(`DELETE FROM totals WHERE day != ?`, day);
    this.day = day;
  }
  private used(key: string): number | null {
    const rows = this.sql.exec(`SELECT used FROM counters WHERE k = ?`, key).toArray();
    return rows.length ? Number((rows[0] as { used: number }).used) : null;
  }
  private total(day: string): number {
    const rows = this.sql.exec(`SELECT total FROM totals WHERE day = ?`, day).toArray();
    return rows.length ? Number((rows[0] as { total: number }).total) : 0;
  }
  async fetch(request: Request): Promise<Response> {
    let body: ConsumeBody;
    try {
      body = (await request.json()) as ConsumeBody;
    } catch {
      return Response.json({ error: "bad_request" }, { status: 400 });
    }
    const day = String(body.day);
    this.roll(day);
    if (body.op === "total") return Response.json({ total: this.total(day) });

    const key = String(body.key ?? "unknown");
    const daily = Number(body.daily ?? 25);
    const cost = Math.max(1, Math.floor(Number(body.cost ?? 1)));
    const deny = () => Response.json({ allowed: false, remaining: Math.max(0, daily - (this.used(key) ?? 0)), total: this.total(day) });
    if (!Number.isFinite(daily) || cost > daily) return deny();
    const current = this.used(key) ?? 0;
    if (current + cost > daily) return deny();
    // First sighting of `key` today must also fit every admission budget. DO requests
    // run serially, so the check-then-charge sequence below is atomic.
    if (body.admit?.length && this.used(key) === null) {
      for (const b of body.admit) {
        if ((this.used(b.key) ?? 0) >= b.daily) return deny();
      }
      for (const b of body.admit) {
        this.sql.exec(`INSERT INTO counters (k, used, day) VALUES (?, 1, ?) ON CONFLICT(k) DO UPDATE SET used = counters.used + 1`, b.key, day);
      }
    }
    this.sql.exec(`INSERT INTO counters (k, used, day) VALUES (?, ?, ?) ON CONFLICT(k) DO UPDATE SET used = counters.used + ?`, key, cost, day, cost);
    let total = this.total(day);
    if (body.countTotal !== false) {
      this.sql.exec(`INSERT INTO totals (day, total) VALUES (?, ?) ON CONFLICT(day) DO UPDATE SET total = totals.total + ?`, day, cost, cost);
      total += cost;
    }
    return Response.json({ allowed: true, remaining: Math.max(0, daily - (current + cost)), total });
  }
}
