// The daily maintenance check (scripts/daily-check.ts, docs/MAINTENANCE.md): what it calls a
// failure, a warning or fine, from /status alone and from the unpaid 402 challenge.
import { test } from "node:test";
import assert from "node:assert";
import { challengeCheck, statusChecks, type Check, type State, type Status } from "../scripts/daily-check.js";

const SOL = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const route = (network: string, margin: number | null, extra: Record<string, unknown> = {}) => ({ network, facilitator: "cdp", transfer_method: "eip3009", margin_usd: margin, margin_pct: margin === null ? null : Math.round(margin * 100000) / 10, offered: true, ...extra });
function status(over: { payments?: Status["payments"]; chains?: Status["data"]["kit_watch"]["chains"]; kwStatus?: string; canary?: Status["model"]["canary"]; facilitators?: Status["facilitators"] } = {}): Status {
  return {
    version: "0.6.9",
    data: {
      ofac_sdn: { as_of: "2026-10-14", age_days: 1, origin: "kv" },
      metamask_phishing: { as_of: "2026-10-15", age_days: 0, origin: "refreshed" },
      scamsniffer: { stale: false, refreshed_at: "2026-10-15T17:37:15Z" },
      kit_watch: { status: over.kwStatus ?? "ok", age_s: 20, chains: over.chains ?? { "eip155:1": { status: "ok", lag_blocks: 0, gaps: 100, unbroken_since: 500, pending_reads: 0 }, "eip155:8453": { status: "ok", lag_blocks: 3, gaps: 10, unbroken_since: 900, pending_reads: 0 } } },
    },
    refresh: { checked_at: null, published_at: null, error: null },
    payments: over.payments ?? [route("eip155:8453", 0.00243), route(SOL, 0.00193, { facilitator: "dexter", transfer_method: "svm" })],
    facilitators: over.facilitators ?? [{ name: "cdp", ok: true }, { name: "dexter", ok: true }],
    attestation: { ok: true, kid: "jev-attest-v1", thumbprint: "t" },
    model: { canary: over.canary === undefined ? { ok: true, stale: false, at: "2026-10-15T18:07:00Z" } : over.canary },
  };
}
const level = (checks: Check[], id: string) => checks.find((c) => c.id === id)?.level;
const prev: State = { at: "2026-10-15T12:00:00Z", kit_watch: { "eip155:1": { gaps: 100, unbroken_since: 500 }, "eip155:8453": { gaps: 10, unbroken_since: 900 } } };

test("a healthy /status is all ok", () => {
  const checks = statusChecks(status(), prev, { metamask: "2026-10-15", ofac: "2026-10-14" });
  assert.deepEqual(checks.filter((c) => c.level !== "ok").map((c) => c.id), []);
});

test("payments: an offered route at a loss, or Base not offered, fails; a network not offered is only noted", () => {
  assert.equal(level(statusChecks(status({ payments: [route("eip155:8453", 0.00243), route("eip155:143", -0.00007)] }), prev), "payments"), "fail");
  assert.equal(level(statusChecks(status({ payments: [route(SOL, 0.002)] }), prev), "payments"), "fail", "Base must be offered");
  assert.equal(level(statusChecks(status({ payments: [route("eip155:8453", null)] }), prev), "payments"), "warn", "an unknown fee");
  const out = statusChecks(status({ payments: [route("eip155:8453", 0.00243), route("eip155:43114", -0.00481, { offered: false, reason: "unprofitable", facilitator: "payai" })] }), prev);
  assert.deepEqual([level(out, "payments"), level(out, "payments.not_offered")], ["ok", "info"]);
  assert.equal(level(statusChecks(status({ facilitators: [{ name: "cdp", ok: false, error: "HTTP 401" }] }), prev), "facilitators"), "fail");
});

test("kit watch: a new hole or a moved unbroken_since warns; a big hole, an hour's lag or a stale watch fails", () => {
  const chains = (eth: Partial<Status["data"]["kit_watch"]["chains"][string]>) => ({ "eip155:1": { status: "ok", lag_blocks: 0, gaps: 100, unbroken_since: 500, pending_reads: 0, ...eth } });
  assert.equal(level(statusChecks(status({ chains: chains({ gaps: 101, unbroken_since: 640 }) }), prev), "kit_watch.ethereum"), "warn");
  assert.equal(level(statusChecks(status({ chains: chains({ gaps: 1200 }) }), prev), "kit_watch.ethereum"), "fail");
  assert.equal(level(statusChecks(status({ chains: chains({ lag_blocks: 301 }) }), prev), "kit_watch.ethereum"), "fail");
  assert.equal(level(statusChecks(status({ chains: chains({ lag_blocks: 30 }) }), prev), "kit_watch.ethereum"), "warn");
  assert.equal(level(statusChecks(status({ chains: chains({ pending_reads: 50 }) }), prev), "kit_watch.ethereum"), "warn");
  assert.equal(level(statusChecks(status({ chains: chains({ error: "Error: rpc http 429" }) }), prev), "kit_watch.ethereum"), "warn");
  assert.equal(level(statusChecks(status({ kwStatus: "stale" }), prev), "kit_watch"), "fail");
  // The first run has nothing to compare with: no delta, no warning.
  assert.equal(level(statusChecks(status({ chains: chains({ gaps: 5000 }) }), null), "kit_watch.ethereum"), "ok");
});

test("feeds and canary: an isolate days behind the published MetaMask list warns; a failed canary fails", () => {
  const s = status();
  s.data.metamask_phishing = { as_of: "2026-09-29", age_days: 16, origin: "embedded" };
  assert.equal(level(statusChecks(s, prev, { metamask: "2026-10-15" }), "feeds.metamask"), "warn");
  assert.equal(level(statusChecks(status({ canary: { ok: false, stale: false, at: "x" } }), prev), "model_canary"), "fail");
  assert.equal(level(statusChecks(status({ canary: { ok: true, stale: true, at: "x" } }), prev), "model_canary"), "warn");
});

test("the 402 challenge must list exactly the offered networks, at the table's prices, Permit2 where routed", () => {
  const routes = [route("eip155:8453", 0.00243), route("eip155:143", 0.00093, { facilitator: "dexter", transfer_method: "permit2" }), route("eip155:43114", -0.00481, { offered: false, reason: "unprofitable" })];
  const good = [{ network: "eip155:8453", amount: "3500" }, { network: "eip155:143", amount: "1000", extra: { assetTransferMethod: "permit2" } }];
  assert.equal(challengeCheck(good, routes).level, "ok");
  assert.equal(challengeCheck([...good, { network: "eip155:43114", amount: "1000" }], routes).level, "fail", "a network not offered leaks into the challenge");
  assert.equal(challengeCheck([good[0] as { network: string; amount: string }], routes).level, "fail", "an offered network is missing");
  assert.equal(challengeCheck([{ network: "eip155:8453", amount: "3000" }, good[1] as { network: string; amount: string }], routes).level, "fail", "a wrong price");
  assert.equal(challengeCheck([good[0] as { network: string; amount: string }, { network: "eip155:143", amount: "1000" }], routes).level, "fail", "Permit2 not declared");
});
