// Routing never offers a route that loses money (2026-10-15): PayAI's Avalanche fee rose to $0.00574
// against a $0.001 price, and CDP began settling Monad at $0.001 against a $0.001 price. A network
// moves to a route that clears its cost, even a Permit2 one; with none, it leaves the 402 challenge
// and /status says why, until a route clears it again.
import { test } from "node:test";
import assert from "node:assert";
import { buildAccepts, paymentRouting, routedFacilitators, type FacilitatorEntry, type PaymentRoute } from "../deploy/protected.js";

const SOL = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const kind = (network: string, extra: Record<string, unknown> = {}) => ({ x402Version: 2, scheme: "exact", network, extra });
const floor = (usd: number, method?: string) => ({ paymentFloorAvailable: true, minPaymentAmountUsd: usd, ...(method ? { assetTransferMethod: method } : {}) });
const client = (kinds: ReturnType<typeof kind>[]) => ({ verify: async () => ({ isValid: true }), settle: async () => ({ success: true }), getSupported: async () => ({ kinds }) }) as never;

// The live tables of 2026-10-15: PayAI's /pricing (EIP-3009), Dexter's floors (Permit2 on EVM), CDP's networks.
const payaiFees = new Map([["eip155:8453", 0.00199], ["eip155:137", 0.0049], ["eip155:42161", 0.0066], ["eip155:43114", 0.00574], ["eip155:1329", 0.00062], [SOL, 0.0016]]);
const entries = (fees: Map<string, number> = payaiFees): FacilitatorEntry[] => [
  { name: "payai", client: client([kind("eip155:8453"), kind("eip155:137"), kind("eip155:42161"), kind("eip155:43114"), kind("eip155:1329"), kind(SOL)]), fees: async () => fees },
  { name: "dexter", client: client([kind("eip155:8453", floor(0.00139, "permit2")), kind("eip155:137", floor(0.0036, "permit2")), kind("eip155:42161", floor(0.0061, "permit2")), kind("eip155:43114", floor(0.00342, "permit2")), kind("eip155:143", floor(0.000234, "permit2")), kind(SOL, floor(0.00116))]), flatFee: 0 },
  { name: "cdp", client: client([kind("eip155:8453"), kind("eip155:137"), kind("eip155:42161"), kind("eip155:143"), kind(SOL)]), flatFee: 0.001 },
];
const byNetwork = (routes: PaymentRoute[]) => Object.fromEntries(routes.map((r) => [r.network, r]));

test("a network is never offered through a route that costs more than its price", async () => {
  const routes = await paymentRouting({}, entries());
  const r = byNetwork(routes);
  // Monad: CDP is payable by any wallet but costs the whole price; Dexter (Permit2, free) clears it.
  assert.deepEqual([r["eip155:143"]?.facilitator, r["eip155:143"]?.transfer_method, r["eip155:143"]?.fee_usd, r["eip155:143"]?.offered], ["dexter", "permit2", 0, true]);
  // Avalanche: PayAI costs 5.7x the price and the price is below Dexter's floor: not offered, and why.
  assert.deepEqual([r["eip155:43114"]?.facilitator, r["eip155:43114"]?.fee_usd, r["eip155:43114"]?.margin_pct, r["eip155:43114"]?.offered, r["eip155:43114"]?.reason], ["payai", 0.00574, -481, false, "unprofitable"]);
  // Everything else is unchanged: CDP for Base, Polygon and Arbitrum, PayAI for Sei, Dexter for Solana.
  assert.deepEqual(["eip155:8453", "eip155:137", "eip155:42161", "eip155:1329", SOL].map((n) => r[n]?.facilitator), ["cdp", "cdp", "cdp", "payai", "dexter"]);
  assert.ok(routes.filter((x) => x.offered).every((x) => (x.margin_usd ?? 0) > 0), "every offered route clears its cost");

  const accepts = buildAccepts({}, undefined, routes);
  assert.deepEqual(accepts.map((a) => a.network), ["eip155:8453", "eip155:137", "eip155:42161", "eip155:143", "eip155:1329", SOL]);
  assert.deepEqual(accepts.find((a) => a.network === "eip155:143")?.extra, { assetTransferMethod: "permit2" });

  // No facilitator is scoped to a network that is not offered.
  const list = routedFacilitators(entries(), routes);
  for (const f of list.slice(0, 3)) assert.ok(!(await f.getSupported()).kinds.some((k) => k.network === "eip155:43114"));
});

test("the network comes back on its own once a route clears its cost again", async () => {
  const cheaper = new Map(payaiFees).set("eip155:43114", 0.0001);
  const r = byNetwork(await paymentRouting({}, entries(cheaper)));
  assert.deepEqual([r["eip155:43114"]?.facilitator, r["eip155:43114"]?.transfer_method, r["eip155:43114"]?.offered, r["eip155:43114"]?.reason], ["payai", "eip3009", true, undefined]);
});

test("an unknown fee is still offered, ranked after known ones; a price below every floor is not", async () => {
  const blind: FacilitatorEntry[] = entries().map((e) => (e.name === "payai" ? { ...e, fees: async () => Promise.reject(new Error("pricing down")) } : e));
  const r = byNetwork(await paymentRouting({}, blind));
  assert.deepEqual([r["eip155:1329"]?.facilitator, r["eip155:1329"]?.margin_usd, r["eip155:1329"]?.offered], ["payai", null, true], "Sei: PayAI only, margin unknown");
  assert.equal(r["eip155:8453"]?.facilitator, "cdp", "a known fee wins over an unknown one");

  const onlyDexter: FacilitatorEntry[] = entries().filter((e) => e.name === "dexter");
  const d = byNetwork(await paymentRouting({}, onlyDexter));
  assert.deepEqual([d["eip155:43114"]?.offered, d["eip155:43114"]?.reason, d["eip155:43114"]?.below_floor], [false, "below_floor", true]);
  assert.deepEqual([d["eip155:1329"]?.offered, d["eip155:1329"]?.reason], [false, "no_facilitator"]);
});

test("every facilitator down: every network is offered except one known to lose money or fall below a floor", () => {
  const route = (network: string, reason: NonNullable<PaymentRoute["reason"]>): PaymentRoute => ({ network, price_usd: 0.001, facilitator: reason === "no_facilitator" ? null : "payai", transfer_method: null, fee_usd: null, floor_usd: null, below_floor: reason === "below_floor", margin_usd: null, margin_pct: null, offered: false, reason });
  const routes = [route("eip155:8453", "no_facilitator"), route("eip155:43114", "unprofitable"), route("eip155:143", "below_floor"), route(SOL, "no_facilitator")];
  assert.deepEqual(buildAccepts({}, undefined, routes).map((a) => a.network), ["eip155:8453", "eip155:137", "eip155:42161", "eip155:1329", SOL]);
});

test("PayAI's fee table survives a failed lookup across routing refreshes (a table read once is reused, not lost)", async () => {
  const { mainnetFacilitators } = await import("../deploy/protected.js");
  const env = { X402_FACILITATOR_URL_PAYAI: "https://payai-fees.test" };
  let pricing: "up" | "down" = "up";
  const realFetch = globalThis.fetch;
  const realNow = Date.now;
  let offset = 0;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url.startsWith("https://payai-fees.test/pricing")) return pricing === "up" ? new Response(JSON.stringify({ rates: [{ network: "eip155:43114", scheme: "exact", transferMethod: "eip3009", usd: "0.00574" }] })) : new Response("down", { status: 503 });
    return realFetch(input, init);
  }) as typeof fetch;
  Date.now = () => realNow() + offset;
  try {
    // Routing builds its facilitator list anew on every refresh: each call here is a new list.
    const first = await mainnetFacilitators(env)[0]?.fees?.();
    assert.equal(first?.get("eip155:43114"), 0.00574);
    offset = 11 * 60_000;
    pricing = "down";
    const later = await mainnetFacilitators(env)[0]?.fees?.();
    assert.equal(later?.get("eip155:43114"), 0.00574, "the last table, not an unknown fee that would put Avalanche back at a loss");
  } finally {
    globalThis.fetch = realFetch;
    Date.now = realNow;
  }
});
