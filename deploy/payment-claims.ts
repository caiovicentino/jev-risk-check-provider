// Single use of a payment. Each x402 payment payload is claimed once, after it verifies and
// before it is evaluated: concurrent or repeated copies of the same PAYMENT-SIGNATURE get a
// 409 instead of N evaluations, N settlements or N credit tokens. Correctness no longer rests
// on every facilitator refusing a duplicate settle (identical Solana transactions share one
// signature, so each settle call could confirm it).
//
// One Durable Object per payment, named by the SHA-256 of what the payer signed (`paymentIdentity`):
// every operation on one payment is serialized, however its JSON is spelled. A claim is released when nothing was settled
// (the payer may retry with the same payment) and kept for a day once it settles.
import type { DurableObjectState, WorkerEnv } from "./runtime.js";

/** How long a settled payment stays claimed. An authorization valid for longer is refused (`admitPayment`). */
export const RETENTION_MS = 24 * 60 * 60 * 1000;

/** Per payer: evaluations in flight that have not settled yet, and settlement failures per hour. */
export const PAYER_INFLIGHT_MAX = 8;
export const PAYER_FAILURES_MAX = 5;
const PAYER_FAILURE_WINDOW_MS = 60 * 60 * 1000;
/** A slot not returned within this time (an isolate that died mid-payment) is forgotten. */
const PAYER_IDLE_MS = 2 * 60 * 1000;

type PayerState = { inflight: number; last: number; failures: number[] };

export class PaymentClaim {
  constructor(private readonly state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const op = new URL(request.url).pathname.slice(1);
    const current = await this.state.storage.get<{ state: "pending" | "settled"; at: number }>("claim");
    if (op === "claim") {
      if (current) return Response.json({ claimed: false, state: current.state }, { status: 409 });
      await this.state.storage.put("claim", { state: "pending", at: Date.now() });
      await this.state.storage.setAlarm(Date.now() + RETENTION_MS);
      return Response.json({ claimed: true });
    }
    if (op === "settled") {
      await this.state.storage.put("claim", { state: "settled", at: Date.now() });
      return Response.json({ ok: true });
    }
    if (op === "release") {
      if (current?.state === "pending") await this.state.storage.delete("claim");
      return Response.json({ ok: true });
    }
    // Per-payer objects ("payer:<address>"): a payer's payments are verified before they settle, so
    // one funded wallet could sign many that verify and never settle. Each is evaluated only within
    // a few in flight at once, and a payer whose payments keep failing to settle is held back.
    if (op === "acquire" || op === "done" || op === "fail") {
      const now = Date.now();
      const s = (await this.state.storage.get<PayerState>("payer")) ?? { inflight: 0, last: 0, failures: [] };
      if (now - s.last > PAYER_IDLE_MS) s.inflight = 0;
      s.failures = s.failures.filter((t) => now - t < PAYER_FAILURE_WINDOW_MS);
      if (op === "acquire") {
        if (s.failures.length >= PAYER_FAILURES_MAX) {
          const retry = Math.ceil(((s.failures[0] as number) + PAYER_FAILURE_WINDOW_MS - now) / 1000);
          return Response.json({ ok: false, reason: "failures", retry_after: retry }, { status: 429 });
        }
        if (s.inflight >= PAYER_INFLIGHT_MAX) return Response.json({ ok: false, reason: "busy", retry_after: 5 }, { status: 429 });
        s.inflight++;
        s.last = now;
      } else {
        s.inflight = Math.max(0, s.inflight - 1);
        if (op === "fail") s.failures.push(now);
      }
      await this.state.storage.put("payer", s);
      // Everything here is stale an hour after the last operation: the alarm then clears it.
      await this.state.storage.setAlarm(now + PAYER_FAILURE_WINDOW_MS + 1000);
      return Response.json({ ok: true });
    }
    return Response.json({ error: "not_found" }, { status: 404 });
  }

  async alarm(): Promise<void> {
    await this.state.storage.deleteAll();
  }
}

async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** The message bytes of a base64 wire transaction (what the payer signed), or null. */
function svmMessageBytes(base64: string): Uint8Array | null {
  try {
    const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
    let count = 0;
    let at = 0;
    for (let shift = 0; shift < 21; shift += 7) {
      const b = bytes[at++];
      if (b === undefined) return null;
      count |= (b & 0x7f) << shift;
      if (!(b & 0x80)) break;
    }
    const start = at + 64 * count;
    return start < bytes.length ? bytes.subarray(start) : null;
  } catch {
    return null;
  }
}

/**
 * The one scheme payload a payment carries, for the route it was paid against: a Solana network
 * takes only `transaction`; an EVM route takes `permit2Authorization` when it is a Permit2 route
 * (`accepted.extra.assetTransferMethod`), else `authorization` (EIP-3009). Anything else is null,
 * and refused: a facilitator verifies one of these and ignores the others, so a decoy object next
 * to the real one must never be what the payer screen, single use or the validity window read.
 * (`accepted` is one of our own requirements: x402 core matches it exactly.)
 */
export type SchemePayload =
  | { kind: "eip3009"; network: string; asset: string; from: string; nonce: string; validBefore: unknown }
  | { kind: "permit2"; network: string; from: string; nonce: string; deadline: unknown }
  | { kind: "svm"; network: string; transaction: string };

const SCHEME_KEYS = ["authorization", "permit2Authorization", "transaction"] as const;

export function paymentScheme(paymentPayload: unknown): SchemePayload | null {
  const pp = paymentPayload as { accepted?: { network?: unknown; asset?: unknown; extra?: { assetTransferMethod?: unknown } | null }; payload?: unknown } | null;
  const p = pp?.payload as Record<string, unknown> | undefined;
  if (!pp || !p || typeof p !== "object" || Array.isArray(p)) return null;
  const network = typeof pp.accepted?.network === "string" ? pp.accepted.network : "";
  const present = SCHEME_KEYS.filter((k) => Object.hasOwn(p, k));
  if (present.length !== 1) return null;
  const key = present[0];
  if (network.startsWith("solana:")) {
    return key === "transaction" && typeof p.transaction === "string" ? { kind: "svm", network, transaction: p.transaction } : null;
  }
  if (!network.startsWith("eip155:")) return null;
  if (pp.accepted?.extra?.assetTransferMethod === "permit2") {
    const a = key === "permit2Authorization" ? (p.permit2Authorization as { from?: unknown; nonce?: unknown; deadline?: unknown } | null) : null;
    if (!a || typeof a !== "object" || typeof a.from !== "string" || !(typeof a.nonce === "string" || typeof a.nonce === "number")) return null;
    let nonce: string;
    try {
      nonce = BigInt(a.nonce).toString();
    } catch {
      return null;
    }
    return { kind: "permit2", network, from: a.from, nonce, deadline: a.deadline };
  }
  const a = key === "authorization" ? (p.authorization as { from?: unknown; nonce?: unknown; validBefore?: unknown } | null) : null;
  if (!a || typeof a !== "object" || typeof a.from !== "string" || typeof a.nonce !== "string") return null;
  return { kind: "eip3009", network, asset: String(pp.accepted?.asset ?? ""), from: a.from, nonce: a.nonce, validBefore: a.validBefore };
}

/**
 * A payment's identity, from what the payer signed, never from how the JSON is spelled:
 * key order, whitespace, extra fields, hex case or base64 padding all name the same payment.
 * - EIP-3009: network, asset, payer and nonce (one authorization per nonce);
 * - Permit2: network, owner and nonce (Permit2 nonces are single-use per owner);
 * - Solana: the transaction message bytes (the fee payer signs the rest).
 * Null for a payload `paymentScheme` refuses: such a payment is refused, not let through.
 */
export async function paymentIdentity(paymentPayload: unknown): Promise<string | null> {
  const s = paymentScheme(paymentPayload);
  if (!s) return null;
  const network = s.network.toLowerCase();
  if (s.kind === "eip3009") return sha256Hex(`eip3009|${network}|${s.asset.toLowerCase()}|${s.from.toLowerCase()}|${s.nonce.toLowerCase()}`);
  if (s.kind === "permit2") return sha256Hex(`permit2|${network}|${s.from.toLowerCase()}|${s.nonce}`);
  const message = svmMessageBytes(s.transaction);
  if (!message) return null;
  const prefix = new TextEncoder().encode(`svm|${network}|`);
  const material = new Uint8Array(prefix.length + message.length);
  material.set(prefix);
  material.set(message, prefix.length);
  return sha256Hex(material);
}

/**
 * A settlement's identity: one on-chain transaction is never two payments. `network` is the
 * requirement the payment matched (not what the facilitator reports); an EVM hash is lowercased,
 * a Solana signature (base58, case-sensitive) is kept as is.
 */
export async function settlementIdentity(network: string, transaction: string): Promise<string> {
  const tx = /^0x[0-9a-fA-F]+$/.test(transaction) ? transaction.toLowerCase() : transaction;
  return sha256Hex(`tx|${network.toLowerCase()}|${tx}`);
}

/** The x402 protocol version a PAYMENT-SIGNATURE declares (null when it does not decode). */
export function paymentVersion(header: string | null): number | null {
  if (!header) return null;
  try {
    const v = (JSON.parse(atob(header)) as { x402Version?: unknown }).x402Version;
    return typeof v === "number" ? v : null;
  } catch {
    return null;
  }
}

export type Claim = { claimed: true; settled: () => Promise<void>; release: () => Promise<void> } | { claimed: false; reason: "duplicate" | "unavailable" | "unidentified" };

/**
 * Claims a payment. Without the Durable Object binding (local development, tests) every payment
 * is claimable; with it, a failure to reach the object refuses the payment (no double spend).
 */
export async function claimPayment(env: WorkerEnv, id: string | null): Promise<Claim> {
  const ns = env.PAYMENT_CLAIMS;
  if (!ns) return { claimed: true, settled: async () => undefined, release: async () => undefined };
  // With the claim store bound, a payment it cannot identify is refused: single use must hold for every payment.
  if (!id) return { claimed: false, reason: "unidentified" };
  const stub = ns.get(ns.idFromName(id));
  const call = (op: string) => stub.fetch(`https://claims/${op}`, { method: "POST" });
  try {
    const res = await call("claim");
    if (res.status === 409) return { claimed: false, reason: "duplicate" };
    if (!res.ok) return { claimed: false, reason: "unavailable" };
  } catch {
    return { claimed: false, reason: "unavailable" };
  }
  return {
    claimed: true,
    settled: async () => {
      await call("settled").catch((err: unknown) => console.error(`payment claim: settled mark failed: ${String(err).slice(0, 120)}`));
    },
    release: async () => {
      await call("release").catch((err: unknown) => console.error(`payment claim: release failed: ${String(err).slice(0, 120)}`));
    },
  };
}

export type PayerSlot = { ok: true; done: (failed: boolean) => Promise<void> } | { ok: false; reason: "failures" | "busy"; retryAfter: number };

/**
 * Takes one of the payer's in-flight slots. Fails open when the claim store is unreachable or the
 * payer cannot be read: single use still holds through the payment's own claim.
 */
export async function acquirePayerSlot(env: WorkerEnv, payer: string | null): Promise<PayerSlot> {
  const ns = env.PAYMENT_CLAIMS;
  const open: PayerSlot = { ok: true, done: async () => undefined };
  if (!ns || !payer) return open;
  const stub = ns.get(ns.idFromName(`payer:${payer.startsWith("0x") ? payer.toLowerCase() : payer}`));
  try {
    const res = await stub.fetch("https://claim/acquire", { method: "POST" });
    if (res.status === 429) {
      const body = (await res.json()) as { reason?: "failures" | "busy"; retry_after?: number };
      return { ok: false, reason: body.reason ?? "busy", retryAfter: Math.max(1, Number(body.retry_after) || 5) };
    }
    if (!res.ok) return open;
  } catch (err) {
    console.error(`payer slot unavailable: ${String(err).slice(0, 120)}`);
    return open;
  }
  return {
    ok: true,
    done: async (failed) => {
      await stub.fetch(`https://claim/${failed ? "fail" : "done"}`, { method: "POST" }).catch((err: unknown) => console.error(`payer slot release: ${String(err).slice(0, 120)}`));
    },
  };
}
